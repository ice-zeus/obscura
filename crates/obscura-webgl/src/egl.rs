//! ANGLE EGL ownership. Displays/libraries are lazily shared for process life;
//! contexts and their draw surfaces belong to one thread and one canvas.
use crate::{bundle::Bundle, selection::Backend};
use libloading::Library;
use std::{
    collections::HashMap,
    ffi::{c_char, c_void, CStr},
    marker::PhantomData,
    ptr,
    rc::Rc,
    sync::{Arc, Mutex, OnceLock},
};

type Handle = *mut c_void;
type Int = i32;
const NONE: Int = 0x3038;
const TRUE: Int = 1;
const FALSE: Int = 0;

macro_rules! egl_functions {
    ($($field:ident: $name:literal ($($arg:ty),*) -> $result:ty;)*) => {
        struct Functions { $( $field: unsafe extern "C" fn($($arg),*) -> $result, )* }
        impl Functions {
            unsafe fn load(library: &Library) -> Result<Self,String> {
                Ok(Self { $( $field: *library.get::<unsafe extern "C" fn($($arg),*) -> $result>(concat!($name,"\0").as_bytes()).map_err(|e|e.to_string())?, )* })
            }
        }
    }
}
egl_functions! {
    get_proc_address: "eglGetProcAddress" (*const c_char) -> *const c_void;
    initialize: "eglInitialize" (Handle,*mut Int,*mut Int) -> u32;
    terminate: "eglTerminate" (Handle) -> u32;
    bind_api: "eglBindAPI" (u32) -> u32;
    choose_config: "eglChooseConfig" (Handle,*const Int,*mut Handle,Int,*mut Int) -> u32;
    get_config_attrib: "eglGetConfigAttrib" (Handle,Handle,Int,*mut Int) -> u32;
    create_context: "eglCreateContext" (Handle,Handle,Handle,*const Int) -> Handle;
    destroy_context: "eglDestroyContext" (Handle,Handle) -> u32;
    create_pbuffer: "eglCreatePbufferSurface" (Handle,Handle,*const Int) -> Handle;
    destroy_surface: "eglDestroySurface" (Handle,Handle) -> u32;
    make_current: "eglMakeCurrent" (Handle,Handle,Handle,Handle) -> u32;
    swap_buffers: "eglSwapBuffers" (Handle,Handle) -> u32;
    query_string: "eglQueryString" (Handle,Int) -> *const c_char;
    get_error: "eglGetError" () -> Int;
}

struct Libraries {
    _egl: Library,
    _gles: Library,
    functions: Functions,
    bundle: Bundle,
}
impl Libraries {
    fn open() -> Result<Self, String> {
        let bundle = Bundle::discover()?;
        if cfg!(target_os = "linux") {
            // ANGLE opens this dependency internally from its module directory.
            // Verify it before loading native code, just like EGL and GLES.
            bundle.verify_vulkan_loader()?;
        }
        let suffix = if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };
        let egl_path = bundle.library(&format!("libEGL.{suffix}"))?;
        let gles_path = bundle.library(&format!("libGLESv2.{suffix}"))?;
        // Only host-controlled, pinned and verified native libraries are loaded.
        unsafe {
            let gles = Library::new(gles_path).map_err(|e| format!("GLES library: {e}"))?;
            let egl = Library::new(egl_path).map_err(|e| format!("EGL library: {e}"))?;
            let functions = Functions::load(&egl)?;
            Ok(Self {
                _egl: egl,
                _gles: gles,
                functions,
                bundle,
            })
        }
    }
    fn error(&self, operation: &str) -> String {
        format!("{operation} failed (EGL 0x{:04x})", unsafe {
            (self.functions.get_error)()
        })
    }
    unsafe fn symbol(&self, name: &CStr) -> *const c_void {
        // dlsym on a GLES library may search its dependencies and return a
        // desktop GL function from the system driver. ANGLE's own procedure
        // table returns only supported entry points from the pinned build.
        (self.functions.get_proc_address)(name.as_ptr())
    }
}

struct Display {
    backend: Backend,
    libraries: Arc<Libraries>,
    handle: usize,
}
impl Display {
    fn handle(&self) -> Handle {
        self.handle as Handle
    }
    fn acquire(backend: Backend) -> Result<Arc<Self>, String> {
        static LIBRARIES: OnceLock<Result<Arc<Libraries>, String>> = OnceLock::new();
        static DISPLAYS: OnceLock<Mutex<HashMap<Backend, Arc<Display>>>> = OnceLock::new();
        let libraries = LIBRARIES
            .get_or_init(|| Libraries::open().map(Arc::new))
            .clone()?;
        let mut displays = DISPLAYS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| "graphics display cache poisoned")?;
        if let Some(display) = displays.get(&backend) {
            return Ok(display.clone());
        }
        if backend == Backend::SwiftShader {
            libraries.bundle.library("libvk_swiftshader.so")?;
            libraries.bundle.library("vk_swiftshader_icd.json")?;
        }
        let attributes = display_attributes(backend);
        unsafe {
            type GetDisplay = unsafe extern "C" fn(u32, Handle, *const Int) -> Handle;
            let name = c"eglGetPlatformDisplayEXT";
            let address = (libraries.functions.get_proc_address)(name.as_ptr());
            if address.is_null() {
                return Err("ANGLE has no eglGetPlatformDisplayEXT".into());
            }
            let get_display: GetDisplay = std::mem::transmute(address);
            let handle = get_display(0x3202, ptr::null_mut(), attributes.as_ptr());
            if handle.is_null() {
                return Err(libraries.error("get ANGLE display"));
            }
            if (libraries.functions.initialize)(handle, ptr::null_mut(), ptr::null_mut()) == 0 {
                return Err(libraries.error("initialize ANGLE display"));
            }
            let extensions = (libraries.functions.query_string)(handle, 0x3055);
            let extensions = if extensions.is_null() {
                ""
            } else {
                CStr::from_ptr(extensions).to_str().unwrap_or("")
            };
            // Browser memory safety relies on robust buffer access and zeroed
            // resources. Never silently run against a non-WebGL GLES context.
            for required in [
                "EGL_ANGLE_create_context_webgl_compatibility",
                "EGL_ANGLE_robust_resource_initialization",
                "EGL_ANGLE_create_context_client_arrays",
                "EGL_ANGLE_create_context_extensions_enabled",
                "EGL_EXT_create_context_robustness",
            ] {
                if !extensions.split_ascii_whitespace().any(|e| e == required) {
                    (libraries.functions.terminate)(handle);
                    return Err(format!("ANGLE display lacks {required}"));
                }
            }
            let display = Arc::new(Self {
                backend,
                libraries,
                handle: handle as usize,
            });
            displays.insert(backend, display.clone());
            Ok(display)
        }
    }
}

fn display_attributes(backend: Backend) -> Vec<Int> {
    let renderer = if backend == Backend::Metal {
        0x3489
    } else {
        0x3450
    };
    let device = if backend == Backend::SwiftShader {
        0x3487
    } else {
        0x320A
    };
    let mut attributes = vec![0x3203, renderer, 0x3209, device];
    if backend != Backend::Metal {
        // Explicit offscreen Vulkan platform, independent of DISPLAY/Wayland.
        attributes.extend_from_slice(&[0x348F, 0x31DD]);
    }
    attributes.push(NONE);
    attributes
}
fn context_attributes(version: u8) -> Result<Vec<Int>, String> {
    let major = match version {
        1 => 2,
        2 => 3,
        _ => return Err("unsupported WebGL version".into()),
    };
    Ok(vec![
        0x3098, major, 0x30FB, 0, // exact ES version; ES3.1 is not WebGL2
        0x3483, FALSE, // EGL_CONTEXT_OPENGL_BACKWARDS_COMPATIBLE_ANGLE
        0x33AC, TRUE, // EGL_CONTEXT_WEBGL_COMPATIBILITY_ANGLE
        0x3452, FALSE, // never permit client-side vertex array pointers
        0x3453, TRUE, // initialize resources before page data can read them
        0x345F, FALSE, // enable extensions only after WebGL getExtension validation
        0x30BF, TRUE, // EGL_CONTEXT_OPENGL_ROBUST_ACCESS_EXT
        0x3138, 0x31BF, // lose context on device reset
        NONE,
    ])
}

#[derive(Clone, Copy, Debug)]
pub struct SurfaceOptions {
    pub alpha: bool,
    pub depth: bool,
    pub stencil: bool,
    pub antialias: bool,
}

/// No Send/Sync: makeCurrent state and GL object names never leave the owning
/// browser thread. Deleting a profile drops every context before its runtime.
pub struct Context {
    display: Arc<Display>,
    config: usize,
    context: usize,
    surface: usize,
    pub gl: glow::Context,
    pub samples: u32,
    pub depth_bits: u32,
    pub stencil_bits: u32,
    width: u32,
    height: u32,
    _thread: PhantomData<Rc<()>>,
}

// The borrowed function table remains valid through the display/library owner.
// Keeping handle ownership independent of dynamic loading lets unit tests drive
// every partial-allocation failure without pretending to provide a GL renderer.
struct PendingContext<'a> {
    functions: &'a Functions,
    display: Handle,
    context: Handle,
    surface: Handle,
}
impl Drop for PendingContext<'_> {
    fn drop(&mut self) {
        unsafe {
            release_handles(self.functions, self.display, self.context, self.surface);
        }
    }
}
unsafe fn release_handles(f: &Functions, display: Handle, context: Handle, surface: Handle) {
    if !context.is_null() {
        (f.make_current)(display, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        (f.destroy_context)(display, context);
    }
    if !surface.is_null() {
        (f.destroy_surface)(display, surface);
    }
}
unsafe fn allocate_context<'a>(
    f: &'a Functions,
    display: Handle,
    config: Handle,
    context_attrs: &[Int],
    surface_attrs: &[Int],
    backend: Backend,
    error: impl Fn(&str) -> String,
) -> Result<PendingContext<'a>, String> {
    let context = (f.create_context)(display, config, ptr::null_mut(), context_attrs.as_ptr());
    if context.is_null() {
        return Err(error("create WebGL-compatible context"));
    }
    let mut pending = PendingContext {
        functions: f,
        display,
        context,
        surface: ptr::null_mut(),
    };
    pending.surface = (f.create_pbuffer)(display, config, surface_attrs.as_ptr());
    if pending.surface.is_null() {
        return Err(error("allocate WebGL drawing buffer"));
    }
    if (f.make_current)(display, pending.surface, pending.surface, context) == 0 {
        return Err(error("activate WebGL context"));
    }
    // Pinned ANGLE Metal allocates pbuffer attachments lazily. Its robust
    // initialization path can clear them before allocation. A pbuffer swap
    // allocates those attachments without exposing or reading their contents.
    // Keep robust initialization enabled for both the context and surface.
    if backend == Backend::Metal && (f.swap_buffers)(display, pending.surface) == 0 {
        return Err(error("initialize Metal WebGL drawing buffer"));
    }
    Ok(pending)
}
unsafe fn replace_surface(
    f: &Functions,
    display: Handle,
    config: Handle,
    context: Handle,
    previous: Handle,
    attrs: &[Int],
    backend: Backend,
    error: impl Fn(&str) -> String,
) -> Result<Handle, String> {
    let replacement = (f.create_pbuffer)(display, config, attrs.as_ptr());
    if replacement.is_null() {
        return Err(error("resize WebGL drawing buffer"));
    }
    if (f.make_current)(display, replacement, replacement, context) == 0 {
        let reason = error("activate resized WebGL buffer");
        (f.destroy_surface)(display, replacement);
        return Err(reason);
    }
    if backend == Backend::Metal && (f.swap_buffers)(display, replacement) == 0 {
        let mut reason = error("initialize resized Metal WebGL buffer");
        // The replacement is current, but the old surface is still owned.
        // Restore it before discarding the failed allocation. If restoration
        // also fails, release the current binding and report both failures.
        if (f.make_current)(display, previous, previous, context) == 0 {
            reason.push_str("; ");
            reason.push_str(&error("restore previous WebGL buffer"));
            (f.make_current)(display, ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        }
        (f.destroy_surface)(display, replacement);
        return Err(reason);
    }
    (f.destroy_surface)(display, previous);
    Ok(replacement)
}

pub fn backing_size(width: u32, height: u32) -> Result<(u32, u32), String> {
    // A zero-size HTML canvas still has a valid GL context with a 1x1 backing
    // store. Canvas serialization remains empty for a zero-size canvas.
    let size = (width.max(1), height.max(1));
    if size.0 > 32767 || size.1 > 32767 || u64::from(size.0) * u64::from(size.1) > 16_777_216 {
        Err("WebGL drawing buffer allocation exceeds the canvas limit".into())
    } else {
        Ok(size)
    }
}

// Disabled buffers must stay absent; requested depth/stencil/MSAA are
// preferences. Hardware that lacks a preferred combination may use fewer.
fn config_score(options: SurfaceOptions, sizes: [i32; 4]) -> Option<i32> {
    let [alpha, depth, stencil, samples] = sizes;
    if sizes.iter().any(|n| *n < 0)
        || (options.alpha && alpha < 8)
        || (!options.alpha && alpha != 0)
        || (!options.depth && depth != 0)
        || (!options.stencil && stencil != 0)
        || (!options.antialias && samples != 0)
    {
        return None;
    }
    Some(
        i32::from(options.depth && depth >= 16) * 100
            + i32::from(options.stencil && stencil >= 8) * 100
            + if options.antialias { samples.min(4) } else { 0 },
    )
}

impl Context {
    pub fn create(
        backend: Backend,
        version: u8,
        width: u32,
        height: u32,
        options: SurfaceOptions,
    ) -> Result<Self, String> {
        let attributes = context_attributes(version)?;
        let (width, height) = backing_size(width, height)?;
        let display = Display::acquire(backend)?;
        unsafe {
            let f = &display.libraries.functions;
            let d = display.handle();
            if (f.bind_api)(0x30A0) == 0 {
                return Err(display.libraries.error("bind OpenGL ES API"));
            }
            // EGL size requests are minima: asking for zero alpha/depth does
            // not exclude a larger buffer. Inspect each candidate explicitly.
            let config_attrs = [
                0x3033,
                1,
                0x3040,
                if version == 2 { 0x0040 } else { 0x0004 },
                0x3024,
                8,
                0x3023,
                8,
                0x3022,
                8,
                NONE,
            ];
            let mut count = 0;
            if (f.choose_config)(d, config_attrs.as_ptr(), ptr::null_mut(), 0, &mut count) == 0
                || !(1..=4096).contains(&count)
            {
                return Err(display.libraries.error("enumerate WebGL configurations"));
            }
            let mut configs = vec![ptr::null_mut(); count as usize];
            let capacity = count;
            if (f.choose_config)(
                d,
                config_attrs.as_ptr(),
                configs.as_mut_ptr(),
                capacity,
                &mut count,
            ) == 0
            {
                return Err(display.libraries.error("read WebGL configurations"));
            }
            let mut selected = None;
            for &candidate in configs.iter().take(count.max(0) as usize) {
                let mut values = [0; 4];
                if ![0x3021, 0x3025, 0x3026, 0x3031]
                    .iter()
                    .zip(&mut values)
                    .all(|(&name, value)| (f.get_config_attrib)(d, candidate, name, value) != 0)
                {
                    continue;
                }
                if let Some(score) = config_score(options, values) {
                    if selected.as_ref().is_none_or(|(best, _, _)| score > *best) {
                        selected = Some((score, candidate, values));
                    }
                }
            }
            let Some((_, config, config_sizes)) = selected else {
                return Err(
                    "no EGL configuration honors WebGL alpha/depth/stencil/antialias exclusions"
                        .into(),
                );
            };
            let surface_attrs = [
                0x3057,
                width as Int,
                0x3056,
                height as Int,
                0x3453,
                TRUE,
                NONE,
            ];
            let mut pending = allocate_context(f, d, config, &attributes, &surface_attrs, backend, |op| {
                display.libraries.error(op)
            })?;
            let gl = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                glow::Context::from_loader_function_cstr(|name| display.libraries.symbol(name))
            }))
            .map_err(|_| "ANGLE GLES entry points are incomplete")?;
            let mut samples = 0;
            if (f.get_config_attrib)(d, config, 0x3031, &mut samples) == 0 {
                return Err(display.libraries.error("query drawing buffer samples"));
            }
            let surface = pending.surface;
            let context = pending.context;
            pending.context = ptr::null_mut();
            pending.surface = ptr::null_mut();
            drop(pending);
            Ok(Self {
                display,
                config: config as usize,
                context: context as usize,
                surface: surface as usize,
                gl,
                samples: samples.max(0) as u32,
                depth_bits: config_sizes[1].max(0) as u32,
                stencil_bits: config_sizes[2].max(0) as u32,
                width,
                height,
                _thread: PhantomData,
            })
        }
    }
    pub fn make_current(&self) -> Result<(), String> {
        unsafe {
            let f = &self.display.libraries.functions;
            if (f.make_current)(
                self.display.handle(),
                self.surface as Handle,
                self.surface as Handle,
                self.context as Handle,
            ) == 0
            {
                Err(self.display.libraries.error("activate WebGL context"))
            } else {
                Ok(())
            }
        }
    }

    /// ANGLE exposes a few GLES entry points that glow does not wrap. Callers
    /// supply a static symbol and its exact GLES ABI, never a page-provided name.
    pub(crate) unsafe fn entry<T: Copy>(&self, name: &std::ffi::CStr) -> Result<T, u32> {
        let address = self.display.libraries.symbol(name);
        if address.is_null() || std::mem::size_of::<T>() != std::mem::size_of_val(&address) {
            return Err(glow::INVALID_OPERATION);
        }
        Ok(std::mem::transmute_copy(&address))
    }
    pub fn resize(&mut self, width: u32, height: u32) -> Result<(), String> {
        let (width, height) = backing_size(width, height)?;
        // Even assigning identical dimensions resets the drawing buffer.
        unsafe {
            let f = &self.display.libraries.functions;
            let d = self.display.handle();
            let attrs = [
                0x3057,
                width as Int,
                0x3056,
                height as Int,
                0x3453,
                TRUE,
                NONE,
            ];
            let replacement = replace_surface(
                f,
                d,
                self.config as Handle,
                self.context as Handle,
                self.surface as Handle,
                &attrs,
                self.display.backend,
                |op| self.display.libraries.error(op),
            )?;
            self.surface = replacement as usize;
            self.width = width;
            self.height = height;
            Ok(())
        }
    }
    pub fn proc_address(&self, name: &CStr) -> *const c_void {
        unsafe { self.display.libraries.symbol(name) }
    }
}
impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            let f = &self.display.libraries.functions;
            let d = self.display.handle();
            release_handles(f, d, self.context as Handle, self.surface as Handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Clone, Copy, Default, PartialEq)]
    enum Failure {
        #[default]
        None,
        Context,
        Surface,
        Activate,
        Prime,
        PrimeAndRestore,
        Destroy,
    }
    #[derive(Default)]
    struct FakeEgl {
        failure: Failure,
        calls: Vec<(&'static str, usize)>,
        current_surfaces: Vec<usize>,
    }
    thread_local! { static FAKE:RefCell<FakeEgl>=RefCell::new(FakeEgl::default()); }
    fn reset(failure: Failure) {
        FAKE.with(|f| {
            *f.borrow_mut() = FakeEgl {
                failure,
                calls: Vec::new(),
                current_surfaces: Vec::new(),
            }
        });
    }
    fn calls() -> Vec<(&'static str, usize)> {
        FAKE.with(|f| f.borrow().calls.clone())
    }
    fn record(name: &'static str, handle: usize) -> Failure {
        FAKE.with(|f| {
            let mut f = f.borrow_mut();
            f.calls.push((name, handle));
            f.failure
        })
    }
    unsafe extern "C" fn create_context(_: Handle, _: Handle, _: Handle, _: *const Int) -> Handle {
        if record("create_context", 10) == Failure::Context {
            ptr::null_mut()
        } else {
            10usize as Handle
        }
    }
    unsafe extern "C" fn create_surface(_: Handle, _: Handle, _: *const Int) -> Handle {
        if record("create_surface", 20) == Failure::Surface {
            ptr::null_mut()
        } else {
            20usize as Handle
        }
    }
    unsafe extern "C" fn make_current(_: Handle, surface: Handle, _: Handle, context: Handle) -> u32 {
        let failure = record("make_current", context as usize);
        FAKE.with(|f| f.borrow_mut().current_surfaces.push(surface as usize));
        u32::from(context.is_null() || (failure != Failure::Activate
            && !(failure == Failure::PrimeAndRestore && surface as usize == 30)))
    }
    unsafe extern "C" fn swap_buffers(_: Handle, surface: Handle) -> u32 {
        let failure = record("swap_buffers", surface as usize);
        u32::from(!matches!(failure, Failure::Prime | Failure::PrimeAndRestore))
    }
    unsafe extern "C" fn destroy_context(_: Handle, context: Handle) -> u32 {
        u32::from(record("destroy_context", context as usize) != Failure::Destroy)
    }
    unsafe extern "C" fn destroy_surface(_: Handle, surface: Handle) -> u32 {
        u32::from(record("destroy_surface", surface as usize) != Failure::Destroy)
    }
    unsafe extern "C" fn get_proc_address(_: *const c_char) -> *const c_void {
        ptr::null()
    }
    unsafe extern "C" fn initialize(_: Handle, _: *mut Int, _: *mut Int) -> u32 {
        0
    }
    unsafe extern "C" fn terminate(_: Handle) -> u32 {
        0
    }
    unsafe extern "C" fn bind_api(_: u32) -> u32 {
        0
    }
    unsafe extern "C" fn choose_config(
        _: Handle,
        _: *const Int,
        _: *mut Handle,
        _: Int,
        _: *mut Int,
    ) -> u32 {
        0
    }
    unsafe extern "C" fn get_config_attrib(_: Handle, _: Handle, _: Int, _: *mut Int) -> u32 {
        0
    }
    unsafe extern "C" fn query_string(_: Handle, _: Int) -> *const c_char {
        ptr::null()
    }
    unsafe extern "C" fn get_error() -> Int {
        0x3003
    }
    fn functions() -> Functions {
        Functions {
            get_proc_address,
            initialize,
            terminate,
            bind_api,
            choose_config,
            get_config_attrib,
            create_context,
            destroy_context,
            create_pbuffer: create_surface,
            destroy_surface,
            make_current,
            swap_buffers,
            query_string,
            get_error,
        }
    }
    unsafe fn allocate(f: &Functions) -> Result<PendingContext<'_>, String> {
        allocate_context(
            f,
            1usize as Handle,
            2usize as Handle,
            &[NONE],
            &[NONE],
            Backend::Vulkan,
            str::to_owned,
        )
    }
    #[test]
    fn partial_context_allocation_releases_each_acquired_handle_once() {
        let f = functions();
        for (failure, message, expected) in [
            (
                Failure::Context,
                "create WebGL-compatible context",
                vec![("create_context", 10)],
            ),
            (
                Failure::Surface,
                "allocate WebGL drawing buffer",
                vec![
                    ("create_context", 10),
                    ("create_surface", 20),
                    ("make_current", 0),
                    ("destroy_context", 10),
                ],
            ),
            (
                Failure::Activate,
                "activate WebGL context",
                vec![
                    ("create_context", 10),
                    ("create_surface", 20),
                    ("make_current", 10),
                    ("make_current", 0),
                    ("destroy_context", 10),
                    ("destroy_surface", 20),
                ],
            ),
        ] {
            reset(failure);
            assert_eq!(unsafe { allocate(&f) }.err().as_deref(), Some(message));
            assert_eq!(calls(), expected);
        }
    }
    #[test]
    fn failures_after_activation_and_unwinding_still_release_both_handles() {
        let f = functions();
        reset(Failure::None);
        let result = std::panic::catch_unwind(|| unsafe {
            let _pending = allocate(&f).unwrap();
            // Mirrors a missing GLES symbol or another error after activation.
            panic!("injected loader failure");
        });
        assert!(result.is_err());
        assert_eq!(
            calls(),
            vec![
                ("create_context", 10),
                ("create_surface", 20),
                ("make_current", 10),
                ("make_current", 0),
                ("destroy_context", 10),
                ("destroy_surface", 20)
            ]
        );
    }
    #[test]
    fn committed_handles_are_destroyed_by_the_final_owner_only() {
        let f = functions();
        reset(Failure::None);
        let mut pending = unsafe { allocate(&f) }.unwrap();
        let (context, surface) = (pending.context, pending.surface);
        pending.context = ptr::null_mut();
        pending.surface = ptr::null_mut();
        drop(pending);
        assert_eq!(calls().len(), 3);
        unsafe {
            release_handles(&f, 1usize as Handle, context, surface);
        }
        assert_eq!(
            &calls()[3..],
            &[
                ("make_current", 0),
                ("destroy_context", 10),
                ("destroy_surface", 20)
            ]
        );
    }
    #[test]
    fn resize_keeps_the_old_surface_until_replacement_activation_succeeds() {
        let f = functions();
        for (failure, expected, result) in [
            (Failure::Surface, vec![("create_surface", 20)], false),
            (
                Failure::Activate,
                vec![
                    ("create_surface", 20),
                    ("make_current", 10),
                    ("destroy_surface", 20),
                ],
                false,
            ),
            (
                Failure::None,
                vec![
                    ("create_surface", 20),
                    ("make_current", 10),
                    ("destroy_surface", 30),
                ],
                true,
            ),
        ] {
            reset(failure);
            let replacement = unsafe {
                replace_surface(
                    &f,
                    1usize as Handle,
                    2usize as Handle,
                    10usize as Handle,
                    30usize as Handle,
                    &[NONE],
                    Backend::Vulkan,
                    str::to_owned,
                )
            };
            assert_eq!(replacement.is_ok(), result);
            assert_eq!(calls(), expected);
            if let Ok(surface) = replacement {
                assert_eq!(surface as usize, 20);
            }
        }
    }
    #[test]
    fn metal_pbuffer_initialization_precedes_gl_and_releases_failed_allocations() {
        let f = functions();
        for failure in [Failure::None, Failure::Prime] {
            reset(failure);
            let result = unsafe { allocate_context(&f, 1usize as Handle, 2usize as Handle,
                &[NONE], &[NONE], Backend::Metal, str::to_owned) };
            assert_eq!(result.is_ok(), failure == Failure::None);
            if failure == Failure::Prime {
                assert_eq!(result.as_ref().err().map(String::as_str),
                    Some("initialize Metal WebGL drawing buffer"));
            }
            drop(result);
            assert_eq!(calls(), vec![("create_context",10),("create_surface",20),
                ("make_current",10),("swap_buffers",20),("make_current",0),
                ("destroy_context",10),("destroy_surface",20)]);
        }
    }
    #[test]
    fn metal_resize_initializes_before_retiring_old_surface_and_rolls_back_failures() {
        let f = functions();
        for failure in [Failure::None, Failure::Prime, Failure::PrimeAndRestore] {
            reset(failure);
            let result = unsafe { replace_surface(&f, 1usize as Handle, 2usize as Handle,
                10usize as Handle, 30usize as Handle, &[NONE], Backend::Metal, str::to_owned) };
            assert_eq!(result.is_ok(), failure == Failure::None);
            let mut expected = vec![("create_surface",20),("make_current",10),("swap_buffers",20)];
            let mut surfaces = vec![20];
            if failure == Failure::None {
                assert_eq!(result.unwrap() as usize,20);
                expected.push(("destroy_surface",30));
            } else {
                let reason = result.unwrap_err();
                assert!(reason.starts_with("initialize resized Metal WebGL buffer"));
                expected.push(("make_current",10));
                surfaces.push(30);
                if failure == Failure::PrimeAndRestore {
                    assert!(reason.contains("restore previous WebGL buffer"));
                    expected.push(("make_current",0));
                    surfaces.push(0);
                }
                expected.push(("destroy_surface",20));
            }
            assert_eq!(calls(), expected);
            FAKE.with(|f| assert_eq!(f.borrow().current_surfaces, surfaces));
        }
    }
    #[test]
    fn cleanup_handles_empty_surface_only_and_failed_driver_destruction() {
        let f = functions();
        reset(Failure::None);
        unsafe {
            release_handles(&f, 1usize as Handle, ptr::null_mut(), ptr::null_mut());
        }
        assert!(calls().is_empty());
        unsafe {
            release_handles(&f, 1usize as Handle, ptr::null_mut(), 20usize as Handle);
        }
        assert_eq!(calls(), vec![("destroy_surface", 20)]);
        reset(Failure::Destroy);
        unsafe {
            release_handles(&f, 1usize as Handle, 10usize as Handle, 20usize as Handle);
        }
        assert_eq!(
            calls(),
            vec![
                ("make_current", 0),
                ("destroy_context", 10),
                ("destroy_surface", 20)
            ]
        );
    }
    #[test]
    fn config_selection_honors_disabled_buffers_and_falls_back_for_preferences() {
        let options = SurfaceOptions {
            alpha: false,
            depth: false,
            stencil: false,
            antialias: false,
        };
        assert_eq!(config_score(options, [0, 0, 0, 0]), Some(0));
        for sizes in [[8, 0, 0, 0], [0, 16, 0, 0], [0, 0, 8, 0], [0, 0, 0, 4]] {
            assert!(config_score(options, sizes).is_none());
        }
        let preferred = SurfaceOptions {
            alpha: true,
            depth: true,
            stencil: true,
            antialias: true,
        };
        assert!(config_score(preferred, [8, 24, 8, 4]) > config_score(preferred, [8, 0, 0, 0]));
        assert!(config_score(preferred, [8, 0, 0, 0]).is_some());
        assert!(config_score(preferred, [0, 24, 8, 4]).is_none());
    }
    #[test]
    fn backing_dimensions_are_checked_without_overflow_and_zero_is_supported() {
        assert_eq!(backing_size(0, 0).unwrap(), (1, 1));
        assert_eq!(backing_size(4096, 4096).unwrap(), (4096, 4096));
        for (w, h) in [(4097, 4096), (32768, 1), (1, 32768), (u32::MAX, u32::MAX)] {
            assert!(backing_size(w, h).is_err());
        }
    }
    #[test]
    fn both_versions_require_webgl_validation_robustness_and_disabled_client_arrays() {
        for (version, es) in [(1, 2), (2, 3)] {
            let a = context_attributes(version).unwrap();
            assert_eq!(&a[..2], &[0x3098, es]);
            let pairs = a[..a.len() - 1].chunks_exact(2).collect::<Vec<_>>();
            for required in [
                &[0x33AC, TRUE][..],
                &[0x3452, FALSE],
                &[0x3453, TRUE],
                &[0x345F, FALSE],
                &[0x30BF, TRUE],
            ] {
                assert!(pairs.contains(&required));
            }
        }
        assert!(context_attributes(0).is_err());
        assert!(context_attributes(3).is_err());
    }
    #[test]
    fn linux_backends_are_explicitly_surfaceless_and_software_is_requested_directly() {
        for backend in [Backend::Vulkan, Backend::SwiftShader] {
            let a = display_attributes(backend);
            assert!(a.windows(2).any(|p| p == [0x348F, 0x31DD]));
        }
        assert!(display_attributes(Backend::SwiftShader)
            .windows(2)
            .any(|p| p == [0x3209, 0x3487]));
        assert!(display_attributes(Backend::Metal)
            .windows(2)
            .any(|p| p == [0x3203, 0x3489]));
    }
}
