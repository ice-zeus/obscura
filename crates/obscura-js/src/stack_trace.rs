//! `Error.prototype.stack` formatting.
//!
//! deno_core installs its own prepare-stack-trace callback, which formats every
//! frame with Deno's formatter. That formatter differs from V8's (and therefore
//! Chrome's) in small ways that page scripts can observe. For example, a
//! `TypeError` thrown by `Function.prototype[Symbol.hasInstance]` for
//! `fn instanceof fn` reads `at fn.[Symbol.hasInstance] (<anonymous>)` instead
//! of Chrome's `at [Symbol.hasInstance] (<anonymous>)`, which fingerprinting
//! scripts use as a proxy/tampering signal on every native function.
//!
//! This callback restores V8's own serialization: each frame is the result of
//! V8's `CallSite.prototype.toString`, the same code V8 uses when no embedder
//! callback is installed. A page-defined `Error.prepareStackTrace` is still
//! honoured with V8's semantics (called with the global `Error` as receiver).
//!
//! In stealth mode the frames of the engine's own internal scripts (named
//! `<...>`, such as `<obscura:bootstrap>`) are omitted, as Chrome's natively
//! implemented APIs never appear in a page's stack traces.

use deno_core::v8;

/// Isolate slot: whether frames of internal scripts are omitted.
pub(crate) struct HideInternalFrames(pub bool);

// deno_core reads the structured frames of an exception from this private
// symbol (`JsError::from_exception`), so keep providing them.
const CALL_SITE_EVALS: &str = "deno_core::call_site_evals";

pub(crate) fn install(isolate: &mut v8::Isolate) {
    isolate.set_slot(HideInternalFrames(false));
    isolate.set_prepare_stack_trace_callback(prepare_stack_trace);
}

pub(crate) fn set_hide_internal_frames(isolate: &mut v8::Isolate, hide: bool) {
    isolate.set_slot(HideInternalFrames(hide));
}

/// Code that an automation client supplied (CDP `Runtime.evaluate`,
/// `Runtime.callFunctionOn`, `Page.addScriptToEvaluateOnNewDocument`). Chrome
/// shows such frames too, so they stay visible.
const CLIENT_SCRIPT_NAMES: &[&str] = &["<anonymous>", "<eval>", "<eval-remote>", "<preload>"];

/// True for the names the engine gives its own scripts (`<obscura:bootstrap>`,
/// `<load-event>`, ...) and for deno_core's internal modules (`ext:core/...`),
/// which run microtask and timer callbacks. Page scripts are named by URL, eval
/// code and builtins have no script name.
fn is_internal_script_name(name: &str) -> bool {
    name.starts_with("ext:")
        || (name.len() > 2
            && name.starts_with('<')
            && name.ends_with('>')
            && !CLIENT_SCRIPT_NAMES.contains(&name)
            && !name.contains(char::is_whitespace))
}

fn property<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let key = v8::String::new(scope, name)?;
    object.get(scope, key.into())
}

fn call_method<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<v8::Local<'s, v8::Value>> {
    let function = property(scope, object, name)?.try_cast::<v8::Function>().ok()?;
    function.call(scope, object.into(), &[])
}

fn script_name<'s, 'i>(scope: &mut v8::PinScope<'s, 'i>, callsite: v8::Local<'s, v8::Object>) -> Option<String> {
    let value = call_method(scope, callsite, "getFileName")?;
    if !value.is_string() {
        return None;
    }
    Some(value.to_rust_string_lossy(scope))
}

fn visible_callsites<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    callsites: v8::Local<'s, v8::Array>,
) -> v8::Local<'s, v8::Array> {
    let hide = scope.get_slot::<HideInternalFrames>().is_some_and(|slot| slot.0);
    if !hide {
        return callsites;
    }
    let mut kept: Vec<v8::Local<'s, v8::Value>> = Vec::with_capacity(callsites.length() as usize);
    let mut dropped = false;
    for index in 0..callsites.length() {
        let Some(value) = callsites.get_index(scope, index) else { continue };
        let Ok(callsite) = value.try_cast::<v8::Object>() else { continue };
        v8::tc_scope!(let tc, scope);
        let internal = script_name(tc, callsite).is_some_and(|name| is_internal_script_name(&name));
        if tc.has_caught() {
            // A frame whose metadata cannot be read is kept as V8 would print it.
            kept.push(value);
            continue;
        }
        if internal {
            dropped = true;
        } else {
            kept.push(value);
        }
    }
    if !dropped {
        return callsites;
    }
    v8::Array::new_with_elements(scope, &kept)
}

fn string_property<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    object: v8::Local<'s, v8::Object>,
    name: &str,
) -> Option<String> {
    let value = property(scope, object, name)?;
    if value.is_undefined() {
        return None;
    }
    Some(value.to_string(scope)?.to_rust_string_lossy(scope))
}

fn error_header<'s, 'i>(scope: &mut v8::PinScope<'s, 'i>, error: v8::Local<'s, v8::Value>) -> String {
    // Error.prototype.toString semantics, as V8's ErrorUtils::ToString.
    let Ok(object) = error.try_cast::<v8::Object>() else {
        return error.to_rust_string_lossy(scope);
    };
    let name = string_property(scope, object, "name").unwrap_or_else(|| "Error".to_string());
    let message = string_property(scope, object, "message").unwrap_or_default();
    match (name.is_empty(), message.is_empty()) {
        (true, _) => message,
        (false, true) => name,
        (false, false) => format!("{name}: {message}"),
    }
}

pub(crate) fn prepare_stack_trace<'s, 'i>(
    scope: &mut v8::PinScope<'s, 'i>,
    error: v8::Local<'s, v8::Value>,
    callsites: v8::Local<'s, v8::Array>,
) -> v8::Local<'s, v8::Value> {
    let callsites = visible_callsites(scope, callsites);
    if let Ok(object) = error.try_cast::<v8::Object>() {
        if let Some(name) = v8::String::new(scope, CALL_SITE_EVALS) {
            let key = v8::Private::for_api(scope, Some(name));
            object.set_private(scope, key, callsites.into());
        }
    }

    // A registered callback replaces V8's `Error.prepareStackTrace` hook, so
    // call a page-defined one exactly as V8 would.
    let global = scope.get_current_context().global(scope);
    let error_constructor = property(scope, global, "Error").and_then(|value| value.try_cast::<v8::Object>().ok());
    if let Some(constructor) = error_constructor {
        if let Some(prepare) = property(scope, constructor, "prepareStackTrace")
            .and_then(|value| value.try_cast::<v8::Function>().ok())
        {
            return prepare
                .call(scope, constructor.into(), &[error, callsites.into()])
                .unwrap_or_else(|| v8::undefined(scope).into());
        }
    }

    let mut result = error_header(scope, error);
    for index in 0..callsites.length() {
        let Some(callsite) = callsites
            .get_index(scope, index)
            .and_then(|value| value.try_cast::<v8::Object>().ok())
        else {
            continue;
        };
        v8::tc_scope!(let tc, scope);
        let frame = call_method(tc, callsite, "toString")
            .filter(|value| value.is_string())
            .map(|value| value.to_rust_string_lossy(tc));
        if tc.has_caught() {
            break;
        }
        let Some(frame) = frame else { break };
        result.push_str("\n    at ");
        result.push_str(&frame);
    }
    v8::String::new(scope, &result)
        .map(Into::into)
        .unwrap_or_else(|| v8::undefined(scope).into())
}

#[cfg(test)]
mod tests {
    use super::is_internal_script_name;

    #[test]
    fn only_bracketed_engine_script_names_are_internal() {
        assert!(is_internal_script_name("<obscura:bootstrap>"));
        assert!(is_internal_script_name("<load-event>"));
        assert!(!is_internal_script_name("<preload>"));
        assert!(!is_internal_script_name("<eval-remote>"));
        assert!(is_internal_script_name("ext:core/01_core.js"));
        assert!(!is_internal_script_name("https://example.com/app.js"));
        assert!(!is_internal_script_name("<anonymous>x"));
        assert!(!is_internal_script_name("<a b>"));
        assert!(!is_internal_script_name("<>"));
        assert!(!is_internal_script_name("<anonymous>"));
    }
}
