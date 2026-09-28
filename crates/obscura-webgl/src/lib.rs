//! Optional ANGLE graphics implementation; no native library is loaded until
//! a page requests a context. Web-facing validation lives above the EGL layer.
pub mod advanced;
pub mod api;
mod bundle;
pub mod color;
pub mod commands;
#[cfg(test)]
mod driver_tests;
mod drawing_buffer;
mod framebuffer;
pub mod egl;
pub mod extensions;
mod image_upload;
pub mod objects;
pub mod pixels;
pub mod queries;
pub mod resources;
pub mod selection;
pub mod transfers;
pub mod uniforms;
