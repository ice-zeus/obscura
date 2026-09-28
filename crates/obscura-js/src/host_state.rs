//! Per-realm state shared with bootstrap, never published to page JavaScript.
//!
//! The snapshot supplies a temporary handoff. The host moves it behind a V8
//! private key before page scripts run. A page's own property with a former
//! internal name remains an ordinary property and cannot change host state.

use deno_core::v8;

const HANDOFF: &str = "__obscura_host_state_handoff";
const PRIVATE_KEY: &str = "obscura.runtime.host_state";

pub(crate) fn seal(scope: &mut v8::PinScope) -> bool {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let Some(name) = v8::String::new(scope, HANDOFF) else {
        return false;
    };
    let Some(key_name) = v8::String::new(scope, PRIVATE_KEY) else {
        return false;
    };
    let key = v8::Private::for_api(scope, Some(key_name));
    let Some(value) = global.get(scope, name.into()) else {
        return false;
    };
    if !value.is_object() {
        return false;
    }
    if global.set_private(scope, key, value) != Some(true) {
        return false;
    }
    global.delete(scope, name.into()) == Some(true)
}

pub(crate) fn get<'s>(scope: &mut v8::PinScope<'s, '_>) -> Option<v8::Local<'s, v8::Value>> {
    let context = scope.get_current_context();
    let global = context.global(scope);
    let name = v8::String::new(scope, PRIVATE_KEY)?;
    let key = v8::Private::for_api(scope, Some(name));
    let value = global.get_private(scope, key)?;
    value.is_object().then_some(value)
}
