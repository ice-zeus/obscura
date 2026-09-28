//! Nomodule skips script work, never the DOM insertion itself.
use crate::runtime::ObscuraJsRuntime;
use obscura_dom::parse_html;
use serde_json::json;

fn page() -> ObscuraJsRuntime {
    let mut runtime = ObscuraJsRuntime::with_base_url("https://nomodule.example/");
    runtime.set_dom(parse_html("<html><head></head><body></body></html>"));
    runtime.set_url("https://nomodule.example/");
    runtime.run_page_init();
    runtime
}

#[test]
fn no_module_reflects_boolean_attribute_presence_and_is_script_specific() {
    let mut runtime = page();
    assert_eq!(
        runtime
            .evaluate(
                r#"(() => {
        const script = document.createElement('script');
        const values = [script instanceof HTMLScriptElement, script.noModule,
            'noModule' in document.createElement('div')];
        script.setAttribute('nomodule', 'false'); values.push(script.noModule);
        script.noModule = false; values.push(script.hasAttribute('nomodule'));
        script.noModule = 'yes'; values.push(script.getAttribute('nomodule'));
        script.removeAttribute('nomodule'); values.push(script.noModule);
        return values;
    })()"#
            )
            .unwrap(),
        json!([true, false, false, true, false, "", false])
    );
}

#[test]
fn dynamic_nomodule_scripts_insert_normally_but_do_not_execute_or_queue_fetches() {
    let mut runtime = page();
    assert_eq!(
        runtime
            .evaluate(
                r#"(() => {
        globalThis.legacyRuns = 0;
        const host = document.createElement('div'); document.body.appendChild(host);
        const observer = new MutationObserver(() => {});
        observer.observe(host, {childList: true});
        for (const external of [false, true]) {
            const script = document.createElement('script'); script.noModule = true;
            if (external) script.src = '/must-not-fetch.js';
            else script.textContent = 'legacyRuns++';
            host.appendChild(script);
        }
        const records = observer.takeRecords();
        return [legacyRuns, host.childNodes.length,
            Array.from(host.children).every(s => s.parentNode === host && s.isConnected),
            records.length, records.every(r => r.type === 'childList' && r.addedNodes.length === 1),
            globalThis.__obscura_hasPendingDynamicScripts(),
            globalThis.__obscura_hasPendingLoadDelayingScripts()];
    })()"#
            )
            .unwrap(),
        json!([0, 2, true, 2, true, false, false])
    );
}

#[test]
fn removing_nomodule_after_preparation_does_not_restart_a_script() {
    let mut runtime = page();
    assert_eq!(
        runtime
            .evaluate(
                r#"(() => {
        globalThis.legacyRuns = 0;
        const script = document.createElement('script');
        script.noModule = true; script.textContent = 'legacyRuns++';
        document.body.append(script); script.remove(); script.noModule = false;
        document.head.append(script);
        return [legacyRuns, script.parentNode === document.head, script.isConnected];
    })()"#
            )
            .unwrap(),
        json!([0, true, true])
    );
}

#[test]
fn removing_nomodule_before_connection_keeps_the_classic_script_executable() {
    let mut runtime = page();
    assert_eq!(
        runtime
            .evaluate(
                r#"(() => {
        globalThis.classicRuns = 0;
        const fragment = document.createDocumentFragment();
        const script = document.createElement('script');
        script.noModule = true; script.textContent = 'classicRuns++';
        fragment.append(script); script.noModule = false;
        document.body.append(fragment);
        return [classicRuns, fragment.childNodes.length, script.parentNode === document.body];
    })()"#
            )
            .unwrap(),
        json!([1, 0, true])
    );
}

#[test]
fn skipped_script_does_not_weaken_dom_exceptions_or_connection_state() {
    let mut runtime = page();
    assert_eq!(
        runtime
            .evaluate(
                r#"(() => {
        const host = document.createElement('div'); document.body.append(host);
        const script = document.createElement('script'); script.noModule = true;
        script.textContent = 'throw new Error("must not execute")'; host.append(script);
        const errors = [];
        try { document.head.removeChild(script); } catch(e) { errors.push(e.name); }
        try { script.appendChild(host); } catch(e) { errors.push(e.name); }
        const connected = script.parentNode === host && script.isConnected;
        host.removeChild(script);
        try { host.removeChild(script); } catch(e) { errors.push(e.name); }
        return [errors, connected, script.parentNode, script.isConnected];
    })()"#
            )
            .unwrap(),
        json!([
            ["NotFoundError", "HierarchyRequestError", "NotFoundError"],
            true,
            null,
            false
        ])
    );
}

#[test]
fn script_interface_descriptors_and_native_accessors_match_webidl() {
    let mut runtime = page();
    assert_eq!(
        runtime
            .evaluate(
                r#"(() => {
        const d = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'noModule');
        const failures = [];
        for (const fn of [d.get, d.set]) {
            try { fn.call(document.createElement('div'), true); }
            catch (error) { failures.push(error.name); }
        }
        return [Object.getOwnPropertyDescriptor(window, 'HTMLScriptElement').enumerable,
            d.enumerable, d.configurable, d.get.toString(), d.set.toString(), failures];
    })()"#
            )
            .unwrap(),
        json!([
            false,
            true,
            true,
            "function get noModule() { [native code] }",
            "function set noModule() { [native code] }",
            ["TypeError", "TypeError"]
        ])
    );
}
