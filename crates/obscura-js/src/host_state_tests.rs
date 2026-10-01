use crate::{frame::FrameRealm, runtime::ObscuraJsRuntime};
use obscura_dom::parse_html;
use serde_json::json;

fn page() -> ObscuraJsRuntime {
    let mut runtime = ObscuraJsRuntime::with_base_url("https://host-state.example/");
    runtime.set_dom(parse_html(
        "<html><body><button id='target'>Target</button></body></html>",
    ));
    runtime.set_url("https://host-state.example/");
    runtime.run_page_init();
    runtime
}

#[test]
fn replacing_a_document_does_not_reuse_cached_wrappers_or_page_owned_state() {
    let mut runtime = ObscuraJsRuntime::with_base_url("https://host-state.example/");
    let markup = "<html><body><canvas id='target'></canvas></body></html>";
    runtime.set_dom(parse_html(markup));
    runtime.run_page_init();
    runtime
        .evaluate(
            r#"(()=>{
      window.oldCanvas=document.getElementById('target');oldCanvas.owned='old';window.oldEvents=0;
      oldCanvas.addEventListener('probe',()=>oldEvents++);
    })()"#,
        )
        .unwrap();
    runtime.execute_script("<fixture-hostile-init>",
        "window.__obscura_init=()=>{throw Error('page-owned initializer');};").unwrap();
    runtime.set_dom(parse_html(markup));
    runtime.run_page_init();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const canvas=document.getElementById('target');canvas.dispatchEvent(new Event('probe'));
      return [canvas!==oldCanvas,canvas.owned===undefined,oldCanvas.owned,oldEvents,canvas.ownerDocument===document];
    })()"#).unwrap(),json!([true,true,"old",0,true]));
}

#[test]
fn repeated_initialization_of_the_same_document_preserves_node_wrappers() {
    let mut runtime = page();
    runtime
        .evaluate(
            r#"(()=>{
      window.savedNode=document.getElementById('target');savedNode.owned=42;window.probes=0;
      savedNode.addEventListener('probe',()=>probes++);
      window.savedIdentity=[navigator.hardwareConcurrency,navigator.deviceMemory,screen.width,screen.height,performance.timeOrigin];
      window.__obscura_init=()=>{throw Error('page-owned initializer');};
    })()"#,
        )
        .unwrap();
    runtime.run_page_init();
    assert_eq!(
        runtime
            .evaluate(
                r#"(()=>{
      const node=document.getElementById('target');node.dispatchEvent(new Event('probe'));
      return [node===savedNode,node.owned,probes,JSON.stringify(savedIdentity)===JSON.stringify(
        [navigator.hardwareConcurrency,navigator.deviceMemory,screen.width,screen.height,performance.timeOrigin])];
    })()"#
            )
            .unwrap(),
        json!([true, 42, 1, true])
    );
}

#[test]
fn reused_native_node_ids_get_the_new_documents_element_interface() {
    let mut runtime=page();
    runtime.evaluate("window.oldElement=document.getElementById('target')").unwrap();
    runtime.set_dom(parse_html("<html><body><canvas id='target'></canvas></body></html>"));
    runtime.run_page_init();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const canvas=document.getElementById('target');
      return [canvas!==oldElement,canvas instanceof HTMLCanvasElement,typeof canvas.getContext,canvas.tagName];
    })()"#).unwrap(),json!([true,true,"function","CANVAS"]));
}

#[test]
fn canvas_pixel_storage_is_private_and_page_owned_former_names_are_harmless() {
    let mut runtime=page();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const canvas=document.createElement('canvas');canvas.width=2;canvas.height=1;
      const context=canvas.getContext('2d');context.fillStyle='red';context.fillRect(0,0,1,1);
      const names=['_buf','_w','_h','_damageQueued','_stateStack','_path'];
      const hidden=names.every(name=>!(name in context)&&Object.getOwnPropertyDescriptor(context,name)===undefined);
      for(const name of names)context[name]='page owned';
      context.fillStyle='blue';context.fillRect(1,0,1,1);
      return [hidden,names.every(name=>context[name]==='page owned'),Array.from(context.getImageData(0,0,2,1).data),canvas.toDataURL().startsWith('data:image/png;')];
    })()"#).unwrap(),json!([true,true,[255,0,0,255,0,0,255,255],true]));
}

#[test]
fn private_canvas_storage_preserves_copy_state_and_resize_behavior() {
    let mut runtime=page();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const canvas=document.createElement('canvas');canvas.width=2;canvas.height=1;const context=canvas.getContext('2d');
      context.fillStyle='red';context.save();context.fillStyle='blue';context.restore();context.fillRect(0,0,2,1);
      const copy=document.createElement('canvas');copy.width=2;copy.height=1;const target=copy.getContext('2d');target.drawImage(canvas,0,0);
      const pixels=Array.from(target.getImageData(0,0,2,1).data);
      copy.width=2;return [pixels,Array.from(target.getImageData(0,0,2,1).data),target.fillStyle];
    })()"#).unwrap(),json!([[255,0,0,255,255,0,0,255],[0,0,0,0,0,0,0,0],"#000000"]));
}

#[test]
fn replaced_canvas_wrappers_cannot_resize_or_create_contexts_for_reused_node_ids() {
    let mut runtime = page();
    let markup = "<canvas id=c width=1 height=1></canvas><canvas id=unused width=1 height=1></canvas>";
    runtime.set_dom(parse_html(markup));
    runtime.run_page_init();
    runtime.execute_script("<fixture-setup>", "window.oldCanvas=document.getElementById('c');window.oldUnused=document.getElementById('unused');window.oldContext=oldCanvas.getContext('2d');oldContext.fillStyle='red';oldContext.fillRect(0,0,1,1)").unwrap();
    runtime.set_dom(parse_html(markup));
    runtime.run_page_init();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const current=document.getElementById('c'),context=current.getContext('2d');
      context.fillStyle='blue';context.fillRect(0,0,1,1);
      const rejects=fn=>{try{fn();return false;}catch(e){return e.name==='InvalidStateError';}};
      oldContext.fillStyle='green';oldContext.fillRect(0,0,1,1);
      return [current!==oldCanvas,current._nid===oldCanvas._nid,oldCanvas.getContext('2d'),oldUnused.getContext('2d'),
        rejects(()=>{oldCanvas.width=9;}),rejects(()=>oldCanvas.removeAttribute('height')),rejects(()=>oldContext._resizeFromCanvas()),
        current.width,current.height,Array.from(context.getImageData(0,0,1,1).data),Array.from(oldContext.getImageData(0,0,1,1).data)];
    })()"#).unwrap(),json!([true,true,null,null,true,true,true,1,1,[0,0,255,255],[0,128,0,255]]));
}

#[test]
fn canvas_native_ownership_ignores_replaced_node_ids_and_survives_same_document_init() {
    let mut runtime = page();
    runtime.execute_script("<fixture-setup>", "window.first=document.createElement('canvas');first.width=1;first.height=1;window.second=document.createElement('canvas');second.width=2;window.ctx=first.getContext('2d');window.original=first._nid;first._nid=second._nid").unwrap();
    assert_eq!(runtime.evaluate(r#"(()=>{
      let rejected=false;try{first.width=8;}catch(e){rejected=e.name==='InvalidStateError';}
      const missing=first.getContext('2d')===null;first._nid=original;
      ctx.fillStyle='red';ctx.fillRect(0,0,1,1);
      return [rejected,missing,second.width,ctx.canvas===first,Array.from(ctx.getImageData(0,0,1,1).data)];
    })()"#).unwrap(),json!([true,true,2,true,[255,0,0,255]]));
    runtime.run_page_init();
    assert_eq!(runtime.evaluate("[first.getContext('2d')===ctx,first.width,Array.from(ctx.getImageData(0,0,1,1).data)]").unwrap(),json!([true,1,[255,0,0,255]]));
}

#[cfg(feature = "render")]
#[test]
fn frame_canvas_storage_uses_its_owner_and_rejects_a_reused_frame_token() {
    let mut runtime = page();
    let markup = "<canvas id=c width=1 height=1></canvas>";
    runtime.set_dom(parse_html(markup));runtime.run_page_init();
    let frame = FrameRealm::new(&mut runtime, 71, 0,"https://host-state.example/frame",markup).unwrap();
    frame.execute_script(&mut runtime,"window.canvas=document.getElementById('c');window.ctx=canvas.getContext('2d');if(!ctx)throw Error('frame 2d missing');ctx.fillRect(0,0,1,1)").unwrap();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const ops=__obscura_test_ops,node=document.getElementById('c')._nid;
      const main=ops.op_canvas_document_epoch(0);window.oldEpoch=ops.op_canvas_document_epoch(71);
      return [main!==oldEpoch,ops.op_canvas_paint_damage(0,main,node),ops.op_canvas_paint_damage(71,oldEpoch,node),
        ops.op_canvas_register_surface(0,oldEpoch,node,1,1,new Uint8Array(4)),ops.op_canvas_document_epoch(999)];
    })()"#).unwrap(),json!([true,false,true,false,0]));
    drop(frame);
    let replacement = FrameRealm::new(&mut runtime,71,0,"https://host-state.example/frame",markup).unwrap();
    assert_eq!(runtime.evaluate(r#"(()=>{
      const ops=__obscura_test_ops,node=document.getElementById('c')._nid,epoch=ops.op_canvas_document_epoch(71);
      return [epoch!==oldEpoch,ops.op_canvas_register_surface(71,oldEpoch,node,1,1,new Uint8Array(4)),
        ops.op_canvas_paint_damage(71,oldEpoch,node),ops.op_canvas_register_surface(71,epoch,node,1,1,new Uint8Array(4))];
    })()"#).unwrap(),json!([true,false,false,true]));
    drop(replacement);
}

const PRIVATE_NAMES: &str = r#"[
    '__obscura_await_rejected', '__obscura_click_target',
    '__obscura_screen_emulated', '__obscura_screen_w', '__obscura_screen_h',
    '__obscura_viewport_w', '__obscura_viewport_h', '__obscura_mouse_down',
    '__obscura_mouse_over_target', '__obscura_host_state_handoff',
    '__obscura_set_screen_override', '__obscura_init'
]"#;

#[test]
fn private_host_state_is_absent_from_direct_and_reflected_page_access() {
    let mut runtime = page();
    runtime.set_viewport(900.0, 700.0);
    runtime.set_screen_size_override(Some((1280.0, 800.0)), true);
    runtime
        .evaluate("document.getElementById('target').focus()")
        .unwrap();
    let result = runtime
        .evaluate(&format!(
            r#"(() => {{
        const names = {PRIVATE_NAMES};
        const surfaces = [Object.keys(window), Object.getOwnPropertyNames(window),
            Reflect.ownKeys(window), Object.keys(Object.getOwnPropertyDescriptors(window))];
        return [names.every(name => !(name in window) && window[name] === undefined
                && Object.getOwnPropertyDescriptor(window, name) === undefined),
            surfaces.every(keys => names.every(name => !keys.includes(name))),
            typeof _hostState, typeof __hostState,
            innerWidth, innerHeight, screen.width, screen.height];
    }})()"#
        ))
        .unwrap();
    assert_eq!(
        result,
        json!([true, true, "undefined", "undefined", 900, 700, 1280, 800])
    );
}

#[test]
fn page_owned_former_internal_names_remain_visible_and_cannot_change_emulation() {
    let mut runtime = page();
    runtime
        .evaluate(
            r#"(() => {
        window.__obscura_screen_w = 1;
        window.__obscura_viewport_w = 2;
        window.__obscura_page_owned = 3;
    })()"#,
        )
        .unwrap();
    runtime.set_viewport(900.0, 700.0);
    runtime.set_screen_size_override(Some((1280.0, 800.0)), true);
    assert_eq!(
        runtime
            .evaluate(
                r#"[
        innerWidth, screen.width, window.__obscura_screen_w,
        window.__obscura_viewport_w, window.__obscura_page_owned,
        Object.keys(window).includes('__obscura_screen_w'),
        Reflect.ownKeys(window).includes('__obscura_viewport_w'),
        Object.getOwnPropertyDescriptors(window).__obscura_screen_w.value,
        Object.keys({__obscura_screen_w: 4})[0]
    ]"#
            )
            .unwrap(),
        json!([900, 1280, 1, 2, 3, true, true, 1, "__obscura_screen_w"])
    );
    runtime.set_screen_size_override(None, false);
    runtime.set_screen_size_override(Some((1440.0, 900.0)), true);
    assert_eq!(
        runtime
            .evaluate("[innerWidth, screen.width, screen.availHeight]")
            .unwrap(),
        json!([900, 1440, 900])
    );
}

#[test]
fn page_setters_cannot_intercept_private_input_or_emulation_state() {
    let mut runtime = page();
    runtime
        .evaluate(&format!(
            r#"(() => {{
        window.trappedHostWrites = 0;
        for (const name of {PRIVATE_NAMES}) Object.defineProperty(window, name, {{
            get() {{ throw new Error('page accessor must not run'); }},
            set(value) {{ window.trappedHostWrites++; }}, configurable: true
        }});
    }})()"#
        ))
        .unwrap();
    runtime.set_viewport(640.0, 480.0);
    runtime.set_screen_size_override(Some((1024.0, 768.0)), true);
    runtime
        .evaluate("document.getElementById('target').focus()")
        .unwrap();
    assert_eq!(
        runtime
            .evaluate("[trappedHostWrites, innerWidth, screen.width, document.activeElement.id]")
            .unwrap(),
        json!([0, 640, 1024, "target"])
    );
    assert_eq!(
        runtime
            .evaluate_host_expression("__hostState.clickTarget.id")
            .unwrap(),
        json!("target")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cdp_evaluation_keeps_rejections_private_and_preserves_global_scope() {
    let mut runtime = page();
    runtime
        .evaluate("window.__obscura_await_rejected = 'page-owned'")
        .unwrap();
    for source in [
        "throw new Error('sync')",
        "Promise.reject(new Error('async'))",
    ] {
        let result = runtime.evaluate_for_cdp(source, true, true).await.unwrap();
        assert!(result.thrown);
    }
    let result = runtime
        .evaluate_for_cdp(
            "var pageGlobal = 7; Promise.resolve(pageGlobal)",
            true,
            true,
        )
        .await
        .unwrap();
    assert!(!result.thrown);
    assert_eq!(result.value.as_ref().and_then(serde_json::Value::as_f64), Some(7.0));
    assert_eq!(
        runtime
            .evaluate("[pageGlobal, window.__obscura_await_rejected, typeof __hostState]")
            .unwrap(),
        json!([7, "page-owned", "undefined"])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cdp_function_declarations_cannot_capture_the_host_wrapper() {
    let mut runtime = page();
    let result = runtime
        .call_function_on_for_cdp(
            "function() { return Promise.resolve([typeof __hostState, typeof _hostState]); }",
            None,
            &[],
            true,
            true,
        )
        .await
        .unwrap();
    assert!(!result.thrown);
    assert_eq!(result.value, Some(json!(["undefined", "undefined"])));
    let returned = runtime
        .call_function_on_for_cdp(
            "function() { return () => typeof __hostState; }",
            None,
            &[],
            false,
            true,
        )
        .await
        .unwrap();
    let called = runtime
        .call_function_on_for_cdp(
            "function() { return this(); }",
            returned.object_id.as_deref(),
            &[],
            true,
            true,
        )
        .await
        .unwrap();
    assert_eq!(called.value, Some(json!("undefined")));
}

#[test]
fn same_origin_frame_intrinsics_cannot_discover_parent_host_state() {
    let mut runtime = page();
    runtime.set_screen_size_override(Some((1280.0, 800.0)), true);
    let frame = FrameRealm::new(
        &mut runtime,
        1,
        0,
        "https://host-state.example/frame",
        "<html><body>frame</body></html>",
    )
    .unwrap();
    let probe = format!(
        r#"(() => {{
        const names = {PRIVATE_NAMES};
        return [names.every(name => !(name in window) && !(name in parent)),
            Object.getOwnPropertyNames(parent).every(name => !names.includes(name)),
            Reflect.ownKeys(parent).every(name => !names.includes(name))];
    }})()"#
    );
    assert_eq!(
        frame.evaluate(&mut runtime, &probe).unwrap(),
        json!([true, true, true])
    );
}

#[test]
fn fresh_navigation_runtime_does_not_retain_a_previous_click_target() {
    let mut first = page();
    first
        .evaluate("document.getElementById('target').focus()")
        .unwrap();
    assert_eq!(
        first
            .evaluate_host_expression("__hostState.clickTarget.id")
            .unwrap(),
        json!("target")
    );
    drop(first);
    let mut second = page();
    assert_eq!(
        second
            .evaluate_host_expression("__hostState.clickTarget")
            .unwrap(),
        json!(null)
    );
    assert_eq!(
        second
            .evaluate("typeof window.__obscura_click_target")
            .unwrap(),
        json!("undefined")
    );
}

#[test]
fn attribute_mutation_records_preserve_old_values_filters_namespaces_and_single_delivery() {
    let mut runtime = page();
    assert_eq!(runtime.evaluate(r#"(() => {
      const parent=document.createElement('div'),target=document.createElement('span');
      parent.appendChild(target);document.body.appendChild(parent);
      target.setAttribute('data-present','old');
      const old=new MutationObserver(()=>{}),fresh=new MutationObserver(()=>{});
      const filtered=new MutationObserver(()=>{}),overlap=new MutationObserver(()=>{});
      old.observe(target,{attributes:true,attributeOldValue:true});
      fresh.observe(target,{attributes:true,attributeOldValue:false});
      filtered.observe(target,{attributeOldValue:true,attributeFilter:['data-a']});
      overlap.observe(parent,{attributes:true,subtree:true,attributeOldValue:true});
      overlap.observe(target,{attributes:true});
      target.setAttribute('data-present','new');
      target.setAttribute('data-a','');target.setAttribute('data-a','');target.setAttribute('data-a','next');
      target.removeAttribute('data-a');target.removeAttribute('data-a');
      target.setAttributeNS('urn:fixture','p:item','one');target.setAttributeNS('urn:fixture','q:item','two');
      target.removeAttributeNS('urn:fixture','item');target.removeAttributeNS('urn:fixture','item');
      target.setAttributeNS(null,'data-a','v');target.removeAttributeNS(null,'data-a');
      const a=old.takeRecords(),b=fresh.takeRecords(),c=filtered.takeRecords(),d=overlap.takeRecords();
      return [a.map(r=>[r.attributeName,r.attributeNamespace,r.oldValue]),
        b.map(r=>r.oldValue),c.map(r=>r.oldValue),d.map(r=>r.oldValue),a.every((r,i)=>r!==b[i]),
        [old,fresh,filtered,overlap].every(o=>o.takeRecords().length===0)];
    })()"#).unwrap(), json!([
        [["data-present",null,"old"],["data-a",null,null],["data-a",null,""],
         ["data-a",null,""],["data-a",null,"next"],["item","urn:fixture",null],
         ["item","urn:fixture","one"],["item","urn:fixture","two"],
         ["data-a",null,null],["data-a",null,"v"]],
        [null,null,null,null,null,null,null,null,null,null],
        [null,"","","next",null,"v"],
        ["old",null,"","","next",null,"one","two",null,"v"],true,true
    ]));
}
