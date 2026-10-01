//! Stealth readback variance on a real WebGL driver. Kept apart from
//! `webgl_tests`, whose ignored cases form the pinned native driver inventory;
//! select this module explicitly with the same driver environment.
use crate::runtime::ObscuraJsRuntime;
use obscura_dom::parse_html;
fn page() -> ObscuraJsRuntime {
    let mut runtime = ObscuraJsRuntime::with_base_url("https://graphics.example/");
    runtime.set_dom(parse_html(
        "<html><body style='margin:0'><canvas id='c' width='8' height='8'></canvas></body></html>",
    ));
    runtime.set_url("https://graphics.example/");
    runtime.run_page_init();
    runtime
}
fn require_driver() {
    let mode = std::env::var("OBSCURA_WEBGL_BACKEND")
        .expect("select hardware or software explicitly for real-driver tests");
    assert!(matches!(mode.as_str(), "hardware" | "software"));
    assert!(std::path::Path::new(
        &std::env::var("OBSCURA_WEBGL_LIB_DIR").expect("pinned ANGLE bundle required")
    )
    .join("bundle.json")
    .is_file());
}

// Stealth readback variance on a real driver: the profile seed decides which
// channels of shaded pixels move by one; reads are repeatable, readPixels and
// canvas exports agree on opaque pixels, flat clears stay exact, and runtime
// stealth off returns the driver's exact pixels.
#[test]
#[ignore = "mandatory real-driver stealth readback variance (readPixels, toDataURL, drawImage)"]
fn real_webgl_stealth_readback_variance_is_profile_stable_and_consistent() {
    require_driver();
    const SCENE: &str = r#"(()=>{
      const c=document.createElement('canvas');c.width=64;c.height=32;
      const gl=c.getContext('webgl',{preserveDrawingBuffer:true,antialias:false});if(!gl)throw Error('WebGL unavailable');
      gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT);
      const buf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buf);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-0.9,-0.7,0.8,-0.7,0,0.5]),gl.STATIC_DRAW);
      const p=gl.createProgram();
      const vs=gl.createShader(gl.VERTEX_SHADER);gl.shaderSource(vs,'attribute vec2 a;varying vec2 v;void main(){v=a+1.0;gl_Position=vec4(a,0,1);}');gl.compileShader(vs);gl.attachShader(p,vs);
      const fs=gl.createShader(gl.FRAGMENT_SHADER);gl.shaderSource(fs,'precision mediump float;varying vec2 v;void main(){gl_FragColor=vec4(v*0.5,0.5,1);}');gl.compileShader(fs);gl.attachShader(p,fs);
      gl.linkProgram(p);gl.useProgram(p);const l=gl.getAttribLocation(p,'a');gl.enableVertexAttribArray(l);gl.vertexAttribPointer(l,2,gl.FLOAT,false,0,0);
      gl.drawArrays(gl.TRIANGLES,0,3);
      const read=()=>{const px=new Uint8Array(64*32*4);gl.readPixels(0,0,64,32,gl.RGBA,gl.UNSIGNED_BYTE,px);return px;};
      const a=read(),b=read();
      const out=document.createElement('canvas');out.width=64;out.height=32;const ctx=out.getContext('2d');ctx.drawImage(c,0,0);
      const drawn=ctx.getImageData(0,0,64,32).data;let mismatch=0;
      for(let y=0;y<32;y++)for(let x=0;x<64;x++){const r=((31-y)*64+x)*4,d=(y*64+x)*4;
        if(a[r+3]===255&&drawn[d+3]===255)for(let k=0;k<4;k++)if(a[r+k]!==drawn[d+k])mismatch++;}
      const flat=document.createElement('canvas');flat.width=flat.height=8;const f=flat.getContext('webgl');
      f.clearColor(0.2,0.4,0.6,1);f.clear(f.COLOR_BUFFER_BIT);const fp=new Uint8Array(8*8*4);f.readPixels(0,0,8,8,f.RGBA,f.UNSIGNED_BYTE,fp);
      return {pixels:Array.from(a),repeat:a.every((v,i)=>v===b[i])&&c.toDataURL()===c.toDataURL(),mismatch,
        flat:fp.every((v,i)=>v===fp[i%4])};
    })()"#;
    let run = |stealth: bool, seed: u32| {
        let mut runtime = page();
        runtime.set_fingerprint_seed(seed);
        runtime.set_stealth(stealth);
        runtime.set_dom(parse_html("<html><body></body></html>"));
        runtime.run_page_init();
        runtime.evaluate(SCENE).unwrap()
    };
    let exact = run(false, 1);
    let a = run(true, 1);
    let a_again = run(true, 1);
    let b = run(true, 2);
    for value in [&exact, &a, &b] {
        assert_eq!(value["repeat"], true);
        assert_eq!(value["mismatch"], 0);
        assert_eq!(value["flat"], true);
    }
    assert_eq!(a["pixels"], a_again["pixels"], "a profile reproduces its readback");
    assert_ne!(a["pixels"], b["pixels"], "profiles differ");
    assert_ne!(a["pixels"], exact["pixels"], "stealth readback varies");
    let bytes = |v: &serde_json::Value| v["pixels"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect::<Vec<_>>();
    let (exact, varied) = (bytes(&exact), bytes(&a));
    let changed = exact.iter().zip(&varied).filter(|(e, v)| e != v).count();
    assert!(exact.iter().zip(&varied).all(|(e, v)| (e - v).abs() <= 1), "variance is at most one level per channel");
    assert!(exact.chunks(4).zip(varied.chunks(4)).all(|(e, v)| e[3] == v[3]), "alpha never changes");
    assert!(changed > 0 && changed * 4 < exact.len(), "{changed} changed channels");
}
