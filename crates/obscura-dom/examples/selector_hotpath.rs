// Deterministic selector traversal benchmark. Run release builds on the Mac Mini.
use obscura_dom::parse_html;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    for attribute_bytes in [0, 4096] {
        let mut html = String::from("<html><body>");
        let payload = "x".repeat(attribute_bytes);
        for _ in 0..10 {
            for _ in 0..32 {
                html.push_str(&format!("<section data-payload='{payload}'>text<!--gap-->"));
            }
            html.push_str("<span class='needle'></span><i></i>text<b></b>");
            html.push_str(&"</section>".repeat(32));
        }
        html.push_str("</body></html>");
        let tree = parse_html(&html);
        let cases = [("section:has(.needle)", 320),
                     ("section:has(> .needle)", 10),
                     ("span + i + b", 10), ("b:nth-child(3)", 10)];
        for (selector, expected) in cases {
            assert_eq!(tree.query_selector_all(selector).unwrap().len(), expected);
            let started = Instant::now();
            for _ in 0..25 {
                let found = black_box(tree.query_selector_all(black_box(selector)).unwrap());
                assert_eq!(found.len(), expected);
            }
            println!("{{\"attribute_bytes\":{attribute_bytes},\"selector\":\"{selector}\",\"iterations\":25,\"seconds\":{:.6}}}", started.elapsed().as_secs_f64());
        }
    }
}
