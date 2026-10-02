//! The order in which Chrome's renderer sends the headers it sets itself.
//!
//! Blink keeps a subresource request's own headers (page-supplied headers,
//! `Content-Type`, an element-initiated `Origin`, the client hints and
//! `User-Agent`) in `HTTPHeaderMap`, a WTF `HashMap` keyed by the
//! case-folded header name, and the network service serializes them in the
//! map's bucket order. That order depends on the names present and on the
//! order they were inserted, so it is reproduced here rather than tabulated:
//! rapidhash over the UTF-16 case-folded name, the low 24 bits, an open
//! addressing table with triangular probing that starts at 8 buckets and
//! doubles once it is half full, rehashing in bucket order.
//!
//! Sources: Chromium 151.0.7922.34 `wtf/text/string_hasher.h`,
//! `wtf/text/case_folding_hash.h`, `wtf/hash_table.h`,
//! `third_party/rapidhash/rapidhash.h` and `network/http_header_map.h`.
//! Verified against Chromium 151 captures (see the tests below).

const SEED: u64 = 0xbdd8_9aa9_8270_4029;
const SECRET: [u64; 3] = [0x2d35_8dcc_aa6c_78a5, 0x8bb8_4b93_962e_acc9, 0x4b33_a62e_d433_d4a3];

fn mul128(a: u64, b: u64) -> (u64, u64) {
    let product = u128::from(a) * u128::from(b);
    (product as u64, (product >> 64) as u64)
}

fn mix(a: u64, b: u64) -> u64 {
    let (low, high) = mul128(a, b);
    low ^ high
}

/// Latin-1 case folding as used for hashing (ASCII header names).
fn fold(byte: u8) -> u64 {
    u64::from(byte.to_ascii_lowercase())
}

/// Four Latin-1 characters starting at `offset`, expanded to UTF-16.
fn read64(name: &[u8], offset: usize) -> u64 {
    fold(name[offset])
        | fold(name[offset + 1]) << 16
        | fold(name[offset + 2]) << 32
        | fold(name[offset + 3]) << 48
}

fn read32(name: &[u8], offset: usize) -> u64 {
    fold(name[offset]) | fold(name[offset + 1]) << 16
}

/// `DeprecatedCaseFoldingHash` of a Latin-1 header name: rapidhash over the
/// case-folded name read as UTF-16 (so every length and offset in bytes is
/// halved when indexing the 8-bit source).
fn rapidhash_case_folded(name: &[u8]) -> u64 {
    let len = name.len() * 2;
    let mut seed = SEED;
    seed ^= mix(seed ^ SECRET[0], SECRET[1]) ^ len as u64;
    let (mut a, mut b);
    if len <= 16 {
        if len >= 4 {
            let last = (len - 4) / 2;
            a = (read32(name, 0) << 32) | read32(name, last);
            let delta = ((len & 24) >> (len >> 3)) / 2;
            b = (read32(name, delta) << 32) | read32(name, last - delta);
        } else if len > 0 {
            // A single UTF-16 unit: bytes [low, 0], so p[len >> 1] and
            // p[len - 1] are both the zero high byte.
            a = fold(name[0]) << 56;
            b = 0;
        } else {
            a = 0;
            b = 0;
        }
    } else {
        let mut p = 0;
        let mut remaining = len;
        if remaining > 48 {
            let (mut see1, mut see2) = (seed, seed);
            loop {
                seed = mix(read64(name, p) ^ SECRET[0], read64(name, p + 4) ^ seed);
                see1 = mix(read64(name, p + 8) ^ SECRET[1], read64(name, p + 12) ^ see1);
                see2 = mix(read64(name, p + 16) ^ SECRET[2], read64(name, p + 20) ^ see2);
                p += 24;
                remaining -= 48;
                if remaining < 48 {
                    break;
                }
            }
            seed ^= see1 ^ see2;
        }
        if remaining > 16 {
            seed = mix(read64(name, p) ^ SECRET[2], read64(name, p + 4) ^ seed ^ SECRET[1]);
            if remaining > 32 {
                seed = mix(read64(name, p + 8) ^ SECRET[2], read64(name, p + 12) ^ seed);
            }
        }
        // The last 16 bytes, which may reach back into the consumed blocks.
        a = read64(name, p + remaining / 2 - 8);
        b = read64(name, p + remaining / 2 - 4);
    }
    a ^= SECRET[1];
    b ^= seed;
    let (low, high) = mul128(a, b);
    mix(low ^ SECRET[0] ^ len as u64, high ^ SECRET[1])
}

/// The 24-bit hash `StringImpl` stores (zero is reserved).
fn blink_hash(name: &str) -> u32 {
    let hash = (rapidhash_case_folded(name.as_bytes()) & 0x00ff_ffff) as u32;
    if hash == 0 { 0x0080_0000 } else { hash }
}

fn place<'a>(table: &mut [Option<&'a str>], name: &'a str) {
    let mask = table.len() - 1;
    let mut index = blink_hash(name) as usize & mask;
    let mut probe = 0;
    while table[index].is_some() {
        probe += 1;
        index = (index + probe) & mask;
    }
    table[index] = Some(name);
}

/// Iteration order of a header map after inserting `names` in order.
/// Names are expected to be distinct ignoring ASCII case.
pub(crate) fn header_map_order<'a>(names: &[&'a str]) -> Vec<&'a str> {
    let mut table: Vec<Option<&'a str>> = vec![None; 8];
    let mut count = 0;
    for name in names {
        place(&mut table, name);
        count += 1;
        if count * 2 >= table.len() {
            let size = table.len() * 2;
            let old = std::mem::replace(&mut table, vec![None; size]);
            for entry in old.into_iter().flatten() {
                place(&mut table, entry);
            }
        }
    }
    table.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::header_map_order;

    /// Blink's insertion order for a subresource: headers set when the
    /// request is created, then `FrameFetchContext::AddClientHintsIfNecessary`
    /// in source order, then `PrepareRequest`'s User-Agent.
    const HINTS: [&str; 27] = [
        "device-memory", "sec-ch-device-memory", "rtt", "downlink", "ect", "sec-ch-ua",
        "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
        "sec-ch-ua-model", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
        "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-form-factors", "save-data",
        "sec-ch-prefers-reduced-transparency", "sec-ch-prefers-reduced-motion",
        "sec-ch-prefers-color-scheme", "dpr", "sec-ch-dpr", "viewport-width",
        "sec-ch-viewport-width", "sec-ch-viewport-height", "width", "sec-ch-width",
    ];

    fn inserted<'a>(created: &[&'a str], present: &[&'a str]) -> Vec<&'a str> {
        let mut out = created.to_vec();
        out.extend(HINTS.iter().copied().filter(|hint| present.contains(hint)));
        out.push("User-Agent");
        out
    }

    /// Header lines Chromium 151.0.7922.34 sent (in wire order, before
    /// `Accept`), recorded by a raw-socket server after an Accept-CH response.
    #[test]
    fn reproduces_chromium_151_subresource_orders() {
        let all: &[&str] = &[
            "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width", "device-memory",
            "sec-ch-ua", "sec-ch-dpr", "sec-ch-ua-model", "sec-ch-ua-mobile", "sec-ch-ua-form-factors",
            "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
            "sec-ch-prefers-reduced-transparency", "sec-ch-ua-full-version", "sec-ch-viewport-width",
            "downlink", "sec-ch-viewport-height", "ect", "sec-ch-device-memory",
            "sec-ch-prefers-reduced-motion", "dpr", "sec-ch-prefers-color-scheme", "User-Agent", "rtt",
            "sec-ch-ua-platform-version",
        ];
        let cases: &[(&[&str], &[&str])] = &[
            // Script, image and fetch() with every hint.
            (&[], all),
            // POST fetch() with a Content-Type.
            (&["Content-Type"], &[
                "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width", "device-memory",
                "sec-ch-ua", "sec-ch-dpr", "sec-ch-ua-model", "sec-ch-ua-mobile", "sec-ch-ua-form-factors",
                "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
                "sec-ch-prefers-reduced-transparency", "sec-ch-ua-full-version", "Content-Type",
                "sec-ch-viewport-width", "downlink", "sec-ch-viewport-height", "ect", "sec-ch-device-memory",
                "sec-ch-prefers-reduced-motion", "dpr", "sec-ch-prefers-color-scheme", "User-Agent", "rtt",
                "sec-ch-ua-platform-version",
            ]),
            // A web font: the element-initiated Origin is one of the map's headers.
            (&["Origin"], &[
                "Origin", "sec-ch-ua-platform", "viewport-width", "sec-ch-ua-full-version-list",
                "device-memory", "sec-ch-ua", "sec-ch-dpr", "sec-ch-ua-model", "sec-ch-ua-mobile",
                "sec-ch-ua-form-factors", "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
                "sec-ch-prefers-reduced-transparency", "sec-ch-ua-full-version", "sec-ch-viewport-width",
                "downlink", "sec-ch-viewport-height", "ect", "sec-ch-device-memory",
                "sec-ch-prefers-reduced-motion", "dpr", "sec-ch-prefers-color-scheme", "User-Agent", "rtt",
                "sec-ch-ua-platform-version",
            ]),
            // An image with sizes adds Width / Sec-CH-Width.
            (&[], &[
                "sec-ch-ua-full-version-list", "sec-ch-ua-platform", "viewport-width", "width",
                "device-memory", "sec-ch-ua", "sec-ch-dpr", "sec-ch-ua-model", "sec-ch-ua-mobile",
                "sec-ch-ua-form-factors", "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-arch",
                "sec-ch-prefers-reduced-transparency", "sec-ch-ua-full-version", "sec-ch-viewport-width",
                "downlink", "sec-ch-viewport-height", "ect", "sec-ch-device-memory",
                "sec-ch-prefers-reduced-motion", "dpr", "sec-ch-width", "sec-ch-prefers-color-scheme",
                "User-Agent", "rtt", "sec-ch-ua-platform-version",
            ]),
            // A subset (Accept-CH: Sec-CH-UA-Arch, Sec-CH-Prefers-Color-Scheme).
            (&[], &[
                "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-prefers-color-scheme", "sec-ch-ua",
                "User-Agent", "sec-ch-ua-mobile",
            ]),
            // No accepted hints, as Obscura already sends them.
            (&[], &["sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile"]),
            (&["Content-Type"], &["sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile"]),
            // Page-supplied headers, without hints.
            (&["X-Requested-With"], &["sec-ch-ua-platform", "X-Requested-With", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile"]),
            (&["X-Foo", "X-Bar"], &["sec-ch-ua-platform", "User-Agent", "X-Bar", "sec-ch-ua", "X-Foo", "sec-ch-ua-mobile"]),
        ];
        for (created, observed) in cases {
            let present: Vec<&str> = observed.iter().copied().filter(|name| HINTS.contains(name)).collect();
            assert_eq!(header_map_order(&inserted(created, &present)), observed.to_vec(), "{created:?}");
        }
    }

    #[test]
    fn insertion_order_decides_collisions() {
        // The same names inserted in another order land elsewhere, so the
        // order is a property of the map, not of the names alone.
        let names = ["sec-ch-ua-arch", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "User-Agent", "sec-ch-prefers-color-scheme"];
        let mut reversed = names;
        reversed.reverse();
        assert_ne!(header_map_order(&names), header_map_order(&reversed));
    }
}
