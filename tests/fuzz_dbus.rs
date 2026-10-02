//! Randomised requests against the live service on a private bus.
//!
//! The bus daemon validates the wire format, so what reaches the service is
//! always a well-formed message; the attack surface is well-formed messages
//! with unexpected paths, interfaces, members, signatures and values. Each
//! request is generated from a seeded PRNG: usually with the signature the
//! member expects and values drawn from pools of interesting ones (real and
//! foreign object paths, property names, algorithm names, empty and long
//! strings, random variants), otherwise with a random signature.
//!
//! Checked for every request: an answer arrives (no hang, no dropped
//! request), errors are well-formed D-Bus errors and never "internal". At
//! the end: B's data is unchanged although A, the host and an unidentified
//! caller sent random requests (including B's paths), none of B's secrets
//! or metadata appeared in any reply to them, and the service still works.
//!
//! `SCOPEVAULT_FUZZ_SEED` and `SCOPEVAULT_FUZZ_ITERATIONS` override the
//! random seed and the number of requests (default 3000).

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::VaultState;
use common::service::*;
use scopevault::identity::Principal;
use scopevault::service_api::interfaces;
use zbus::Connection;
use zbus::message::{Flags, Message};
use zbus::zvariant::{Array, Dict, ObjectPath, Signature, StructureBuilder, Value};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Values the generator draws from.
struct Pools {
    paths: Vec<String>,
    /// Paths of objects implementing each interface (own and foreign).
    by_interface: HashMap<&'static str, Vec<String>>,
    strings: Vec<String>,
}

const B_SECRET: &str = "B-SECRET-7d1f0c";
const B_LABEL: &str = "B-LABEL-93ae21";
const B_ATTR: &str = "B-ATTR-5520be";
const B_COLLECTION_LABEL: &str = "B-COLLECTION-0f6d2a";

fn random_string(r: &mut Rng) -> String {
    // No NUL: D-Bus strings cannot hold it, and the bus disconnects senders.
    let alphabet: Vec<char> = "abcXYZ019 _-/.:=\u{e4}\u{1f511}\t\u{7f}".chars().collect();
    let len = match r.below(10) {
        0 => 0,
        1 => 5000,
        _ => r.below(40),
    };
    (0..len).map(|_| *r.pick(&alphabet)).collect()
}

fn random_path(r: &mut Rng, pools: &Pools) -> String {
    match r.below(4) {
        0 => {
            let base = r.pick(&[
                "/org/freedesktop/secrets/collection/",
                "/org/freedesktop/secrets/aliases/",
                "/org/freedesktop/secrets/session/",
                "/org/freedesktop/secrets/prompt/",
                "/org/freedesktop/secrets/collection/login/",
                "/org/",
            ]);
            let elem: String = (0..1 + r.below(70)).map(|_| *r.pick(&['a', 'Z', '0', '_'])).collect();
            format!("{base}{elem}")
        }
        _ => r.pick(&pools.paths).clone(),
    }
}

/// A random signature without file descriptors, at most `depth` levels deep.
fn random_signature(r: &mut Rng, depth: usize) -> Signature {
    let leaves = [
        Signature::U8,
        Signature::Bool,
        Signature::I16,
        Signature::U16,
        Signature::I32,
        Signature::U32,
        Signature::I64,
        Signature::U64,
        Signature::F64,
        Signature::Str,
        Signature::ObjectPath,
        Signature::Signature,
        Signature::Variant,
    ];
    if depth == 0 || r.chance(50) {
        return r.pick(&leaves).clone();
    }
    match r.below(3) {
        0 => Signature::Array(random_signature(r, depth - 1).into()),
        1 => {
            let key = r.pick(&[Signature::Str, Signature::ObjectPath, Signature::U32, Signature::Str]).clone();
            Signature::Dict { key: key.into(), value: random_signature(r, depth - 1).into() }
        }
        _ => {
            Signature::Structure((0..1 + r.below(4)).map(|_| random_signature(r, depth - 1)).collect::<Vec<_>>().into())
        }
    }
}

fn random_value(r: &mut Rng, pools: &Pools, sig: &Signature, depth: usize) -> Value<'static> {
    match sig {
        Signature::U8 => Value::U8(r.next() as u8),
        Signature::Bool => Value::Bool(r.chance(50)),
        Signature::I16 => Value::I16(r.next() as i16),
        Signature::U16 => Value::U16(r.next() as u16),
        Signature::I32 => Value::I32(r.next() as i32),
        Signature::U32 => Value::U32(r.next() as u32),
        Signature::I64 => Value::I64(r.next() as i64),
        Signature::U64 => Value::U64(r.next()),
        Signature::F64 => Value::F64(f64::from_bits(r.next())),
        Signature::Str => {
            let s = if r.chance(60) { r.pick(&pools.strings).clone() } else { random_string(r) };
            Value::from(s)
        }
        Signature::ObjectPath => Value::from(ObjectPath::try_from(random_path(r, pools)).unwrap().into_owned()),
        Signature::Signature => Value::from(random_signature(r, 2)),
        Signature::Variant => {
            let inner = if depth == 0 { Signature::Str } else { random_signature(r, 2) };
            Value::Value(Box::new(random_value(r, pools, &inner, depth.saturating_sub(1))))
        }
        Signature::Array(child) => {
            let mut a = Array::new(child);
            let n = match r.below(8) {
                0 => 0,
                1 if matches!(**child, Signature::U8) => 128,
                _ => r.below(5),
            };
            for _ in 0..n {
                a.append(random_value(r, pools, child, depth.saturating_sub(1))).unwrap();
            }
            Value::Array(a)
        }
        Signature::Dict { key, value } => {
            let mut d = Dict::new(key, value);
            for _ in 0..r.below(5) {
                let k = random_value(r, pools, key, 0);
                let v = random_value(r, pools, value, depth.saturating_sub(1));
                // Duplicate keys are refused by Dict; skip them.
                let _ = d.append(k, v);
            }
            Value::Dict(d)
        }
        Signature::Structure(fields) => {
            let mut b = StructureBuilder::new();
            for f in fields.iter() {
                b = b.append_field(random_value(r, pools, f, depth.saturating_sub(1)));
            }
            Value::Structure(b.build().unwrap())
        }
        other => panic!("unexpected signature {other}"),
    }
}

/// Every (interface, member, expected signature) the service implements.
fn members() -> Vec<(&'static str, &'static str, String)> {
    let mut out = Vec::new();
    let secret =
        [&interfaces::SERVICE, &interfaces::COLLECTION, &interfaces::ITEM, &interfaces::SESSION, &interfaces::PROMPT];
    for i in interfaces::STANDARD.iter().copied().chain(secret) {
        for m in i.methods {
            out.push((i.name, m.name, m.in_signature()));
        }
    }
    out
}

fn build_request(r: &mut Rng, pools: &Pools, members: &[(&'static str, &'static str, String)]) -> Message {
    let (iface, member, sig) = r.pick(members).clone();
    // Mostly a path of the right kind of object, so requests get past path
    // resolution and into the handlers.
    let path = match pools.by_interface.get(iface) {
        Some(p) if r.chance(70) => r.pick(p).clone(),
        _ => random_path(r, pools),
    };
    let member = if r.chance(5) { "NoSuchMember" } else { member };
    let sig: Signature =
        if r.chance(25) { random_signature(r, 3) } else { format!("({sig})").parse().unwrap_or(Signature::Unit) };
    let mut b = Message::method_call(path.as_str(), member).unwrap().destination(DEST).unwrap();
    match r.below(20) {
        0 => {}
        1 => b = b.interface("org.example.NoSuchInterface").unwrap(),
        _ => b = b.interface(iface).unwrap(),
    }
    if r.chance(5) {
        b = b.with_flags(Flags::NoReplyExpected).unwrap();
    }
    let fields: Vec<Signature> = match &sig {
        Signature::Structure(f) => f.iter().cloned().collect(),
        Signature::Unit => Vec::new(),
        other => vec![other.clone()],
    };
    if fields.is_empty() {
        return b.build(&()).unwrap();
    }
    let mut s = StructureBuilder::new();
    for f in &fields {
        s = s.append_field(random_value(r, pools, f, 3));
    }
    b.build(&s.build().unwrap()).unwrap()
}

/// Sends a request and waits for its reply. `Ok(None)` when no reply was
/// requested.
async fn request(c: &Connection, m: &Message) -> Result<Option<Message>, String> {
    use futures_util::StreamExt;
    let expects_reply = !m.primary_header().flags().contains(Flags::NoReplyExpected);
    let mut stream = zbus::MessageStream::from(c);
    c.send(m).await.map_err(|e| format!("send failed: {e}"))?;
    if !expects_reply {
        return Ok(None);
    }
    let serial = m.primary_header().serial_num();
    let wait = async {
        while let Some(Ok(reply)) = stream.next().await {
            if reply.header().reply_serial() == Some(serial) {
                return Ok(Some(reply));
            }
        }
        Err("connection closed".to_owned())
    };
    tokio::time::timeout(Duration::from_secs(10), wait).await.map_err(|_| "no reply within 10 s".to_owned())?
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[tokio::test(flavor = "multi_thread")]
async fn random_requests_are_answered_and_change_nothing_foreign() {
    let seed = std::env::var("SCOPEVAULT_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        u64::from_le_bytes(b)
    });
    let iterations: usize =
        std::env::var("SCOPEVAULT_FUZZ_ITERATIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(3000);
    eprintln!("fuzz seed {seed} ({iterations} requests); rerun with SCOPEVAULT_FUZZ_SEED={seed}");
    let mut r = Rng(seed);

    let fx = fixture(VaultState::Unlocked).await;
    fx.vault.set_pins(&["CANCEL"; 64]);
    let a = fx.client(Some(flatpak("org.example.A"))).await;
    let a2 = fx.client(Some(flatpak("org.example.A"))).await;
    let host = fx.client(Some(Principal::Host)).await;
    let stranger = fx.client(None).await;
    let b = fx.client(Some(flatpak("org.example.B"))).await;

    // The victim's data.
    let b_col = create_collection(&b, B_COLLECTION_LABEL, "default").await;
    let bs = ClientSession::plain(&b).await;
    let b_item =
        create_item(&b, &b_col, &bs, B_LABEL, &[("marker", B_ATTR)], B_SECRET.as_bytes(), false).await.unwrap();
    // The attackers' own objects, so requests also reach real code paths.
    let a_col = create_collection(&a, "login", "default").await;
    let as_ = ClientSession::plain(&a).await;
    let a_item = create_item(&a, &a_col, &as_, "a", &[("k", "v")], b"a-secret", false).await.unwrap();
    let host_session = ClientSession::plain(&host).await;
    // A pending prompt of A's (a logically locked collection to reopen).
    let a_locked = create_collection(&a, "locked", "").await;
    xlock(&a, "Lock", &[&a_locked]).await.unwrap();
    let (_, a_prompt) = xlock(&a, "Unlock", &[&a_locked]).await.unwrap();
    assert_ne!(a_prompt, "/");
    let b_alias_item = format!("/org/freedesktop/secrets/aliases/default/{}", b_item.rsplit('/').next().unwrap());
    let by_interface: HashMap<&'static str, Vec<String>> = [
        ("org.freedesktop.Secret.Service", vec![SERVICE.to_owned()]),
        (
            "org.freedesktop.Secret.Collection",
            vec![a_col.clone(), a_locked.clone(), b_col.clone(), "/org/freedesktop/secrets/aliases/default".into()],
        ),
        ("org.freedesktop.Secret.Item", vec![a_item.clone(), b_item.clone(), b_alias_item.clone()]),
        ("org.freedesktop.Secret.Session", vec![as_.path.to_string(), bs.path.to_string()]),
        ("org.freedesktop.Secret.Prompt", vec![a_prompt.clone()]),
    ]
    .into();

    let pools = Pools {
        paths: vec![
            "/".into(),
            "/org/freedesktop/secrets".into(),
            "/org/freedesktop/secrets/collection".into(),
            "/org/freedesktop/secrets/aliases".into(),
            "/org/freedesktop/secrets/aliases/default".into(),
            "/org/freedesktop/secrets/aliases/session".into(),
            "/org/freedesktop/secrets/session".into(),
            "/org/freedesktop/secrets/prompt".into(),
            a_col.clone(),
            a_item.clone(),
            b_col.clone(),
            b_item.clone(),
            b_alias_item.clone(),
            a_locked.clone(),
            a_prompt.clone(),
            as_.path.to_string(),
            bs.path.to_string(),
            host_session.path.to_string(),
        ],
        strings: [
            "",
            "plain",
            "dh-ietf1024-sha256-aes128-cbc-pkcs7",
            "default",
            "session",
            "login",
            "org.freedesktop.Secret.Service",
            "org.freedesktop.Secret.Collection",
            "org.freedesktop.Secret.Item",
            "org.freedesktop.Secret.Collection.Label",
            "org.freedesktop.Secret.Item.Label",
            "org.freedesktop.Secret.Item.Attributes",
            "Label",
            "Attributes",
            "Items",
            "Collections",
            "Locked",
            "Created",
            "marker",
            "k",
            "v",
            "text/plain",
        ]
        .map(String::from)
        .to_vec(),
        by_interface,
    };
    let members = members();

    let attackers = [("A", &a), ("A2", &a2), ("host", &host), ("stranger", &stranger)];
    let mut answered = 0;
    let mut errors: HashMap<String, usize> = HashMap::new();
    for n in 0..iterations {
        let (who, c) = *r.pick(&attackers);
        let m = build_request(&mut r, &pools, &members);
        let h = m.header();
        let describe = format!(
            "request {n} from {who}: {} {}.{} ({})",
            h.path().unwrap(),
            h.interface().map(|i| i.as_str()).unwrap_or("-"),
            h.member().unwrap(),
            m.body().signature()
        );
        let reply = request(c, &m).await.unwrap_or_else(|e| panic!("{describe}: {e} (seed {seed})"));
        let Some(reply) = reply else { continue };
        answered += 1;
        let bytes: &[u8] = reply.data();
        for marker in [B_SECRET, B_LABEL, B_ATTR, B_COLLECTION_LABEL] {
            assert!(!contains(bytes, marker), "{describe}: reply leaks B's {marker} (seed {seed})");
        }
        if let Some(name) = reply.header().error_name() {
            let msg: String = reply.body().deserialize::<(String,)>().map(|m| m.0).unwrap_or_default();
            assert!(
                name.starts_with("org.freedesktop.DBus.Error.") || name.starts_with("org.freedesktop.Secret.Error."),
                "{describe}: unexpected error {name}: {msg} (seed {seed})"
            );
            assert!(
                !(name.as_str() == "org.freedesktop.DBus.Error.Failed" && msg == "Internal error"),
                "{describe}: internal error (seed {seed})"
            );
            *errors.entry(format!("{name}: {msg}")).or_default() += 1;
        }
    }
    eprintln!("answered {answered}; errors by name: {errors:?}");
    assert!(answered > iterations / 2);
    assert!(errors.len() > 3, "requests should reach many different error paths: {errors:?}");
    assert!(answered > errors.values().sum::<usize>(), "some requests should succeed: {errors:?}");

    // B's data is exactly as before.
    assert_eq!(collections(&b).await, vec![b_col.clone()]);
    assert_eq!(get(&b, &b_col, COL_IFACE, "Label").await.unwrap(), Value::from(B_COLLECTION_LABEL).try_into().unwrap());
    let items: Vec<zbus::zvariant::OwnedObjectPath> =
        get(&b, &b_col, COL_IFACE, "Items").await.unwrap().try_into().unwrap();
    assert_eq!(strings(items), vec![b_item.clone()]);
    assert_eq!(get(&b, &b_item, ITEM_IFACE, "Label").await.unwrap(), Value::from(B_LABEL).try_into().unwrap());
    assert_eq!(get_secret(&b, &b_item, &bs).await.unwrap().0, B_SECRET.as_bytes());
    assert!(!bool::try_from(get(&b, &b_col, COL_IFACE, "Locked").await.unwrap()).unwrap());

    // Still serving, and nothing piled up.
    for c in [&a, &host, &b] {
        call(c, SERVICE, "org.freedesktop.DBus.Peer", "Ping", &()).await.unwrap();
    }
    assert!(fx.service.open_sessions() <= 5 * scopevault::service_api::dispatch::MAX_SESSIONS_PER_CONNECTION);
    assert!(fx.service.pending_prompts() <= 5 * scopevault::service_api::dispatch::MAX_PROMPTS_PER_CONNECTION);
}
