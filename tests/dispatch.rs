//! Caller-dependent views on a real (private) bus.
//!
//! Identity comes from a fixed test mapping of unique names to principals;
//! everything after identification (dispatch, scoping, signals) is the
//! production code. Real identification is covered by `identity_e2e.rs`.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use scopevault::identity::{AppId, CallerResolver, IdentityError, Principal, Resolved};
use scopevault::service_api::SecretService;
use zbus::message::{Message, Type as MessageType};
use zbus::names::{OwnedUniqueName, UniqueName};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MessageStream};

const DEST: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";
const SVC_IFACE: &str = "org.freedesktop.Secret.Service";
const COL_IFACE: &str = "org.freedesktop.Secret.Collection";
const PROPS: &str = "org.freedesktop.DBus.Properties";

/// Test-only identity: a fixed table filled in by the test.
#[derive(Default)]
struct FixedResolver(Mutex<HashMap<OwnedUniqueName, Principal>>);

impl CallerResolver for FixedResolver {
    async fn resolve(&self, sender: &UniqueName<'_>) -> Resolved {
        let key = OwnedUniqueName::from(sender.to_owned());
        Arc::new(match self.0.lock().unwrap().get(&key) {
            Some(p) => Ok(p.clone()),
            None => Err(IdentityError::NotHost("unknown test caller".into())),
        })
    }
}

fn flatpak(id: &str) -> Principal {
    Principal::Flatpak { app_id: AppId::parse(id).unwrap(), instance_id: "1".into(), risks: Default::default() }
}

struct Fixture {
    service: Arc<SecretService<FixedResolver>>,
    resolver: Arc<FixedResolver>,
    bus: Arc<common::TestBus>,
}

async fn fixture() -> (Fixture, Arc<common::TestBus>) {
    let bus = Arc::new(common::TestBus::start());
    let conn = bus.connect().await;
    let resolver = Arc::new(FixedResolver::default());
    let service = SecretService::new(conn.clone(), resolver.clone());
    let serving = service.clone().start().await.unwrap();
    tokio::spawn(serving);
    conn.request_name(DEST).await.unwrap();
    (Fixture { service, resolver, bus: bus.clone() }, bus)
}

impl Fixture {
    async fn client(&self, who: Option<Principal>) -> Connection {
        let c = self.bus.connect().await;
        if let Some(p) = who {
            self.resolver.0.lock().unwrap().insert(c.unique_name().unwrap().clone(), p);
        }
        c
    }
}

async fn call<B>(c: &Connection, path: &str, iface: &str, method: &str, body: &B) -> Result<Message, (String, String)>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    match c.call_method(Some(DEST), path, Some(iface), method, body).await {
        Ok(m) => Ok(m),
        Err(zbus::Error::MethodError(name, msg, _)) => Err((name.to_string(), msg.unwrap_or_default())),
        Err(e) => panic!("transport error: {e}"),
    }
}

async fn get(c: &Connection, path: &str, iface: &str, prop: &str) -> Result<OwnedValue, (String, String)> {
    let m = call(c, path, PROPS, "Get", &(iface, prop)).await?;
    let (v,): (OwnedValue,) = m.body().deserialize().unwrap();
    Ok(v)
}

async fn collections(c: &Connection) -> Vec<String> {
    let v = get(c, SERVICE, SVC_IFACE, "Collections").await.unwrap();
    let paths: Vec<OwnedObjectPath> = v.try_into().unwrap();
    let mut s: Vec<String> = paths.into_iter().map(|p| p.to_string()).collect();
    s.sort();
    s
}

async fn create_collection(c: &Connection, label: &str, alias: &str) -> String {
    let mut props: HashMap<&str, Value> = HashMap::new();
    props.insert("org.freedesktop.Secret.Collection.Label", Value::from(label));
    let m = call(c, SERVICE, SVC_IFACE, "CreateCollection", &(props, alias)).await.unwrap();
    let (col, prompt): (OwnedObjectPath, OwnedObjectPath) = m.body().deserialize().unwrap();
    assert_eq!(prompt.as_str(), "/");
    col.to_string()
}

async fn introspect_children(c: &Connection, path: &str) -> Result<Vec<String>, (String, String)> {
    let m = call(c, path, "org.freedesktop.DBus.Introspectable", "Introspect", &()).await?;
    let (xml,): (String,) = m.body().deserialize().unwrap();
    let mut names: Vec<String> = xml
        .lines()
        .filter_map(|l| l.trim().strip_prefix("<node name=\"").and_then(|r| r.strip_suffix("\"/>")))
        .map(String::from)
        .collect();
    names.sort();
    Ok(names)
}

/// Collects signals sent to `c` by `from` during `wait`.
async fn signals_during(c: &Connection, from: &str, wait: Duration) -> Vec<(String, String, String)> {
    let mut stream = MessageStream::from(c);
    let mut out = Vec::new();
    let _ = tokio::time::timeout(wait, async {
        while let Some(Ok(m)) = stream.next().await {
            let h = m.header();
            if m.message_type() == MessageType::Signal && h.sender().map(|s| s.as_str()) == Some(from) {
                out.push((
                    h.path().unwrap().to_string(),
                    h.interface().unwrap().to_string(),
                    h.member().unwrap().to_string(),
                ));
            }
        }
    })
    .await;
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn collections_and_aliases_are_scoped() {
    let (fx, _bus) = fixture().await;
    let a = fx.client(Some(flatpak("org.example.A"))).await;
    let b = fx.client(Some(flatpak("org.example.B"))).await;
    let host = fx.client(Some(Principal::Host)).await;

    let ca = create_collection(&a, "Login", "default").await;
    let cb = create_collection(&b, "Login", "default").await;
    create_collection(&a, "Secret Project", "").await;
    // Same readable path in two scopes, but different objects.
    assert_eq!(ca, "/org/freedesktop/secrets/collection/login");
    assert_eq!(ca, cb);

    assert_eq!(
        collections(&a).await,
        ["/org/freedesktop/secrets/collection/login", "/org/freedesktop/secrets/collection/secret_project"]
    );
    assert_eq!(collections(&b).await, ["/org/freedesktop/secrets/collection/login"]);
    assert!(collections(&host).await.is_empty());

    // Labels differ per scope through the same path and through the alias path.
    call(&b, &cb, PROPS, "Set", &(COL_IFACE, "Label", Value::from("B's login"))).await.unwrap();
    for path in [ca.as_str(), "/org/freedesktop/secrets/aliases/default"] {
        let la: String = get(&a, path, COL_IFACE, "Label").await.unwrap().try_into().unwrap();
        let lb: String = get(&b, path, COL_IFACE, "Label").await.unwrap().try_into().unwrap();
        assert_eq!((la.as_str(), lb.as_str()), ("Login", "B's login"));
    }

    // ReadAlias resolves within the caller's scope only.
    let m = call(&host, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap();
    let (p,): (OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), "/");
    let m = call(&a, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap();
    let (p,): (OwnedObjectPath,) = m.body().deserialize().unwrap();
    assert_eq!(p.as_str(), ca);

    // GetAll on the service shows only the caller's collections.
    let m = call(&b, SERVICE, PROPS, "GetAll", &(SVC_IFACE,)).await.unwrap();
    let (all,): (HashMap<String, OwnedValue>,) = m.body().deserialize().unwrap();
    let cols: Vec<OwnedObjectPath> = all["Collections"].try_clone().unwrap().try_into().unwrap();
    assert_eq!(cols.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_paths_are_indistinguishable_from_missing_ones() {
    let (fx, _bus) = fixture().await;
    let a = fx.client(Some(flatpak("org.example.A"))).await;
    let b = fx.client(Some(flatpak("org.example.B"))).await;
    let foreign = create_collection(&a, "Secret Project", "work").await;
    let missing = "/org/freedesktop/secrets/collection/does_not_exist";

    let probes: [(&str, &str, &str); 3] =
        [(PROPS, "Get", "Label"), (PROPS, "GetAll", ""), ("org.freedesktop.DBus.Introspectable", "Introspect", "")];
    for (iface, method, prop) in probes {
        let r = |path: String| {
            let b = b.clone();
            async move {
                match method {
                    "Get" => call(&b, &path, iface, method, &(COL_IFACE, prop)).await.map(|_| ()),
                    "GetAll" => call(&b, &path, iface, method, &(COL_IFACE,)).await.map(|_| ()),
                    _ => call(&b, &path, iface, method, &()).await.map(|_| ()),
                }
            }
        };
        let foreign_err = r(foreign.clone()).await.unwrap_err();
        let missing_err = r(missing.to_owned()).await.unwrap_err();
        assert_eq!(foreign_err, missing_err, "{method}");
        assert_eq!(foreign_err.0, "org.freedesktop.DBus.Error.UnknownObject");
    }

    // Also through the alias path and as a method argument.
    let e1 = get(&b, "/org/freedesktop/secrets/aliases/work", COL_IFACE, "Label").await.unwrap_err();
    let e2 = get(&b, "/org/freedesktop/secrets/aliases/nothing", COL_IFACE, "Label").await.unwrap_err();
    assert_eq!(e1, e2);
    let arg = |p: &str| OwnedObjectPath::try_from(p.to_owned()).unwrap();
    let e1 = call(&b, SERVICE, SVC_IFACE, "SetAlias", &("x", arg(&foreign))).await.unwrap_err();
    let e2 = call(&b, SERVICE, SVC_IFACE, "SetAlias", &("x", arg(missing))).await.unwrap_err();
    assert_eq!(e1, e2);
    assert_eq!(e1.0, "org.freedesktop.Secret.Error.NoSuchObject");

    // Deleting a foreign collection is impossible, and A still has it.
    let e = call(&b, &foreign, COL_IFACE, "Delete", &()).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.UnknownObject");
    assert_eq!(collections(&a).await, [foreign]);
}

#[tokio::test(flavor = "multi_thread")]
async fn introspection_is_scoped() {
    let (fx, _bus) = fixture().await;
    let a = fx.client(Some(flatpak("org.example.A"))).await;
    let b = fx.client(Some(flatpak("org.example.B"))).await;
    create_collection(&a, "Alpha", "default").await;
    create_collection(&a, "Beta", "").await;
    create_collection(&b, "Gamma", "").await;

    let dir = "/org/freedesktop/secrets/collection";
    assert_eq!(introspect_children(&a, dir).await.unwrap(), ["alpha", "beta"]);
    assert_eq!(introspect_children(&b, dir).await.unwrap(), ["gamma"]);
    assert_eq!(introspect_children(&a, "/org/freedesktop/secrets/aliases").await.unwrap(), ["default"]);
    assert!(introspect_children(&b, "/org/freedesktop/secrets/aliases").await.unwrap().is_empty());
    assert_eq!(introspect_children(&b, "/").await.unwrap(), ["org"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn signals_reach_only_the_owning_scope() {
    let (fx, _bus) = fixture().await;
    let a1 = fx.client(Some(flatpak("org.example.A"))).await;
    let a2 = fx.client(Some(flatpak("org.example.A"))).await;
    let b = fx.client(Some(flatpak("org.example.B"))).await;
    let host = fx.client(Some(Principal::Host)).await;
    // Signals go to connections that have talked to the service.
    for c in [&a2, &b, &host] {
        collections(c).await;
    }
    let svc_name = fx.service_name().await;

    let watch = |c: Connection| {
        let from = svc_name.clone();
        tokio::spawn(async move { signals_during(&c, &from, Duration::from_millis(800)).await })
    };
    let (wa2, wb, wh) = (watch(a2.clone()), watch(b.clone()), watch(host.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let col = create_collection(&a1, "Private", "").await;
    call(&a1, &col, PROPS, "Set", &(COL_IFACE, "Label", Value::from("Renamed"))).await.unwrap();

    let got_a2 = wa2.await.unwrap();
    assert!(got_a2.contains(&(SERVICE.into(), SVC_IFACE.into(), "CollectionCreated".into())), "{got_a2:?}");
    assert!(got_a2.contains(&(SERVICE.into(), SVC_IFACE.into(), "CollectionChanged".into())), "{got_a2:?}");
    assert!(got_a2.contains(&(col.clone(), PROPS.into(), "PropertiesChanged".into())), "{got_a2:?}");
    assert_eq!(wb.await.unwrap(), vec![]);
    assert_eq!(wh.await.unwrap(), vec![]);
}

#[tokio::test(flavor = "multi_thread")]
async fn unidentified_callers_are_denied_everything() {
    let (fx, _bus) = fixture().await;
    let stranger = fx.client(None).await;
    for (path, iface, method) in [
        (SERVICE, "org.freedesktop.DBus.Introspectable", "Introspect"),
        (SERVICE, "org.freedesktop.DBus.Peer", "Ping"),
        ("/", "org.freedesktop.DBus.Introspectable", "Introspect"),
    ] {
        let e = call(&stranger, path, iface, method, &()).await.unwrap_err();
        assert_eq!(e.0, "org.freedesktop.DBus.Error.AccessDenied");
    }
    let e = call(&stranger, SERVICE, SVC_IFACE, "ReadAlias", &("default",)).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.AccessDenied");
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_are_rejected() {
    let (fx, _bus) = fixture().await;
    let a = fx.client(Some(flatpak("org.example.A"))).await;
    let e = call(&a, SERVICE, SVC_IFACE, "ReadAlias", &(42u32,)).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.InvalidArgs");
    let e = call(&a, SERVICE, SVC_IFACE, "NoSuchMethod", &()).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.UnknownMethod");
    let e = call(&a, SERVICE, "org.example.Nope", "X", &()).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.UnknownInterface");
    let e = call(&a, SERVICE, PROPS, "Set", &(SVC_IFACE, "Collections", Value::from(1u32))).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.PropertyReadOnly");
    let col = create_collection(&a, "X", "").await;
    let e = call(&a, &col, PROPS, "Set", &(COL_IFACE, "Label", Value::from(5u32))).await.unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.InvalidArgs");
    let e = call(&a, SERVICE, SVC_IFACE, "SetAlias", &("bad/alias", OwnedObjectPath::try_from(col).unwrap()))
        .await
        .unwrap_err();
    assert_eq!(e.0, "org.freedesktop.DBus.Error.InvalidArgs");
}

#[tokio::test(flavor = "multi_thread")]
async fn exactly_one_reply_per_call_and_disconnects_are_forgotten() {
    let (fx, _bus) = fixture().await;
    let a = fx.client(Some(flatpak("org.example.A"))).await;
    let mut stream = MessageStream::from(&a);
    let msg = Message::method_call(SERVICE, "ReadAlias")
        .unwrap()
        .destination(DEST)
        .unwrap()
        .interface(SVC_IFACE)
        .unwrap()
        .build(&("default",))
        .unwrap();
    let serial = msg.primary_header().serial_num();
    a.send(&msg).await.unwrap();
    let mut replies = 0;
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(Ok(m)) = stream.next().await {
            if m.header().reply_serial() == Some(serial) {
                replies += 1;
            }
        }
    })
    .await;
    assert_eq!(replies, 1);

    let before = fx.service.active_connections();
    let extra = fx.client(Some(Principal::Host)).await;
    collections(&extra).await;
    assert_eq!(fx.service.active_connections(), before + 1);
    drop(extra);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fx.service.active_connections(), before);
}

impl Fixture {
    async fn service_name(&self) -> String {
        let c = self.bus.connect().await;
        let dbus = zbus::fdo::DBusProxy::new(&c).await.unwrap();
        dbus.get_name_owner(DEST.try_into().unwrap()).await.unwrap().to_string()
    }
}
