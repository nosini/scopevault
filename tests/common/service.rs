//! Helpers for tests that run the service on a private bus.
//!
//! Identity comes from a fixed table filled in by the test; everything after
//! identification (dispatch, scoping, signals, store) is production code.
//! Real identification is covered by `identity_e2e.rs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U1024};
use futures_util::StreamExt;
use scopevault::identity::{AppId, CallerResolver, IdentityError, Principal, Resolved};
use scopevault::service_api::SecretService;
use zbus::message::{Message, Type as MessageType};
use zbus::names::{OwnedUniqueName, UniqueName};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MessageStream};

use super::{TestBus, VaultFixture, VaultState};

pub const DEST: &str = "org.freedesktop.secrets";
pub const SERVICE: &str = "/org/freedesktop/secrets";
pub const SVC_IFACE: &str = "org.freedesktop.Secret.Service";
pub const COL_IFACE: &str = "org.freedesktop.Secret.Collection";
pub const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
pub const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
pub const PROPS: &str = "org.freedesktop.DBus.Properties";

/// Test-only identity: a fixed table filled in by the test.
#[derive(Default)]
pub struct FixedResolver(Mutex<HashMap<OwnedUniqueName, Principal>>);

impl CallerResolver for FixedResolver {
    async fn resolve(&self, sender: &UniqueName<'_>) -> Resolved {
        let key = OwnedUniqueName::from(sender.to_owned());
        Arc::new(match self.0.lock().unwrap().get(&key) {
            Some(p) => Ok(p.clone()),
            None => Err(IdentityError::NotHost("unknown test caller".into())),
        })
    }
}

pub fn flatpak(id: &str) -> Principal {
    Principal::Flatpak { app_id: AppId::parse(id).unwrap(), instance_id: "1".into(), risks: Default::default() }
}

pub struct Fixture {
    pub service: Arc<SecretService<FixedResolver>>,
    pub resolver: Arc<FixedResolver>,
    pub bus: Arc<TestBus>,
    pub vault: VaultFixture,
}

pub async fn fixture(state: VaultState) -> Fixture {
    let bus = Arc::new(TestBus::start());
    let conn = bus.connect().await;
    let resolver = Arc::new(FixedResolver::default());
    let vault = VaultFixture::new(state);
    let service = SecretService::new(conn.clone(), resolver.clone(), vault.unlocker.clone());
    let serving = service.clone().start().await.unwrap();
    tokio::spawn(serving);
    conn.request_name(DEST).await.unwrap();
    Fixture { service, resolver, bus, vault }
}

impl Fixture {
    pub async fn client(&self, who: Option<Principal>) -> Connection {
        let c = self.bus.connect().await;
        if let Some(p) = who {
            self.resolver.0.lock().unwrap().insert(c.unique_name().unwrap().clone(), p);
        }
        c
    }

    pub async fn service_name(&self) -> String {
        let c = self.bus.connect().await;
        let dbus = zbus::fdo::DBusProxy::new(&c).await.unwrap();
        dbus.get_name_owner(DEST.try_into().unwrap()).await.unwrap().to_string()
    }
}

pub type Failure = (String, String);

pub async fn call<B>(c: &Connection, path: &str, iface: &str, method: &str, body: &B) -> Result<Message, Failure>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    match c.call_method(Some(DEST), path, Some(iface), method, body).await {
        Ok(m) => Ok(m),
        Err(zbus::Error::MethodError(name, msg, _)) => Err((name.to_string(), msg.unwrap_or_default())),
        Err(e) => panic!("transport error: {e}"),
    }
}

pub async fn get(c: &Connection, path: &str, iface: &str, prop: &str) -> Result<OwnedValue, Failure> {
    let m = call(c, path, PROPS, "Get", &(iface, prop)).await?;
    let (v,): (OwnedValue,) = m.body().deserialize().unwrap();
    Ok(v)
}

pub fn obj(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p.to_owned()).unwrap()
}

pub fn strings(paths: Vec<OwnedObjectPath>) -> Vec<String> {
    let mut s: Vec<String> = paths.into_iter().map(|p| p.to_string()).collect();
    s.sort();
    s
}

pub async fn collections(c: &Connection) -> Vec<String> {
    let v = get(c, SERVICE, SVC_IFACE, "Collections").await.unwrap();
    strings(v.try_into().unwrap())
}

/// Calls `CreateCollection`; returns `(collection, prompt)`.
pub async fn try_create_collection(c: &Connection, label: &str, alias: &str) -> Result<(String, String), Failure> {
    let mut props: HashMap<&str, Value> = HashMap::new();
    props.insert("org.freedesktop.Secret.Collection.Label", Value::from(label));
    let m = call(c, SERVICE, SVC_IFACE, "CreateCollection", &(props, alias)).await?;
    let (col, prompt): (OwnedObjectPath, OwnedObjectPath) = m.body().deserialize().unwrap();
    Ok((col.to_string(), prompt.to_string()))
}

pub async fn create_collection(c: &Connection, label: &str, alias: &str) -> String {
    let (col, prompt) = try_create_collection(c, label, alias).await.unwrap();
    assert_eq!(prompt, "/");
    col
}

pub async fn introspect_children(c: &Connection, path: &str) -> Result<Vec<String>, Failure> {
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

/// Records signals sent to a connection by the service, from the moment
/// it is created.
pub struct SignalLog {
    messages: Arc<Mutex<Vec<Message>>>,
    task: tokio::task::JoinHandle<()>,
}

impl SignalLog {
    pub fn start(c: &Connection, from: &str) -> Self {
        let mut stream = MessageStream::from(c);
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = messages.clone();
        let from = from.to_owned();
        let task = tokio::spawn(async move {
            while let Some(Ok(m)) = stream.next().await {
                if m.message_type() == MessageType::Signal && m.header().sender().map(|s| s.as_str()) == Some(&from) {
                    sink.lock().unwrap().push(m);
                }
            }
        });
        SignalLog { messages, task }
    }

    /// `(path, interface, member)` of every signal so far.
    pub fn names(&self) -> Vec<(String, String, String)> {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .map(|m| {
                let h = m.header();
                (h.path().unwrap().to_string(), h.interface().unwrap().to_string(), h.member().unwrap().to_string())
            })
            .collect()
    }

    pub fn find(&self, path: &str, member: &str) -> Option<Message> {
        self.messages
            .lock()
            .unwrap()
            .iter()
            .find(|m| {
                let h = m.header();
                h.path().map(|p| p.as_str()) == Some(path) && h.member().map(|m| m.as_str()) == Some(member)
            })
            .cloned()
    }

    /// Waits until a signal with this path and member arrives.
    pub async fn wait_for(&self, path: &str, member: &str, timeout: Duration) -> Option<Message> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(m) = self.find(path, member) {
                return Some(m);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for SignalLog {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Calls `Prompt` and waits for `Completed`. Returns `(dismissed, result)`.
pub async fn run_prompt(c: &Connection, from: &str, prompt: &str) -> (bool, OwnedValue) {
    let log = SignalLog::start(c, from);
    call(c, prompt, PROMPT_IFACE, "Prompt", &("",)).await.unwrap();
    let m = log.wait_for(prompt, "Completed", Duration::from_secs(30)).await.expect("Completed signal");
    m.body().deserialize().unwrap()
}

// ---- client side of transfer sessions ----

const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
                         EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
                         EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

pub type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// A transfer session as a client holds it.
pub struct ClientSession {
    pub path: OwnedObjectPath,
    key: Option<[u8; 16]>,
}

impl ClientSession {
    pub async fn plain(c: &Connection) -> Self {
        let m = call(c, SERVICE, SVC_IFACE, "OpenSession", &("plain", Value::from(""))).await.unwrap();
        let (_, path): (OwnedValue, OwnedObjectPath) = m.body().deserialize().unwrap();
        ClientSession { path, key: None }
    }

    /// Negotiates `dh-ietf1024-sha256-aes128-cbc-pkcs7` the way libsecret does.
    pub async fn dh(c: &Connection) -> Self {
        let p = U1024::from_be_hex(PRIME_HEX);
        let params = FixedMontyParams::new_vartime(Odd::new(p).unwrap());
        let mut xb = [0u8; 128];
        getrandom::fill(&mut xb).unwrap();
        xb[0] &= 0x7f;
        let x = U1024::from_be_slice(&xb);
        let public = FixedMontyForm::new(&U1024::from_u8(2), &params).pow(&x).retrieve().to_be_bytes();
        let m = call(
            c,
            SERVICE,
            SVC_IFACE,
            "OpenSession",
            &("dh-ietf1024-sha256-aes128-cbc-pkcs7", Value::from(public.as_ref().to_vec())),
        )
        .await
        .unwrap();
        let (output, path): (OwnedValue, OwnedObjectPath) = m.body().deserialize().unwrap();
        let server: Vec<u8> = output.try_into().unwrap();
        let mut buf = [0u8; 128];
        buf[128 - server.len()..].copy_from_slice(&server);
        let shared = FixedMontyForm::new(&U1024::from_be_slice(&buf), &params).pow(&x).retrieve().to_be_bytes();
        let mut key = [0u8; 16];
        hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_ref()).expand(&[], &mut key).unwrap();
        ClientSession { path, key: Some(key) }
    }

    pub fn encode(&self, secret: &[u8], content_type: &str) -> WireSecret {
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
        match &self.key {
            None => (self.path.clone(), Vec::new(), secret.to_vec(), content_type.into()),
            Some(key) => {
                let mut iv = [0u8; 16];
                getrandom::fill(&mut iv).unwrap();
                let enc = cbc::Encryptor::<aes::Aes128>::new(&(*key).into(), &iv.into());
                let ct = enc.encrypt_padded_vec::<cbc::cipher::block_padding::Pkcs7>(secret);
                (self.path.clone(), iv.to_vec(), ct, content_type.into())
            }
        }
    }

    pub fn decode(&self, wire: &WireSecret) -> (Vec<u8>, String) {
        use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
        assert_eq!(wire.0, self.path, "secret encoded for another session");
        let value = match &self.key {
            None => {
                assert!(wire.1.is_empty());
                wire.2.clone()
            }
            Some(key) => {
                let iv: [u8; 16] = wire.1.as_slice().try_into().unwrap();
                let dec = cbc::Decryptor::<aes::Aes128>::new(&(*key).into(), &iv.into());
                dec.decrypt_padded_vec::<cbc::cipher::block_padding::Pkcs7>(&wire.2).unwrap()
            }
        };
        (value, wire.3.clone())
    }
}

/// Creates an item; returns `(item, prompt)`.
pub async fn create_item(
    c: &Connection,
    collection: &str,
    session: &ClientSession,
    label: &str,
    attrs: &[(&str, &str)],
    secret: &[u8],
    replace: bool,
) -> Result<String, Failure> {
    let attrs: HashMap<&str, &str> = attrs.iter().copied().collect();
    let mut props: HashMap<&str, Value> = HashMap::new();
    props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
    props.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs));
    let wire = session.encode(secret, "text/plain");
    let m = call(c, collection, COL_IFACE, "CreateItem", &(props, wire, replace)).await?;
    let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = m.body().deserialize().unwrap();
    assert_eq!(prompt.as_str(), "/");
    Ok(item.to_string())
}

pub async fn get_secret(c: &Connection, item: &str, session: &ClientSession) -> Result<(Vec<u8>, String), Failure> {
    let m = call(c, item, ITEM_IFACE, "GetSecret", &(&session.path,)).await?;
    let (wire,): (WireSecret,) = m.body().deserialize().unwrap();
    Ok(session.decode(&wire))
}

/// `SearchItems` on the service: `(unlocked, locked)`, sorted.
pub async fn search(c: &Connection, attrs: &[(&str, &str)]) -> Result<(Vec<String>, Vec<String>), Failure> {
    let attrs: HashMap<&str, &str> = attrs.iter().copied().collect();
    let m = call(c, SERVICE, SVC_IFACE, "SearchItems", &(attrs,)).await?;
    let (u, l): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = m.body().deserialize().unwrap();
    Ok((strings(u), strings(l)))
}

/// `Unlock` or `Lock` on the service: `(objects, prompt)`.
pub async fn xlock(c: &Connection, method: &str, objects: &[&str]) -> Result<(Vec<String>, String), Failure> {
    let objects: Vec<OwnedObjectPath> = objects.iter().map(|p| obj(p)).collect();
    let m = call(c, SERVICE, SVC_IFACE, method, &(objects,)).await?;
    let (done, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = m.body().deserialize().unwrap();
    Ok((strings(done), prompt.to_string()))
}
