//! A Secret Service client for another provider: the one migrated from
//! (gnome-keyring, before switching) or rolled back to.
//!
//! It is an ordinary client of the standard API: it never reads the other
//! provider's files. Secrets travel in an encrypted
//! (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) transfer session; a provider
//! offering only `plain` is refused. Unlocking and creating collections may
//! need the provider's own prompts, which this client runs.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use futures_util::StreamExt;
use zbus::message::Message;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MatchRule, MessageStream};

use crate::service_api::transfer::{Algorithm, ClientDh, DH_AES};
use crate::store::{PortableCollection, PortableItem, Secret, same_attributes};

const DEST: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";
const SVC: &str = "org.freedesktop.Secret.Service";
const COL: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
const PROPS: &str = "org.freedesktop.DBus.Properties";
/// Long enough for a person to answer the provider's dialog.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);
/// Items per `GetSecrets` call.
const BATCH: usize = 50;

type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// What [`Provider::write`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteReport {
    pub collections_created: usize,
    pub items_written: usize,
    /// Already present with the same label, attributes and secret.
    pub items_skipped: usize,
}

pub struct Provider {
    conn: Connection,
    session: OwnedObjectPath,
    algorithm: Algorithm,
}

fn err(what: &str) -> impl Fn(zbus::Error) -> String + '_ {
    move |e| match e {
        zbus::Error::MethodError(name, msg, _) => {
            format!("{what}: {name}{}", msg.map(|m| format!(": {m}")).unwrap_or_default())
        }
        other => format!("{what}: {other}"),
    }
}

impl Provider {
    /// Connects to the provider owning `org.freedesktop.secrets` on the bus
    /// at `address` (the session bus if `None`) and opens an encrypted
    /// transfer session.
    pub async fn connect(address: Option<&str>) -> Result<Self, String> {
        let builder = match address {
            Some(a) => zbus::connection::Builder::address(a).map_err(|e| format!("bad bus address: {e}"))?,
            None => zbus::connection::Builder::session().map_err(|e| format!("no session bus: {e}"))?,
        };
        let conn = builder.build().await.map_err(|e| format!("cannot connect to the bus: {e}"))?;
        let (dh, public) = ClientDh::start().map_err(|f| f.message)?;
        let m = conn
            .call_method(Some(DEST), SERVICE, Some(SVC), "OpenSession", &(DH_AES, Value::from(public)))
            .await
            .map_err(err("the provider refused an encrypted session"))?;
        let (output, session): (OwnedValue, OwnedObjectPath) =
            m.body().deserialize().map_err(|e| format!("unexpected OpenSession reply: {e}"))?;
        let server: Vec<u8> = output.try_into().map_err(|_| "unexpected OpenSession output".to_owned())?;
        let algorithm = dh.finish(&server).map_err(|f| format!("key exchange failed: {}", f.message))?;
        Ok(Provider { conn, session, algorithm })
    }

    /// The program owning the name, for display: "comm (PID n)".
    pub async fn owner(&self) -> String {
        let dbus = match zbus::fdo::DBusProxy::new(&self.conn).await {
            Ok(d) => d,
            Err(_) => return "unknown".into(),
        };
        let Ok(name) = zbus::names::BusName::try_from(DEST) else { return "unknown".into() };
        match dbus.get_connection_unix_process_id(name).await {
            Ok(pid) => {
                let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                format!("{} (PID {pid})", comm.trim())
            }
            Err(_) => "unknown".into(),
        }
    }

    async fn call<B>(&self, p: &str, iface: &str, method: &str, body: &B) -> Result<Message, zbus::Error>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.conn.call_method(Some(DEST), p, Some(iface), method, body).await
    }

    async fn get<T: TryFrom<OwnedValue>>(&self, p: &str, iface: &str, prop: &str) -> Result<T, String> {
        let m = self.call(p, PROPS, "Get", &(iface, prop)).await.map_err(err(&format!("reading {prop} of {p}")))?;
        let v: OwnedValue = m.body().deserialize().map_err(|e| e.to_string())?;
        T::try_from(v).map_err(|_| format!("unexpected {prop} of {p}"))
    }

    /// Runs a prompt and returns its result, or an error if dismissed.
    async fn prompt(&self, prompt: &OwnedObjectPath) -> Result<OwnedValue, String> {
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(PROMPT)
            .and_then(|b| b.member("Completed"))
            .and_then(|b| b.path(prompt.as_str()))
            .map_err(|e| e.to_string())?
            .build();
        let mut stream =
            MessageStream::for_match_rule(rule, &self.conn, None).await.map_err(|e| format!("cannot watch: {e}"))?;
        self.call(prompt.as_str(), PROMPT, "Prompt", &("",)).await.map_err(err("the prompt failed"))?;
        let wait = async {
            while let Some(Ok(msg)) = stream.next().await {
                if let Ok((dismissed, result)) = msg.body().deserialize::<(bool, OwnedValue)>() {
                    return Some((dismissed, result));
                }
            }
            None
        };
        match tokio::time::timeout(PROMPT_TIMEOUT, wait).await {
            Ok(Some((false, result))) => Ok(result),
            Ok(Some((true, _))) => Err("the provider's dialog was cancelled".into()),
            Ok(None) => Err("the provider went away during its dialog".into()),
            Err(_) => Err("the provider's dialog timed out".into()),
        }
    }

    /// Unlocks `objects` through the provider (with its dialog if needed).
    async fn unlock(&self, objects: &[OwnedObjectPath]) -> Result<(), String> {
        if objects.is_empty() {
            return Ok(());
        }
        let m = self.call(SERVICE, SVC, "Unlock", &(objects,)).await.map_err(err("unlocking failed"))?;
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = m.body().deserialize().map_err(|e| e.to_string())?;
        if prompt.as_str() != "/" {
            self.prompt(&prompt).await?;
        }
        Ok(())
    }

    fn decode(&self, w: &WireSecret) -> Result<Secret, String> {
        let value =
            self.algorithm.decrypt(&w.1, &w.2).map_err(|f| format!("cannot decrypt a secret: {}", f.message))?;
        Ok(Secret::new(value.to_vec(), &w.3))
    }

    /// Every persistent collection with its items and secrets. Unlocks
    /// what is locked, which may show the provider's dialog.
    pub async fn read_all(&self) -> Result<Vec<PortableCollection>, String> {
        let cols: Vec<OwnedObjectPath> = self.get(SERVICE, SVC, "Collections").await?;
        // The provider's in-memory session collection is not migrated.
        let cols: Vec<OwnedObjectPath> = cols.into_iter().filter(|c| !c.as_str().ends_with("/session")).collect();
        let m = self.call(SERVICE, SVC, "ReadAlias", &("default",)).await.map_err(err("ReadAlias failed"))?;
        let (default,): (OwnedObjectPath,) = m.body().deserialize().map_err(|e| e.to_string())?;

        let mut locked = Vec::new();
        for c in &cols {
            if self.get::<bool>(c.as_str(), COL, "Locked").await? {
                locked.push(c.clone());
            }
        }
        self.unlock(&locked).await?;

        let mut out = Vec::new();
        for c in &cols {
            let label: String = self.get(c.as_str(), COL, "Label").await?;
            let items: Vec<OwnedObjectPath> = self.get(c.as_str(), COL, "Items").await?;
            let mut locked_items = Vec::new();
            let mut meta = Vec::new();
            for i in &items {
                let m = self.call(i.as_str(), PROPS, "GetAll", &(ITEM,)).await.map_err(err("reading an item"))?;
                let (props,): (HashMap<String, OwnedValue>,) = m.body().deserialize().map_err(|e| e.to_string())?;
                let take = |k: &str| props.get(k).and_then(|v| v.try_clone().ok());
                let label: String = take("Label").and_then(|v| v.try_into().ok()).unwrap_or_default();
                let attributes: HashMap<String, String> =
                    take("Attributes").and_then(|v| v.try_into().ok()).unwrap_or_default();
                let created: u64 = take("Created").and_then(|v| v.try_into().ok()).unwrap_or(0);
                let modified: u64 = take("Modified").and_then(|v| v.try_into().ok()).unwrap_or(0);
                if take("Locked").and_then(|v| bool::try_from(v).ok()).unwrap_or(false) {
                    locked_items.push(i.clone());
                }
                meta.push((i.clone(), label, attributes.into_iter().collect::<BTreeMap<_, _>>(), created, modified));
            }
            self.unlock(&locked_items).await?;
            let mut secrets: HashMap<OwnedObjectPath, WireSecret> = HashMap::new();
            for chunk in items.chunks(BATCH) {
                let m = self
                    .call(SERVICE, SVC, "GetSecrets", &(chunk, &self.session))
                    .await
                    .map_err(err("reading secrets"))?;
                let (got,): (HashMap<OwnedObjectPath, WireSecret>,) =
                    m.body().deserialize().map_err(|e| e.to_string())?;
                secrets.extend(got);
            }
            let mut portable = Vec::new();
            for (i, label, attributes, created, modified) in meta {
                let w = secrets.get(&i).ok_or_else(|| format!("the provider returned no secret for {i}"))?;
                portable.push(PortableItem { label, attributes, secret: self.decode(w)?, created, modified });
            }
            let aliases = if *c == default { vec!["default".to_owned()] } else { Vec::new() };
            out.push(PortableCollection { label, aliases, items: portable });
        }
        Ok(out)
    }

    /// Writes collections into the provider. A collection carrying the
    /// `default` alias goes into the provider's default collection; others
    /// into the collection with the same label, created if needed. Items
    /// already there with the same label, attributes and secret are
    /// skipped. Timestamps are the provider's own (they are read-only).
    pub async fn write(&self, cols: &[PortableCollection]) -> Result<WriteReport, String> {
        let mut report = WriteReport::default();
        for pc in cols {
            let target = match self.find_collection(pc).await? {
                Some(t) => t,
                None => {
                    report.collections_created += 1;
                    self.create_collection(pc).await?
                }
            };
            self.unlock(std::slice::from_ref(&target)).await?;
            for item in &pc.items {
                if self.has_identical(&target, item).await? {
                    report.items_skipped += 1;
                    continue;
                }
                let mut props: HashMap<&str, Value<'_>> = HashMap::new();
                props.insert("org.freedesktop.Secret.Item.Label", Value::from(item.label.as_str()));
                let attrs: HashMap<&str, &str> =
                    item.attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                props.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs));
                let (params, value) =
                    self.algorithm.encrypt(&item.secret.value).map_err(|f| format!("cannot encrypt: {}", f.message))?;
                let wire = (&self.session, params, value, item.secret.content_type.as_str());
                let m = self
                    .call(target.as_str(), COL, "CreateItem", &(props, wire, false))
                    .await
                    .map_err(err("CreateItem failed"))?;
                let (created, prompt): (OwnedObjectPath, OwnedObjectPath) =
                    m.body().deserialize().map_err(|e| e.to_string())?;
                if created.as_str() == "/" && prompt.as_str() != "/" {
                    self.prompt(&prompt).await?;
                }
                report.items_written += 1;
            }
        }
        Ok(report)
    }

    async fn find_collection(&self, pc: &PortableCollection) -> Result<Option<OwnedObjectPath>, String> {
        if pc.aliases.iter().any(|a| a == "default") {
            let m = self.call(SERVICE, SVC, "ReadAlias", &("default",)).await.map_err(err("ReadAlias failed"))?;
            let (default,): (OwnedObjectPath,) = m.body().deserialize().map_err(|e| e.to_string())?;
            if default.as_str() != "/" {
                return Ok(Some(default));
            }
        }
        let cols: Vec<OwnedObjectPath> = self.get(SERVICE, SVC, "Collections").await?;
        for c in cols.into_iter().filter(|c| !c.as_str().ends_with("/session")) {
            let label: String = self.get(c.as_str(), COL, "Label").await?;
            if label == pc.label {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    async fn create_collection(&self, pc: &PortableCollection) -> Result<OwnedObjectPath, String> {
        let alias = if pc.aliases.iter().any(|a| a == "default") { "default" } else { "" };
        let props: HashMap<&str, Value<'_>> =
            HashMap::from([("org.freedesktop.Secret.Collection.Label", Value::from(pc.label.as_str()))]);
        let m = self.call(SERVICE, SVC, "CreateCollection", &(props, alias)).await.map_err(err("CreateCollection"))?;
        let (col, prompt): (OwnedObjectPath, OwnedObjectPath) = m.body().deserialize().map_err(|e| e.to_string())?;
        if col.as_str() != "/" {
            return Ok(col);
        }
        let result = self.prompt(&prompt).await?;
        OwnedObjectPath::try_from(result).map_err(|_| "unexpected CreateCollection prompt result".into())
    }

    async fn has_identical(&self, collection: &OwnedObjectPath, item: &PortableItem) -> Result<bool, String> {
        // Without the schema: gnome-keyring may or may not report it yet (see
        // `same_attributes`); the comparison below accounts for it.
        let attrs: HashMap<&str, &str> =
            item.attributes.iter().filter(|(k, _)| *k != "xdg:schema").map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let m = self.call(collection.as_str(), COL, "SearchItems", &(attrs,)).await.map_err(err("SearchItems"))?;
        let (found,): (Vec<OwnedObjectPath>,) = m.body().deserialize().map_err(|e| e.to_string())?;
        for f in found {
            let label: String = self.get(f.as_str(), ITEM, "Label").await?;
            let attributes: HashMap<String, String> = self.get(f.as_str(), ITEM, "Attributes").await?;
            if label != item.label || !same_attributes(&attributes.into_iter().collect(), &item.attributes) {
                continue;
            }
            let m = self.call(f.as_str(), ITEM, "GetSecret", &(&self.session,)).await.map_err(err("GetSecret"))?;
            let (w,): (WireSecret,) = m.body().deserialize().map_err(|e| e.to_string())?;
            if self.decode(&w)? == item.secret {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
