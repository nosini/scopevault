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
/// Items per `GetSecrets` call: as many secrets of the largest size as
/// scopevault returns in one reply, so a scopevault provider (and the
/// tests' stand-in) never refuses a batch.
const BATCH: usize = crate::service_api::dispatch::MAX_SECRET_BYTES_PER_REPLY / crate::store::MAX_SECRET_BYTES;

type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// What [`Provider::write`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteReport {
    pub collections_created: usize,
    pub items_written: usize,
    /// Already present with the same label, attributes and secret.
    pub items_skipped: usize,
    /// Present with the same attributes but another secret or label, and
    /// replaced (see [`Provider::write`]).
    pub items_replaced: usize,
}

/// Why [`Provider::write`] failed, and whether it had written anything.
#[derive(Debug)]
pub struct WriteError {
    pub message: String,
    /// False if it failed while planning, before writing anything.
    pub partial: bool,
}

/// A source collection, its existing target, and an action per item.
type Planned<'a> = (&'a PortableCollection, Option<OwnedObjectPath>, Vec<Action>);

/// What [`Provider::write`] does with one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Skip,
    Create,
    /// Replace the secret (and label) of the item at this path, whose
    /// current label is given.
    Replace(OwnedObjectPath, String),
    /// Several items in the target have its attributes.
    Ambiguous,
}

/// Matches the items to write against the target collection's items.
/// First, items identical to one there are skipped (each target item
/// accounts for one item to write, but duplicates of an item already
/// accounted for are skipped as well). Then an item whose attributes match
/// exactly one target item not yet accounted for replaces it; with none it
/// is created, with several it is ambiguous. Items the provider held
/// in duplicate before therefore still match one to one.
pub fn plan(items: &[PortableItem], there: &[(OwnedObjectPath, PortableItem)]) -> Vec<Action> {
    let mut used = vec![false; there.len()];
    let mut actions: Vec<Option<Action>> = vec![None; items.len()];
    for (n, item) in items.iter().enumerate() {
        let unused = (0..there.len()).find(|&k| !used[k] && there[k].1.same_as(item));
        if let Some(k) = unused {
            used[k] = true;
            actions[n] = Some(Action::Skip);
        } else if there.iter().any(|(_, t)| t.same_as(item)) {
            actions[n] = Some(Action::Skip);
        }
    }
    for (n, item) in items.iter().enumerate() {
        if actions[n].is_some() {
            continue;
        }
        let candidates: Vec<usize> = (0..there.len())
            .filter(|&k| !used[k] && same_attributes(&there[k].1.attributes, &item.attributes))
            .collect();
        actions[n] = Some(match candidates[..] {
            [] => Action::Create,
            [k] => {
                used[k] = true;
                Action::Replace(there[k].0.clone(), there[k].1.label.clone())
            }
            _ => Action::Ambiguous,
        });
    }
    actions.into_iter().map(|a| a.expect("every item has an action")).collect()
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
            let items = self.read_items(c).await?.into_iter().map(|(_, i)| i).collect();
            let aliases = if *c == default { vec!["default".to_owned()] } else { Vec::new() };
            out.push(PortableCollection { label, aliases, items });
        }
        Ok(out)
    }

    /// The items of one unlocked collection, with their paths and secrets.
    /// Unlocks items that are locked on their own.
    async fn read_items(&self, c: &OwnedObjectPath) -> Result<Vec<(OwnedObjectPath, PortableItem)>, String> {
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
            let m =
                self.call(SERVICE, SVC, "GetSecrets", &(chunk, &self.session)).await.map_err(err("reading secrets"))?;
            let (got,): (HashMap<OwnedObjectPath, WireSecret>,) = m.body().deserialize().map_err(|e| e.to_string())?;
            secrets.extend(got);
        }
        let mut portable = Vec::new();
        for (i, label, attributes, created, modified) in meta {
            let w = secrets.get(&i).ok_or_else(|| format!("the provider returned no secret for {i}"))?;
            let secret = self.decode(w)?;
            portable.push((i, PortableItem { label, attributes, secret, created, modified }));
        }
        Ok(portable)
    }

    /// Writes collections into the provider. A collection carrying the
    /// `default` alias goes into the provider's default collection; others
    /// into the collection with the same label, created if needed.
    /// Timestamps are the provider's own (they are read-only).
    ///
    /// Each item is matched against what the target collection holds (see
    /// [`plan`]): an identical item is skipped; an item whose attributes
    /// match exactly one other item there replaces that item's secret and
    /// label (scopevault holds the newer value, so a rollback must not leave
    /// the old one beside it for lookups to find); otherwise it is created.
    /// Everything is planned before anything is written, so an ambiguous
    /// match stops the export with nothing written.
    pub async fn write(&self, cols: &[PortableCollection]) -> Result<WriteReport, WriteError> {
        let plans = self.plan_write(cols).await.map_err(|message| WriteError { message, partial: false })?;
        self.apply(plans).await.map_err(|message| WriteError { message, partial: true })
    }

    /// What [`Provider::write`] will do with each collection: its target, if
    /// it exists, and an action per item. Reads the provider only.
    async fn plan_write<'a>(&self, cols: &'a [PortableCollection]) -> Result<Vec<Planned<'a>>, String> {
        // Several source collections can go into the same target (two
        // called "Login", or one with the default alias and one with the
        // default collection's label): they are planned together, so no
        // target item is assigned twice.
        let mut targets: Vec<Option<OwnedObjectPath>> = Vec::new();
        for pc in cols {
            targets.push(self.find_collection(pc).await?);
        }
        let mut actions: Vec<Vec<Action>> = cols.iter().map(|pc| vec![Action::Create; pc.items.len()]).collect();
        let mut planned: Vec<&OwnedObjectPath> = Vec::new();
        for t in targets.iter().flatten() {
            if planned.contains(&t) {
                continue;
            }
            planned.push(t);
            self.unlock(std::slice::from_ref(t)).await?;
            let there = self.read_items(t).await?;
            let members: Vec<usize> = (0..cols.len()).filter(|&n| targets[n].as_ref() == Some(t)).collect();
            let items: Vec<PortableItem> = members.iter().flat_map(|&n| cols[n].items.iter().cloned()).collect();
            let mut joint = plan(&items, &there).into_iter();
            for &n in &members {
                actions[n] = joint.by_ref().take(cols[n].items.len()).collect();
            }
        }
        let mut ambiguous = Vec::new();
        for (pc, acts) in cols.iter().zip(&actions) {
            for (item, action) in pc.items.iter().zip(acts) {
                if *action == Action::Ambiguous {
                    ambiguous.push(format!("{:?} in {:?}", item.label, pc.label));
                }
            }
        }
        let plans: Vec<_> = cols.iter().zip(targets).zip(actions).map(|((pc, t), a)| (pc, t, a)).collect();
        if !ambiguous.is_empty() {
            return Err(format!(
                "the provider holds several items with the same attributes as {}; it is unclear which one to \
                 replace. Remove the obsolete ones there (for example in Seahorse) and export again",
                ambiguous.join(", ")
            ));
        }
        Ok(plans)
    }

    async fn apply(&self, plans: Vec<Planned<'_>>) -> Result<WriteReport, String> {
        let mut report = WriteReport::default();
        // New collections by label, so two sources with one label share one.
        let mut created: HashMap<&str, OwnedObjectPath> = HashMap::new();
        for (pc, target, actions) in plans {
            let target = match target {
                Some(t) => t,
                // Created with the `default` alias; never shared with an
                // ordinary collection of the same label.
                None if pc.aliases.iter().any(|a| a == "default") => {
                    report.collections_created += 1;
                    self.create_collection(pc).await?
                }
                None => match created.get(pc.label.as_str()) {
                    Some(t) => t.clone(),
                    None => {
                        report.collections_created += 1;
                        let t = self.create_collection(pc).await?;
                        created.insert(&pc.label, t.clone());
                        t
                    }
                },
            };
            for (item, action) in pc.items.iter().zip(actions) {
                match action {
                    Action::Skip => report.items_skipped += 1,
                    Action::Create => {
                        self.create_item(&target, item).await?;
                        report.items_written += 1;
                    }
                    Action::Replace(path, old_label) => {
                        let (params, value) = self
                            .algorithm
                            .encrypt(&item.secret.value)
                            .map_err(|f| format!("cannot encrypt: {}", f.message))?;
                        let wire = (&self.session, params, value, item.secret.content_type.as_str());
                        self.call(path.as_str(), ITEM, "SetSecret", &(wire,)).await.map_err(err("SetSecret failed"))?;
                        if old_label != item.label {
                            self.call(path.as_str(), PROPS, "Set", &(ITEM, "Label", Value::from(item.label.as_str())))
                                .await
                                .map_err(err("setting a label failed"))?;
                        }
                        report.items_replaced += 1;
                    }
                    Action::Ambiguous => unreachable!("refused above"),
                }
            }
        }
        Ok(report)
    }

    async fn create_item(&self, target: &OwnedObjectPath, item: &PortableItem) -> Result<(), String> {
        let mut props: HashMap<&str, Value<'_>> = HashMap::new();
        props.insert("org.freedesktop.Secret.Item.Label", Value::from(item.label.as_str()));
        let attrs: HashMap<&str, &str> = item.attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
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
        Ok(())
    }

    /// The provider's collection for `pc`: for the default collection the
    /// provider's own default (`None` if it has none, so one is created with
    /// the alias), otherwise one with the same label.
    async fn find_collection(&self, pc: &PortableCollection) -> Result<Option<OwnedObjectPath>, String> {
        if pc.aliases.iter().any(|a| a == "default") {
            let m = self.call(SERVICE, SVC, "ReadAlias", &("default",)).await.map_err(err("ReadAlias failed"))?;
            let (default,): (OwnedObjectPath,) = m.body().deserialize().map_err(|e| e.to_string())?;
            // A collection with the same label is not the default one: what
            // looks for the default (the portal backend) would miss it.
            return Ok((default.as_str() != "/").then_some(default));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(label: &str, attrs: &[(&str, &str)], secret: &str) -> PortableItem {
        PortableItem {
            label: label.into(),
            attributes: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            secret: Secret::new(secret.as_bytes().to_vec(), "text/plain"),
            created: 0,
            modified: 0,
        }
    }

    fn at(n: u8, i: PortableItem) -> (OwnedObjectPath, PortableItem) {
        (OwnedObjectPath::try_from(format!("/i/{n}")).unwrap(), i)
    }

    #[test]
    fn plan_skips_replaces_creates_and_refuses_ambiguity() {
        let a = [("service", "a")];
        let there = [at(1, item("A", &a, "old")), at(2, item("B", &[("service", "b")], "b"))];
        let items = [item("A", &a, "new"), item("B", &[("service", "b")], "b"), item("C", &[("service", "c")], "c")];
        assert_eq!(
            plan(&items, &there),
            [Action::Replace(OwnedObjectPath::try_from("/i/1").unwrap(), "A".into()), Action::Skip, Action::Create]
        );

        // Two candidates for one changed item: ambiguous.
        let there = [at(1, item("A", &a, "1")), at(2, item("A", &a, "2"))];
        assert_eq!(plan(&[item("A", &a, "3")], &there), [Action::Ambiguous]);
        // Duplicates the provider already had match one to one: the
        // unchanged one is skipped, the changed one replaces the other.
        assert_eq!(
            plan(&[item("A", &a, "3"), item("A", &a, "2")], &there),
            [Action::Replace(OwnedObjectPath::try_from("/i/1").unwrap(), "A".into()), Action::Skip]
        );
        // Identical duplicates in the vault are both skipped.
        assert_eq!(plan(&[item("A", &a, "1"), item("A", &a, "1")], &there[..1]), [Action::Skip, Action::Skip]);
    }
}
