//! A scriptable Secret Service client for isolation tests.
//!
//! Runs its steps in order on ONE session-bus connection, so transfer
//! sessions and prompts opened by one step stay valid for the next, and
//! prints one tab-separated line per step:
//!
//! ```text
//! STEP<TAB>ok<TAB>RESULT
//! STEP<TAB>error<TAB>ERROR-NAME: MESSAGE
//! ```
//!
//! It is an ordinary client with no privileges. The tests run it on the
//! host and inside sandboxes (real Flatpaks on the desktop, simulated ones in
//! the container) and compare what each caller can see. It uses a `plain`
//! transfer session, so secrets cross the bus unencrypted: use test values.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use zbus::message::{Message, Type as MessageType};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, MessageStream};

const USAGE: &str = "\
usage: scopevault-client STEP...

Steps run in order on one connection. COLLECTION is a path, or an alias name
such as `default`. ATTRS is `name=value,name=value` (or `-` for none).
ITEMS and PATHS are comma-separated.

  list                              Service.Collections
  create LABEL ALIAS                CreateCollection (runs the prompt if any)
  store COLLECTION LABEL SECRET ATTRS
                                    CreateItem, replacing a matching item
  search ATTRS                      Service.SearchItems: unlocked | locked
  lookup ATTRS                      first unlocked match's secret, like
                                    `secret-tool lookup` (unlocks if needed)
  secret ITEM                       Item.GetSecret
  secrets ITEMS                     Service.GetSecrets: path=secret ...
  get PATH IFACE PROPERTY           Properties.Get
  getall PATH IFACE                 Properties.GetAll
  set-label PATH LABEL              Properties.Set Label on a collection or item
  introspect PATH                   child node names
  alias NAME                        Service.ReadAlias
  set-alias NAME PATH               Service.SetAlias
  lock PATHS | unlock PATHS         Service.Lock / Service.Unlock (+ prompt)
  delete PATH                       Collection.Delete or Item.Delete
  session                           open a plain transfer session; print it
  use-session PATH                  use PATH as the session from now on
  prompt PATH                       Prompt.Prompt and wait for Completed
  dismiss PATH                      Prompt.Dismiss
  watch MS                          subscribe to all signals; print each one
                                    received during MS milliseconds
  eavesdrop MS                      like watch, with an eavesdrop=true rule
  monitor MS                        BecomeMonitor; print what arrives in MS ms
  sleep MS                          wait
  name                              print this connection's unique name
";

const DEST: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";
const SVC: &str = "org.freedesktop.Secret.Service";
const COL: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
const PROPS: &str = "org.freedesktop.DBus.Properties";
/// Long enough for a person to type a password into a real dialog.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(300);

type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
type Outcome = Result<String, String>;

struct Client {
    conn: Connection,
    session: Option<OwnedObjectPath>,
}

fn path(p: &str) -> Result<OwnedObjectPath, String> {
    OwnedObjectPath::try_from(p.to_owned()).map_err(|e| format!("bad path {p:?}: {e}"))
}

fn collection_path(c: &str) -> Result<OwnedObjectPath, String> {
    if c.starts_with('/') { path(c) } else { path(&format!("{SERVICE}/aliases/{c}")) }
}

fn paths(list: &str) -> Result<Vec<OwnedObjectPath>, String> {
    list.split(',').filter(|s| !s.is_empty()).map(path).collect()
}

fn attrs(spec: &str) -> Result<HashMap<String, String>, String> {
    if spec == "-" {
        return Ok(HashMap::new());
    }
    spec.split(',')
        .map(|kv| kv.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())).ok_or(format!("bad attribute {kv:?}")))
        .collect()
}

fn join(paths: &[OwnedObjectPath]) -> String {
    let mut s: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
    s.sort();
    s.join(",")
}

fn error_text(e: zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, msg, _) => format!("{name}: {}", msg.unwrap_or_default()),
        other => format!("transport: {other}"),
    }
}

fn ms(arg: &str) -> Result<Duration, String> {
    arg.parse().map(Duration::from_millis).map_err(|_| format!("bad milliseconds {arg:?}"))
}

/// Secrets are printed as text when they are UTF-8, otherwise as hex.
fn show_secret(v: &[u8]) -> String {
    match std::str::from_utf8(v) {
        Ok(s) => s.to_owned(),
        Err(_) => format!("hex:{}", v.iter().map(|b| format!("{b:02x}")).collect::<String>()),
    }
}

impl Client {
    async fn call<B>(&self, path: &str, iface: &str, method: &str, body: &B) -> Result<Message, String>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.conn.call_method(Some(DEST), path, Some(iface), method, body).await.map_err(error_text)
    }

    async fn session(&mut self) -> Result<OwnedObjectPath, String> {
        if let Some(s) = &self.session {
            return Ok(s.clone());
        }
        let m = self.call(SERVICE, SVC, "OpenSession", &("plain", Value::from(""))).await?;
        let (_, s): (OwnedValue, OwnedObjectPath) = m.body().deserialize().map_err(error_text)?;
        self.session = Some(s.clone());
        Ok(s)
    }

    /// Runs a prompt (unless it is `/`) and returns its result.
    async fn maybe_prompt(&mut self, prompt: &OwnedObjectPath) -> Result<Option<OwnedValue>, String> {
        if prompt.as_str() == "/" {
            return Ok(None);
        }
        let (dismissed, result) = self.prompt(prompt.as_str()).await?;
        if dismissed { Err("prompt dismissed".into()) } else { Ok(Some(result)) }
    }

    async fn prompt(&mut self, prompt: &str) -> Result<(bool, OwnedValue), String> {
        // Streams are created only while needed: zbus stops reading from
        // the bus once an unread stream holds 64 messages.
        let mut stream = MessageStream::from(&self.conn);
        self.call(prompt, PROMPT, "Prompt", &("",)).await?;
        let wait = async {
            while let Some(Ok(m)) = stream.next().await {
                let h = m.header();
                if m.message_type() == MessageType::Signal
                    && h.path().map(|p| p.as_str()) == Some(prompt)
                    && h.member().map(|m| m.as_str()) == Some("Completed")
                {
                    return m.body().deserialize::<(bool, OwnedValue)>().map_err(error_text);
                }
            }
            Err("connection closed".into())
        };
        tokio::time::timeout(PROMPT_TIMEOUT, wait).await.map_err(|_| "no Completed signal".to_string())?
    }

    async fn search(&self, spec: &str) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), String> {
        let m = self.call(SERVICE, SVC, "SearchItems", &(attrs(spec)?,)).await?;
        m.body().deserialize().map_err(error_text)
    }

    async fn secret(&mut self, item: &str) -> Outcome {
        let s = self.session().await?;
        let m = self.call(item, ITEM, "GetSecret", &(s,)).await?;
        let (wire,): (WireSecret,) = m.body().deserialize().map_err(error_text)?;
        Ok(show_secret(&wire.2))
    }

    async fn xlock(&mut self, method: &str, list: &str) -> Outcome {
        let m = self.call(SERVICE, SVC, method, &(paths(list)?,)).await?;
        let (mut done, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = m.body().deserialize().map_err(error_text)?;
        if let Some(v) = self.maybe_prompt(&prompt).await? {
            done = v.try_into().map_err(|e: zbus::zvariant::Error| e.to_string())?;
        }
        Ok(join(&done))
    }

    /// Prints the signals (or, for monitors, all messages) received for `d`.
    async fn collect(&mut self, mut stream: MessageStream, d: Duration, everything: bool) -> Outcome {
        let me = self.conn.unique_name().map(|n| n.to_string()).unwrap_or_default();
        let mut lines = Vec::new();
        let deadline = tokio::time::Instant::now() + d;
        while let Ok(Some(Ok(m))) = tokio::time::timeout_at(deadline, stream.next()).await {
            let h = m.header();
            if !everything && m.message_type() != MessageType::Signal {
                continue;
            }
            // The bus's own announcements are not of interest.
            if h.sender().map(|s| s.as_str()) == Some("org.freedesktop.DBus") {
                continue;
            }
            let dest = h.destination().map(|d| d.to_string()).unwrap_or_default();
            let dest = if dest == me {
                "me".to_owned()
            } else if dest.is_empty() {
                "broadcast".to_owned()
            } else {
                dest
            };
            lines.push(format!(
                "{:?} from={} to={} path={} member={}.{} body={}",
                m.message_type(),
                h.sender().map(|s| s.to_string()).unwrap_or_default(),
                dest,
                h.path().map(|p| p.to_string()).unwrap_or_default(),
                h.interface().map(|i| i.to_string()).unwrap_or_default(),
                h.member().map(|m| m.to_string()).unwrap_or_default(),
                m.body().signature(),
            ));
        }
        Ok(format!("{} message(s){}{}", lines.len(), if lines.is_empty() { "" } else { ": " }, lines.join(" | ")))
    }

    async fn add_match(&self, rule: &str) -> Result<(), String> {
        self.conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "AddMatch",
                &(rule,),
            )
            .await
            .map(|_| ())
            .map_err(error_text)
    }

    async fn step(&mut self, name: &str, a: &[String]) -> Outcome {
        match (name, a) {
            ("list", []) => {
                let m = self.call(SERVICE, PROPS, "Get", &(SVC, "Collections")).await?;
                let (v,): (OwnedValue,) = m.body().deserialize().map_err(error_text)?;
                Ok(join(&Vec::<OwnedObjectPath>::try_from(v).map_err(|e| e.to_string())?))
            }
            ("create", [label, alias]) => {
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert("org.freedesktop.Secret.Collection.Label", Value::from(label.as_str()));
                let m = self.call(SERVICE, SVC, "CreateCollection", &(props, alias.as_str())).await?;
                let (col, prompt): (OwnedObjectPath, OwnedObjectPath) = m.body().deserialize().map_err(error_text)?;
                match self.maybe_prompt(&prompt).await? {
                    Some(v) => Ok(OwnedObjectPath::try_from(v).map_err(|e| e.to_string())?.to_string()),
                    None => Ok(col.to_string()),
                }
            }
            ("store", [col, label, secret, spec]) => {
                let s = self.session().await?;
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert("org.freedesktop.Secret.Item.Label", Value::from(label.as_str()));
                props.insert("org.freedesktop.Secret.Item.Attributes", Value::from(attrs(spec)?));
                let wire: WireSecret = (s, Vec::new(), secret.as_bytes().to_vec(), "text/plain".into());
                let m = self.call(collection_path(col)?.as_str(), COL, "CreateItem", &(props, wire, true)).await?;
                let (item, _): (OwnedObjectPath, OwnedObjectPath) = m.body().deserialize().map_err(error_text)?;
                Ok(item.to_string())
            }
            ("search", [spec]) => {
                let (u, l) = self.search(spec).await?;
                Ok(format!("{} | {}", join(&u), join(&l)))
            }
            ("lookup", [spec]) => {
                let (u, l) = self.search(spec).await?;
                let item = match (u.first(), l.first()) {
                    (Some(i), _) => i.clone(),
                    (None, Some(i)) => {
                        self.xlock("Unlock", i.as_str()).await?;
                        i.clone()
                    }
                    (None, None) => return Ok(String::new()),
                };
                self.secret(item.as_str()).await
            }
            ("secret", [item]) => self.secret(item).await,
            ("secrets", [items]) => {
                let s = self.session().await?;
                let m = self.call(SERVICE, SVC, "GetSecrets", &(paths(items)?, s)).await?;
                let (map,): (HashMap<OwnedObjectPath, WireSecret>,) = m.body().deserialize().map_err(error_text)?;
                let mut out: Vec<String> = map.iter().map(|(p, w)| format!("{p}={}", show_secret(&w.2))).collect();
                out.sort();
                Ok(out.join(","))
            }
            ("get", [p, iface, prop]) => {
                let m = self.call(p, PROPS, "Get", &(iface.as_str(), prop.as_str())).await?;
                let (v,): (OwnedValue,) = m.body().deserialize().map_err(error_text)?;
                Ok(format!("{}", *v))
            }
            ("getall", [p, iface]) => {
                let m = self.call(p, PROPS, "GetAll", &(iface.as_str(),)).await?;
                let (v,): (HashMap<String, OwnedValue>,) = m.body().deserialize().map_err(error_text)?;
                let mut out: Vec<String> = v.iter().map(|(k, v)| format!("{k}={}", **v)).collect();
                out.sort();
                Ok(out.join(" "))
            }
            ("set-label", [p, label]) => {
                let iface = if p.matches('/').count() > 5 { ITEM } else { COL };
                self.call(p, PROPS, "Set", &(iface, "Label", Value::from(label.as_str()))).await.map(|_| String::new())
            }
            ("introspect", [p]) => {
                let m = self.call(p, "org.freedesktop.DBus.Introspectable", "Introspect", &()).await?;
                let (xml,): (String,) = m.body().deserialize().map_err(error_text)?;
                let mut kids: Vec<&str> = xml
                    .lines()
                    .filter_map(|l| l.trim().strip_prefix("<node name=\"").and_then(|r| r.strip_suffix("\"/>")))
                    .collect();
                kids.sort();
                Ok(kids.join(","))
            }
            ("alias", [n]) => {
                let m = self.call(SERVICE, SVC, "ReadAlias", &(n.as_str(),)).await?;
                let (p,): (OwnedObjectPath,) = m.body().deserialize().map_err(error_text)?;
                Ok(p.to_string())
            }
            ("set-alias", [n, p]) => {
                self.call(SERVICE, SVC, "SetAlias", &(n.as_str(), path(p)?)).await.map(|_| String::new())
            }
            ("lock", [list]) => self.xlock("Lock", list).await,
            ("unlock", [list]) => self.xlock("Unlock", list).await,
            ("delete", [p]) => {
                let iface = if p.matches('/').count() > 5 { ITEM } else { COL };
                let m = self.call(p, iface, "Delete", &()).await?;
                let (prompt,): (OwnedObjectPath,) = m.body().deserialize().map_err(error_text)?;
                self.maybe_prompt(&prompt).await?;
                Ok(String::new())
            }
            ("session", []) => {
                self.session = None;
                Ok(self.session().await?.to_string())
            }
            ("use-session", [p]) => {
                self.session = Some(path(p)?);
                Ok(p.clone())
            }
            ("prompt", [p]) => {
                let (dismissed, v) = self.prompt(p).await?;
                Ok(format!("dismissed={dismissed} result={}", *v))
            }
            ("dismiss", [p]) => self.call(p, PROMPT, "Dismiss", &()).await.map(|_| String::new()),
            ("watch", [d]) => {
                let stream = MessageStream::from(&self.conn);
                self.add_match("type='signal'").await?;
                self.collect(stream, ms(d)?, false).await
            }
            ("eavesdrop", [d]) => {
                let stream = MessageStream::from(&self.conn);
                self.add_match("type='signal',eavesdrop=true").await?;
                self.add_match("type='method_return',eavesdrop=true").await?;
                self.collect(stream, ms(d)?, true).await
            }
            ("monitor", [d]) => {
                let stream = MessageStream::from(&self.conn);
                self.conn
                    .call_method(
                        Some("org.freedesktop.DBus"),
                        "/org/freedesktop/DBus",
                        Some("org.freedesktop.DBus.Monitoring"),
                        "BecomeMonitor",
                        &(Vec::<&str>::new(), 0u32),
                    )
                    .await
                    .map_err(error_text)?;
                self.collect(stream, ms(d)?, true).await
            }
            ("sleep", [d]) => {
                tokio::time::sleep(ms(d)?).await;
                Ok(String::new())
            }
            ("name", []) => Ok(self.conn.unique_name().map(|n| n.to_string()).unwrap_or_default()),
            _ => Err(format!("unknown step or wrong arguments: {name} {a:?}")),
        }
    }
}

fn arity(step: &str) -> Option<usize> {
    Some(match step {
        "list" | "session" | "name" => 0,
        "search" | "lookup" | "secret" | "secrets" | "introspect" | "alias" | "lock" | "unlock" | "delete"
        | "use-session" | "prompt" | "dismiss" | "watch" | "eavesdrop" | "monitor" | "sleep" => 1,
        "create" | "getall" | "set-label" | "set-alias" => 2,
        "get" => 3,
        "store" => 4,
        _ => return None,
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print!("{USAGE}");
        return;
    }
    // Parse everything first, so a typo fails before anything is sent.
    let mut steps = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let Some(n) = arity(&args[i]) else {
            eprintln!("unknown step {:?}\n\n{USAGE}", args[i]);
            std::process::exit(2);
        };
        if args.len() - i - 1 < n {
            eprintln!("step {:?} needs {n} argument(s)", args[i]);
            std::process::exit(2);
        }
        steps.push((args[i].clone(), args[i + 1..i + 1 + n].to_vec()));
        i += 1 + n;
    }
    let conn = match Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            println!("connect\terror\t{}", error_text(e));
            std::process::exit(1);
        }
    };
    let mut client = Client { conn, session: None };
    let mut failed = false;
    for (name, a) in steps {
        let out = client.step(&name, &a).await;
        // Tabs and newlines would break the line format.
        let clean = |s: String| s.replace(['\t', '\n'], " ");
        match out {
            Ok(r) => println!("{name}\tok\t{}", clean(r)),
            Err(e) => {
                failed = true;
                println!("{name}\terror\t{}", clean(e));
            }
        }
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
    std::process::exit(i32::from(failed));
}
