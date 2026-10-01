//! Per-connection identity resolution and caching.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use tokio::sync::OnceCell;
use zbus::fdo::DBusProxy;
use zbus::names::{BusName, OwnedUniqueName, UniqueName};

use super::{BusCredentials, Classifier, IdentityError, Resolved};

/// Maps a unique connection name to a principal. Production code uses
/// [`BusIdentityResolver`]; tests may substitute a fixed mapping, but there
/// is deliberately no runtime switch that selects one.
pub trait CallerResolver: Send + Sync + 'static {
    fn resolve(&self, sender: &UniqueName<'_>) -> impl Future<Output = Resolved> + Send;
}

type Cache = Mutex<HashMap<OwnedUniqueName, Arc<OnceCell<Resolved>>>>;

/// Resolves callers through the bus daemon's credentials and the kernel.
///
/// Results are cached per unique name. Unique names are never reused on a
/// bus instance, and entries are dropped when the bus announces that the
/// connection went away. The resolver is tied to one bus connection: when
/// that connection is lost the daemon must exit, which discards the cache.
pub struct BusIdentityResolver {
    dbus: DBusProxy<'static>,
    classifier: Arc<Classifier>,
    cache: Arc<Cache>,
}

impl BusIdentityResolver {
    pub async fn new(conn: &zbus::Connection, classifier: Classifier) -> zbus::Result<Arc<Self>> {
        let dbus = DBusProxy::new(conn).await?;
        let cache: Arc<Cache> = Arc::default();

        // Subscribe before any lookup so no disconnect can be missed.
        let mut changes = dbus.receive_name_owner_changed().await?;
        let weak = Arc::downgrade(&cache);
        tokio::spawn(async move {
            while let Some(signal) = changes.next().await {
                let Ok(args) = signal.args() else { continue };
                let BusName::Unique(name) = args.name() else { continue };
                if args.new_owner().is_none() {
                    let Some(cache) = weak.upgrade() else { break };
                    cache.lock().unwrap().remove(&OwnedUniqueName::from(name.to_owned()));
                }
            }
        });

        Ok(Arc::new(BusIdentityResolver { dbus, classifier: Arc::new(classifier), cache }))
    }

    pub fn classifier(&self) -> &Classifier {
        &self.classifier
    }

    /// Classifies without caching, returning the evidence too. For the probe.
    pub async fn classify_uncached(&self, sender: &UniqueName<'_>) -> super::Classification {
        let creds = match self.credentials(sender).await {
            Ok(c) => c,
            Err(e) => return super::Classification { result: Err(e), evidence: Default::default() },
        };
        let classifier = self.classifier.clone();
        tokio::task::spawn_blocking(move || classifier.classify(creds)).await.expect("classifier panicked")
    }

    async fn credentials(&self, sender: &UniqueName<'_>) -> Result<BusCredentials, IdentityError> {
        let c = self
            .dbus
            .get_connection_credentials(BusName::Unique(sender.as_ref()))
            .await
            .map_err(|e| IdentityError::Bus(e.to_string()))?;
        let pidfd = match c.process_fd() {
            Some(fd) => Some(
                std::os::fd::AsFd::as_fd(fd)
                    .try_clone_to_owned()
                    .map_err(|e| IdentityError::Inspect("dup pidfd", e))?,
            ),
            None => None,
        };
        Ok(BusCredentials {
            uid: c.unix_user_id(),
            pid: c.process_id(),
            pidfd,
            security_label: c.into_linux_security_label(),
        })
    }

    pub fn cached_connections(&self) -> usize {
        self.cache.lock().unwrap().len()
    }
}

impl CallerResolver for BusIdentityResolver {
    async fn resolve(&self, sender: &UniqueName<'_>) -> Resolved {
        let key = OwnedUniqueName::from(sender.to_owned());
        let cell = self.cache.lock().unwrap().entry(key.clone()).or_default().clone();
        let mut initialised_here = false;
        let resolved = cell
            .get_or_init(|| async {
                initialised_here = true;
                let classification = self.classify_uncached(sender).await;
                match &classification.result {
                    Ok(p) => tracing::debug!(sender = %sender, scope = %p.scope(), "identified caller"),
                    Err(e) => tracing::info!(sender = %sender, error = %e, "denied caller"),
                }
                Arc::new(classification.result)
            })
            .await
            .clone();

        // If the connection vanished while we were resolving, the removal may
        // have run before our insertion. Drop the entry so it cannot linger.
        if initialised_here && !matches!(self.dbus.name_has_owner(BusName::Unique(sender.as_ref())).await, Ok(true)) {
            self.cache.lock().unwrap().remove(&key);
        }
        resolved
    }
}
