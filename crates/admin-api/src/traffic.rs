use std::{
    collections::HashMap,
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use mousevpn_account_client::{NodeConnection, NodeTraffic, NodeTrafficHour};

const TRAFFIC_VERSION: u8 = 1;
const SECONDS_PER_HOUR: u64 = 3_600;
const RETENTION_HOURS: u64 = 24 * 400;
const LEGACY_MIGRATION_KEY: &str = "legacy_toml_v1";
pub(crate) const MAX_QUERY_HOURS: u64 = 24 * 31;

#[derive(Debug, Default)]
pub struct DeviceTrafficCounter {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
}

impl DeviceTrafficCounter {
    pub fn add_upload(&self, bytes: u64) {
        self.upload_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

struct RegisteredCounter {
    name: RwLock<String>,
    counter: Arc<DeviceTrafficCounter>,
}

struct TrafficStoreInner {
    database: Mutex<Connection>,
    counters: RwLock<HashMap<String, Arc<RegisteredCounter>>>,
}

#[derive(Clone)]
pub struct TrafficStore(Arc<TrafficStoreInner>);

impl TrafficStore {
    /// Opens or creates the `SQLite` traffic store and imports a legacy TOML file once.
    ///
    /// A requested `*.toml` path is treated as the legacy path and mapped to a
    /// sibling `*.sqlite` database for compatibility with the old environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error for insecure permissions, invalid legacy data, `SQLite` or I/O failures.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TrafficError> {
        let requested = path.into();
        let (database_path, legacy_path) = storage_paths(&requested);
        prepare_database_file(&database_path)?;
        let connection = Connection::open(&database_path)?;
        configure_database(&connection)?;
        migrate_legacy_toml(&connection, &legacy_path)?;
        Ok(Self(Arc::new(TrafficStoreInner {
            database: Mutex::new(connection),
            counters: RwLock::new(HashMap::new()),
        })))
    }

    #[must_use]
    pub fn counter(&self, public_key: &str, name: &str) -> Arc<DeviceTrafficCounter> {
        if let Some(registered) = self
            .0
            .counters
            .read()
            .ok()
            .and_then(|counters| counters.get(public_key).cloned())
        {
            if let Ok(mut current_name) = registered.name.write() {
                name.clone_into(&mut current_name);
            }
            return Arc::clone(&registered.counter);
        }
        let Ok(mut counters) = self.0.counters.write() else {
            return Arc::new(DeviceTrafficCounter::default());
        };
        let registered = counters
            .entry(public_key.to_owned())
            .or_insert_with(|| {
                Arc::new(RegisteredCounter {
                    name: RwLock::new(name.to_owned()),
                    counter: Arc::new(DeviceTrafficCounter::default()),
                })
            })
            .clone();
        Arc::clone(&registered.counter)
    }

    /// Persists pending counters in a background thread.
    pub fn spawn_flusher(&self, interval: Duration) {
        let store = self.clone();
        thread::spawn(move || loop {
            thread::sleep(interval);
            if let Err(error) = store.flush() {
                eprintln!("MouseVPN traffic persistence failed: {error}");
            }
        });
    }

    /// Upserts current atomic counters into the durable hourly history.
    ///
    /// # Errors
    ///
    /// Returns an error if locks are poisoned or the `SQLite` transaction fails.
    pub fn flush(&self) -> Result<(), TrafficError> {
        self.flush_at(unix_seconds())
    }

    pub(crate) fn report(&self, hours: u64) -> Result<TrafficReport, TrafficError> {
        self.report_at(hours, unix_seconds())
    }

    fn flush_at(&self, now: u64) -> Result<(), TrafficError> {
        let pending = self.take_pending()?;
        if pending.is_empty() {
            return Ok(());
        }
        let current_hour = now / SECONDS_PER_HOUR;
        let oldest = current_hour.saturating_sub(RETENTION_HOURS);
        let result = self.persist_pending(current_hour, oldest, &pending);
        if result.is_err() {
            self.restore_pending(&pending);
        }
        result
    }

    fn persist_pending(
        &self,
        current_hour: u64,
        oldest: u64,
        pending: &[PendingTraffic],
    ) -> Result<(), TrafficError> {
        let mut connection = self
            .0
            .database
            .lock()
            .map_err(|_| TrafficError::new("traffic database lock is poisoned"))?;
        let transaction = connection.transaction()?;
        for item in pending {
            transaction.execute(
                "INSERT INTO traffic_hourly
                    (hour, public_key, name, upload_bytes, download_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(hour, public_key) DO UPDATE SET
                    name = excluded.name,
                    upload_bytes = traffic_hourly.upload_bytes + excluded.upload_bytes,
                    download_bytes = traffic_hourly.download_bytes + excluded.download_bytes",
                params![
                    to_sql_integer(current_hour),
                    item.public_key,
                    item.name,
                    to_sql_integer(item.upload_bytes),
                    to_sql_integer(item.download_bytes),
                ],
            )?;
        }
        transaction.execute(
            "DELETE FROM traffic_hourly WHERE hour < ?1",
            [to_sql_integer(oldest)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn report_at(&self, hours: u64, now: u64) -> Result<TrafficReport, TrafficError> {
        let hours = hours.clamp(1, MAX_QUERY_HOURS);
        let current_hour = now / SECONDS_PER_HOUR;
        let series_start = current_hour.saturating_sub(hours - 1);
        let week_start = current_hour.saturating_sub(167);
        let query_start = series_start.min(week_start);
        let mut buckets = self.load_buckets(query_start, current_hour)?;
        merge_pending(&mut buckets, current_hour, &self.peek_pending()?);
        Ok(build_report(
            hours,
            now,
            current_hour,
            series_start,
            buckets,
        ))
    }

    fn load_buckets(&self, start: u64, end: u64) -> Result<Vec<TrafficBucket>, TrafficError> {
        let connection = self
            .0
            .database
            .lock()
            .map_err(|_| TrafficError::new("traffic database lock is poisoned"))?;
        let mut statement = connection.prepare(
            "SELECT hour, public_key, name, upload_bytes, download_bytes
             FROM traffic_hourly
             WHERE hour BETWEEN ?1 AND ?2
             ORDER BY hour",
        )?;
        let rows =
            statement.query_map(params![to_sql_integer(start), to_sql_integer(end)], |row| {
                Ok(TrafficBucket {
                    hour: from_sql_integer(row.get(0)?),
                    public_key: row.get(1)?,
                    name: row.get(2)?,
                    upload_bytes: from_sql_integer(row.get(3)?),
                    download_bytes: from_sql_integer(row.get(4)?),
                })
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn take_pending(&self) -> Result<Vec<PendingTraffic>, TrafficError> {
        self.pending_with(|counter| {
            (
                counter.upload_bytes.swap(0, Ordering::AcqRel),
                counter.download_bytes.swap(0, Ordering::AcqRel),
            )
        })
    }

    fn peek_pending(&self) -> Result<Vec<PendingTraffic>, TrafficError> {
        self.pending_with(|counter| {
            (
                counter.upload_bytes.load(Ordering::Acquire),
                counter.download_bytes.load(Ordering::Acquire),
            )
        })
    }

    fn pending_with(
        &self,
        read: impl Fn(&DeviceTrafficCounter) -> (u64, u64),
    ) -> Result<Vec<PendingTraffic>, TrafficError> {
        let counters = self
            .0
            .counters
            .read()
            .map_err(|_| TrafficError::new("traffic counter lock is poisoned"))?;
        let mut pending = Vec::with_capacity(counters.len());
        for (public_key, registered) in counters.iter() {
            let (upload_bytes, download_bytes) = read(&registered.counter);
            if upload_bytes == 0 && download_bytes == 0 {
                continue;
            }
            let name = registered
                .name
                .read()
                .map_err(|_| TrafficError::new("traffic device name lock is poisoned"))?
                .clone();
            pending.push(PendingTraffic {
                public_key: public_key.clone(),
                name,
                upload_bytes,
                download_bytes,
            });
        }
        Ok(pending)
    }

    fn restore_pending(&self, pending: &[PendingTraffic]) {
        for item in pending {
            let counter = self.counter(&item.public_key, &item.name);
            counter.add_upload(item.upload_bytes);
            counter.add_download(item.download_bytes);
        }
    }
}

impl TrafficStore {
    /// Records an authenticated new handshake, excluding retransmissions.
    /// # Errors
    /// Returns a database error if the event cannot be persisted.
    pub fn record_connection(&self, public_key: &str, protocol: &str) -> Result<(), TrafficError> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let db = self
            .0
            .database
            .lock()
            .map_err(|_| TrafficError::new("traffic lock poisoned"))?;
        db.execute(
            "INSERT OR IGNORE INTO connection_outbox VALUES(?,?,?,?)",
            params![
                format!("{}-{}", stamp.as_nanos(), public_key),
                to_sql_integer(stamp.as_secs()),
                public_key,
                protocol
            ],
        )?;
        db.execute(
            "DELETE FROM connection_outbox WHERE at < ?",
            [to_sql_integer(
                stamp.as_secs().saturating_sub(RETENTION_HOURS * 3600),
            )],
        )?;
        Ok(())
    }

    /// Exports a bounded durable outbox; unacknowledged batches survive restart.
    /// # Errors
    /// Returns a database error; callers must not acknowledge failed exports.
    pub fn export_traffic(&self) -> Result<NodeTraffic, TrafficError> {
        self.flush()?;
        let db = self
            .0
            .database
            .lock()
            .map_err(|_| TrafficError::new("traffic lock poisoned"))?;
        let mut query = db.prepare("SELECT h.hour*3600,h.public_key,h.upload_bytes,h.download_bytes FROM traffic_hourly h LEFT JOIN traffic_sent s ON s.hour=h.hour AND s.public_key=h.public_key WHERE s.hour IS NULL OR h.upload_bytes!=s.upload_bytes OR h.download_bytes!=s.download_bytes ORDER BY h.hour DESC,h.public_key LIMIT 128")?;
        let hours = query
            .query_map([], |r| {
                Ok(NodeTrafficHour {
                    hour: r.get(0)?,
                    public_key: r.get(1)?,
                    upload_bytes: r.get(2)?,
                    download_bytes: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut query = db.prepare(
            "SELECT id,at,public_key,protocol FROM connection_outbox ORDER BY at,id LIMIT 128",
        )?;
        let connections = query
            .query_map([], |r| {
                Ok(NodeConnection {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    public_key: r.get(2)?,
                    protocol: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NodeTraffic { hours, connections })
    }

    /// Acknowledges exactly the exported values, never newer counters.
    /// # Errors
    /// Returns a database error; retrying the same batch is safe.
    pub fn acknowledge_traffic(&self, report: &NodeTraffic) -> Result<(), TrafficError> {
        let mut db = self
            .0
            .database
            .lock()
            .map_err(|_| TrafficError::new("traffic lock poisoned"))?;
        let tx = db.transaction()?;
        for h in &report.hours {
            tx.execute("INSERT INTO traffic_sent VALUES(?,?,?,?) ON CONFLICT(hour,public_key) DO UPDATE SET upload_bytes=max(upload_bytes,excluded.upload_bytes),download_bytes=max(download_bytes,excluded.download_bytes)", params![h.hour/3600,h.public_key,h.upload_bytes,h.download_bytes])?;
        }
        for e in &report.connections {
            tx.execute("DELETE FROM connection_outbox WHERE id=?", [&e.id])?;
        }
        tx.execute(
            "DELETE FROM traffic_sent WHERE hour < ?",
            [to_sql_integer(
                (unix_seconds() / 3600).saturating_sub(RETENTION_HOURS),
            )],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn build_report(
    hours: u64,
    now: u64,
    current_hour: u64,
    series_start: u64,
    buckets: Vec<TrafficBucket>,
) -> TrafficReport {
    let mut hourly = (series_start..=current_hour)
        .map(|hour| TrafficPoint {
            hour: hour * SECONDS_PER_HOUR,
            upload_bytes: 0,
            download_bytes: 0,
        })
        .collect::<Vec<_>>();
    let mut devices = HashMap::<String, DeviceTrafficSummary>::new();
    let mut hour_total = TrafficTotals::default();
    let mut day_total = TrafficTotals::default();
    let mut week_total = TrafficTotals::default();

    for bucket in buckets {
        let age = current_hour.saturating_sub(bucket.hour);
        if bucket.hour > current_hour {
            continue;
        }
        let totals = TrafficTotals {
            upload_bytes: bucket.upload_bytes,
            download_bytes: bucket.download_bytes,
        };
        if age < 168 {
            week_total.add(totals);
        }
        if age < 24 {
            day_total.add(totals);
        }
        if age == 0 {
            hour_total.add(totals);
        }
        if bucket.hour >= series_start {
            let index = usize::try_from(bucket.hour - series_start).unwrap_or_default();
            if let Some(point) = hourly.get_mut(index) {
                point.add(totals);
            }
            let device =
                devices
                    .entry(bucket.public_key.clone())
                    .or_insert_with(|| DeviceTrafficSummary {
                        public_key: bucket.public_key,
                        name: bucket.name.clone(),
                        upload_bytes: 0,
                        download_bytes: 0,
                    });
            device.name = bucket.name;
            device.upload_bytes = device.upload_bytes.saturating_add(bucket.upload_bytes);
            device.download_bytes = device.download_bytes.saturating_add(bucket.download_bytes);
        }
    }
    let mut devices = devices.into_values().collect::<Vec<_>>();
    devices.sort_by(|left, right| {
        right
            .total_bytes()
            .cmp(&left.total_bytes())
            .then_with(|| left.name.cmp(&right.name))
    });
    TrafficReport {
        generated_at: now,
        selected_hours: hours,
        totals: TrafficPeriodTotals {
            hour: hour_total,
            day: day_total,
            week: week_total,
        },
        hourly,
        devices,
    }
}

#[derive(Clone)]
struct PendingTraffic {
    public_key: String,
    name: String,
    upload_bytes: u64,
    download_bytes: u64,
}

#[derive(Clone)]
struct TrafficBucket {
    hour: u64,
    public_key: String,
    name: String,
    upload_bytes: u64,
    download_bytes: u64,
}

fn merge_pending(buckets: &mut Vec<TrafficBucket>, hour: u64, pending: &[PendingTraffic]) {
    for item in pending {
        if let Some(bucket) = buckets
            .iter_mut()
            .find(|bucket| bucket.hour == hour && bucket.public_key == item.public_key)
        {
            bucket.name.clone_from(&item.name);
            bucket.upload_bytes = bucket.upload_bytes.saturating_add(item.upload_bytes);
            bucket.download_bytes = bucket.download_bytes.saturating_add(item.download_bytes);
        } else {
            buckets.push(TrafficBucket {
                hour,
                public_key: item.public_key.clone(),
                name: item.name.clone(),
                upload_bytes: item.upload_bytes,
                download_bytes: item.download_bytes,
            });
        }
    }
}

fn configure_database(connection: &Connection) -> Result<(), TrafficError> {
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         CREATE TABLE IF NOT EXISTS traffic_hourly (
            hour INTEGER NOT NULL,
            public_key TEXT NOT NULL,
            name TEXT NOT NULL,
            upload_bytes INTEGER NOT NULL CHECK(upload_bytes >= 0),
            download_bytes INTEGER NOT NULL CHECK(download_bytes >= 0),
            PRIMARY KEY (hour, public_key)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS traffic_sent (
            hour INTEGER NOT NULL, public_key TEXT NOT NULL,
            upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
            PRIMARY KEY(hour, public_key)
         ) WITHOUT ROWID;
         CREATE TABLE IF NOT EXISTS connection_outbox (
            id TEXT PRIMARY KEY, at INTEGER NOT NULL, public_key TEXT NOT NULL, protocol TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS traffic_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
         ) WITHOUT ROWID;",
    )?;
    Ok(())
}

fn storage_paths(requested: &Path) -> (PathBuf, PathBuf) {
    if requested
        .extension()
        .is_some_and(|extension| extension == "toml")
    {
        (requested.with_extension("sqlite"), requested.to_owned())
    } else {
        (requested.to_owned(), requested.with_extension("toml"))
    }
}

fn prepare_database_file(path: &Path) -> Result<(), TrafficError> {
    let parent = path
        .parent()
        .ok_or_else(|| TrafficError::new("traffic database has no parent directory"))?;
    fs::create_dir_all(parent)?;
    if path.exists() {
        ensure_private_permissions(path)?;
        return Ok(());
    }
    create_private_file(path)?;
    Ok(())
}

fn migrate_legacy_toml(connection: &Connection, path: &Path) -> Result<(), TrafficError> {
    let migrated = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM traffic_metadata WHERE key = ?1)",
        [LEGACY_MIGRATION_KEY],
        |row| row.get::<_, bool>(0),
    )?;
    if migrated {
        return Ok(());
    }
    if path.exists() {
        ensure_private_permissions(path)?;
        let legacy: LegacyTrafficDocument = toml::from_str(&fs::read_to_string(path)?)?;
        if legacy.version != TRAFFIC_VERSION {
            return Err(TrafficError::new(
                "unsupported legacy traffic store version",
            ));
        }
        let transaction = connection.unchecked_transaction()?;
        for bucket in legacy.buckets {
            transaction.execute(
                "INSERT INTO traffic_hourly
                    (hour, public_key, name, upload_bytes, download_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(hour, public_key) DO UPDATE SET
                    name = excluded.name,
                    upload_bytes = traffic_hourly.upload_bytes + excluded.upload_bytes,
                    download_bytes = traffic_hourly.download_bytes + excluded.download_bytes",
                params![
                    to_sql_integer(bucket.hour),
                    bucket.public_key,
                    bucket.name,
                    to_sql_integer(bucket.upload_bytes),
                    to_sql_integer(bucket.download_bytes),
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO traffic_metadata (key, value) VALUES (?1, 'done')",
            [LEGACY_MIGRATION_KEY],
        )?;
        transaction.commit()?;
    } else {
        connection.execute(
            "INSERT INTO traffic_metadata (key, value) VALUES (?1, 'none')",
            [LEGACY_MIGRATION_KEY],
        )?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct LegacyTrafficDocument {
    version: u8,
    buckets: Vec<LegacyTrafficBucket>,
}

#[derive(Deserialize)]
struct LegacyTrafficBucket {
    hour: u64,
    public_key: String,
    name: String,
    upload_bytes: u64,
    download_bytes: u64,
}

fn to_sql_integer(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_sql_integer(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TrafficTotals {
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl TrafficTotals {
    fn add(&mut self, other: Self) {
        self.upload_bytes = self.upload_bytes.saturating_add(other.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(other.download_bytes);
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficPeriodTotals {
    pub hour: TrafficTotals,
    pub day: TrafficTotals,
    pub week: TrafficTotals,
}

#[derive(Debug, Serialize)]
pub struct TrafficPoint {
    /// Start of the UTC hour as a Unix timestamp.
    pub hour: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl TrafficPoint {
    fn add(&mut self, totals: TrafficTotals) {
        self.upload_bytes = self.upload_bytes.saturating_add(totals.upload_bytes);
        self.download_bytes = self.download_bytes.saturating_add(totals.download_bytes);
    }
}

#[derive(Debug, Serialize)]
pub struct DeviceTrafficSummary {
    pub public_key: String,
    pub name: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

impl DeviceTrafficSummary {
    fn total_bytes(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficReport {
    pub generated_at: u64,
    pub selected_hours: u64,
    pub totals: TrafficPeriodTotals,
    pub hourly: Vec<TrafficPoint>,
    pub devices: Vec<DeviceTrafficSummary>,
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<(), TrafficError> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<(), TrafficError> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    Ok(())
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path) -> Result<(), TrafficError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TrafficError::new(format!(
            "traffic store permissions are insecure: {mode:o}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(_path: &Path) -> Result<(), TrafficError> {
    Ok(())
}

#[derive(Debug)]
pub struct TrafficError(String);

impl TrafficError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TrafficError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TrafficError {}

impl From<std::io::Error> for TrafficError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<rusqlite::Error> for TrafficError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<toml::de::Error> for TrafficError {
    fn from(error: toml::de::Error) -> Self {
        Self::new(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{TrafficStore, SECONDS_PER_HOUR};

    #[test]
    fn outbox_survives_restart_and_acknowledges_only_exported_totals() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("traffic.sqlite");
        let store = TrafficStore::open(&path).unwrap();
        store.counter("device", "Phone").add_upload(100);
        store.record_connection("device", "legacy").unwrap();
        let batch = store.export_traffic().unwrap();
        assert_eq!(batch.connections.len(), 1);
        store.counter("device", "Phone").add_upload(50);
        store.flush().unwrap();
        store.acknowledge_traffic(&batch).unwrap();
        drop(store);
        let reopened = TrafficStore::open(&path).unwrap();
        let next = reopened.export_traffic().unwrap();
        assert_eq!(next.hours[0].upload_bytes, 150);
        assert!(next.connections.is_empty());
        reopened.acknowledge_traffic(&next).unwrap();
        assert!(reopened.export_traffic().unwrap().hours.is_empty());
        reopened.acknowledge_traffic(&batch).unwrap();
        assert!(reopened.export_traffic().unwrap().hours.is_empty());
    }

    #[test]
    fn reports_and_reopens_hourly_traffic() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join("traffic.sqlite");
        let store = TrafficStore::open(&path).expect("traffic store");
        let alice = store.counter("alice-key", "Alice phone");
        alice.add_upload(1_000);
        alice.add_download(3_000);
        store
            .flush_at(100 * SECONDS_PER_HOUR)
            .expect("traffic flush");
        drop(store);

        let reopened = TrafficStore::open(path).expect("reopened traffic store");
        let report = reopened
            .report_at(24, 100 * SECONDS_PER_HOUR + 10)
            .expect("traffic report");
        assert_eq!(report.totals.hour.upload_bytes, 1_000);
        assert_eq!(report.totals.day.download_bytes, 3_000);
        assert_eq!(report.devices.len(), 1);
        assert_eq!(report.devices[0].name, "Alice phone");
        assert_eq!(
            report.hourly.last().expect("current hour").upload_bytes,
            1_000
        );
    }

    #[test]
    fn includes_unflushed_counters_in_reports() {
        let temporary = TempDir::new().expect("temporary directory");
        let store =
            TrafficStore::open(temporary.path().join("traffic.sqlite")).expect("traffic store");
        let counter = store.counter("key", "Laptop");
        counter.add_upload(42);
        counter.add_download(84);

        let report = store
            .report_at(1, 10 * SECONDS_PER_HOUR)
            .expect("traffic report");
        assert_eq!(report.totals.hour.upload_bytes, 42);
        assert_eq!(report.totals.hour.download_bytes, 84);
    }

    #[test]
    fn migrates_legacy_toml_once() {
        let temporary = TempDir::new().expect("temporary directory");
        let legacy = temporary.path().join("traffic.toml");
        fs::write(
            &legacy,
            "version = 1\n\n[[buckets]]\nhour = 50\npublic_key = \"old-key\"\nname = \"Old phone\"\nupload_bytes = 123\ndownload_bytes = 456\n",
        )
        .expect("legacy traffic file");
        set_private_test_permissions(&legacy);

        let store = TrafficStore::open(&legacy).expect("migrated store");
        let report = store
            .report_at(1, 50 * SECONDS_PER_HOUR)
            .expect("traffic report");
        assert_eq!(report.totals.hour.upload_bytes, 123);
        assert_eq!(report.totals.hour.download_bytes, 456);
        drop(store);

        let reopened = TrafficStore::open(&legacy).expect("reopened store");
        let report = reopened
            .report_at(1, 50 * SECONDS_PER_HOUR)
            .expect("traffic report");
        assert_eq!(report.totals.hour.upload_bytes, 123);
        assert!(temporary.path().join("traffic.sqlite").exists());
    }

    #[cfg(unix)]
    fn set_private_test_permissions(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private permissions");
    }

    #[cfg(not(unix))]
    fn set_private_test_permissions(_path: &std::path::Path) {}
}
