use crate::{
    backend::LocalApi,
    messages::{self, Access},
};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread,
    time::Duration,
};
use tauri::Manager;

const INTERVAL: Duration = Duration::from_secs(3);
const RUNNING: &str = "Monitoring new incoming plaintext messages.";
const PAUSED: &str = "Monitoring is paused. Resume to check messages that arrived while paused.";
const STOPPED: &str = "Monitoring is off.";
const STORAGE_ERROR: &str = "Messages scan history is unavailable.";
const CLASSIFIER_ERROR: &str = "The local classifier is unavailable. Monitoring will retry.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    #[default]
    Stopped,
    Running,
    Paused,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct Status {
    state: Phase,
    detail: &'static str,
}

struct State {
    session: u64,
    status: Status,
}

impl Default for State {
    fn default() -> Self {
        Self {
            session: 0,
            status: Status {
                state: Phase::Stopped,
                detail: STOPPED,
            },
        }
    }
}

impl State {
    fn running(&self, session: u64) -> bool {
        self.session == session && self.status.state == Phase::Running
    }

    fn set(&mut self, state: Phase, detail: &'static str) -> Status {
        self.status = Status { state, detail };
        self.status
    }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

#[derive(Default, Clone)]
pub(crate) struct Monitor(Arc<Shared>);

impl Monitor {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wait_for_poll(&self, session: u64, delayed: bool) -> bool {
        let mut state = self.state();
        if delayed {
            // Wake immediately on Pause or Stop instead of waiting for the next poll.
            state = self
                .0
                .wake
                .wait_timeout_while(state, INTERVAL, |state| state.running(session))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let state = self
            .0
            .wake
            .wait_while(state, |state| {
                state.session == session && state.status.state == Phase::Paused
            })
            .unwrap_or_else(PoisonError::into_inner);
        state.running(session)
    }
}

#[derive(Serialize)]
pub(crate) struct ScanEntry {
    id: i64,
    source: &'static str,
    detected_at: String,
    prediction: String,
    phishing_probability: f64,
    status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct ClearResult {
    deleted: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct HistorySummary {
    total_scans: u64,
    phishing_detections: u64,
}

enum Assessment {
    Scored {
        prediction: &'static str,
        probability: f64,
    },
    Insufficient,
}

impl Assessment {
    fn from_model(prediction: &str, probability: f64) -> Option<Self> {
        let prediction = match prediction {
            "Phishing" => "Phishing",
            "Legitimate" => "Legitimate",
            _ => return None,
        };
        if !(0.0..=1.0).contains(&probability) {
            return None;
        }
        Some(Self::Scored {
            prediction,
            probability,
        })
    }
}

fn history_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let directory = app.path().app_data_dir().map_err(|_| STORAGE_ERROR)?;
    std::fs::create_dir_all(&directory).map_err(|_| STORAGE_ERROR)?;
    Ok(directory.join("messages-history.sqlite3"))
}

fn open_history(path: &Path) -> rusqlite::Result<Connection> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.busy_timeout(Duration::from_millis(300))?;
    db.execute_batch(
        "PRAGMA secure_delete = ON;
         CREATE TABLE IF NOT EXISTS message_scans (
            id INTEGER PRIMARY KEY,
            detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            prediction TEXT NOT NULL CHECK (prediction IN ('Phishing', 'Legitimate')),
            phishing_probability REAL NOT NULL CHECK (phishing_probability BETWEEN 0 AND 1)
         );
         CREATE TABLE IF NOT EXISTS checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cursor INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO checkpoint VALUES (1, 0);",
    )?;
    Ok(db)
}

fn cursor(db: &Connection) -> rusqlite::Result<i64> {
    db.query_row("SELECT cursor FROM checkpoint WHERE id = 1", [], |row| {
        row.get(0)
    })
}

fn advance(db: &Connection, through_id: i64) -> rusqlite::Result<usize> {
    db.execute(
        "UPDATE checkpoint SET cursor = ?1 WHERE id = 1 AND cursor < ?1",
        [through_id],
    )
}

fn record(db: &mut Connection, rowid: i64, result: Assessment) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    // Commit the result with its checkpoint so recorded scans cannot be added twice.
    if advance(&tx, rowid)? != 0 {
        if let Assessment::Scored {
            prediction,
            probability,
        } = result
        {
            tx.execute(
                "INSERT INTO message_scans (prediction, phishing_probability) VALUES (?1, ?2)",
                params![prediction, probability],
            )?;
        }
    }
    tx.commit()
}

fn history(db: &Connection) -> rusqlite::Result<Vec<ScanEntry>> {
    let mut query = db.prepare(
        "SELECT id, detected_at, prediction, phishing_probability
         FROM message_scans ORDER BY id DESC LIMIT 100",
    )?;
    let rows = query.query_map([], |row| {
        Ok(ScanEntry {
            id: row.get(0)?,
            source: "Apple Messages",
            detected_at: row.get(1)?,
            prediction: row.get(2)?,
            phishing_probability: row.get(3)?,
            status: "scanned",
        })
    })?;
    rows.collect()
}

fn history_summary(db: &Connection) -> rusqlite::Result<HistorySummary> {
    db.query_row(
        "SELECT COUNT(*), COUNT(CASE WHEN prediction = 'Phishing' THEN 1 END)
         FROM message_scans",
        [],
        |row| {
            Ok(HistorySummary {
                total_scans: row.get(0)?,
                phishing_detections: row.get(1)?,
            })
        },
    )
}

#[derive(Debug)]
enum PollError {
    Messages(Access),
    History,
    Classifier,
}

fn poll_once(
    monitor: &Monitor,
    session: u64,
    path: &Path,
    db: &mut Connection,
    mut classify: impl FnMut(&str) -> Option<Assessment>,
) -> Result<(), PollError> {
    let batch = {
        // Before reading bodies, hold the same state lock used by Pause and Stop.
        let state = monitor.state();
        if !state.running(session) {
            return Ok(());
        }
        let after_id = cursor(db).map_err(|_| PollError::History)?;
        messages::read_incoming(path, after_id).map_err(PollError::Messages)?
    };

    for (rowid, text) in batch.messages {
        if !monitor.state().running(session) {
            return Ok(());
        }
        let assessment = classify(&text).ok_or(PollError::Classifier)?;
        let state = monitor.state();
        if state.session != session || state.status.state == Phase::Stopped {
            return Ok(());
        }
        // Finish an in-flight scan on Pause to avoid classifying it again after Resume.
        record(db, rowid, assessment).map_err(|_| PollError::History)?;
    }

    let state = monitor.state();
    if state.running(session) {
        // Skip past outbound rows and bodies that lack supported plaintext.
        advance(db, batch.through_id).map_err(|_| PollError::History)?;
    }
    Ok(())
}

fn worker(
    app: tauri::AppHandle,
    monitor: Monitor,
    session: u64,
    path: PathBuf,
    mut db: Connection,
) {
    let api = app.state::<LocalApi>();
    let mut delayed = false;
    while monitor.wait_for_poll(session, delayed) {
        let result = poll_once(&monitor, session, &path, &mut db, |text| {
            let result = tauri::async_runtime::block_on(api.classify_message(text)).ok()?;
            match result.phishing_probability {
                Some(probability) => Assessment::from_model(&result.prediction, probability),
                None => Some(Assessment::Insufficient),
            }
        });
        let mut state = monitor.state();
        if state.running(session) {
            match result {
                Ok(()) => state.set(Phase::Running, RUNNING),
                Err(PollError::Classifier) => state.set(Phase::Running, CLASSIFIER_ERROR),
                Err(PollError::History) => state.set(Phase::Paused, STORAGE_ERROR),
                Err(PollError::Messages(Access::Busy)) => state.set(
                    Phase::Running,
                    "The Messages database is busy. Monitoring will retry.",
                ),
                Err(PollError::Messages(access)) => state.set(Phase::Paused, access.message()),
            };
        }
        delayed = true;
    }
}

async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|_| "The Messages operation could not finish.".to_owned())?
}

#[tauri::command]
pub(crate) async fn start_monitoring(
    app: tauri::AppHandle,
    monitor: tauri::State<'_, Monitor>,
) -> Result<Status, String> {
    let monitor = monitor.inner().clone();
    run_blocking(move || {
        let mut state = monitor.state();
        match state.status.state {
            Phase::Running => return Ok(state.status),
            Phase::Paused => {
                return Err("Use Resume to continue the existing monitoring session.".into())
            }
            Phase::Stopped => {}
        }
        let path = messages::messages_path(&app).map_err(Access::message)?;
        // A new session ignores messages that existed before the user's Start action.
        let baseline = messages::initial_cursor(&path).map_err(Access::message)?;
        let db = open_history(&history_path(&app)?).map_err(|_| STORAGE_ERROR)?;
        db.execute("UPDATE checkpoint SET cursor = ?1 WHERE id = 1", [baseline])
            .map_err(|_| STORAGE_ERROR)?;

        state.session += 1;
        let session = state.session;
        let worker_monitor = monitor.clone();
        thread::Builder::new()
            .name("messages-monitor".into())
            .spawn(move || worker(app, worker_monitor, session, path, db))
            .map_err(|_| "Could not start the Messages monitor.")?;
        Ok(state.set(Phase::Running, RUNNING))
    })
    .await
}

#[tauri::command]
pub(crate) fn monitoring_status(monitor: tauri::State<'_, Monitor>) -> Status {
    monitor.state().status
}

#[tauri::command]
pub(crate) fn pause_monitoring(monitor: tauri::State<'_, Monitor>) -> Status {
    let mut state = monitor.state();
    if state.status.state == Phase::Running {
        state.set(Phase::Paused, PAUSED);
        monitor.0.wake.notify_all();
    }
    state.status
}

#[tauri::command]
pub(crate) async fn resume_monitoring(
    app: tauri::AppHandle,
    monitor: tauri::State<'_, Monitor>,
) -> Result<Status, String> {
    let monitor = monitor.inner().clone();
    run_blocking(move || {
        let mut state = monitor.state();
        if state.status.state == Phase::Paused {
            let path = messages::messages_path(&app).map_err(Access::message)?;
            messages::initial_cursor(&path).map_err(Access::message)?;
            state.set(Phase::Running, RUNNING);
            monitor.0.wake.notify_all();
        }
        Ok(state.status)
    })
    .await
}

#[tauri::command]
pub(crate) fn stop_monitoring(monitor: tauri::State<'_, Monitor>) -> Status {
    let status = monitor.state().set(Phase::Stopped, STOPPED);
    monitor.0.wake.notify_all();
    status
}

#[tauri::command]
pub(crate) async fn message_scan_history(app: tauri::AppHandle) -> Result<Vec<ScanEntry>, String> {
    run_blocking(move || {
        let db = open_history(&history_path(&app)?).map_err(|_| STORAGE_ERROR)?;
        history(&db).map_err(|_| STORAGE_ERROR.into())
    })
    .await
}

#[tauri::command]
pub(crate) async fn message_history_summary(
    app: tauri::AppHandle,
) -> Result<HistorySummary, String> {
    run_blocking(move || {
        let db = open_history(&history_path(&app)?).map_err(|_| STORAGE_ERROR)?;
        history_summary(&db).map_err(|_| STORAGE_ERROR.into())
    })
    .await
}

#[tauri::command]
pub(crate) async fn clear_message_scan_history(
    app: tauri::AppHandle,
) -> Result<ClearResult, String> {
    run_blocking(move || {
        let db = open_history(&history_path(&app)?).map_err(|_| STORAGE_ERROR)?;
        // Keep the checkpoint so cleared scans do not come back during this session.
        let deleted = db
            .execute("DELETE FROM message_scans", [])
            .map_err(|_| STORAGE_ERROR)?;
        Ok(ClearResult { deleted })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstention_advances_checkpoint_without_a_history_entry() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("history.sqlite3");
        let mut db = open_history(&path).unwrap();
        record(&mut db, 1, Assessment::Insufficient).unwrap();
        assert_eq!(cursor(&db).unwrap(), 1);
        assert!(history(&db).unwrap().is_empty());
        let scored = Assessment::from_model("Legitimate", 0.1).unwrap();
        record(&mut db, 2, scored).unwrap();
        assert_eq!(history(&db).unwrap().len(), 1);
    }

    #[test]
    fn summary_counts_messages_outside_the_recent_history_window() {
        let db = open_history(Path::new(":memory:")).unwrap();
        assert_eq!(
            history_summary(&db).unwrap(),
            HistorySummary {
                total_scans: 0,
                phishing_detections: 0,
            }
        );
        db.execute_batch(
            "INSERT INTO message_scans (prediction, phishing_probability) VALUES ('Phishing', 0.8);
             WITH RECURSIVE records(n) AS (
                VALUES(1) UNION ALL SELECT n + 1 FROM records WHERE n < 100
             )
             INSERT INTO message_scans (prediction, phishing_probability)
                SELECT 'Legitimate', 0.1 FROM records;",
        )
        .unwrap();

        let recent = history(&db).unwrap();
        assert_eq!(recent.len(), 100);
        assert!(recent.iter().all(|entry| entry.prediction == "Legitimate"));
        assert_eq!(
            history_summary(&db).unwrap(),
            HistorySummary {
                total_scans: 101,
                phishing_detections: 1,
            }
        );
    }

    #[test]
    fn first_poll_skips_existing_and_unsupported_rows_and_dedupe_survives_history_delete() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().canonicalize().unwrap();
        let messages_path = directory.join("chat.db");
        let history_path = directory.join("history.sqlite3");
        let source = Connection::open(&messages_path).unwrap();
        source
            .execute_batch(
                "PRAGMA journal_mode = WAL;
             CREATE TABLE message (is_from_me INTEGER, text TEXT, attributedBody BLOB);
             INSERT INTO message VALUES (0, 'Synthetic text from before the session', NULL);",
            )
            .unwrap();

        let monitor = Monitor::default();
        let mut db = open_history(&history_path).unwrap();
        let baseline = messages::initial_cursor(&messages_path).unwrap();
        assert_eq!(baseline, 1);
        advance(&db, baseline).unwrap();
        assert_eq!(monitor.state().status.state, Phase::Stopped);

        source
            .execute_batch(
                "INSERT INTO message VALUES
              (1, 'Synthetic outbound text', NULL),
              (0, NULL, X'1234'),
              (0, 'Synthetic incoming text', NULL),
              (0, '', NULL);",
            )
            .unwrap();
        poll_once(&monitor, 1, &messages_path, &mut db, |_| {
            panic!("Scanned while stopped")
        })
        .unwrap();
        assert_eq!(cursor(&db).unwrap(), baseline);
        monitor.state().session = 1;
        monitor.state().set(Phase::Running, RUNNING);
        poll_once(&monitor, 1, &messages_path, &mut db, |text| {
            assert_eq!(text, "Synthetic incoming text");
            Assessment::from_model("Phishing", 0.91)
        })
        .unwrap();

        let rows = history(&db).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "Apple Messages");
        assert_eq!(rows[0].prediction, "Phishing");
        assert_eq!(rows[0].phishing_probability, 0.91);
        assert_eq!(rows[0].status, "scanned");
        assert!(rows[0].detected_at.ends_with('Z'));
        assert!(!std::fs::read(&history_path)
            .unwrap()
            .windows(b"Synthetic".len())
            .any(|window| window == b"Synthetic"));
        assert_eq!(cursor(&db).unwrap(), 5);

        db.execute("DELETE FROM message_scans", []).unwrap();
        drop(db);
        let mut db = open_history(&history_path).unwrap();
        assert!(history(&db).unwrap().is_empty());
        assert_eq!(cursor(&db).unwrap(), 5);
        poll_once(&monitor, 1, &messages_path, &mut db, |_| {
            panic!("Scanned a deleted history entry again")
        })
        .unwrap();
        assert!(history(&db).unwrap().is_empty());
    }

    #[test]
    fn classifier_failure_retries_and_pause_stops_further_batches() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("chat.db");
        let source = Connection::open(&path).unwrap();
        source
            .execute_batch(
                "CREATE TABLE message (is_from_me INTEGER, text TEXT);
             INSERT INTO message VALUES (0, 'Test one'), (0, 'Test two');",
            )
            .unwrap();
        let monitor = Monitor::default();
        monitor.state().set(Phase::Running, RUNNING);
        let mut db =
            open_history(&temp.path().canonicalize().unwrap().join("history.sqlite3")).unwrap();
        assert!(matches!(
            poll_once(&monitor, 0, &path, &mut db, |_| None),
            Err(PollError::Classifier)
        ));
        assert_eq!(cursor(&db).unwrap(), 0);

        poll_once(&monitor, 0, &path, &mut db, |text| {
            assert_eq!(text, "Test one");
            monitor.state().set(Phase::Paused, PAUSED);
            Assessment::from_model("Legitimate", 0.1)
        })
        .unwrap();
        assert_eq!(history(&db).unwrap().len(), 1);
        assert_eq!(cursor(&db).unwrap(), 1);
        monitor.state().set(Phase::Running, RUNNING);
        poll_once(&monitor, 0, &path, &mut db, |text| {
            assert_eq!(text, "Test two");
            Assessment::from_model("Phishing", 0.9)
        })
        .unwrap();
        assert_eq!(history(&db).unwrap().len(), 2);
    }
}
