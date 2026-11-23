use rusqlite::{params, Connection, DatabaseName, Error, ErrorCode, OpenFlags};
use serde::Serialize;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::Manager;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Access {
    Ready,
    Denied,
    Busy,
    Unavailable,
    Unsupported,
}

#[derive(Serialize)]
pub(crate) struct AccessStatus {
    status: Access,
    message: &'static str,
}

impl Access {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Ready => "SentinelAI verified read-only access to the local Messages database.",
            Self::Denied => {
                "macOS blocked access to Messages. Review Privacy & Security, then try again."
            }
            Self::Busy => "The Messages database is busy. Try again shortly.",
            Self::Unavailable => {
                "The local Messages database is unavailable. Open Messages and try again."
            }
            Self::Unsupported => "SentinelAI could not recognize this Messages database format.",
        }
    }

    fn response(self) -> AccessStatus {
        AccessStatus {
            status: self,
            message: self.message(),
        }
    }
}

fn file_error(error: &std::io::Error) -> Access {
    match error.kind() {
        ErrorKind::PermissionDenied => Access::Denied,
        ErrorKind::WouldBlock => Access::Busy,
        _ => Access::Unavailable,
    }
}

fn sqlite_error(error: &Error) -> Access {
    let code = match error {
        Error::SqlInputError { error, .. } => Some(error.code),
        _ => error.sqlite_error_code(),
    };
    match code {
        Some(ErrorCode::PermissionDenied | ErrorCode::AuthorizationForStatementDenied) => {
            Access::Denied
        }
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked | ErrorCode::ReadOnly) => {
            Access::Busy
        }
        Some(
            ErrorCode::DatabaseCorrupt
            | ErrorCode::NotADatabase
            | ErrorCode::SchemaChanged
            | ErrorCode::Unknown,
        ) => Access::Unsupported,
        _ => Access::Unavailable,
    }
}

fn open_read_only(path: &Path) -> Result<Connection, Access> {
    // A nonregular file or symbolically linked database is outside this integration's scope.
    let metadata = fs::symlink_metadata(path).map_err(|error| file_error(&error))?;
    if !metadata.is_file() {
        return Err(Access::Unavailable);
    }

    // Preserve the OS permission error before SQLite combines it with other open errors.
    File::open(path).map_err(|error| file_error(&error))?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let db = Connection::open_with_flags(path, flags).map_err(|error| sqlite_error(&error))?;
    db.busy_timeout(Duration::from_millis(300))
        .map_err(|error| sqlite_error(&error))?;
    db.execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|error| sqlite_error(&error))?;
    if !db
        .is_readonly(DatabaseName::Main)
        .map_err(|error| sqlite_error(&error))?
    {
        return Err(Access::Unavailable);
    }
    Ok(db)
}

fn incoming_text(
    db: &Connection,
    after_id: i64,
    through_id: i64,
) -> rusqlite::Result<Vec<(i64, String)>> {
    let mut query = db.prepare(
        "SELECT rowid, substr(text, 1, 20000)
         FROM main.message
         WHERE rowid > ?1 AND rowid <= ?2
           AND is_from_me = 0 AND typeof(text) = 'text' AND trim(text) <> ''
         ORDER BY rowid ASC",
    )?;
    let mut rows = query.query(params![after_id, through_id])?;
    let mut incoming = Vec::new();
    while let Some(row) = rows.next()? {
        let Ok(text) = row.get_ref(1)?.as_str() else {
            continue;
        };
        if !text.trim().is_empty() {
            incoming.push((row.get(0)?, text.to_owned()));
        }
    }
    Ok(incoming)
}

fn verify_schema(db: &Connection) -> Result<(), Access> {
    let message_table = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = 'message')",
        [],
        |row| row.get::<_, bool>(0),
    );
    match message_table {
        Ok(true) => {}
        Ok(false) => return Err(Access::Unsupported),
        Err(error) => return Err(sqlite_error(&error)),
    }

    // Compile the read query against the real schema without retrieving any message bodies.
    incoming_text(db, 0, 0)
        .map(|_| ())
        .map_err(|error| sqlite_error(&error))
}

fn verify_messages_database(path: &Path) -> Access {
    open_read_only(path)
        .and_then(|db| verify_schema(&db))
        .err()
        .unwrap_or(Access::Ready)
}

pub(crate) fn messages_path(app: &tauri::AppHandle) -> Result<PathBuf, Access> {
    if !cfg!(target_os = "macos") {
        return Err(Access::Unsupported);
    }
    let home = app.path().home_dir().map_err(|_| Access::Unavailable)?;
    Ok(home.join("Library/Messages/chat.db"))
}

pub(crate) fn initial_cursor(path: &Path) -> Result<i64, Access> {
    let db = open_read_only(path)?;
    verify_schema(&db)?;
    db.query_row(
        "SELECT COALESCE(MAX(rowid), 0) FROM main.message",
        [],
        |row| row.get(0),
    )
    .map_err(|error| sqlite_error(&error))
}

pub(crate) struct IncomingBatch {
    pub(crate) through_id: i64,
    pub(crate) messages: Vec<(i64, String)>,
}

pub(crate) fn read_incoming(path: &Path, after_id: i64) -> Result<IncomingBatch, Access> {
    let mut db = open_read_only(path)?;
    // Both queries use the same read snapshot, including writes visible in SQLite's WAL.
    let tx = db.transaction().map_err(|error| sqlite_error(&error))?;
    verify_schema(&tx)?;
    let through_id: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(rowid), ?1) FROM (
           SELECT rowid FROM main.message WHERE rowid > ?1 ORDER BY rowid ASC LIMIT 20
         )",
            [after_id],
            |row| row.get(0),
        )
        .map_err(|error| sqlite_error(&error))?;
    let messages =
        incoming_text(&tx, after_id, through_id).map_err(|error| sqlite_error(&error))?;
    Ok(IncomingBatch {
        through_id,
        messages,
    })
}

#[tauri::command]
pub(crate) async fn check_messages_access(app: tauri::AppHandle) -> AccessStatus {
    let path = match messages_path(&app) {
        Ok(path) => path,
        Err(status) => return status.response(),
    };
    tauri::async_runtime::spawn_blocking(move || verify_messages_database(&path))
        .await
        .unwrap_or(Access::Unavailable)
        .response()
}

#[tauri::command]
pub(crate) async fn open_privacy_settings() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("Privacy & Security settings are available on macOS.".into());
    }
    let status = tauri::async_runtime::spawn_blocking(|| {
        std::process::Command::new("/usr/bin/open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
    })
    .await;
    match status {
        Ok(Ok(code)) if code.success() => Ok(()),
        _ => Err("Open System Settings → Privacy & Security → Full Disk Access manually.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denial_has_a_distinct_status() {
        let error = std::io::Error::from(ErrorKind::PermissionDenied);
        assert_eq!(file_error(&error), Access::Denied);
    }

    #[test]
    fn verification_handles_missing_incompatible_and_busy_databases() {
        let dir = tempfile::tempdir().unwrap();
        // macOS can expose its temporary directory through a /var symlink.
        let path = dir.path().canonicalize().unwrap().join("chat.db");

        assert_eq!(verify_messages_database(&path), Access::Unavailable);
        assert!(!path.exists());

        let writer = Connection::open(&path).unwrap();
        writer
            .execute("CREATE TABLE message (is_from_me INTEGER)", [])
            .unwrap();
        assert_eq!(verify_messages_database(&path), Access::Unsupported);

        writer
            .execute("ALTER TABLE message ADD COLUMN text TEXT", [])
            .unwrap();
        assert_eq!(verify_messages_database(&path), Access::Ready);
        writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
        assert_eq!(verify_messages_database(&path), Access::Busy);
    }

    #[test]
    fn synthetic_inbound_query_is_read_only_filtered_and_paginated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("chat.db");
        let writer = Connection::open(&path).unwrap();
        writer
            .execute_batch(
                "CREATE TABLE message (is_from_me INTEGER, text TEXT, attributedBody BLOB);
                 INSERT INTO message VALUES
                   (0, 'earlier text', NULL),
                   (1, 'outgoing text', NULL),
                   (0, NULL, X'1234'),
                   (0, 'newer inbound text', NULL),
                   (0, 'latest text', NULL);",
            )
            .unwrap();
        let db = open_read_only(&path).unwrap();
        assert!(db.is_readonly(DatabaseName::Main).unwrap());
        assert!(db.execute("DELETE FROM message", []).is_err());
        assert!(incoming_text(&db, 0, 0).unwrap().is_empty());
        assert_eq!(
            incoming_text(&db, 1, 4).unwrap(),
            vec![(4, "newer inbound text".to_string())]
        );
        assert_eq!(
            incoming_text(&db, 4, 5).unwrap(),
            vec![(5, "latest text".to_string())]
        );
    }
}
