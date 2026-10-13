//! Async pump that drains an `AsyncRead` into a [`super::shared_body::SharedBody`] and/or a file.

use crate::net::events::NetEvent;
use crate::net::fs_utils::temp_path_for;
use crate::net::observer::NetObserver;
use crate::net::shared_body::SharedBody;
use crate::net::types::NetError;
use crate::types::PeekBuf;
use bytes::BytesMut;
use std::sync::Arc;
use std::{path::PathBuf, time::Instant};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::task::JoinHandle;
use tokio::{
    io::AsyncRead,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Configuration for a single pump run.
pub struct PumpCfg {
    /// Maximum silence between consecutive reads before the pump aborts with an idle timeout
    pub idle: std::time::Duration,
    /// Absolute wall-clock deadline for the entire transfer; `None` disables it
    pub total_deadline: Option<Instant>,
}

/// Destinations for a pump run.
///
/// At least one of `shared` or `file_dest` should be `Some`. If both are set
/// the pump tees bytes to both concurrently.
pub struct PumpTargets {
    /// Fan-out stream target; slow subscribers may be dropped if their queue fills
    pub shared: Option<Arc<SharedBody>>,
    /// File path to write to; the pump stages to a temp file and renames on success
    pub file_dest: Option<PathBuf>,
    /// Bytes already peeked from the source that must be replayed before streaming the tail
    pub peek_buf: PeekBuf,
}

/// Pumps bytes from an `AsyncRead` into one or both targets:
/// a fan-out [`SharedBody`] and/or a file on disk.
///
/// The pump enforces:
/// - **Idle timeout**: no bytes read within `idle` → `NetError::Timeout("Pump idle timeout")`.
/// - **Total deadline**: wall-clock deadline via `total_deadline` → `NetError::Timeout("Pump total timeout")`.
/// - **Cancellation**: cooperative cancellation via [`CancellationToken`] → `NetError::Cancelled("Pump cancelled")`.
///
/// If a file destination is provided, the pump writes to a **temporary file in the destination
/// directory** (via `temp_path_for`) and **atomically renames** it to the final destination
/// *only if* the transfer finishes cleanly. On read errors, timeouts, or cancellation, the
/// temporary file is removed automatically (it is a `tempfile::NamedTempFile`).
///
/// A failure to *set up* the file target (temp-file creation, open, or peek write) degrades the
/// same way as a mid-stream write failure: when a `shared` target is present, an observer
/// warning is emitted and streaming continues without a file target, so the subscribers still
/// get the whole body. A file-only pump stops at once — there is nothing left to deliver to.
///
/// `peek` is emitted *first* to both targets (if present), then the streamed tail.
///
/// # Return
/// The task resolves to:
/// - `Ok(Some(final_path))` on a clean EOF and successful rename,
/// - `Ok(None)` when no file target was requested and the stream ended cleanly,
/// - `Err(NetError)` whenever the transfer failed: the read error, the timeout or the cancel
///   above, or for a file target the setup, write or rename that failed. Subscribers of a
///   `shared` target get the transfer's error too.
pub fn spawn_pump<R>(
    // Reader we pump from
    mut reader: R,
    targets: PumpTargets,
    cfg: PumpCfg,
    cancel: CancellationToken,
    observer: Arc<dyn NetObserver>,
    url: Url,
) -> JoinHandle<Result<Option<PathBuf>, NetError>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let PumpTargets {
        shared,
        file_dest,
        peek_buf,
    } = targets;
    let idle = cfg.idle;
    let total_deadline = cfg.total_deadline;

    tokio::spawn(async move {
        // If we need to send to file, first open the file and write the peek data.
        // A setup failure must not strand live subscribers: with a shared target we degrade to
        // stream-only (like a mid-stream write failure); a file-only pump fails outright.
        let mut file_error: Option<NetError> = None;
        let mut writer = if let Some(dest) = &file_dest {
            let setup = async {
                let tmp_dest = temp_path_for(dest).map_err(|e| NetError::Io(Arc::new(e)))?;

                let mut f = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(tmp_dest.path())
                    .await
                    .map_err(|e| NetError::Io(Arc::new(e)))?;

                // Write peek data first
                if !peek_buf.is_empty() {
                    f.write_all(&peek_buf)
                        .await
                        .map_err(|e| NetError::Io(Arc::new(e)))?;
                }

                Ok::<_, NetError>((tmp_dest, BufWriter::new(f)))
            };

            match setup.await {
                Ok(w) => Some(w),
                Err(e) if shared.is_none() => return Err(e),
                Err(e) => {
                    observer.on_event(NetEvent::Warning {
                        url: url.clone(),
                        message: format!("file setup failed, streaming without file target: {}", e),
                    });
                    file_error = Some(e);
                    None
                }
            }
        } else {
            None
        };

        // Next, push the peek data to the shared first
        if let Some(s) = &shared {
            if !peek_buf.is_empty() {
                s.push(peek_buf.into_bytes());
            }
        }

        // Peek writes are done. Continue with the main loop that deals with the stream
        let mut buf = BytesMut::with_capacity(16 * 1024);

        // How the transfer ended. A file write that fails stops the file, not the stream:
        // subscribers still get the whole body, and the failure is in `file_error`.
        let transfer: Result<(), NetError> = loop {
            let total_left = total_deadline.map(|dl| dl.saturating_duration_since(Instant::now()));

            let read_res = tokio::select! {
                _ = cancel.cancelled() => {
                    break Err(NetError::Cancelled("Pump cancelled".into()));
                }
                _ = async {
                    // Wait for total time to expire, if set
                    if let Some(rem) = total_left {
                        sleep(rem).await
                    } else {
                        futures_util::future::pending::<()>().await
                    }
                } => {
                    break Err(NetError::Timeout("Pump total timeout".into()));
                }
                r = timeout(idle, reader.read_buf(&mut buf)) => r,
            };

            match read_res {
                // Idle timeout — break regardless of whether a file target is present
                Err(_) => break Err(NetError::Timeout("Pump idle timeout".into())),
                Ok(Ok(0)) => {
                    // EOF: flush any bytes accumulated in the read buffer
                    if !buf.is_empty() {
                        let chunk = buf.split().freeze();
                        if let Some(s) = &shared {
                            s.push(chunk.clone());
                        }
                        write_to_file(&mut writer, &mut file_error, &chunk, &observer, &url).await;
                    }
                    if file_error.is_none() {
                        if let Some((_tmp, w)) = &mut writer {
                            if let Err(e) = w.flush().await {
                                observer.on_event(NetEvent::Warning {
                                    url: url.clone(),
                                    message: format!("Failed to flush file: {}", e),
                                });
                                file_error = Some(NetError::Io(Arc::new(e)));
                            }
                        }
                    }
                    // HTTP body complete — finish shared cleanly regardless of file status
                    if let Some(s) = &shared {
                        s.finish();
                    }
                    break Ok(());
                }

                Ok(Ok(_)) => {
                    // Data received
                    let chunk = buf.split().freeze();
                    if !chunk.is_empty() {
                        // Always push to shared; streaming is independent of file writes
                        if let Some(s) = &shared {
                            s.push(chunk.clone());
                        }
                        write_to_file(&mut writer, &mut file_error, &chunk, &observer, &url).await;
                    }
                }
                Ok(Err(e)) => break Err(NetError::from(e)),
            }
        };

        // The subscribers hear how the transfer ended; the temporary file goes with `writer`.
        if let (Err(e), Some(s)) = (&transfer, &shared) {
            s.error(e.clone());
        }
        transfer?;
        let Some(dest) = file_dest else {
            return Ok(None);
        };
        if let Some(e) = file_error {
            return Err(e);
        }
        let Some((tmp, _w)) = writer else {
            return Ok(None);
        };
        tokio::fs::rename(&tmp, &dest)
            .await
            .map_err(|e| NetError::Io(Arc::new(e)))?;
        Ok(Some(dest))
    })
}

/// Write `chunk` to the file target while its writes are succeeding; the first failure is
/// kept in `file_error` and stops the writes that follow.
async fn write_to_file(
    writer: &mut Option<(tempfile::NamedTempFile, BufWriter<tokio::fs::File>)>,
    file_error: &mut Option<NetError>,
    chunk: &[u8],
    observer: &Arc<dyn NetObserver>,
    url: &Url,
) {
    if file_error.is_some() {
        return;
    }
    if let Some((_tmp, w)) = writer {
        if let Err(e) = w.write_all(chunk).await {
            observer.on_event(NetEvent::Warning {
                url: url.clone(),
                message: format!("Failed to write to file: {}", e),
            });
            *file_error = Some(NetError::Io(Arc::new(e)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::events::NetEvent;
    use crate::net::observer::NetObserver;
    use crate::net::shared_body::SharedBody;
    use crate::types::PeekBuf;
    use futures_util::StreamExt;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::ReadBuf;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    struct NullObserver;
    impl NetObserver for NullObserver {
        fn on_event(&self, _: NetEvent) {}
    }

    fn observer() -> Arc<dyn NetObserver> {
        Arc::new(NullObserver)
    }
    fn url() -> Url {
        Url::parse("http://example.com/").unwrap()
    }
    fn long_timeout() -> PumpCfg {
        PumpCfg {
            idle: Duration::from_secs(60),
            total_deadline: None,
        }
    }

    // Never produces bytes — triggers idle timeout
    struct BlockingReader;
    impl AsyncRead for BlockingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    // Immediately returns an IO error
    struct ErrorReader;
    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "test error")))
        }
    }

    async fn drain(shared: &Arc<SharedBody>) -> Result<Vec<u8>, crate::net::types::NetError> {
        let mut stream = shared.subscribe_stream();
        let mut out = Vec::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_delivers_peek_then_stream() {
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();

        spawn_pump(
            std::io::Cursor::new(b" world".to_vec()),
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::from_slice(b"hello"),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );

        let mut out = Vec::new();
        while let Some(chunk) = sub.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(out, b"hello world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_empty_reader_delivers_only_peek() {
        let shared = Arc::new(SharedBody::new(32));
        spawn_pump(
            tokio::io::empty(),
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::from_slice(b"peek"),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        assert_eq!(drain(&shared).await.unwrap(), b"peek");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_no_peek_streams_reader() {
        let shared = Arc::new(SharedBody::new(32));
        spawn_pump(
            std::io::Cursor::new(b"data".to_vec()),
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        assert_eq!(drain(&shared).await.unwrap(), b"data");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_idle_timeout_errors_shared() {
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();
        spawn_pump(
            BlockingReader,
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            PumpCfg {
                idle: Duration::from_millis(50),
                total_deadline: None,
            },
            CancellationToken::new(),
            observer(),
            url(),
        );
        let err = sub.next().await.unwrap().unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("idle"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_total_timeout_errors_shared() {
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();
        spawn_pump(
            BlockingReader,
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            PumpCfg {
                idle: Duration::from_secs(60),
                total_deadline: Some(Instant::now()),
            },
            CancellationToken::new(),
            observer(),
            url(),
        );
        let err = sub.next().await.unwrap().unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("total"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_cancellation_errors_shared() {
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();
        let cancel = CancellationToken::new();
        spawn_pump(
            BlockingReader,
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            long_timeout(),
            cancel.clone(),
            observer(),
            url(),
        );
        cancel.cancel();
        assert!(sub.next().await.unwrap().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_io_error_errors_shared() {
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();
        spawn_pump(
            ErrorReader,
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        assert!(sub.next().await.unwrap().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_writes_to_file_and_renames() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        let handle = spawn_pump(
            std::io::Cursor::new(b" tail".to_vec()),
            PumpTargets {
                shared: None,
                file_dest: Some(dest.clone()),
                peek_buf: PeekBuf::from_slice(b"head"),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        let result = handle.await.unwrap().unwrap();
        assert_eq!(result, Some(dest.clone()));
        assert_eq!(std::fs::read(&dest).unwrap(), b"head tail");
    }

    /// A file-setup failure (unwritable destination directory) must not strand shared
    /// subscribers: the pump degrades to stream-only and they still get the full body. The
    /// file asked for was not made, so the pump ends in that error.
    #[tokio::test(flavor = "current_thread")]
    async fn pump_file_setup_failure_still_streams_to_shared() {
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();
        let dest = PathBuf::from("/nonexistent-gosub-test-dir/out.bin");
        let handle = spawn_pump(
            std::io::Cursor::new(b" tail".to_vec()),
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: Some(dest.clone()),
                peek_buf: PeekBuf::from_slice(b"head"),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );

        let mut out = Vec::new();
        let drain_fut = async {
            while let Some(chunk) = sub.next().await {
                out.extend_from_slice(&chunk.unwrap());
            }
        };
        tokio::time::timeout(Duration::from_secs(2), drain_fut)
            .await
            .expect("subscriber hung after file-setup failure");
        assert_eq!(out, b"head tail");
        assert!(matches!(handle.await.unwrap(), Err(NetError::Io(_))));
        assert!(!dest.exists());
    }

    /// With no shared target there is nothing left to deliver to: a file-setup failure
    /// resolves the pump task to an error.
    #[tokio::test(flavor = "current_thread")]
    async fn pump_file_only_setup_failure_returns_error() {
        let handle = spawn_pump(
            std::io::Cursor::new(b"data".to_vec()),
            PumpTargets {
                shared: None,
                file_dest: Some(PathBuf::from("/nonexistent-gosub-test-dir/out.bin")),
                peek_buf: PeekBuf::empty(),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        assert!(handle.await.unwrap().is_err());
    }

    /// A file transfer that does not complete ends in its error, file-only or not: read
    /// error, idle timeout, cancel. No file is left behind.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_file_transfer_ends_in_its_error() {
        let dir = tempfile::tempdir().unwrap();
        let pump = |reader: Box<dyn AsyncRead + Unpin + Send>, cancel: CancellationToken| {
            spawn_pump(
                reader,
                PumpTargets {
                    shared: None,
                    file_dest: Some(dir.path().join("out.bin")),
                    peek_buf: PeekBuf::from_slice(b"head"),
                },
                PumpCfg {
                    idle: Duration::from_millis(50),
                    total_deadline: None,
                },
                cancel,
                observer(),
                url(),
            )
        };
        let read_error = pump(Box::new(ErrorReader), CancellationToken::new());
        assert!(matches!(read_error.await.unwrap(), Err(NetError::Io(_))));
        let idle = pump(Box::new(BlockingReader), CancellationToken::new());
        assert!(matches!(idle.await.unwrap(), Err(NetError::Timeout(_))));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let cancelled = pump(Box::new(BlockingReader), cancel);
        assert!(matches!(
            cancelled.await.unwrap(),
            Err(NetError::Cancelled(_))
        ));
        assert!(!dir.path().join("out.bin").exists());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "no temp file left"
        );
    }

    /// A reader error that carries a `NetError` (the body over its cap, the total timeout) is
    /// that error to the subscribers and the pump task, not an `Io` wrapping it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_carried_read_error_keeps_its_variant() {
        struct CarryingReader;
        impl AsyncRead for CarryingReader {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(NetError::Timeout("total".into()).to_io()))
            }
        }
        let shared = Arc::new(SharedBody::new(32));
        let mut sub = shared.subscribe_stream();
        let handle = spawn_pump(
            CarryingReader,
            PumpTargets {
                shared: Some(shared.clone()),
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        let err = sub.next().await.unwrap().unwrap_err();
        assert!(
            matches!(err, NetError::Timeout(_)),
            "subscriber got {err:?}"
        );
        let result = handle.await.unwrap();
        assert!(
            matches!(result, Err(NetError::Timeout(_))),
            "pump got {result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pump_no_targets_completes_cleanly() {
        let handle = spawn_pump(
            std::io::Cursor::new(b"ignored".to_vec()),
            PumpTargets {
                shared: None,
                file_dest: None,
                peek_buf: PeekBuf::empty(),
            },
            long_timeout(),
            CancellationToken::new(),
            observer(),
            url(),
        );
        assert_eq!(handle.await.unwrap().unwrap(), None);
    }
}
