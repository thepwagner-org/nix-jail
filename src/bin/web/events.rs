//! Server-Sent Events handler for the global job lifecycle stream.
//!
//! `GET /api/events` — long-lived SSE stream served on the home subdomain.
//!
//! **Connect protocol (replay-then-sentinel):**
//!
//! 1. Subscribe to the internal broadcast channel (so no events are missed).
//! 2. Snapshot running jobs from the cache.
//! 3. Emit one `job:started` per running job.
//! 4. Emit `job:connected` sentinel.
//! 5. Stream live `job:started` / `job:stopped` events as they arrive,
//!    skipping any `job:started` whose `job_id` was already in the snapshot
//!    (dedup window that covers the race between subscribe and snapshot).
//!
//! meowser uses the sentinel to reconcile stale tabs after a server restart:
//! it snapshots known jobs before connecting, rebuilds state from the replay,
//! then diffs against the snapshot to detect disappeared/surviving jobs.

use crate::cache::{JobCache, SseEvent};
use crate::util::BoxedBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Response, StatusCode};
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;

/// Handler for `GET /api/events`.
///
/// Opens an SSE stream that follows the replay-then-sentinel protocol.
pub async fn api_events(cache: Arc<JobCache>) -> Result<Response<BoxedBody>, Infallible> {
    // Subscribe BEFORE taking the snapshot to avoid missing events that fire
    // between the snapshot and when we start reading from the receiver.
    let mut events_rx = cache.subscribe();

    // Snapshot currently-running jobs for the replay burst.
    let snapshot = cache.running_jobs_snapshot().await;
    let replay_ids: HashSet<String> = snapshot.iter().map(|j| j.job_id.clone()).collect();

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(64);

    drop(tokio::spawn(async move {
        // 1. Replay running jobs
        for job in &snapshot {
            let subdomain = job.subdomain.as_deref().unwrap_or("");
            let frame = format!(
                "event: job:started\ndata: {{\"job_id\":\"{}\",\"subdomain\":\"{}\"}}\n\n",
                job.job_id, subdomain
            );
            if tx.send(Ok(Frame::data(Bytes::from(frame)))).await.is_err() {
                return; // client disconnected during replay
            }
        }

        // 2. Sentinel
        if tx
            .send(Ok(Frame::data(Bytes::from(
                "event: job:connected\ndata: {}\n\n",
            ))))
            .await
            .is_err()
        {
            return;
        }

        // 3. Stream live events, deduplicating replayed starts
        loop {
            match events_rx.recv().await {
                Ok(SseEvent::Started { job_id, subdomain }) => {
                    // Skip if this job was already in the replay snapshot.
                    if replay_ids.contains(&job_id) {
                        continue;
                    }
                    let frame = format!(
                        "event: job:started\ndata: {{\"job_id\":\"{job_id}\",\"subdomain\":\"{subdomain}\"}}\n\n"
                    );
                    if tx.send(Ok(Frame::data(Bytes::from(frame)))).await.is_err() {
                        break;
                    }
                }
                Ok(SseEvent::Stopped { job_id, subdomain }) => {
                    let frame = format!(
                        "event: job:stopped\ndata: {{\"job_id\":\"{job_id}\",\"subdomain\":\"{subdomain}\"}}\n\n"
                    );
                    if tx.send(Ok(Frame::data(Bytes::from(frame)))).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // The client is too slow or was paused. Log and continue;
                    // meowser will reconnect and get a fresh replay.
                    tracing::warn!(skipped = n, "sse events stream lagged, skipping events");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break; // cache dropped, process shutting down
                }
            }
        }
    }));

    let stream_body = StreamBody::new(ReceiverStream::new(rx));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no") // disable nginx buffering
        .body(stream_body.boxed())
        .unwrap_or_else(|_| {
            crate::util::error_response(StatusCode::INTERNAL_SERVER_ERROR, "sse failed")
        }))
}
