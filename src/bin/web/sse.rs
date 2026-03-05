//! Server-Sent Events streaming handler for job log output.

use crate::util::{json_error, BoxedBody};
use http_body_util::BodyExt;
use http_body_util::StreamBody;
use hyper::body::{Bytes, Frame};
use hyper::{Response, StatusCode};
use nix_jail::jail::jail_service_client::JailServiceClient;
use nix_jail::jail::{LogSource, StreamRequest};
use std::convert::Infallible;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, warn};

/// Open a gRPC `StreamJob` RPC and forward log entries as SSE frames.
///
/// Each log entry is emitted as:
/// ```text
/// event: log
/// data: {"source":"stdout","content":"..."}
///
/// ```
/// When the stream ends, a terminal `event: done` frame is sent.
pub async fn api_stream_job(daemon: &str, job_id: &str) -> Result<Response<BoxedBody>, Infallible> {
    let mut client = match JailServiceClient::connect(daemon.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to connect to daemon for stream");
            return Ok(json_error(
                StatusCode::BAD_GATEWAY,
                "failed to connect to daemon",
            ));
        }
    };

    let mut grpc_stream = match client
        .stream_job(StreamRequest {
            job_id: job_id.to_owned(),
            tail_lines: Some(500),
            follow: true,
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            error!(job_id = %job_id, error = %e, "stream_job rpc failed");
            return Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("stream failed: {e}"),
            ));
        }
    };

    // True streaming SSE: pipe gRPC log entries to the HTTP response body
    // as they arrive via an mpsc channel + StreamBody.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(64);
    let job_id_owned = job_id.to_owned();

    drop(tokio::spawn(async move {
        loop {
            match grpc_stream.message().await {
                Ok(Some(entry)) => {
                    let source = match entry.source {
                        s if s == LogSource::JobStdout as i32 => "stdout",
                        s if s == LogSource::JobStderr as i32 => "stderr",
                        s if s == LogSource::ProxyStdout as i32 => "proxy_stdout",
                        s if s == LogSource::ProxyStderr as i32 => "proxy_stderr",
                        s if s == LogSource::System as i32 => "system",
                        _ => "stdout",
                    };
                    let content_escaped = entry
                        .content
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r");

                    let data = if let Some(code) = entry.exit_code {
                        format!(
                            r#"{{"source":"{source}","content":"{content_escaped}","exit_code":{code}}}"#
                        )
                    } else {
                        format!(r#"{{"source":"{source}","content":"{content_escaped}"}}"#)
                    };

                    let frame = format!("event: log\ndata: {data}\n\n");
                    if tx.send(Ok(Frame::data(Bytes::from(frame)))).await.is_err() {
                        break; // client disconnected
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(job_id = %job_id_owned, error = %e, "stream error");
                    break;
                }
            }
        }
        // Send the terminal "done" event
        let _ = tx
            .send(Ok(Frame::data(Bytes::from("event: done\ndata: {}\n\n"))))
            .await;
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
