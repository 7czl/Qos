use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use crate::map_manager::MapManager;
use crate::protocol::{parse_and_validate_request, Request, Response};

/// Run the Unix Domain Socket server at the given path.
///
/// Listens for client connections, reads line-delimited JSON requests,
/// dispatches them to the MapManager, and writes back JSON responses.
/// If the socket file already exists it is removed before binding.
pub async fn run_uds_server(
    socket_path: &str,
    map_manager: Arc<Mutex<MapManager>>,
) -> Result<()> {
    // Remove stale socket file if it exists
    if std::path::Path::new(socket_path).exists() {
        log::warn!("removing existing socket file: {}", socket_path);
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    log::info!("UDS server listening on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let mgr = Arc::clone(&map_manager);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, mgr).await {
                        log::warn!("client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                log::warn!("failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a single client connection.
///
/// Reads lines from the stream, parses each as a JSON `Request`,
/// executes it via the `MapManager`, and writes back a JSON `Response`
/// followed by a newline.
async fn handle_client(
    stream: tokio::net::UnixStream,
    map_manager: Arc<Mutex<MapManager>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        log::debug!("received request: {}", line);

        let response = process_request(&line, &map_manager).await;

        let mut resp_json = serde_json::to_string(&response)?;
        resp_json.push('\n');
        writer.write_all(resp_json.as_bytes()).await?;
        writer.flush().await?;
    }

    log::debug!("client disconnected");
    Ok(())
}

/// Parse a JSON line into a `Request` and execute it, returning a `Response`.
async fn process_request(
    line: &str,
    map_manager: &Arc<Mutex<MapManager>>,
) -> Response {
    match parse_and_validate_request(line) {
        Ok(request) => execute_request(request, map_manager).await,
        Err(error_response) => error_response,
    }
}

/// Execute a validated `Request` against the `MapManager`.
async fn execute_request(
    request: Request,
    map_manager: &Arc<Mutex<MapManager>>,
) -> Response {
    match request {
        Request::Add { ip, rate, burst } => {
            let mut mgr = map_manager.lock().await;
            match mgr.add_rule(&ip, rate, burst) {
                Ok(()) => {
                    log::info!("added rule: {} rate={} burst={}", ip, rate, burst);
                    Response {
                        status: "ok".to_string(),
                        data: None,
                        message: None,
                    }
                }
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("invalid") || msg.contains("prefix length") {
                        Response {
                            status: "error".to_string(),
                            data: None,
                            message: Some(format!("invalid CIDR format: {}", ip)),
                        }
                    } else {
                        Response {
                            status: "error".to_string(),
                            data: None,
                            message: Some(msg),
                        }
                    }
                }
            }
        }
        Request::Delete { ip } => {
            let mut mgr = map_manager.lock().await;
            match mgr.delete_rule(&ip) {
                Ok(()) => {
                    log::info!("deleted rule: {}", ip);
                    Response {
                        status: "ok".to_string(),
                        data: None,
                        message: None,
                    }
                }
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("invalid") || msg.contains("prefix length") {
                        Response {
                            status: "error".to_string(),
                            data: None,
                            message: Some(format!("invalid CIDR format: {}", ip)),
                        }
                    } else {
                        Response {
                            status: "error".to_string(),
                            data: None,
                            message: Some(msg),
                        }
                    }
                }
            }
        }
        Request::List => {
            let mgr = map_manager.lock().await;
            match mgr.list_rules() {
                Ok(rules) => {
                    let data = serde_json::to_value(&rules).unwrap_or(serde_json::Value::Null);
                    Response {
                        status: "ok".to_string(),
                        data: Some(data),
                        message: None,
                    }
                }
                Err(e) => Response {
                    status: "error".to_string(),
                    data: None,
                    message: Some(format!("{}", e)),
                },
            }
        }
    }
}
