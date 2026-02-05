mod security;

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Query, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{sink::SinkExt, stream::StreamExt};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::Deserialize;
use std::{io::{Read, Write}, net::SocketAddr, path::Path, sync::{Arc, Mutex}, collections::HashMap, time::{Instant, Duration}};
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};
use rand::Rng;
use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use security::{InputFilter, SecurityConfig};
use portable_pty::{MasterPty, Child};

/// Represents an active terminal session with PTY and broadcast channel
struct Session {
    /// PTY master handle for terminal control
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    /// PTY writer for sending input to shell
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    /// Broadcast channel for terminal output distribution
    tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Session output history for reconnection support
    history: Arc<Mutex<Vec<u8>>>,
    /// Shell process handle (kept alive to prevent premature termination)
    _child: Arc<Mutex<Box<dyn Child + Send>>>,
    /// Active WebSocket connection count for this session
    active_connections: Arc<Mutex<usize>>,
    /// Timestamp of last output for idle detection
    last_output: Arc<Mutex<Instant>>,
}

impl Drop for Session {
    /// Cleanup: kill shell process when session is dropped
    fn drop(&mut self) {
        if let Ok(mut child) = self._child.lock() {
            let _ = child.kill();
        }
    }
}

/// Application state shared across all requests
#[derive(Clone)]
struct AppState {
    /// Authentication token for WebSocket connections
    token: String,
    /// Read-only mode flag (blocks all input)
    readonly: bool,
    /// Input filter for security validation
    filter: Arc<InputFilter>,
    /// Map of active sessions by session ID
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>,
}

/// WebSocket connection authentication parameters
#[derive(Deserialize)]
struct AuthParams {
    token: String,
    session_id: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Generate secure random token or use ENV
    // Security Feature: Random secret verification for local mode (CLI Secret)
    // If env var not set, use CSPRNG to generate 32-char random token
    let token: String = std::env::var("WCODE_TERMINAL_TOKEN").unwrap_or_else(|_| {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    });
    
    // Check if readonly mode is enabled
    let readonly = std::env::var("WCODE_TERMINAL_READONLY").map(|v| v == "true" || v == "1").unwrap_or(false);

    // Initialize Security Filter
    let mut security_config = SecurityConfig::default();
    if let Ok(blocklist_str) = std::env::var("WCODE_TERMINAL_BLOCKLIST") {
        security_config.blocklist.extend(
            blocklist_str.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        );
    }
    let filter = Arc::new(InputFilter::new(security_config));

    info!("==================================================");
    info!("WCode Terminal Proxy Started");
    info!("Security Token: {}", token);
    if readonly {
        info!("Mode: Read-Only");
    }
    info!("Security Filter: Active (Rate Limit: 1KB/s)");
    info!("==================================================");

    let state = Arc::new(AppState { 
        token, 
        readonly, 
        filter,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    });

    // Start background cleanup task (Idle Timeout)
    let sessions_clone = state.sessions.clone();
    tokio::spawn(async move {
        // Default timeout: 30 minutes
        let timeout_duration = std::env::var("WCODE_TERMINAL_IDLE_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30 * 60));
            
        info!("Idle timeout checker started (Timeout: {:?})", timeout_duration);

        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            
            let mut sessions_to_remove = Vec::new();
            {
                let map = sessions_clone.lock().unwrap();
                for (id, session) in map.iter() {
                    let connections = *session.active_connections.lock().unwrap();
                    if connections == 0 {
                        let last = *session.last_output.lock().unwrap();
                        if last.elapsed() > timeout_duration {
                            info!("Session {} is idle (No connections, last output {:?} ago). Marking for removal.", id, last.elapsed());
                            sessions_to_remove.push(id.clone());
                        }
                    }
                }
            } // Drop lock before removing to avoid deadlocks if drop is complex
            
            if !sessions_to_remove.is_empty() {
                let mut map = sessions_clone.lock().unwrap();
                for id in sessions_to_remove {
                    if let Some(_session) = map.remove(&id) {
                         // Session dropped here, Drop impl will kill child
                         info!("Removed idle session: {}", id);
                    }
                }
            }
        }
    });

    // Define router
    let app = Router::new()
        .route("/terminal", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Bind address
    let port = std::env::var("WCODE_TERMINAL_PORT")
        .or_else(|_| std::env::var("PORT"))
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3001);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("listening on {}", addr);

    // Start server
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Server error: {}", e);
            }
        },
        Err(e) => {
            error!("Failed to bind address {}: {}", addr, e);
            std::process::exit(1);
        }
    }
}

/// WebSocket upgrade handler with token validation
async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<AuthParams>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if params.token != state.token {
        warn!("Invalid token attempt: {}", params.token);
        return "Unauthorized".into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, state.token.clone(), state.readonly, state.filter.clone(), params.session_id, state.sessions.clone()))
}

/// Client message types received from WebSocket
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum ClientMessage {
    /// Terminal input (keyboard/clipboard data)
    #[serde(rename = "input")]
    Input { data: String },
    /// Terminal resize request
    #[serde(rename = "resize")]
    Resize { cols: u16, rows: u16 },
}

/// Main WebSocket connection handler
async fn handle_socket(
    socket: WebSocket, 
    token: String, 
    readonly: bool, 
    filter: Arc<InputFilter>, 
    session_id: Option<String>,
    sessions: Arc<Mutex<HashMap<String, Arc<Session>>>>
) {
    info!("Client connected with valid token (readonly: {}, session_id: {:?})", readonly, session_id);

    // Derive AES Key from Token (SHA256)
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let key_bytes = hasher.finalize();
    let cipher = Aes256Gcm::new(&key_bytes);

    // Get or Create Session
    let session = {
        let mut map = sessions.lock().unwrap();
        let id = session_id.unwrap_or_else(|| {
             let rand_id: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
             format!("term_{}", rand_id)
        });

        if let Some(s) = map.get(&id) {
            info!("Reconnecting to existing session: {}", id);
            s.clone()
        } else {
            info!("Creating new session: {}", id);
            
            // Initialize PTY system
            let pty_system = native_pty_system();
            let pair = match pty_system.openpty(PtySize {
                rows: 24, cols: 80, pixel_width: 0, pixel_height: 0,
            }) {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to create PTY: {}", e);
                    return;
                }
            };

            let cmd = if cfg!(target_os = "windows") {
                let ps_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
                if Path::new(ps_path).exists() { CommandBuilder::new(ps_path) } else { CommandBuilder::new("cmd.exe") }
            } else {
                let shell = std::env::var("SHELL").unwrap_or("bash".into());
                CommandBuilder::new(shell)
            };

            let child = match pair.slave.spawn_command(cmd) {
                Ok(c) => c,
                Err(e) => { error!("Failed to spawn shell: {}", e); return; }
            };
            drop(pair.slave); // Close slave in parent

            let mut reader = match pair.master.try_clone_reader() {
                Ok(r) => r,
                Err(e) => { error!("Failed to clone reader: {}", e); return; }
            };
            let writer = match pair.master.take_writer() {
                Ok(w) => w,
                Err(e) => { error!("Failed to take writer: {}", e); return; }
            };

            // Broadcast channel (Capacity 128)
            let (tx, _) = tokio::sync::broadcast::channel(128);
            let history = Arc::new(Mutex::new(Vec::new()));
            let last_output = Arc::new(Mutex::new(Instant::now()));

            // PTY Reader Thread
            let tx_clone = tx.clone();
            let history_clone = history.clone();
            let last_output_clone = last_output.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            // Update last output time
                            *last_output_clone.lock().unwrap() = Instant::now();
                            
                            let data = buf[..n].to_vec();
                            // Append to history (Limit 100KB)
                            {
                                let mut h = history_clone.lock().unwrap();
                                h.extend_from_slice(&data);
                                // Simple retention policy: Keep last 100KB
                                if h.len() > 100 * 1024 {
                                    let split_idx = h.len() - 100 * 1024;
                                    *h = h.split_off(split_idx);
                                }
                            }
                            // Broadcast
                            if tx_clone.send(data).is_err() {
                                // No receivers is fine
                            }
                        }
                        Err(_) => break,
                    }
                }
                info!("PTY Reader thread exited");
            });

            let s = Arc::new(Session {
                master: Arc::new(Mutex::new(pair.master)),
                writer: Arc::new(Mutex::new(writer)),
                tx,
                history,
                _child: Arc::new(Mutex::new(child)),
                active_connections: Arc::new(Mutex::new(0)),
                last_output,
            });
            map.insert(id, s.clone());
            s
        }
    };

    // Increment active connections
    {
        let mut count = session.active_connections.lock().unwrap();
        *count += 1;
    }

    let (mut ws_sender, mut ws_receiver) = socket.split();
    
    // Subscribe to session output
    let mut rx = session.tx.subscribe();
    
    // Send History first
    {
        let history_data = session.history.lock().unwrap().clone();
        if !history_data.is_empty() {
             let nonce_bytes = rand::thread_rng().r#gen::<[u8; 12]>();
             let nonce = Nonce::from_slice(&nonce_bytes);
             if let Ok(ciphertext) = cipher.encrypt(nonce, history_data.as_ref()) {
                 let mut payload = Vec::with_capacity(12 + ciphertext.len());
                 payload.extend_from_slice(&nonce_bytes);
                 payload.extend_from_slice(&ciphertext);
                 if let Err(e) = ws_sender.send(Message::Binary(payload)).await {
                     error!("Failed to send history: {}", e);
                 }
             }
        }
    }

    // Forward PTY output to WebSocket (Encrypted)
    let cipher_send = cipher.clone();
    let send_task = tokio::spawn(async move {
        while let Ok(data) = rx.recv().await {
            // Encrypt data
            let nonce_bytes = rand::thread_rng().r#gen::<[u8; 12]>();
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            match cipher_send.encrypt(nonce, data.as_ref()) {
                Ok(ciphertext) => {
                    let mut payload = Vec::with_capacity(12 + ciphertext.len());
                    payload.extend_from_slice(&nonce_bytes);
                    payload.extend_from_slice(&ciphertext);
                    
                    if ws_sender.send(Message::Binary(payload)).await.is_err() {
                        break;
                    }
                },
                Err(e) => {
                    error!("Encryption error: {}", e);
                    break;
                }
            }
        }
    });

    // Handle incoming WebSocket messages (Encrypted)
    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Binary(payload)) => {
                if payload.len() < 12 {
                    error!("Invalid payload length");
                    continue;
                }
                
                let (nonce_bytes, ciphertext) = payload.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                
                match cipher.decrypt(nonce, ciphertext) {
                    Ok(plaintext) => {
                        if let Ok(text) = String::from_utf8(plaintext) {
                            if let Ok(cmd) = serde_json::from_str::<ClientMessage>(&text) {
                                match cmd {
                                    ClientMessage::Input { data } => {
                                        if readonly {
                                            warn!("Input blocked in read-only mode");
                                            continue;
                                        }

                                        if let Err(reason) = filter.check(&data) {
                                            warn!("Input blocked by security filter: {}", reason);
                                            let warning = format!("\r\n\x1b[31m[WCode Security] {}\x1b[0m\r\n", reason);
                                            // Write to session writer
                                            if let Ok(mut w) = session.writer.lock() {
                                                 let _ = w.write_all(warning.as_bytes());
                                            }
                                            continue;
                                        }

                                        if let Ok(mut w) = session.writer.lock() {
                                            if let Err(e) = w.write_all(data.as_bytes()) {
                                                error!("Failed to write to PTY: {}", e);
                                            }
                                        }
                                    },
                                    ClientMessage::Resize { cols, rows } => {
                                        if let Ok(m) = session.master.lock() {
                                            if let Err(e) = m.resize(PtySize {
                                                rows, cols, pixel_width: 0, pixel_height: 0,
                                            }) {
                                                error!("Failed to resize PTY: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => {
                         error!("Decryption error: {}", e);
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    info!("Client disconnected from session");
    send_task.abort();
    
    // Decrement active connections
    {
        let mut count = session.active_connections.lock().unwrap();
        if *count > 0 {
            *count -= 1;
        }
    }
    // Do NOT kill the child or remove session here. Persistence!
}
