use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use chrono::Utc;
use tokio::net::{UdpSocket, TcpStream};

/// The main structure for a WAF Log entry
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafLog {
    pub timestamp: String,
    pub correlation_id: String,
    pub client_info: ClientInfo,
    pub http_context: HttpContext,
    pub waf_details: WafDetails,
    pub performance: PerformanceInfo,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_payload: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientInfo {
    pub remote_ip: String,
    pub user_agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpContext {
    pub method: String,
    pub full_url: String,
    pub host: String,
    pub http_version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WafDetails {
    pub is_blocked: bool,
    pub matched_rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_match: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PerformanceInfo {
    pub latency_ms: u64,
}

impl WafLog {
    pub fn new(
        correlation_id: String,
        client_info: ClientInfo,
        http_context: HttpContext,
        waf_details: WafDetails,
        performance: PerformanceInfo,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            correlation_id,
            client_info,
            http_context,
            waf_details,
            performance,
            extra_headers: None,
            security_payload: None,
        }
    }

    pub fn mask_sensitive_data(&mut self) {
        let sensitive_keys = ["password", "token", "authorization", "cookie", "secret_key"];
        
        if let Some(headers) = &mut self.extra_headers {
            for (key, value) in headers.iter_mut() {
                if sensitive_keys.iter().any(|&sk| key.to_lowercase().contains(sk)) {
                    *value = "*** MASKED ***".to_string();
                }
            }
        }

        let url_lower = self.http_context.full_url.to_lowercase();
        if sensitive_keys.iter().any(|&sk| url_lower.contains(sk)) {
            self.http_context.full_url = "[URL CONTAINS MASKED DATA]".to_string();
        }
    }

    pub fn apply_sampling(&mut self) {
        let is_threat = self.waf_details.is_blocked || !self.waf_details.matched_rules.is_empty();
        
        if !is_threat {
            self.extra_headers = None;
            self.security_payload = None;
            self.waf_details.attack_type = None;
            self.waf_details.signature_match = None;
        }
    }
}

pub struct WafAsyncLogger {
    sender: mpsc::Sender<WafLog>,
}

impl WafAsyncLogger {
    /// Creates a new async logger, optionally syncing via TCP or UDP syslog, writing to local disk, and outputting to console.
    pub fn new(log_file_path: Option<&str>, syslog_url: Option<&str>, enable_console_log: bool, buffer_capacity: usize) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<WafLog>(buffer_capacity);
        let path_opt = log_file_path.map(|s| s.to_string());
        let syslog = syslog_url.map(|s| s.to_string());
        
        tokio::spawn(async move {
            let mut file = if let Some(path) = path_opt {
                match OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await 
                {
                    Ok(f) => Some(f),
                    Err(e) => {
                        tracing::error!("[WAF_LOGGER_FATAL] Cannot open log file {}: {}", path, e);
                        None 
                    }
                }
            } else {
                None
            };
            
            let mut tcp_stream = None;
            let mut udp_socket = None;
            let mut remote_addr = None;

            if let Some(url) = &syslog {
                if url.starts_with("tcp://") {
                    let addr = &url[6..];
                    match TcpStream::connect(addr).await {
                        Ok(s) => tcp_stream = Some(s),
                        Err(e) => tracing::warn!("[WAF_LOGGER_WARN] Failed to connect to TCP Syslog {}: {}", addr, e),
                    }
                } else if url.starts_with("udp://") {
                    let addr = &url[6..];
                    match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => {
                            udp_socket = Some(s);
                            remote_addr = Some(addr.to_string());
                        }
                        Err(e) => tracing::warn!("[WAF_LOGGER_WARN] Failed to bind UDP Syslog: {}", e),
                    }
                }
            }

            while let Some(mut waf_log) = rx.recv().await {
                waf_log.apply_sampling();
                waf_log.mask_sensitive_data();

                match serde_json::to_string(&waf_log) {
                    Ok(mut json_str) => {
                        // Console Write (Raw JSON directly to stdout)
                        if enable_console_log {
                            println!("{}", json_str);
                        }

                        json_str.push('\n'); 
                        let payload = json_str.as_bytes();

                        // Disk Write
                        if let Some(f) = &mut file {
                            if let Err(e) = f.write_all(payload).await {
                                tracing::error!("[WAF_LOGGER_ERROR] Disk write failed: {}", e);
                            }
                        }
                        
                        // Syslog Write
                        if tcp_stream.is_some() || udp_socket.is_some() {
                            let syslog_msg = format!("<134> WAF: {}", json_str);
                            let syslog_payload = syslog_msg.as_bytes();

                            if let Some(ref mut tcp) = tcp_stream {
                                if let Err(e) = tcp.write_all(syslog_payload).await {
                                    tracing::error!("[WAF_LOGGER_ERROR] TCP Syslog failed: {}", e);
                                }
                            } else if let Some(ref udp) = udp_socket {
                                if let Some(ref addr) = remote_addr {
                                    if let Err(e) = udp.send_to(syslog_payload, addr).await {
                                        tracing::error!("[WAF_LOGGER_ERROR] UDP Syslog failed: {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("[WAF_LOGGER_ERROR] Serialize failed: {}", e);
                    }
                }
            }
        });

        Arc::new(Self { sender: tx })
    }

    pub fn log_request(&self, log: WafLog) {
        if let Err(e) = self.sender.try_send(log) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!("[WAF_LOGGER_WARN] Buffer đầy, đang tiến hành drop WAF log do hệ thống quá tải IO.");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("[WAF_LOGGER_ERROR] Background worker đã ngừng hoạt động.");
                }
            }
        }
    }
}
