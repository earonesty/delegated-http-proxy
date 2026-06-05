use std::{
    collections::{HashMap, HashSet},
    env,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use reqwest::{
    Client, Method, Proxy,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use url::Url;

const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 45_000;

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    cookie_jars: Arc<RwLock<HashMap<String, HashMap<String, String>>>>,
    proxy_pool: Arc<RwLock<Vec<String>>>,
}

#[derive(Clone)]
struct Config {
    bind: SocketAddr,
    bearer_token: String,
    allow_hosts: Option<HashSet<String>>,
    deny_private_ips: bool,
    allow_invalid_certs: bool,
    max_body_bytes: usize,
    default_timeout_ms: u64,
    proxy_pool_url: Option<String>,
    proxy_pool_token: Option<String>,
    proxy_pool_refresh_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct FetchRequest {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body_base64: Option<String>,
    #[serde(default)]
    body_text: Option<String>,
    #[serde(default)]
    cookie_jar: Option<String>,
    #[serde(default)]
    proxy: ProxySelection,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    follow_redirects: Option<bool>,
    #[serde(default)]
    danger_accept_invalid_certs: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProxySelection {
    #[default]
    Direct,
    Url(String),
    Random,
    Offset(usize),
}

#[derive(Debug, Serialize)]
struct FetchResponse {
    status: u16,
    final_url: String,
    headers: HashMap<String, String>,
    set_cookies: Vec<String>,
    body_base64: String,
    elapsed_ms: u128,
    proxy_used: Option<String>,
    body_sha256: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

fn default_method() -> String {
    "GET".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Arc::new(Config::from_env()?);
    let state = AppState {
        config: Arc::clone(&config),
        cookie_jars: Arc::new(RwLock::new(HashMap::new())),
        proxy_pool: Arc::new(RwLock::new(
            load_proxy_pool(&config).await.unwrap_or_default(),
        )),
    };

    if config.proxy_pool_url.is_some() && config.proxy_pool_refresh_seconds > 0 {
        spawn_proxy_pool_refresh(state.clone());
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/fetch", post(fetch_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    info!("listening on {}", config.bind);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

impl Config {
    fn from_env() -> Result<Self> {
        let bind = env::var("BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .context("BIND must be host:port")?;
        let bearer_token =
            env::var("DELEGATED_HTTP_TOKEN").context("DELEGATED_HTTP_TOKEN is required")?;
        let allow_hosts = parse_host_set(env::var("ALLOW_HOSTS").ok());
        Ok(Self {
            bind,
            bearer_token,
            allow_hosts,
            deny_private_ips: parse_bool_env("DENY_PRIVATE_IPS", true),
            allow_invalid_certs: parse_bool_env("ALLOW_INVALID_CERTS", false),
            max_body_bytes: parse_usize_env("MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES),
            default_timeout_ms: parse_u64_env("DEFAULT_TIMEOUT_MS", DEFAULT_TIMEOUT_MS),
            proxy_pool_url: env::var("PROXY_POOL_URL").ok().filter(|s| !s.is_empty()),
            proxy_pool_token: env::var("PROXY_POOL_TOKEN").ok().filter(|s| !s.is_empty()),
            proxy_pool_refresh_seconds: parse_u64_env("PROXY_POOL_REFRESH_SECONDS", 300),
        })
    }
}

fn parse_host_set(raw: Option<String>) -> Option<HashSet<String>> {
    let set: HashSet<String> = raw?
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if set.is_empty() { None } else { Some(set) }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn fetch_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FetchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match authorize(&state.config, &headers).and_then(|_| validate_request(&state.config, &request))
    {
        Ok(()) => {}
        Err(err) => return error(StatusCode::FORBIDDEN, err),
    }

    match execute_fetch(state, request).await {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::to_value(response).unwrap_or_else(|_| serde_json::json!({}))),
        ),
        Err(err) => error(StatusCode::BAD_GATEWAY, err),
    }
}

fn error(status: StatusCode, err: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(
            serde_json::to_value(ErrorResponse {
                error: err.to_string(),
            })
            .unwrap(),
        ),
    )
}

fn authorize(config: &Config, headers: &HeaderMap) -> Result<()> {
    let Some(value) = headers.get("authorization").and_then(|h| h.to_str().ok()) else {
        return Err(anyhow!("missing authorization header"));
    };
    let expected = format!("Bearer {}", config.bearer_token);
    if value != expected {
        return Err(anyhow!("invalid authorization token"));
    }
    Ok(())
}

fn validate_request(config: &Config, request: &FetchRequest) -> Result<()> {
    let url = Url::parse(&request.url).context("url is invalid")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("only http and https URLs are allowed"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("url host is required"))?;
    if let Some(allow_hosts) = &config.allow_hosts {
        let host_lc = host.to_ascii_lowercase();
        if !allow_hosts.contains(&host_lc) {
            return Err(anyhow!("host is not in ALLOW_HOSTS"));
        }
    }
    if config.deny_private_ips {
        reject_private_host(host)?;
    }
    if request.body_base64.is_some() && request.body_text.is_some() {
        return Err(anyhow!("send only one of body_base64 or body_text"));
    }
    if request.danger_accept_invalid_certs.unwrap_or(false) && !config.allow_invalid_certs {
        return Err(anyhow!(
            "danger_accept_invalid_certs requires ALLOW_INVALID_CERTS=true"
        ));
    }
    Ok(())
}

fn reject_private_host(host: &str) -> Result<()> {
    let addrs = (host, 0)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve host {host}"))?;
    for addr in addrs {
        if is_private_ip(addr.ip()) {
            return Err(anyhow!(
                "private/link-local/loopback destination is blocked"
            ));
        }
    }
    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

async fn execute_fetch(state: AppState, request: FetchRequest) -> Result<FetchResponse> {
    let started = Instant::now();
    let method = Method::from_bytes(request.method.as_bytes()).context("invalid method")?;
    let timeout_ms = request
        .timeout_ms
        .unwrap_or(state.config.default_timeout_ms);
    let body = decode_body(&request)?;
    if body.len() > state.config.max_body_bytes {
        return Err(anyhow!("request body exceeds MAX_BODY_BYTES"));
    }

    let proxy_used = select_proxy(&state, &request.proxy).await?;
    let client = build_client(
        Duration::from_millis(timeout_ms),
        request.follow_redirects.unwrap_or(true),
        proxy_used.as_deref(),
        request.danger_accept_invalid_certs.unwrap_or(false),
    )?;

    let mut builder = client.request(method, &request.url);
    let mut header_map = reqwest::header::HeaderMap::new();
    for (name, value) in &request.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid header name: {name}"))?;
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("invalid header value for {name}"))?;
        header_map.insert(name, value);
    }
    if let Some(jar_name) = request.cookie_jar.as_deref() {
        if let Some(cookie_header) = cookie_header_for_jar(&state, jar_name).await {
            header_map.insert(
                reqwest::header::COOKIE,
                HeaderValue::from_str(&cookie_header).context("cookie header invalid")?,
            );
        }
    }
    builder = builder.headers(header_map);
    if !body.is_empty() {
        builder = builder.body(body);
    }

    let response = builder.send().await.context("upstream request failed")?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = collect_headers(response.headers());
    let set_cookies = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    if let Some(jar_name) = request.cookie_jar.as_deref() {
        store_set_cookies(&state, jar_name, &set_cookies).await;
    }

    let bytes = response
        .bytes()
        .await
        .context("failed to read response body")?;
    if bytes.len() > state.config.max_body_bytes {
        return Err(anyhow!("response body exceeds MAX_BODY_BYTES"));
    }
    let body_sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(FetchResponse {
        status,
        final_url,
        headers,
        set_cookies,
        body_base64: B64.encode(bytes),
        elapsed_ms: started.elapsed().as_millis(),
        proxy_used,
        body_sha256,
    })
}

fn decode_body(request: &FetchRequest) -> Result<Vec<u8>> {
    if let Some(value) = &request.body_base64 {
        return B64.decode(value).context("body_base64 is invalid");
    }
    if let Some(value) = &request.body_text {
        return Ok(value.as_bytes().to_vec());
    }
    Ok(Vec::new())
}

fn build_client(
    timeout: Duration,
    follow_redirects: bool,
    proxy: Option<&str>,
    accept_invalid_certs: bool,
) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
        .danger_accept_invalid_certs(accept_invalid_certs)
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        });
    if let Some(proxy_url) = proxy {
        builder = builder.proxy(Proxy::all(proxy_url).context("invalid proxy URL")?);
    }
    builder.build().context("failed to build reqwest client")
}

fn collect_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            out.insert(name.as_str().to_string(), value.to_string());
        }
    }
    out
}

async fn cookie_header_for_jar(state: &AppState, jar_name: &str) -> Option<String> {
    let jars = state.cookie_jars.read().await;
    let jar = jars.get(jar_name)?;
    if jar.is_empty() {
        return None;
    }
    Some(
        jar.iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

async fn store_set_cookies(state: &AppState, jar_name: &str, set_cookies: &[String]) {
    if set_cookies.is_empty() {
        return;
    }
    let mut jars = state.cookie_jars.write().await;
    let jar = jars.entry(jar_name.to_string()).or_default();
    for raw in set_cookies {
        match cookie::Cookie::parse(raw.as_str()) {
            Ok(cookie) => {
                jar.insert(cookie.name().to_string(), cookie.value().to_string());
            }
            Err(err) => warn!("failed to parse set-cookie header: {err}"),
        }
    }
}

async fn select_proxy(state: &AppState, selection: &ProxySelection) -> Result<Option<String>> {
    let pool = state.proxy_pool.read().await;
    match selection {
        ProxySelection::Direct => Ok(None),
        ProxySelection::Url(url) => Ok(Some(url.clone())),
        ProxySelection::Random => {
            if pool.is_empty() {
                return Err(anyhow!("proxy pool is empty"));
            }
            let idx = pseudo_random_index(pool.len());
            Ok(pool.get(idx).cloned())
        }
        ProxySelection::Offset(idx) => pool
            .get(*idx)
            .cloned()
            .map(Some)
            .ok_or_else(|| anyhow!("proxy offset outside pool")),
    }
}

fn pseudo_random_index(len: usize) -> usize {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as usize)
        .unwrap_or(0);
    nanos % len
}

async fn load_proxy_pool(config: &Config) -> Result<Vec<String>> {
    let Some(url) = &config.proxy_pool_url else {
        return Ok(parse_proxy_env());
    };
    let mut builder = Client::builder().timeout(Duration::from_secs(30));
    builder = builder.user_agent("delegated-http-proxy/0.1");
    let client = builder.build()?;
    let mut request = client.get(url);
    if let Some(token) = &config.proxy_pool_token {
        request = request.bearer_auth(token);
    }
    let text = request.send().await?.error_for_status()?.text().await?;
    Ok(parse_proxy_text(&text))
}

fn parse_proxy_env() -> Vec<String> {
    env::var("PROXY_POOL")
        .ok()
        .map(|s| parse_proxy_text(&s))
        .unwrap_or_default()
}

fn parse_proxy_text(text: &str) -> Vec<String> {
    text.lines()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn spawn_proxy_pool_refresh(state: AppState) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(state.config.proxy_pool_refresh_seconds);
        loop {
            tokio::time::sleep(interval).await;
            match load_proxy_pool(&state.config).await {
                Ok(pool) => {
                    info!("refreshed proxy pool: {} entries", pool.len());
                    *state.proxy_pool.write().await = pool;
                }
                Err(err) => warn!("failed to refresh proxy pool: {err}"),
            }
        }
    });
}
