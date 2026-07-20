//! HTTP/HTTPS egress proxy with secret deobfuscation and domain filtering.
//!
//! Runs on the host, outside the sandbox. Intercepts outbound traffic and
//! swaps fake secrets back to real values.
//!
//! Built on hudsucker for MITM TLS interception with an ephemeral CA.

use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use http_body_util::{BodyExt, LengthLimitError, Limited};
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::rcgen::{CertificateParams, Issuer, KeyPair};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use tokio::net::TcpListener;
use tower_service::Service;

use crate::network::DomainPolicy;
use crate::secrets::SecretMapping;

pub type BlockCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;

const MAX_REWRITTEN_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyStats {
    pub requests_allowed: u64,
    pub requests_blocked: u64,
    pub substitutions: u64,
    pub bytes_from_child: u64,
    pub bytes_to_upstream: u64,
    pub bytes_from_upstream: u64,
    pub bytes_to_child: u64,
    pub rejected_messages: u64,
}

#[derive(Default)]
struct ProxyCounters {
    requests_allowed: AtomicU64,
    requests_blocked: AtomicU64,
    substitutions: AtomicU64,
    bytes_from_child: AtomicU64,
    bytes_to_upstream: AtomicU64,
    bytes_from_upstream: AtomicU64,
    bytes_to_child: AtomicU64,
    rejected_messages: AtomicU64,
}

impl ProxyCounters {
    fn snapshot(&self) -> ProxyStats {
        ProxyStats {
            requests_allowed: self.requests_allowed.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            substitutions: self.substitutions.load(Ordering::Relaxed),
            bytes_from_child: self.bytes_from_child.load(Ordering::Relaxed),
            bytes_to_upstream: self.bytes_to_upstream.load(Ordering::Relaxed),
            bytes_from_upstream: self.bytes_from_upstream.load(Ordering::Relaxed),
            bytes_to_child: self.bytes_to_child.load(Ordering::Relaxed),
            rejected_messages: self.rejected_messages.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// HttpHandler implementation
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CdmProxy {
    pub mapping: Arc<RwLock<SecretMapping>>,
    pub domains: DomainPolicy,
    pub on_block: Option<BlockCallback>,
    pub debug: bool,
    counters: Arc<ProxyCounters>,
}

impl HttpHandler for CdmProxy {
    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, _req: &Request<Body>) -> bool {
        // Hudsucker's opaque CONNECT path performs its own DNS resolution and
        // raw TCP connect, bypassing CDM's address-filtering connector. Always
        // keep CONNECT inside the inspected path so every upstream connection
        // uses PolicyResolver and its per-resolution address checks.
        true
    }

    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        _client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        true
    }

    async fn should_tunnel_unknown_connect(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> bool {
        // Unknown opaque protocols would bypass the HTTP connector and cannot
        // be made safe against DNS rebinding or host-service deputy attacks.
        false
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // Domain filtering
        let authority = req
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_string())
            .or_else(|| {
                req.headers()
                    .get(hudsucker::hyper::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_default();

        let blocked = self.domains.is_blocked(&authority);
        if blocked.as_ref().is_err() || blocked == Ok(true) {
            self.counters
                .requests_blocked
                .fetch_add(1, Ordering::Relaxed);
            let reason = if blocked.is_err() {
                "invalid destination authority"
            } else if self.domains.has_allowlist() {
                "not in allow list"
            } else {
                "in deny list"
            };
            if let Some(ref cb) = self.on_block {
                cb(&authority, reason);
            }
            if self.debug {
                eprintln!("[cdm-proxy] BLOCKED {}: {}", authority, reason);
            }
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .unwrap()
                .into();
        }
        self.counters
            .requests_allowed
            .fetch_add(1, Ordering::Relaxed);

        // Snapshot the mapping so we don't hold the lock during body collection.
        let mapping = self.mapping.read().unwrap().clone();

        // Hudsucker's WebSocket path has its own connector, so it bypasses both
        // CDM's per-resolution private-address checks and bidirectional secret
        // scrubbing. Reject every upgrade until that path is policy-aware.
        if is_websocket_upgrade(req.headers()) {
            self.counters
                .rejected_messages
                .fetch_add(1, Ordering::Relaxed);
            return proxy_error(
                StatusCode::NOT_IMPLEMENTED,
                self.debug,
                "WebSocket upgrades are not supported by the policy-aware proxy",
            )
            .into();
        }

        let (mut parts, body) = req.into_parts();

        if let Some(path_and_query) = parts.uri.path_and_query() {
            let original = path_and_query.as_str();
            let rewritten = match mapping.deobfuscate_for_authority(original, &authority) {
                Ok(value) => value,
                Err(error) => {
                    return proxy_error(StatusCode::BAD_REQUEST, self.debug, &error).into();
                }
            };
            if rewritten != original {
                let mut uri_parts = parts.uri.clone().into_parts();
                uri_parts.path_and_query = match rewritten.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        return proxy_error(
                            StatusCode::BAD_REQUEST,
                            self.debug,
                            "rewritten request target is invalid",
                        )
                        .into();
                    }
                };
                parts.uri = match hudsucker::hyper::Uri::from_parts(uri_parts) {
                    Ok(uri) => uri,
                    Err(_) => {
                        return proxy_error(
                            StatusCode::BAD_REQUEST,
                            self.debug,
                            "rewritten request URI is invalid",
                        )
                        .into();
                    }
                };
                self.counters.substitutions.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Deobfuscate header values that might contain secrets
        for value in parts.headers.values_mut() {
            let original = value.as_bytes();
            let deob = match mapping.deobfuscate_bytes_for_authority(original, &authority) {
                Ok(value) => value,
                Err(error) => {
                    return proxy_error(StatusCode::BAD_REQUEST, self.debug, &error).into();
                }
            };
            if deob != original {
                match hudsucker::hyper::header::HeaderValue::from_bytes(&deob) {
                    Ok(new_value) => {
                        *value = new_value;
                        self.counters.substitutions.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        return proxy_error(
                            StatusCode::BAD_REQUEST,
                            self.debug,
                            "rewritten request header is invalid",
                        )
                        .into();
                    }
                }
            }
        }
        force_identity_encoding(&mut parts.headers, &mapping);

        // Deobfuscate body
        let body_bytes = match Limited::new(body, MAX_REWRITTEN_BODY_BYTES).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                self.counters
                    .rejected_messages
                    .fetch_add(1, Ordering::Relaxed);
                let status = if error.downcast_ref::<LengthLimitError>().is_some() {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                if self.debug {
                    eprintln!("[cdm-proxy] request body rejected: {error}");
                }
                return Response::builder()
                    .status(status)
                    .body(Body::empty())
                    .expect("static proxy error response")
                    .into();
            }
        };
        let deobfuscated = match deobfuscate_bytes(&body_bytes, &mapping, &authority) {
            Ok(value) => value,
            Err(error) => return proxy_error(StatusCode::BAD_REQUEST, self.debug, &error).into(),
        };
        self.counters
            .bytes_from_child
            .fetch_add(body_bytes.len() as u64, Ordering::Relaxed);
        self.counters
            .bytes_to_upstream
            .fetch_add(deobfuscated.len() as u64, Ordering::Relaxed);
        if deobfuscated != body_bytes {
            self.counters.substitutions.fetch_add(1, Ordering::Relaxed);
        }

        // Update content-length if body changed
        if deobfuscated.len() != body_bytes.len() {
            parts
                .headers
                .remove(hudsucker::hyper::header::TRANSFER_ENCODING);
            parts.headers.insert(
                hudsucker::hyper::header::CONTENT_LENGTH,
                deobfuscated.len().to_string().parse().unwrap(),
            );
        }

        if self.debug {
            let replaced = deobfuscated[..] != body_bytes[..];
            eprintln!(
                "[cdm-proxy] {} {} ({} bytes, deob={}, mappings={})",
                parts.method,
                authority,
                deobfuscated.len(),
                replaced,
                mapping.fake_to_real.len(),
            );
        }

        let new_body = Body::from(deobfuscated);
        Request::from_parts(parts, new_body).into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let mapping = self.mapping.read().unwrap().clone();
        rewrite_response(res, &mapping, &self.counters, self.debug).await
    }
}

fn is_websocket_upgrade(headers: &hudsucker::hyper::HeaderMap) -> bool {
    let websocket = headers
        .get(hudsucker::hyper::header::UPGRADE)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let connection_upgrade = headers
        .get_all(hudsucker::hyper::header::CONNECTION)
        .iter()
        .any(|value| {
            value
                .as_bytes()
                .split(|byte| *byte == b',')
                .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"))
        });
    websocket && connection_upgrade
}

async fn rewrite_response(
    res: Response<Body>,
    mapping: &SecretMapping,
    counters: &ProxyCounters,
    debug: bool,
) -> Response<Body> {
    let (mut parts, body) = res.into_parts();
    if !mapping.fake_to_real.is_empty()
        && parts
            .headers
            .get(hudsucker::hyper::header::CONTENT_ENCODING)
            .is_some_and(|value| {
                !value
                    .to_str()
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
            })
    {
        counters.rejected_messages.fetch_add(1, Ordering::Relaxed);
        return proxy_error(
            StatusCode::BAD_GATEWAY,
            debug,
            "encoded upstream response rejected while secret scrubbing is active",
        );
    }
    for value in parts.headers.values_mut() {
        let original = value.as_bytes();
        let obfuscated = mapping.scrub_response_bytes(original);
        if obfuscated != original {
            match hudsucker::hyper::header::HeaderValue::from_bytes(&obfuscated) {
                Ok(new_value) => {
                    *value = new_value;
                    counters.substitutions.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    return proxy_error(
                        StatusCode::BAD_GATEWAY,
                        debug,
                        "obfuscated response header is invalid",
                    );
                }
            }
        }
    }
    let body_bytes = match Limited::new(body, MAX_REWRITTEN_BODY_BYTES).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_error) => {
            counters.rejected_messages.fetch_add(1, Ordering::Relaxed);
            return proxy_error(
                StatusCode::BAD_GATEWAY,
                debug,
                "upstream response body rejected",
            );
        }
    };
    let obfuscated = mapping.scrub_response_bytes(&body_bytes);
    counters
        .bytes_from_upstream
        .fetch_add(body_bytes.len() as u64, Ordering::Relaxed);
    counters
        .bytes_to_child
        .fetch_add(obfuscated.len() as u64, Ordering::Relaxed);
    if obfuscated != body_bytes {
        counters.substitutions.fetch_add(1, Ordering::Relaxed);
    }
    if obfuscated.len() != body_bytes.len() {
        parts
            .headers
            .remove(hudsucker::hyper::header::TRANSFER_ENCODING);
        parts.headers.insert(
            hudsucker::hyper::header::CONTENT_LENGTH,
            obfuscated.len().to_string().parse().unwrap(),
        );
    }
    Response::from_parts(parts, Body::from(obfuscated))
}

fn proxy_error(status: StatusCode, debug: bool, message: &str) -> Response<Body> {
    if debug {
        eprintln!("[cdm-proxy] message rejected: {message}");
    }
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static proxy error response")
}

fn force_identity_encoding(headers: &mut hudsucker::hyper::HeaderMap, mapping: &SecretMapping) {
    if !mapping.fake_to_real.is_empty() {
        headers.insert(
            hudsucker::hyper::header::ACCEPT_ENCODING,
            hudsucker::hyper::header::HeaderValue::from_static("identity"),
        );
    }
}

// ---------------------------------------------------------------------------
// CA generation
// ---------------------------------------------------------------------------

/// Generates an ephemeral CA for MITM proxy and returns the authority
/// plus the PEM-encoded CA certificate string (cert + key).
pub fn generate_ca() -> io::Result<(RcgenAuthority, String)> {
    let key_pair = KeyPair::generate().map_err(|e| io::Error::other(format!("CA key gen: {e}")))?;

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = hudsucker::rcgen::IsCa::Ca(hudsucker::rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(hudsucker::rcgen::DnType::CommonName, "CDM Proxy CA");
    ca_params
        .distinguished_name
        .push(hudsucker::rcgen::DnType::OrganizationName, "CDM");

    let ca_cert = ca_params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::other(format!("CA self-sign: {e}")))?;

    let ca_cert_pem = ca_cert.pem();
    let key_pem = key_pair.serialize_pem();

    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)
        .map_err(|e| io::Error::other(format!("CA issuer: {e}")))?;

    let authority = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());

    Ok((authority, format!("{}\n{}", ca_cert_pem, key_pem)))
}

/// Returns just the certificate portion of a CA PEM string (strips the key).
pub fn ca_cert_pem_only(full_pem: &str) -> String {
    // Extract everything from the first -----BEGIN CERTIFICATE----- to
    // the first -----END CERTIFICATE-----  (inclusive).
    if let Some(start) = full_pem.find("-----BEGIN CERTIFICATE-----") {
        if let Some(end_marker_start) = full_pem.find("-----END CERTIFICATE-----") {
            let end = end_marker_start + "-----END CERTIFICATE-----".len();
            return full_pem[start..end].to_string();
        }
    }
    full_pem.to_string()
}

// ---------------------------------------------------------------------------
// Proxy start
// ---------------------------------------------------------------------------

/// Starts the hudsucker proxy on the given port.
///
/// Returns the actual port the proxy bound to.  The proxy runs until
/// `shutdown` fires.
pub struct ProxyOptions {
    pub preferred_port: u16,
    pub mapping: SecretMapping,
    pub domains: DomainPolicy,
    pub on_block: Option<BlockCallback>,
    pub debug: bool,
    pub runtime_dir: PathBuf,
}

#[derive(Clone)]
struct PolicyResolver {
    domains: DomainPolicy,
}

impl Service<hudsucker::hyper_util::client::legacy::connect::dns::Name> for PolicyResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        name: hudsucker::hyper_util::client::legacy::connect::dns::Name,
    ) -> Self::Future {
        let domains = self.domains.clone();
        let hostname = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((hostname.as_str(), 0)).await?;
            let allowed = filter_resolved_addresses(&domains, &hostname, addresses);
            if allowed.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destination resolved only to private or non-routable addresses",
                ));
            }
            Ok(allowed.into_iter())
        })
    }
}

fn filter_resolved_addresses(
    domains: &DomainPolicy,
    hostname: &str,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .filter(|address| domains.allows_resolved_ip(hostname, address.ip()))
        .collect()
}

fn policy_connector(
    domains: DomainPolicy,
) -> io::Result<impl hudsucker::hyper_util::client::legacy::connect::Connect + Clone> {
    use hyper_rustls::ConfigBuilderExt;
    let rustls_config = hudsucker::rustls::ClientConfig::builder_with_provider(Arc::new(
        aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| io::Error::other(format!("TLS protocol configuration: {error}")))?
    .with_webpki_roots()
    .with_no_client_auth();
    let mut http = hudsucker::hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(
        PolicyResolver { domains },
    );
    http.enforce_http(false);
    Ok(hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(rustls_config)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http))
}

pub struct ProxySession {
    port: u16,
    artifact_dir: PathBuf,
    ca_cert_path: PathBuf,
    ca_bundle_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<io::Result<()>>>,
    counters: Arc<ProxyCounters>,
}

impl ProxySession {
    pub fn start(options: ProxyOptions) -> io::Result<Self> {
        let (ca, ca_pem) = generate_ca()?;
        let ca_cert = ca_cert_pem_only(&ca_pem);
        let artifact_dir = create_artifact_dir(&options.runtime_dir)?;
        let artifact_cleanup = ArtifactCleanup(Some(artifact_dir.clone()));
        let cert_path = artifact_dir.join("ca.pem");
        let bundle_path = artifact_dir.join("ca-bundle.pem");
        (|| {
            std::fs::write(&cert_path, &ca_cert)?;
            std::fs::write(&bundle_path, create_ca_bundle(&ca_cert)?)?;
            Ok::<_, io::Error>(())
        })()?;

        let address = SocketAddr::from(([127, 0, 0, 1], options.preferred_port));
        let listener = match StdTcpListener::bind(address) {
            Ok(listener) => listener,
            Err(error)
                if error.kind() == io::ErrorKind::AddrInUse && options.preferred_port != 0 =>
            {
                StdTcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?
            }
            Err(error) => return Err(error),
        };
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let counters = Arc::new(ProxyCounters::default());
        let connector = policy_connector(options.domains.clone())?;
        let handler = CdmProxy {
            mapping: Arc::new(RwLock::new(options.mapping)),
            domains: options.domains,
            on_block: options.on_block,
            debug: options.debug,
            counters: Arc::clone(&counters),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("cdm-proxy".into())
            .spawn(move || {
                let runtime = tokio::runtime::Runtime::new()
                    .map_err(|error| io::Error::other(format!("proxy runtime: {error}")))?;
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener)?;
                    let proxy = Proxy::builder()
                        .with_listener(listener)
                        .with_ca(ca)
                        .with_http_connector(connector)
                        .with_http_handler(handler)
                        .with_graceful_shutdown(async move {
                            let _ = shutdown_rx.await;
                        })
                        .build()
                        .map_err(|error| io::Error::other(format!("proxy build: {error}")))?;
                    let _ = ready_tx.send(());
                    eprintln!("[cdm-proxy] listening on :{port}");
                    proxy
                        .start()
                        .await
                        .map_err(|error| io::Error::other(format!("proxy: {error}")))
                })
            })?;
        if ready_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_err()
        {
            let _ = shutdown_tx.send(());
            let _ = thread.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy did not become ready",
            ));
        }
        let artifact_dir = artifact_cleanup.disarm();
        Ok(Self {
            port,
            artifact_dir,
            ca_cert_path: cert_path,
            ca_bundle_path: bundle_path,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            counters,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn ca_cert_path(&self) -> &Path {
        &self.ca_cert_path
    }
    pub fn ca_bundle_path(&self) -> &Path {
        &self.ca_bundle_path
    }

    pub fn stats(&self) -> ProxyStats {
        self.counters.snapshot()
    }

    pub fn stop(&mut self) -> io::Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let result = if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| io::Error::other("proxy thread panicked"))
                .and_then(|result| result)
        } else {
            Ok(())
        };
        let cleanup = std::fs::remove_dir_all(&self.artifact_dir);
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(thread), Err(cleanup)) => Err(io::Error::new(
                thread.kind(),
                format!("{thread}; proxy artifact cleanup also failed: {cleanup}"),
            )),
        }
    }
}

struct ArtifactCleanup(Option<PathBuf>);

impl ArtifactCleanup {
    fn disarm(mut self) -> PathBuf {
        self.0.take().expect("artifact cleanup must own a path")
    }
}

impl Drop for ArtifactCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

impl Drop for ProxySession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn create_artifact_dir(runtime_dir: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = runtime_dir.join(format!("proxy-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// CA bundle creation (moved from tls.rs)
// ---------------------------------------------------------------------------

/// Creates a combined CA bundle (system CAs + CDM CA) for tools that use
/// SSL_CERT_FILE.  On macOS, exports system root certificates from the
/// Keychain; on Linux, reads the standard CA bundle path.
#[cfg(target_os = "macos")]
pub fn create_ca_bundle(ca_pem: &str) -> io::Result<String> {
    let security =
        crate::trusted_exec::fixed(Path::new("/usr/bin/security"), "macOS security tool")?;
    let mut command = security.command()?;
    crate::trusted_exec::sanitize_host_environment(&mut command);
    let output = command
        .args([
            "find-certificate",
            "-a",
            "-p",
            "/System/Library/Keychains/SystemRootCertificates.keychain",
        ])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(
            "failed to export system CAs from Keychain",
        ));
    }

    let mut bundle = String::from_utf8_lossy(&output.stdout).to_string();
    bundle.push('\n');
    bundle.push_str(ca_pem);
    Ok(bundle)
}

#[cfg(target_os = "linux")]
pub fn create_ca_bundle(ca_pem: &str) -> io::Result<String> {
    let candidates = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    ];

    for path in &candidates {
        if let Ok(system_certs) = std::fs::read_to_string(path) {
            let mut bundle = system_certs;
            bundle.push('\n');
            bundle.push_str(ca_pem);
            return Ok(bundle);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no system CA bundle found",
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn create_ca_bundle(ca_pem: &str) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "CA bundle creation not supported on this platform",
    ))
}

// ---------------------------------------------------------------------------
// Domain filtering helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Byte-level deobfuscation
// ---------------------------------------------------------------------------

/// Deobfuscates a byte chunk by replacing fake secrets with real values.
/// Only processes valid UTF-8 chunks (HTTP headers are always ASCII).
/// Binary data passes through unchanged.
pub fn deobfuscate_bytes(
    data: &[u8],
    mapping: &SecretMapping,
    authority: &str,
) -> Result<Vec<u8>, String> {
    mapping.deobfuscate_bytes_for_authority(data, authority)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
