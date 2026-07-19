//! Unit tests for the parent module.
//!
//! The tests live separately so production responsibilities remain quick to inspect.

use super::*;
use hudsucker::rustls::pki_types::{
    pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use hudsucker::rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn proxy_with_mapping(mapping: SecretMapping) -> CdmProxy {
    CdmProxy {
        mapping: Arc::new(RwLock::new(mapping)),
        domains: DomainPolicy::default(),
        on_block: None,
        debug: false,
        counters: Arc::new(ProxyCounters::default()),
    }
}

#[test]
fn test_deobfuscate_bytes_utf8() {
    let mut mapping = SecretMapping::new();
    let fake = mapping
        .add_with_destinations("real_secret_value".to_string(), &["api.example.com"])
        .unwrap();

    let input = format!("Authorization: Bearer {}\r\n", fake);
    let result = deobfuscate_bytes(input.as_bytes(), &mapping, "api.example.com:443").unwrap();
    let result_str = String::from_utf8(result).unwrap();
    assert!(result_str.contains("real_secret_value"));
}

#[test]
fn test_deobfuscate_bytes_binary_passthrough() {
    let mapping = SecretMapping::new();
    let binary = vec![0xFF, 0xFE, 0x00, 0x01, 0x80];
    let result = deobfuscate_bytes(&binary, &mapping, "example.com").unwrap();
    assert_eq!(result, binary);
}

#[test]
fn attacker_and_cross_provider_destinations_never_receive_real_secrets() {
    let mut mapping = SecretMapping::new();
    let github_fake = mapping
        .add_with_destinations("github-real-secret".into(), &["github.com"])
        .unwrap();
    let openai_fake = mapping
        .add_with_destinations("openai-real-secret".into(), &["api.openai.com"])
        .unwrap();
    let payload = format!("{github_fake}:{openai_fake}");

    let attacker = deobfuscate_bytes(payload.as_bytes(), &mapping, "attacker.example").unwrap();
    assert_eq!(attacker, payload.as_bytes());
    let github = String::from_utf8(
        deobfuscate_bytes(payload.as_bytes(), &mapping, "api.github.com").unwrap(),
    )
    .unwrap();
    assert!(github.contains("github-real-secret"));
    assert!(github.contains(&openai_fake));
    assert!(!github.contains("openai-real-secret"));
}

#[test]
fn encoded_fake_values_are_not_decoded_or_restored() {
    let mut mapping = SecretMapping::new();
    let fake = mapping
        .add_with_destinations("provider-real-secret".into(), &["api.example.com"])
        .unwrap();
    let encoded = fake
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let result = deobfuscate_bytes(encoded.as_bytes(), &mapping, "api.example.com").unwrap();
    assert_eq!(result, encoded.as_bytes());
    assert!(!String::from_utf8(result)
        .unwrap()
        .contains("provider-real-secret"));
}

#[tokio::test]
async fn upstream_echoes_are_reobfuscated_before_reaching_the_child() {
    let mut mapping = SecretMapping::new();
    let fake = mapping
        .add_with_destinations("real-echo-secret".into(), &["api.example.com"])
        .unwrap();
    let proxy = proxy_with_mapping(mapping);
    let response = Response::builder()
        .header("x-echo", "real-echo-secret")
        .body(Body::from("prefix real-echo-secret suffix"))
        .unwrap();

    let mapping = proxy.mapping.read().unwrap().clone();
    let response = rewrite_response(response, &mapping, &proxy.counters, false).await;
    assert_eq!(response.headers()["x-echo"], fake);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!body
        .windows("real-echo-secret".len())
        .any(|window| window == b"real-echo-secret"));
    assert!(body
        .windows(fake.len())
        .any(|window| window == fake.as_bytes()));
    let stats = proxy.counters.snapshot();
    assert_eq!(stats.bytes_from_upstream, 30);
    assert_eq!(stats.bytes_to_child, 30);
}

#[tokio::test]
async fn compressed_upstream_responses_fail_closed_while_secrets_are_active() {
    let mut mapping = SecretMapping::new();
    mapping
        .add_with_destinations("real-compressed-secret".into(), &["api.example.com"])
        .unwrap();
    let counters = ProxyCounters::default();
    let response = Response::builder()
        .header(hudsucker::hyper::header::CONTENT_ENCODING, "gzip")
        .body(Body::from([0x1f, 0x8b, 0x08, 0x00].as_slice()))
        .unwrap();
    let response = rewrite_response(response, &mapping, &counters, false).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(counters.snapshot().rejected_messages, 1);
    assert!(response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty());
}

#[test]
fn request_compression_is_disabled_while_response_scrubbing_is_required() {
    let mut mapping = SecretMapping::new();
    mapping.add("known-real-secret".into()).unwrap();
    let mut headers = hudsucker::hyper::HeaderMap::new();
    headers.insert(
        hudsucker::hyper::header::ACCEPT_ENCODING,
        hudsucker::hyper::header::HeaderValue::from_static("gzip, br"),
    );
    force_identity_encoding(&mut headers, &mapping);
    assert_eq!(
        headers[hudsucker::hyper::header::ACCEPT_ENCODING],
        "identity"
    );
}

#[test]
fn websocket_upgrades_fail_closed_even_without_secret_mappings() {
    let mapping = SecretMapping::new();
    let runtime = std::env::temp_dir().join(format!("cdm-proxy-websocket-{}", std::process::id()));
    std::fs::create_dir(&runtime).unwrap();
    let mut session = ProxySession::start(ProxyOptions {
        preferred_port: 0,
        mapping,
        domains: DomainPolicy::default(),
        on_block: None,
        debug: false,
        runtime_dir: runtime.clone(),
    })
    .unwrap();
    let mut child = TcpStream::connect(("127.0.0.1", session.port())).unwrap();
    child
            .write_all(
                b"GET http://example.test/socket HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        child.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&response).contains(" 501 "));
    assert_eq!(session.stats().rejected_messages, 1);
    session.stop().unwrap();
    std::fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn upstream_tls_verification_failure_never_falls_back_to_a_tunnel() {
    let _ = aws_lc_rs::default_provider().install_default();

    // The upstream deliberately uses a self-signed certificate that the
    // proxy must reject. If hudsucker ever fell back to a raw CONNECT
    // tunnel, this marker response would reach the child instead.
    let upstream_key = KeyPair::generate().unwrap();
    let upstream_cert = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&upstream_key)
        .unwrap();
    let upstream_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![upstream_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(upstream_key.serialize_der())),
        )
        .unwrap();
    let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_thread = std::thread::spawn(move || {
        let (socket, _) = upstream.accept().unwrap();
        let connection =
            hudsucker::rustls::ServerConnection::new(Arc::new(upstream_config)).unwrap();
        let mut tls = hudsucker::rustls::StreamOwned::new(connection, socket);
        let mut request = [0_u8; 1024];
        if tls.read(&mut request).is_ok() {
            let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nUPSTREAM_TUNNEL_LEAK",
                );
        }
    });

    let runtime = std::env::temp_dir().join(format!(
        "cdm-proxy-tls-failclosed-{}-{}",
        std::process::id(),
        upstream_port
    ));
    std::fs::create_dir(&runtime).unwrap();
    let mut mapping = SecretMapping::new();
    mapping.add("known-real-secret".into()).unwrap();
    let mut session = ProxySession::start(ProxyOptions {
        preferred_port: 0,
        mapping,
        domains: DomainPolicy::parse(Some("localhost"), None, true).unwrap(),
        on_block: None,
        debug: false,
        runtime_dir: runtime.clone(),
    })
    .unwrap();

    let mut socket = TcpStream::connect(("127.0.0.1", session.port())).unwrap();
    socket
            .write_all(
                format!(
                    "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
    let mut connect_response = Vec::new();
    let mut byte = [0_u8; 1];
    while !connect_response.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).unwrap();
        connect_response.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&connect_response).contains(" 200 "));

    let ca_pem = std::fs::read(session.ca_cert_path()).unwrap();
    let ca = CertificateDer::from_pem_slice(&ca_pem).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = hudsucker::rustls::StreamOwned::new(client, socket);
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: localhost:{upstream_port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.contains(" 502 "),
        "unexpected response: {response}"
    );
    assert!(!response.contains("UPSTREAM_TUNNEL_LEAK"));

    session.stop().unwrap();
    upstream_thread.join().unwrap();
    std::fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn unknown_connect_protocol_never_falls_back_to_an_opaque_tunnel() {
    let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let runtime = std::env::temp_dir().join(format!(
        "cdm-proxy-unknown-connect-{}-{}",
        std::process::id(),
        upstream_port
    ));
    std::fs::create_dir(&runtime).unwrap();
    let mut session = ProxySession::start(ProxyOptions {
        preferred_port: 0,
        mapping: SecretMapping::new(),
        domains: DomainPolicy::parse(Some("127.0.0.1"), None, true).unwrap(),
        on_block: None,
        debug: false,
        runtime_dir: runtime.clone(),
    })
    .unwrap();

    let mut child = TcpStream::connect(("127.0.0.1", session.port())).unwrap();
    child
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
    let mut connect_response = Vec::new();
    let mut byte = [0_u8; 1];
    while !connect_response.ends_with(b"\r\n\r\n") {
        child.read_exact(&mut byte).unwrap();
        connect_response.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&connect_response).contains(" 200 "));
    child.write_all(b"NOPE").unwrap();
    child
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    assert_eq!(child.read(&mut byte).unwrap(), 0);
    std::thread::sleep(std::time::Duration::from_millis(25));
    assert!(matches!(upstream.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));

    session.stop().unwrap();
    std::fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn localhost_http_deputy_is_blocked_before_upstream_connect() {
    let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let runtime = std::env::temp_dir().join(format!(
        "cdm-proxy-local-deputy-{}-{upstream_port}",
        std::process::id()
    ));
    std::fs::create_dir(&runtime).unwrap();
    let mut session = ProxySession::start(ProxyOptions {
        preferred_port: 0,
        mapping: SecretMapping::new(),
        domains: DomainPolicy::default(),
        on_block: None,
        debug: false,
        runtime_dir: runtime.clone(),
    })
    .unwrap();
    let mut child = TcpStream::connect(("127.0.0.1", session.port())).unwrap();
    child
            .write_all(
                format!(
                    "GET http://127.0.0.1:{upstream_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
    let mut response = Vec::new();
    child.read_to_end(&mut response).unwrap();
    assert!(String::from_utf8_lossy(&response).contains(" 403 "));
    assert!(
        matches!(upstream.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
        "blocked proxy request must not connect to the host-local service"
    );
    session.stop().unwrap();
    std::fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn every_dns_answer_is_rechecked_to_prevent_rebinding() {
    let policy = DomainPolicy::parse(Some("rebind.example"), None, false).unwrap();
    let first = filter_resolved_addresses(
        &policy,
        "rebind.example",
        [SocketAddr::from(([93, 184, 216, 34], 443))],
    );
    assert_eq!(first.len(), 1);
    let rebound = filter_resolved_addresses(
        &policy,
        "rebind.example",
        [SocketAddr::from(([127, 0, 0, 1], 443))],
    );
    assert!(rebound.is_empty());
}

#[test]
fn proxy_session_is_ready_and_joined_before_artifacts_are_removed() {
    let runtime = std::env::temp_dir().join(format!("cdm-proxy-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&runtime);
    std::fs::create_dir(&runtime).unwrap();
    let mut session = ProxySession::start(ProxyOptions {
        preferred_port: 0,
        mapping: SecretMapping::new(),
        domains: DomainPolicy::default(),
        on_block: None,
        debug: false,
        runtime_dir: runtime.clone(),
    })
    .unwrap();
    let cert = session.ca_cert_path().to_path_buf();
    assert_eq!(session.stats(), ProxyStats::default());
    assert!(cert.is_file());
    assert!(std::net::TcpStream::connect(("127.0.0.1", session.port())).is_ok());
    session.stop().unwrap();
    assert!(!cert.exists());
    let _ = std::fs::remove_dir_all(runtime);
}
