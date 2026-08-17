//! Followup-poll registration flow, over a real Noise-encrypted connection.
//!
//! Split into a sibling file because `wire_integration.rs` + this test
//! exceeded the `RUST/file-too-long` threshold.

use super::*;

/// WHY: `poll_registration` runs the same wire round-trip as
/// `register` and must validate its response through the same exhaustive
/// classifier -- an unvalidated followup response was the original defect's
/// second, untested entry point. This drives `register` to `NeedsAuth` and
/// then the followup to `Rejected`, over one real Noise-encrypted
/// connection, proving the rejection is not discarded on the polled path
/// either.
#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "integration tests use expect to keep fixture failures explicit"
)]
async fn poll_registration_validates_the_followup_response_into_an_outcome() {
    let (server_tls_cfg, client_tls_cfg) = make_test_tls_pair();
    let keys = Arc::new(MockServerKeys::generate());

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let acceptor = TlsAcceptor::from(Arc::new(server_tls_cfg));

    let keys_clone = Arc::clone(&keys);
    let server = tokio::spawn(async move {
        // Connection 1: key fetch.
        let (tcp1, _) = listener.accept().await.expect("accept key conn");
        let mut tls1 = acceptor.accept(tcp1).await.expect("tls accept key conn");
        handle_key_request(&mut tls1, &keys_clone).await;

        // Connection 2: Noise upgrade + register RPC + followup poll RPC.
        let (tcp2, _) = listener.accept().await.expect("accept noise conn");
        let mut tls2 = acceptor.accept(tcp2).await.expect("tls accept noise conn");
        let mut transport = handle_noise_upgrade(&mut tls2, &keys_clone).await;

        // First register request: respond NeedsAuth.
        let ciphertext = read_noise_frame(&mut tls2).await;
        let mut plaintext_buf = vec![0u8; ciphertext.len()];
        let pt_len = transport
            .read_message(&ciphertext, &mut plaintext_buf)
            .expect("decrypt register request");
        let json_payload = control_payload(&plaintext_buf[..pt_len], "register request");
        let req: serde_json::Value =
            serde_json::from_slice(json_payload).expect("register request should be valid JSON");
        assert!(
            req.get("Followup").is_none(),
            "initial register request should carry no Followup"
        );

        let needs_auth_json =
            br#"{"MachineAuthorized":false,"AuthURL":"https://login.tailscale.com/a/xyz"}"#;
        write_noise_frame(&mut tls2, &mut transport, needs_auth_json).await;
        tls2.flush().await.expect("flush after register response");

        // Followup poll request: respond Rejected.
        let ciphertext = read_noise_frame(&mut tls2).await;
        let mut plaintext_buf = vec![0u8; ciphertext.len()];
        let pt_len = transport
            .read_message(&ciphertext, &mut plaintext_buf)
            .expect("decrypt followup request");
        let json_payload = control_payload(&plaintext_buf[..pt_len], "followup request");
        let req: serde_json::Value =
            serde_json::from_slice(json_payload).expect("followup request should be valid JSON");
        assert_eq!(
            req.get("Followup").and_then(serde_json::Value::as_str),
            Some("https://login.tailscale.com/a/xyz"),
            "followup request should carry the NeedsAuth URL"
        );

        let rejected_json =
            br#"{"Error":"invalid auth key","MachineAuthorized":false,"AuthURL":""}"#;
        write_noise_frame(&mut tls2, &mut transport, rejected_json).await;
        tls2.flush().await.expect("flush after followup response");
    });

    let machine_key = MachinePrivate::generate();
    let node_key = mitos::keys::NodePrivate::generate();
    let disco_key = mitos::keys::DiscoPrivate::generate();

    let config = dictyon::wire::ControlConfig::new(
        format!("https://127.0.0.1:{}", addr.port()),
        MachinePrivate::from_bytes(*machine_key.as_bytes()),
    );

    let mut stream = dictyon::wire::connect_with_tls(&config, client_tls_cfg)
        .await
        .expect("connect should succeed");

    let (conn, ()) = make_dummy_transport();
    let mut client = dictyon::control::ControlClient::new(conn, machine_key, node_key, disco_key);

    let first = client
        .register(&mut stream, None)
        .await
        .expect("register should succeed");
    let dictyon::control::RegisterOutcome::NeedsAuth(url) = first else {
        panic!("expected NeedsAuth from the initial register");
    };
    assert_eq!(url.as_str(), "https://login.tailscale.com/a/xyz");

    let followup = client
        .poll_registration(&mut stream, url.as_str())
        .await
        .expect("poll_registration should succeed");
    match followup {
        dictyon::control::RegisterOutcome::Rejected { reason } => {
            assert_eq!(reason, "invalid auth key");
        }
        other => panic!("expected Rejected from the followup poll, got {other:?}"),
    }

    server.await.expect("mock server should not panic");
}
