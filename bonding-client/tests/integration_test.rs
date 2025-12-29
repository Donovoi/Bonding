use anyhow::Result;
use base64::Engine;
use bonding_client::runtime::run_client;
use bonding_core::control::{BondingConfig, ServerConfig};
use bonding_core::transport::PacketCrypto;
use bonding_server::runtime::run_server;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

#[tokio::test]
async fn test_client_server_handshake_no_tun() -> Result<()> {
    // This test verifies that the client can connect to the server,
    // perform the encryption handshake (if enabled), and exchange keepalives.
    // It runs with enable_tun = false to avoid needing admin privileges/drivers.

    // 1. Setup shared encryption key
    let key = PacketCrypto::generate_key();
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);

    // 2. Configure Server
    // Use a fixed port or simple random logic since fastrand isn't a direct dependency
    let server_port = 50000 + (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() as u16 % 1000);
    let server_config = ServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: server_port,
        enable_encryption: true,
        encryption_key_b64: Some(key_b64.clone()),
        enable_tun: false, // Important: No TUN for this test
        ..Default::default()
    };

    // 3. Configure Client
    let client_config = BondingConfig {
        server_addr: "127.0.0.1".to_string(),
        server_port,
        enable_encryption: true,
        encryption_key_b64: Some(key_b64),
        enable_tun: false, // Important: No TUN for this test
        ..Default::default()
    };

    // 4. Start Server
    let (server_stop_tx, server_stop_rx) = watch::channel(false);
    let server_log = Arc::new(Mutex::new(Vec::new()));
    let server_log_clone = server_log.clone();

    let server_handle = tokio::spawn(async move {
        run_server(
            server_config,
            server_stop_rx,
            Box::new(move |msg| {
                println!("[SERVER] {}", msg);
                server_log_clone.lock().unwrap().push(msg);
            }),
        )
        .await
    });

    // Give server a moment to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. Start Client
    let (client_stop_tx, client_stop_rx) = watch::channel(false);
    let client_log = Arc::new(Mutex::new(Vec::new()));
    let client_log_clone = client_log.clone();

    let client_handle = tokio::spawn(async move {
        run_client(
            client_config,
            client_stop_rx,
            Box::new(move |msg| {
                println!("[CLIENT] {}", msg);
                client_log_clone.lock().unwrap().push(msg);
            }),
        )
        .await
    });

    // 6. Wait for interaction
    // We expect the client to send a keepalive/hello and the server to receive it.
    // Since we are not in TUN mode, the "handshake" is just the first packet exchange.
    // The logs should show "Recv pkt" on both sides.

    let start = std::time::Instant::now();
    let mut success = false;

    while start.elapsed() < Duration::from_secs(5) {
        let server_msgs = server_log.lock().unwrap().clone();
        let client_msgs = client_log.lock().unwrap().clone();

        let server_received = server_msgs.iter().any(|m| m.contains("Recv pkt"));
        // Client might not receive anything back in non-TUN mode if the server logic
        // for non-TUN doesn't echo keepalives explicitly, but let's check.
        // In non-TUN mode, the server code (runtime.rs) does:
        // "Recv pkt ... bonding-server:ack" -> sends back.
        // So client should receive something.
        let client_received = client_msgs.iter().any(|m| m.contains("Recv pkt"));

        if server_received && client_received {
            success = true;
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 7. Cleanup
    let _ = server_stop_tx.send(true);
    let _ = client_stop_tx.send(true);

    let _ = server_handle.await;
    let _ = client_handle.await;

    if !success {
        println!("Server Logs:");
        for msg in server_log.lock().unwrap().iter() {
            println!("  {}", msg);
        }
        println!("Client Logs:");
        for msg in client_log.lock().unwrap().iter() {
            println!("  {}", msg);
        }
        anyhow::bail!("Test failed: Client and Server did not exchange packets successfully");
    }

    Ok(())
}
