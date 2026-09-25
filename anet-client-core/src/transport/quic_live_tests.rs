//! Explicit operator probe: real QUIC + IP traffic without a local TUN or routes.
use super::*;
use anet_common::stream_framing::{frame_packet, read_next_packet};
use anyhow::{Context, ensure};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

async fn echo(
    result: &mut ConnectionResult,
    target: Ipv4Addr,
    seq: u16,
    size: usize,
) -> Result<()> {
    let source: Ipv4Addr = result.auth_response.ip.parse()?;
    let mut packet = vec![0x5a; size];
    packet[..28].fill(0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.octets());
    packet[20] = 8;
    packet[24..26].copy_from_slice(&0x4753u16.to_be_bytes());
    packet[26..28].copy_from_slice(&seq.to_be_bytes());
    let crc = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&crc.to_be_bytes());
    let crc = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&crc.to_be_bytes());
    result
        .vpn_stream
        .write_all(&frame_packet(Bytes::from(packet)))
        .await?;
    result.vpn_stream.flush().await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let reply = read_next_packet(&mut result.vpn_stream)
                .await?
                .context("VPN stream EOF")?;
            if reply.len() < 28 || reply[0] != 0x45 || reply[9] != 1 || reply[20] != 0 {
                continue;
            }
            if reply[12..16] != target.octets()
                || reply[24..26] != 0x4753u16.to_be_bytes()
                || reply[26..28] != seq.to_be_bytes()
            {
                continue;
            }
            ensure!(reply[16..20] == source.octets(), "incorrect destination");
            ensure!(
                reply.len() == size && reply[28..].iter().all(|b| *b == 0x5a),
                "echo payload corruption"
            );
            ensure!(checksum(&reply[20..]) == 0, "bad ICMP checksum");
            println!("echo verified: target={target}, bytes={size}, seq={seq}");
            return Ok::<_, anyhow::Error>(());
        }
    })
    .await
    .context("echo reply timed out")??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ANET_PROBE_CONFIG pointing to an authorized private profile"]
async fn live_quic_probe() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let path = std::env::var("ANET_PROBE_CONFIG")?;
    let config: CoreConfig = toml::from_str(&std::fs::read_to_string(path)?)?;
    let server = config
        .servers
        .first()
        .context("no server in profile")?
        .clone();
    let transport = QuicTransport::new(config, server);
    let mut result = tokio::time::timeout(Duration::from_secs(25), transport.connect()).await??;
    println!(
        "authenticated; assigned_ip={}, gateway={}",
        result.auth_response.ip, result.auth_response.gateway
    );
    let gateway: Ipv4Addr = result.auth_response.gateway.parse()?;
    echo(&mut result, gateway, 1, 84).await?;
    echo(&mut result, gateway, 2, 1280).await?;
    if let Ok(target) = std::env::var("ANET_PROBE_EXTERNAL") {
        echo(&mut result, target.parse()?, 3, 84).await?;
    }
    // Longer than server's inactive-client threshold; QUIC keepalive must suffice.
    tokio::time::sleep(Duration::from_secs(40)).await;
    echo(&mut result, gateway, 4, 1280).await?;
    let connection = result.connection.as_ref().context("not QUIC")?;
    ensure!(
        connection.close_reason().is_none(),
        "connection closed during probe"
    );
    println!(
        "idle survival verified; rtt={:?}, loss={}",
        connection.stats().path.rtt,
        connection.stats().path.lost_packets
    );
    connection.close(0u32.into(), b"operator probe complete");
    if let Some(endpoint) = result.endpoint {
        tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle()).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires ANET_PROBE_CONFIG matching the running test server"]
async fn live_quic_rejects_wrong_algorithm() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    use anet_common::encryption::CryptoAlgorithm;
    let path = std::env::var("ANET_PROBE_CONFIG")?;
    let mut config: CoreConfig = toml::from_str(&std::fs::read_to_string(path)?)?;
    config.crypto.algorithm = match config.crypto.algorithm {
        CryptoAlgorithm::KuznyechikMgm => CryptoAlgorithm::ChaCha20Poly1305,
        CryptoAlgorithm::ChaCha20Poly1305 => CryptoAlgorithm::KuznyechikMgm,
    };
    let server = config
        .servers
        .first()
        .context("no server in profile")?
        .clone();
    let transport = QuicTransport::new(config, server);
    let outcome = tokio::time::timeout(Duration::from_secs(5), transport.connect()).await;
    ensure!(
        !matches!(outcome, Ok(Ok(_))),
        "wrong algorithm unexpectedly connected"
    );
    Ok(())
}
