use crate::client_registry::ClientRegistry;
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::aead::rand_core::RngCore;
use rand::rngs::OsRng;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[inline]
pub fn generate_seid() -> String {
    let mut rng = rand::thread_rng();
    let mut session_id = [0u8; 16];
    rng.fill_bytes(&mut session_id);
    // Используем безопасный URL-алфавит без падинга
    general_purpose::URL_SAFE_NO_PAD.encode(session_id)
}

#[inline]
pub fn extract_ip_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }

    if (pkt[0] >> 4) != 4 {
        return None;
    }

    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

#[inline]
pub fn generate_unique_nonce_prefix(
    registry: Arc<ClientRegistry>,
    algorithm: anet_common::encryption::CryptoAlgorithm,
) -> Vec<u8> {
    let mut rng = OsRng;
    loop {
        let mut prefix = vec![0u8; algorithm.nonce_prefix_len()];
        rng.fill_bytes(&mut prefix);
        if algorithm == anet_common::encryption::CryptoAlgorithm::KuznyechikMgm {
            prefix[0] &= 0x7f;
        }
        if registry.get_by_prefix(&prefix).is_none() {
            return prefix;
        }
    }
}
