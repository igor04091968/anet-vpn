use crate::consts::PADDING_MTU;
use crate::encryption::{Cipher, EncryptionError};
use crate::padding_utils::calculate_padding_needed;
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Упаковывает и шифрует QUIC-пакет с новым протоколом
pub fn wrap_packet(
    cipher: &Cipher,
    nonce_prefix: &[u8],
    sequence: u64,
    quic_payload: Bytes,
    padding_size: u16,
) -> Result<Bytes, EncryptionError> {
    wrap_packet_slice(cipher, nonce_prefix, sequence, &quic_payload, padding_size)
}

/// Packs and encrypts a packet using a single output allocation.
pub fn wrap_packet_slice(
    cipher: &Cipher,
    nonce_prefix: &[u8],
    sequence: u64,
    payload: &[u8],
    padding_size: u16,
) -> Result<Bytes, EncryptionError> {
    let payload_len = payload.len();

    let nonce = cipher.generate_nonce(nonce_prefix, sequence)?;

    // Reserve the final wire buffer once: nonce + plaintext + authentication tag.
    let mut final_packet = BytesMut::with_capacity(
        cipher.wire_marker_len()
            + nonce.len()
            + 10
            + payload_len
            + padding_size as usize
            + cipher.tag_len(),
    );
    final_packet.put_slice(cipher.wire_marker());
    final_packet.put_slice(&nonce);
    final_packet.put_u64(sequence);
    final_packet.put_u16(payload_len as u16);
    final_packet.put_slice(payload);
    final_packet.put_bytes(0, padding_size as usize);

    let tag = {
        let plaintext = &mut final_packet[cipher.wire_marker_len() + nonce.len()..];
        cipher.encrypt_in_place_detached(&nonce, plaintext)?
    };
    final_packet.put_slice(&tag);

    Ok(final_packet.freeze())
}

/// Applies the configured transport padding and encrypts an owned packet.
#[inline]
pub fn wrap_packet_padded(
    cipher: &Cipher,
    nonce_prefix: &[u8],
    sequence: u64,
    payload: Bytes,
    padding_step: u16,
) -> Result<Bytes, EncryptionError> {
    let wire_len_without_padding = payload.len() + cipher.envelope_overhead();
    let requested_padding = calculate_padding_needed(wire_len_without_padding, padding_step);
    let padding = if wire_len_without_padding + usize::from(requested_padding) <= PADDING_MTU {
        requested_padding
    } else {
        0
    };
    wrap_packet_slice(cipher, nonce_prefix, sequence, &payload, padding)
}

/// Расшифровывает пакет, полученный от сервера
pub fn unwrap_packet(cipher: &Cipher, raw_packet: &[u8]) -> Result<Bytes> {
    if raw_packet.len() < cipher.wire_marker_len() + cipher.nonce_len() + cipher.tag_len()
        || !raw_packet.starts_with(cipher.wire_marker())
    {
        // Nonce + минимум 1 байт payload
        return Err(anyhow!("Packet too short"));
    }

    // Извлекаем nonce и зашифрованные данные
    let (nonce, ciphertext) = cipher.split_frame(raw_packet)?;

    // Расшифровываем
    let mut plaintext = cipher.decrypt(nonce, Bytes::copy_from_slice(ciphertext))?;

    if plaintext.len() < 10 {
        return Err(anyhow!("Payload too short"));
    }

    let _seq = plaintext.get_u64();
    let data_len = plaintext.get_u16() as usize; // Читаем длину

    if data_len > plaintext.remaining() {
        return Err(anyhow!("Malformed packet length"));
    }
    // Обрезаем паддинг
    Ok(plaintext.copy_to_bytes(data_len))
}

/// Расшифровывает пакет на месте (без выделения памяти).
/// buffer: полный пакет (Nonce + Ciphertext + Tag).
/// Возвращает срез с полезной нагрузкой (Quic Payload).
pub fn unwrap_packet_in_place<'a>(cipher: &Cipher, buffer: &'a mut [u8]) -> Result<&'a [u8]> {
    // 16 байт - размер тега Poly1305
    if buffer.len() < cipher.wire_marker_len() + cipher.nonce_len() + cipher.tag_len()
        || !buffer.starts_with(cipher.wire_marker())
    {
        return Err(anyhow!("Packet too short"));
    }

    let nonce_len = cipher.nonce_len();
    let mut nonce = [0u8; 16];
    let marker_len = cipher.wire_marker_len();
    nonce[..nonce_len].copy_from_slice(&buffer[marker_len..marker_len + nonce_len]);

    // 2. Берем срез данных (включая Tag в конце)
    let payload_buffer = &mut buffer[marker_len + nonce_len..];

    // 3. Расшифровываем на месте
    cipher.decrypt_in_place(&nonce[..nonce_len], payload_buffer)?;

    // 4. Отрезаем тег (логически).
    // Реальная длина данных теперь меньше на 16 байт.
    let plaintext_len = payload_buffer.len() - cipher.tag_len();
    let plaintext = &payload_buffer[..plaintext_len];

    // 5. Парсим заголовок ANet: [Seq (8)] [Len (2)] [Payload...] [Padding...]
    if plaintext.len() < 10 {
        return Err(anyhow!("Payload too short (header missing)"));
    }

    // Читаем длину (offset 8, 2 байта) вручную, чтобы не использовать Buf
    let data_len = u16::from_be_bytes([plaintext[8], plaintext[9]]) as usize;

    if 10 + data_len > plaintext.len() {
        return Err(anyhow!("Malformed packet length"));
    }

    // Возвращаем срез чистого пейлоуда
    Ok(&plaintext[10..10 + data_len])
}

/// Decrypts an owned packet in place and returns a zero-copy view of its IP payload.
///
/// Unlike [`unwrap_packet`], this reuses the receive buffer for both ciphertext and
/// plaintext. `Bytes` produced directly from a freshly read `Vec` is normally unique;
/// a shared buffer is rejected rather than silently copied.
pub fn unwrap_packet_bytes_in_place(cipher: &Cipher, raw_packet: Bytes) -> Result<Bytes> {
    let mut buffer = raw_packet
        .try_into_mut()
        .map_err(|_| anyhow!("Encrypted packet buffer is unexpectedly shared"))?;

    let payload = unwrap_packet_in_place(cipher, &mut buffer)?;
    let payload_len = payload.len();
    let payload_start = cipher.wire_marker_len() + cipher.nonce_len() + 10;
    let payload_end = payload_start + payload_len;
    buffer.truncate(payload_end);
    Ok(buffer.freeze().slice(payload_start..payload_end))
}

/// Decrypts an owned packet in place when its buffer is unique and falls back to the
/// allocating path for shared buffers such as slices owned by a WebSocket frame parser.
pub fn unwrap_packet_bytes(cipher: &Cipher, raw_packet: Bytes) -> Result<Bytes> {
    let mut buffer = match raw_packet.try_into_mut() {
        Ok(buffer) => buffer,
        Err(shared) => return unwrap_packet(cipher, &shared),
    };

    let payload = unwrap_packet_in_place(cipher, &mut buffer)?;
    let payload_len = payload.len();
    let payload_start = cipher.wire_marker_len() + cipher.nonce_len() + 10;
    let payload_end = payload_start + payload_len;
    buffer.truncate(payload_end);
    Ok(buffer.freeze().slice(payload_start..payload_end))
}

#[cfg(test)]
mod in_place_tests {
    use super::*;

    #[test]
    fn session_routing_uses_prefix_before_counter_for_both_algorithms() {
        use crate::encryption::CryptoAlgorithm::*;
        for algorithm in [ChaCha20Poly1305, KuznyechikMgm] {
            let cipher = Cipher::with_algorithm(&[3; 32], algorithm).unwrap();
            let prefix = vec![0x31; algorithm.nonce_prefix_len()];
            let packet = wrap_packet(&cipher, &prefix, 42, Bytes::from_static(b"data"), 0).unwrap();
            assert_eq!(algorithm.session_prefix(&packet), Some(prefix.as_slice()));
            for len in 0..algorithm.envelope_overhead() {
                assert!(algorithm.session_prefix(&packet[..len]).is_none());
            }
        }
    }

    #[test]
    fn directions_have_distinct_nonces_and_preserve_ordering_counter() {
        use crate::encryption::CryptoAlgorithm::{ChaCha20Poly1305, KuznyechikMgm};
        for algorithm in [ChaCha20Poly1305, KuznyechikMgm] {
            let client = Cipher::with_algorithm(&[3; 32], algorithm).unwrap();
            let server = client.clone().with_server_nonce_domain();
            let prefix = vec![0x31; algorithm.nonce_prefix_len()];
            let data = Bytes::from_static(b"same packet in both directions");
            for seq in [0, 1, (1u64 << 63) - 1] {
                let up = wrap_packet(&client, &prefix, seq, data.clone(), 0).unwrap();
                let down = wrap_packet(&server, &prefix, seq, data.clone(), 0).unwrap();
                assert_ne!(
                    client.split_frame(&up).unwrap().0,
                    client.split_frame(&down).unwrap().0
                );
                assert_eq!(unwrap_packet(&client, &down).unwrap(), data);
                assert_eq!(unwrap_packet(&server, &up).unwrap(), data);
                assert_eq!(algorithm.session_prefix(&down), Some(prefix.as_slice()));
                let (nonce, body) = client.split_frame(&down).unwrap();
                let plaintext = client.decrypt(nonce, Bytes::copy_from_slice(body)).unwrap();
                assert_eq!(&plaintext[..8], &seq.to_be_bytes());
                let mut corrupted = down.to_vec();
                *corrupted.last_mut().unwrap() ^= 1;
                assert!(unwrap_packet(&client, &corrupted).is_err());
            }
            assert!(client.generate_nonce(&prefix, 1u64 << 63).is_err());
            assert!(server.generate_nonce(&prefix, 1u64 << 63).is_err());
        }
    }

    #[test]
    fn owned_in_place_unwrap_matches_allocating_path() {
        let cipher = Cipher::new(&[9; 32]);
        let payload = Bytes::from_static(b"test IP packet payload");
        let encrypted = wrap_packet(&cipher, &[1, 2, 3, 4], 7, payload.clone(), 13).unwrap();

        let allocating = unwrap_packet(&cipher, &encrypted).unwrap();
        let in_place = unwrap_packet_bytes_in_place(&cipher, encrypted).unwrap();

        assert_eq!(allocating, payload);
        assert_eq!(in_place, payload);
    }

    #[test]
    fn padded_wrap_round_trips_without_changing_payload() {
        let cipher = Cipher::new(&[3; 32]);
        let payload = Bytes::from(vec![7; 1400]);
        let encrypted = wrap_packet_padded(&cipher, &[4, 3, 2, 1], 9, payload.clone(), 64)
            .expect("packet must encrypt");

        assert!(encrypted.len() <= PADDING_MTU);
        assert_eq!(unwrap_packet(&cipher, &encrypted).unwrap(), payload);
    }

    #[test]
    fn owned_unwrap_falls_back_for_shared_buffers() {
        let cipher = Cipher::new(&[8; 32]);
        let payload = Bytes::from_static(b"shared WebSocket frame payload");
        let encrypted = wrap_packet(&cipher, &[9, 8, 7, 6], 11, payload.clone(), 0).unwrap();
        let shared = encrypted.clone();

        assert_eq!(unwrap_packet_bytes(&cipher, encrypted).unwrap(), payload);
        assert!(!shared.is_empty());
    }

    #[test]
    fn kuznyechik_mgm_transport_round_trips() {
        let cipher = Cipher::with_algorithm(
            &[0x42; 32],
            crate::encryption::CryptoAlgorithm::KuznyechikMgm,
        )
        .unwrap();
        let payload = Bytes::from_static(b"GOST QUIC payload");
        let encrypted =
            wrap_packet(&cipher, &[1, 2, 3, 4, 5, 6, 7, 8], 42, payload.clone(), 7).unwrap();
        assert_eq!(
            encrypted.len(),
            cipher.wire_marker_len() + 16 + 10 + payload.len() + 7 + 16
        );
        assert!(encrypted.starts_with(b"ANETGOST1"));
        assert_eq!(unwrap_packet(&cipher, &encrypted).unwrap(), payload);
    }
}
