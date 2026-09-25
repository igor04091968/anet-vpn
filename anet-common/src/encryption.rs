use aead::{Aead, AeadInPlace, KeyInit, Nonce, Tag};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use kuznyechik::Kuznyechik;
use mgm::aead::{Aead as GostAead, AeadInPlace as GostAeadInPlace, NewAead};
use rand::RngCore;
use serde::Deserialize;
use std::{str::FromStr, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Default)]
pub enum CryptoAlgorithm {
    #[default]
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "kuznyechik-mgm")]
    KuznyechikMgm,
}

impl CryptoAlgorithm {
    pub const fn wire_marker(self) -> &'static [u8] {
        match self {
            Self::ChaCha20Poly1305 => b"",
            Self::KuznyechikMgm => b"ANETGOST1",
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 12,
            Self::KuznyechikMgm => 16,
        }
    }
    pub const fn tag_len(self) -> usize {
        16
    }
    pub const fn nonce_prefix_len(self) -> usize {
        self.nonce_len() - 8
    }

    pub const fn envelope_overhead(self) -> usize {
        self.wire_marker().len() + self.nonce_len() + self.tag_len() + 10
    }
}

impl FromStr for CryptoAlgorithm {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            "kuznyechik-mgm" => Ok(Self::KuznyechikMgm),
            other => Err(format!("unsupported crypto algorithm: {other}")),
        }
    }
}

#[derive(Clone)]
enum CipherInner {
    ChaCha(ChaCha20Poly1305),
    KuznyechikMgm(mgm::Mgm<Kuznyechik>),
}

#[derive(Clone)]
pub struct Cipher {
    cipher: Arc<CipherInner>,
    algorithm: CryptoAlgorithm,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Self {
        Self::with_algorithm(key, CryptoAlgorithm::ChaCha20Poly1305)
            .expect("valid 32-byte cipher key")
    }

    pub fn with_algorithm(key: &[u8], algorithm: CryptoAlgorithm) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }
        let cipher = match algorithm {
            CryptoAlgorithm::ChaCha20Poly1305 => CipherInner::ChaCha(
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| EncryptionError::InvalidKeyLength)?,
            ),
            CryptoAlgorithm::KuznyechikMgm => {
                let key = mgm::aead::generic_array::GenericArray::from_slice(key);
                CipherInner::KuznyechikMgm(mgm::Mgm::<Kuznyechik>::new(key))
            }
        };
        Ok(Self {
            cipher: Arc::new(cipher),
            algorithm,
        })
    }

    pub const fn algorithm(&self) -> CryptoAlgorithm {
        self.algorithm
    }
    pub const fn nonce_len(&self) -> usize {
        self.algorithm.nonce_len()
    }
    pub const fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
    }
    pub const fn nonce_prefix_len(&self) -> usize {
        self.algorithm.nonce_prefix_len()
    }
    pub const fn wire_marker(&self) -> &'static [u8] {
        self.algorithm.wire_marker()
    }
    pub const fn wire_marker_len(&self) -> usize {
        self.algorithm.wire_marker().len()
    }
    pub const fn envelope_overhead(&self) -> usize {
        self.algorithm.envelope_overhead()
    }

    pub fn split_frame<'a>(
        &self,
        packet: &'a [u8],
    ) -> Result<(&'a [u8], &'a [u8]), EncryptionError> {
        let marker = self.wire_marker();
        if packet.len() < marker.len() + self.nonce_len() + self.tag_len()
            || !packet.starts_with(marker)
        {
            return Err(EncryptionError::InvalidPacketHeader);
        }
        let body = &packet[marker.len()..];
        Ok(body.split_at(self.nonce_len()))
    }

    pub fn random_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0; self.nonce_len()];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        if self.algorithm == CryptoAlgorithm::KuznyechikMgm {
            nonce[0] &= 0x7f;
        }
        nonce
    }

    pub fn encrypt(&self, nonce: &[u8], data: Bytes) -> Result<Bytes, EncryptionError> {
        if nonce.len() != self.nonce_len() {
            return Err(EncryptionError::InvalidNonceLength);
        }
        match self.cipher.as_ref() {
            CipherInner::ChaCha(c) => c
                .encrypt(Nonce::<ChaCha20Poly1305>::from_slice(nonce), data.as_ref())
                .map(Bytes::from)
                .map_err(|_| EncryptionError::EncryptionFailed),
            CipherInner::KuznyechikMgm(c) => {
                let n = mgm::Nonce::<mgm::aead::consts::U16>::from_slice(nonce);
                c.encrypt(n, data.as_ref())
                    .map(Bytes::from)
                    .map_err(|_| EncryptionError::EncryptionFailed)
            }
        }
    }

    pub fn decrypt(&self, nonce: &[u8], data: Bytes) -> Result<Bytes, EncryptionError> {
        if nonce.len() != self.nonce_len() {
            return Err(EncryptionError::InvalidNonceLength);
        }
        match self.cipher.as_ref() {
            CipherInner::ChaCha(c) => c
                .decrypt(Nonce::<ChaCha20Poly1305>::from_slice(nonce), data.as_ref())
                .map(Bytes::from)
                .map_err(|_| EncryptionError::DecryptionFailed),
            CipherInner::KuznyechikMgm(c) => {
                let n = mgm::Nonce::<mgm::aead::consts::U16>::from_slice(nonce);
                c.decrypt(n, data.as_ref())
                    .map(Bytes::from)
                    .map_err(|_| EncryptionError::DecryptionFailed)
            }
        }
    }

    pub fn decrypt_in_place(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        if nonce.len() != self.nonce_len() || buffer.len() < self.tag_len() {
            return Err(EncryptionError::DecryptionFailed);
        }
        let body_len = buffer.len() - self.tag_len();
        let (body, tag) = buffer.split_at_mut(body_len);
        match self.cipher.as_ref() {
            CipherInner::ChaCha(c) => {
                let n = Nonce::<ChaCha20Poly1305>::from_slice(nonce);
                c.decrypt_in_place_detached(n, &[], body, Tag::<ChaCha20Poly1305>::from_slice(tag))
                    .map_err(|_| EncryptionError::DecryptionFailed)?;
            }
            CipherInner::KuznyechikMgm(c) => {
                let n = mgm::Nonce::<mgm::aead::consts::U16>::from_slice(nonce);
                let t = mgm::Tag::<mgm::aead::consts::U16>::from_slice(tag);
                c.decrypt_in_place_detached(n, &[], body, t)
                    .map_err(|_| EncryptionError::DecryptionFailed)?;
            }
        }
        Ok(body_len)
    }

    pub fn encrypt_in_place_detached(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != self.nonce_len() {
            return Err(EncryptionError::InvalidNonceLength);
        }
        let tag = match self.cipher.as_ref() {
            CipherInner::ChaCha(c) => {
                let n = Nonce::<ChaCha20Poly1305>::from_slice(nonce);
                c.encrypt_in_place_detached(n, &[], buffer)
                    .map(|tag| tag.to_vec())
                    .map_err(|_| EncryptionError::EncryptionFailed)?
            }
            CipherInner::KuznyechikMgm(c) => {
                let n = mgm::Nonce::<mgm::aead::consts::U16>::from_slice(nonce);
                c.encrypt_in_place_detached(n, &[], buffer)
                    .map(|tag| tag.to_vec())
                    .map_err(|_| EncryptionError::EncryptionFailed)?
            }
        };
        Ok(tag)
    }

    pub fn generate_nonce(&self, prefix: &[u8], sequence: u64) -> Result<Vec<u8>, EncryptionError> {
        if prefix.len() != self.nonce_prefix_len() {
            return Err(EncryptionError::InvalidNonceLength);
        }
        let mut nonce = vec![0; self.nonce_len()];
        nonce[..prefix.len()].copy_from_slice(prefix);
        nonce[prefix.len()..].copy_from_slice(&sequence.to_be_bytes());
        if self.algorithm == CryptoAlgorithm::KuznyechikMgm {
            nonce[0] &= 0x7f;
        }
        Ok(nonce)
    }
}

#[derive(Debug)]
pub enum EncryptionError {
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidPacketHeader,
    EncryptionFailed,
    DecryptionFailed,
}
impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EncryptionError {}
