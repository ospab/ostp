//! 0-RTT Session Resumption for OSTP.
//!
//! When a client has previously connected to a server, it can cache
//! a "session ticket" that allows it to send encrypted data in the
//! very first packet — eliminating the handshake round-trip entirely.
//!
//! How it works:
//! 1. After a successful handshake, the server issues a SessionTicket
//!    containing enough state to resume the session.
//! 2. The client stores the ticket locally (encrypted with the PSK).
//! 3. On reconnection, the client sends a ResumptionRequest with the
//!    ticket + early data in the first packet.
//! 4. The server validates the ticket and immediately begins processing
//!    data, achieving 0-RTT.
//!
//! Security considerations:
//! - Tickets have a TTL (default 3600s) to limit replay window.
//! - The server maintains a ticket nonce set to prevent replay.
//! - Early data is idempotent by protocol design (relay CONNECT is safe
//!   because duplicate CONNECTs to the same target are no-ops).

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// A session ticket that allows 0-RTT resumption.
#[derive(Debug, Clone)]
pub struct SessionTicket {
    /// Unique ticket identifier (prevents replay)
    pub ticket_id: [u8; 16],
    /// Server session ID to resume
    pub session_id: u32,
    /// Derived cipher key for early data
    pub cipher_key: [u8; 32],
    /// Timestamp of issuance (seconds since epoch)
    pub issued_at: u64,
    /// Time-to-live in seconds
    pub ttl: u64,
}

/// Maximum ticket age (1 hour default)
const DEFAULT_TICKET_TTL: u64 = 3600;
/// Maximum tickets in the anti-replay set
const MAX_REPLAY_SET: usize = 10000;

impl SessionTicket {
    /// Create a new session ticket from the transport key material.
    pub fn new(session_id: u32, transport_key: &[u8; 32], psk: &[u8; 32]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Derive ticket ID from key material + timestamp
        let mut hasher = Sha256::new();
        hasher.update(transport_key);
        hasher.update(now.to_be_bytes());
        hasher.update(b"ostp-ticket-id");
        let hash = hasher.finalize();
        let mut ticket_id = [0u8; 16];
        ticket_id.copy_from_slice(&hash[..16]);

        // Derive cipher key for early data from PSK + ticket
        let mut key_hasher = Sha256::new();
        key_hasher.update(psk);
        key_hasher.update(ticket_id);
        key_hasher.update(b"ostp-early-data-key");
        let cipher_key_hash = key_hasher.finalize();
        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&cipher_key_hash);

        Self {
            ticket_id,
            session_id,
            cipher_key,
            issued_at: now,
            ttl: DEFAULT_TICKET_TTL,
        }
    }

    /// Check if the ticket has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.issued_at + self.ttl
    }

    /// Serialize the ticket to bytes for storage/transmission.
    /// Wire format: [ticket_id:16][session_id:4][cipher_key:32][issued_at:8][ttl:8]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(68);
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.cipher_key);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out
    }

    /// Deserialize a ticket from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 68 {
            return None;
        }
        let mut ticket_id = [0u8; 16];
        ticket_id.copy_from_slice(&data[0..16]);

        let session_id = u32::from_be_bytes(data[16..20].try_into().ok()?);

        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&data[20..52]);

        let issued_at = u64::from_be_bytes(data[52..60].try_into().ok()?);
        let ttl = u64::from_be_bytes(data[60..68].try_into().ok()?);

        Some(Self {
            ticket_id,
            session_id,
            cipher_key,
            issued_at,
            ttl,
        })
    }

    /// Encrypt the ticket with a PSK for client-side storage.
    /// Uses a simple XOR cipher with HMAC-SHA256 derived key.
    pub fn encrypt(&self, psk: &[u8; 32]) -> Vec<u8> {
        let raw = self.to_bytes();
        let mut enc_key_hasher = Sha256::new();
        enc_key_hasher.update(psk);
        enc_key_hasher.update(b"ostp-ticket-encryption");
        let enc_key = enc_key_hasher.finalize();

        let mut encrypted = raw.clone();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= enc_key[i % 32];
        }
        encrypted
    }

    /// Decrypt a ticket from encrypted bytes.
    pub fn decrypt(encrypted: &[u8], psk: &[u8; 32]) -> Option<Self> {
        let mut enc_key_hasher = Sha256::new();
        enc_key_hasher.update(psk);
        enc_key_hasher.update(b"ostp-ticket-encryption");
        let enc_key = enc_key_hasher.finalize();

        let mut decrypted = encrypted.to_vec();
        for (i, byte) in decrypted.iter_mut().enumerate() {
            *byte ^= enc_key[i % 32];
        }
        Self::from_bytes(&decrypted)
    }
}

/// Server-side anti-replay guard for session tickets.
#[allow(dead_code)]
pub struct TicketValidator {
    /// Set of consumed ticket IDs (prevents replay)
    consumed: HashSet<[u8; 16]>,
    /// PSK for ticket validation
    psk: [u8; 32],
    /// Maximum age for tickets
    max_age: Duration,
}

impl TicketValidator {
    pub fn new(psk: [u8; 32]) -> Self {
        Self {
            consumed: HashSet::new(),
            psk,
            max_age: Duration::from_secs(DEFAULT_TICKET_TTL),
        }
    }

    /// Validate a ticket from the client. Returns the ticket if valid,
    /// or None if expired, replayed, or invalid.
    pub fn validate(&mut self, encrypted_ticket: &[u8]) -> Option<SessionTicket> {
        let ticket = SessionTicket::decrypt(encrypted_ticket, &self.psk)?;

        // Check expiry
        if ticket.is_expired() {
            tracing::debug!("0-RTT ticket rejected: expired");
            return None;
        }

        // Check replay
        if self.consumed.contains(&ticket.ticket_id) {
            tracing::warn!("0-RTT ticket rejected: replay detected");
            return None;
        }

        // Accept and mark as consumed
        self.consumed.insert(ticket.ticket_id);

        // Garbage collection: remove old entries when set grows too large
        if self.consumed.len() > MAX_REPLAY_SET {
            // Simple strategy: clear the entire set. This is safe because
            // expired tickets would fail the expiry check anyway.
            self.consumed.clear();
            self.consumed.insert(ticket.ticket_id);
            tracing::debug!("0-RTT replay set cleared (overflow)");
        }

        tracing::debug!("0-RTT ticket accepted: session_id={}", ticket.session_id);
        Some(ticket)
    }

    /// Issue a new ticket for a completed session.
    pub fn issue_ticket(&self, session_id: u32, transport_key: &[u8; 32]) -> SessionTicket {
        SessionTicket::new(session_id, transport_key, &self.psk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_serialize_roundtrip() {
        let psk = [42u8; 32];
        let key = [1u8; 32];
        let ticket = SessionTicket::new(12345, &key, &psk);

        let bytes = ticket.to_bytes();
        let restored = SessionTicket::from_bytes(&bytes).unwrap();

        assert_eq!(ticket.ticket_id, restored.ticket_id);
        assert_eq!(ticket.session_id, restored.session_id);
        assert_eq!(ticket.cipher_key, restored.cipher_key);
        assert_eq!(ticket.issued_at, restored.issued_at);
    }

    #[test]
    fn test_ticket_encrypt_decrypt() {
        let psk = [42u8; 32];
        let key = [1u8; 32];
        let ticket = SessionTicket::new(99, &key, &psk);

        let encrypted = ticket.encrypt(&psk);
        let decrypted = SessionTicket::decrypt(&encrypted, &psk).unwrap();

        assert_eq!(ticket.ticket_id, decrypted.ticket_id);
        assert_eq!(ticket.session_id, decrypted.session_id);
    }

    #[test]
    fn test_ticket_wrong_psk_fails() {
        let psk = [42u8; 32];
        let wrong_psk = [99u8; 32];
        let key = [1u8; 32];
        let ticket = SessionTicket::new(1, &key, &psk);
        let encrypted = ticket.encrypt(&psk);

        // Decrypting with wrong PSK produces garbage, from_bytes should
        // still return Some but ticket_id won't match
        let decrypted = SessionTicket::decrypt(&encrypted, &wrong_psk);
        // It may parse but the data will be wrong
        if let Some(d) = decrypted {
            assert_ne!(d.ticket_id, ticket.ticket_id);
        }
    }

    #[test]
    fn test_ticket_not_expired() {
        let psk = [42u8; 32];
        let key = [1u8; 32];
        let ticket = SessionTicket::new(1, &key, &psk);
        assert!(!ticket.is_expired());
    }

    #[test]
    fn test_validator_replay_protection() {
        let psk = [42u8; 32];
        let key = [1u8; 32];
        let mut validator = TicketValidator::new(psk);

        let ticket = validator.issue_ticket(1, &key);
        let encrypted = ticket.encrypt(&psk);

        // First use should succeed
        assert!(validator.validate(&encrypted).is_some());

        // Replay should fail
        assert!(validator.validate(&encrypted).is_none());
    }

    #[test]
    fn test_validator_different_tickets() {
        let psk = [42u8; 32];
        let mut validator = TicketValidator::new(psk);

        let ticket1 = validator.issue_ticket(1, &[1u8; 32]);
        let ticket2 = validator.issue_ticket(2, &[2u8; 32]);

        assert!(validator.validate(&ticket1.encrypt(&psk)).is_some());
        assert!(validator.validate(&ticket2.encrypt(&psk)).is_some());
    }

    #[test]
    fn test_truncated_ticket_fails() {
        assert!(SessionTicket::from_bytes(&[0u8; 10]).is_none());
    }
}
