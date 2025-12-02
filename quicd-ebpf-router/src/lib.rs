use aya::{
    maps::{MapData, SockHash},
    programs::SkMsg,
};
use common::SockKey;
#[rustfmt::skip]
use log::debug;
use siphasher::sip::SipHasher13;
use std::hash::Hasher;
use std::os::fd::AsRawFd;

// Re-export Cookie utilities for applications
pub use common::Cookie;

/// Standard Connection ID length used by this router (20 bytes)
pub const CID_LENGTH: usize = 20;

const WORKER_MAP_NAME: &str = "QUICD_WORKERS";
const ROUTER_PROGRAM_NAME: &str = "quicd_ebpf_router";

/// High-level interface for managing the QUIC router eBPF program and worker sockets
///
/// This type wraps the lifecycle of the userspace eBPF loader, exposes helpers for
/// registering sockets, and allows applications to interact with the underlying
/// worker map if they need custom behaviour.
///
/// # Example
///
/// ```no_run
/// use std::net::UdpSocket;
/// use quicd_ebpf_router::{Router, ConnectionId};
///
/// fn main() -> anyhow::Result<()> {
///     // Initialise logging/rlimits and load the eBPF router program
///     let mut router = Router::new()?;
///
///     // Prepare a worker socket which should receive QUIC packets
///     let socket = UdpSocket::bind("127.0.0.1:0")?;
///
///     // Register the socket by generation/worker index
///     let cookie = router.register_worker_socket(0, 1, &socket)?;
///
///     // Use the cookie when building 20-byte connection IDs for clients
///     let cid = ConnectionId::generate(0, 1)?; // Recommended: uses secure randomness
///     assert_eq!(ConnectionId::extract_cookie(&cid), Some(cookie));
///     assert!(ConnectionId::verify_protection(&cid));
///
///     Ok(())
/// }
/// ```
pub struct Router {
    ebpf: aya::Ebpf,
    sock_map: SockHash<MapData, SockKey>,
}

impl Router {
    /// Load the eBPF program, attach it, and return a router ready for socket registration
    pub fn new() -> anyhow::Result<Self> {
        setup_rlimit()?;
        let ebpf = load_ebpf()?;
        Self::from_loaded_ebpf(ebpf)
    }

    /// Build a router from a pre-loaded eBPF object
    pub fn from_loaded_ebpf(mut ebpf: aya::Ebpf) -> anyhow::Result<Self> {
        let sock_map: SockHash<_, SockKey> = ebpf
            .take_map(WORKER_MAP_NAME)
            .ok_or_else(|| anyhow::anyhow!("map '{}' not found", WORKER_MAP_NAME))?
            .try_into()?;

        let map_fd = sock_map.fd().try_clone()?;

        let prog: &mut SkMsg = ebpf
            .program_mut(ROUTER_PROGRAM_NAME)
            .ok_or_else(|| anyhow::anyhow!("program '{}' not found", ROUTER_PROGRAM_NAME))?
            .try_into()?;
        prog.load()?;
        prog.attach(&map_fd)?;

        Ok(Self { ebpf, sock_map })
    }

    /// Insert a socket file descriptor keyed by a precomputed cookie
    pub fn insert_socket<S: AsRawFd>(&mut self, cookie: SockKey, socket: &S) -> anyhow::Result<()> {
        let fd = socket.as_raw_fd();
        self.sock_map.insert(cookie, fd, 0)?;
        Ok(())
    }

    /// Convenience helper to compute the cookie and insert the socket in one step
    pub fn register_worker_socket<S: AsRawFd>(
        &mut self,
        generation: u8,
        worker_idx: u8,
        socket: &S,
    ) -> anyhow::Result<u16> {
        let cookie = Cookie::generate(generation, worker_idx);
        self.insert_socket(cookie, socket)?;
        Ok(cookie)
    }

    /// Remove a socket entry from the routing map
    pub fn remove_socket(&mut self, cookie: SockKey) -> anyhow::Result<()> {
        self.sock_map.remove(&cookie)?;
        Ok(())
    }

    /// Borrow the underlying socket map for advanced manipulations
    pub fn sock_map(&mut self) -> &mut SockHash<MapData, SockKey> {
        &mut self.sock_map
    }

    /// Access the underlying eBPF object for custom configuration
    pub fn ebpf(&mut self) -> &mut aya::Ebpf {
        &mut self.ebpf
    }
}

/// Helper struct for working with QUIC Connection IDs
///
/// # Overview
///
/// This module provides utilities to embed routing cookies into QUIC Connection IDs,
/// enabling eBPF-based routing of QUIC packets to specific worker sockets.
///
/// # QUIC Connection ID Flow
///
/// 1. **Client sends Initial packet** - Contains client-chosen DCID (no valid cookie)
/// 2. **Server generates SCID** - Server creates a new Connection ID with embedded cookie
/// 3. **Server responds** - Sends Initial/Handshake with the new CID as SCID
/// 4. **Client adopts SCID** - Client uses server's SCID as DCID in subsequent packets
/// 5. **eBPF routes packets** - eBPF extracts cookie from DCID and redirects to correct socket
///
/// # 20-byte Connection ID Format
///
/// - Bytes 0-5: Random prefix (6 bytes)
/// - Bytes 6-7: Routing cookie (u16 big-endian)
/// - Bytes 8-18: Random entropy (11 bytes)
/// - Byte 19: Protection byte (SipHash-1-3 LSB over bytes 0-18)
///
/// Total entropy: 136 bits → safe for >100M concurrent connections
///
/// # Cookie Format
///
/// The 16-bit cookie is embedded in bytes 6-7 of the 20-byte Connection ID:
/// - Bits 11-15 (5 bits): Generation counter (allows rotation)
/// - Bits 3-10 (8 bits): Worker/socket index (0-255)
/// - Bits 0-2 (3 bits): Checksum for validation
///
/// # Example Usage
///
/// ```no_run
/// use quicd_ebpf_router::{ConnectionId, Cookie};
///
/// // When receiving a client Initial packet without a valid cookie:
/// let worker_idx = 42u8; // This socket's worker index
/// let generation = 0u8;   // Current generation (can increment over time)
///
/// // Option 1: Fully automatic generation (recommended for production)
/// let server_cid = ConnectionId::generate(generation, worker_idx).unwrap();
///
/// // Option 2: Bring-your-own randomness (for testing or custom entropy)
/// let entropy = [0u8; 17]; // 6 bytes prefix + 11 bytes suffix
/// let server_cid = ConnectionId::generate_with_entropy(generation, worker_idx, entropy);
///
/// // Option 3: Seeded generation (for tests only)
/// let prefix_seed = 0x12345678u32;
/// let server_cid = ConnectionId::generate_with_seed(generation, worker_idx, prefix_seed);
///
/// // Use server_cid as SCID in the Server Initial packet
/// // The client will echo it back as DCID in subsequent packets
///
/// // Later, when receiving packets, validate the cookie:
/// if ConnectionId::validate_cookie(&server_cid) {
///     let worker = ConnectionId::get_worker_idx(&server_cid).unwrap();
///     println!("Valid cookie for worker {}", worker);
/// }
///
/// // The eBPF program will automatically extract and validate the cookie
/// // and redirect packets to the appropriate socket in the QUICD_WORKERS map
/// ```
pub struct ConnectionId;

// SipHash key for CID protection (can be rotated for additional security)
const SIPHASH_KEY: (u64, u64) = (0x0706050403020100, 0x0f0e0d0c0b0a0908);

impl ConnectionId {
    /// Generate a new 20-byte Connection ID with automatic randomness (recommended)
    ///
    /// This is the recommended method for production use. It:
    /// - Fills bytes 0-5 and 8-18 with cryptographically secure random data
    /// - Writes the routing cookie to bytes 6-7
    /// - Computes SipHash-1-3 over bytes 0-18 and writes LSB to byte 19
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    ///
    /// # Returns
    /// A 20-byte array representing the Connection ID, or an error if randomness fails
    ///
    /// # Example
    /// ```no_run
    /// use quicd_ebpf_router::ConnectionId;
    ///
    /// let cid = ConnectionId::generate(0, 42).unwrap();
    /// assert_eq!(cid.len(), 20);
    /// ```
    pub fn generate(generation: u8, worker_idx: u8) -> Result<[u8; CID_LENGTH], getrandom::Error> {
        let mut entropy = [0u8; 17];
        getrandom::getrandom(&mut entropy)?;
        Ok(Self::generate_with_entropy(generation, worker_idx, entropy))
    }

    /// Generate a new 20-byte Connection ID with provided entropy
    ///
    /// Use this method when you want to provide your own randomness source.
    /// The entropy is split into prefix (6 bytes) and suffix (11 bytes).
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `entropy` - 17 bytes of random data (6 for prefix, 11 for suffix)
    ///
    /// # Returns
    /// A 20-byte array representing the Connection ID
    ///
    /// # Example
    /// ```
    /// use quicd_ebpf_router::ConnectionId;
    ///
    /// let entropy = [0xAAu8; 17]; // In production, use real random data
    /// let cid = ConnectionId::generate_with_entropy(0, 42, entropy);
    /// assert_eq!(cid.len(), 20);
    /// ```
    pub fn generate_with_entropy(
        generation: u8,
        worker_idx: u8,
        entropy: [u8; 17],
    ) -> [u8; CID_LENGTH] {
        let cookie = Cookie::generate(generation, worker_idx);
        let cookie_bytes = cookie.to_be_bytes();

        let mut cid = [0u8; CID_LENGTH];

        // Bytes 0-5: Random prefix from entropy
        cid[0..6].copy_from_slice(&entropy[0..6]);

        // Bytes 6-7: Routing cookie
        cid[6..8].copy_from_slice(&cookie_bytes);

        // Bytes 8-18: Random entropy (11 bytes)
        cid[8..19].copy_from_slice(&entropy[6..17]);

        // Byte 19: SipHash-1-3 protection byte
        let mut hasher = SipHasher13::new_with_keys(SIPHASH_KEY.0, SIPHASH_KEY.1);
        hasher.write(&cid[0..19]);
        let hash = hasher.finish();
        cid[19] = (hash & 0xFF) as u8;

        cid
    }

    /// Generate a new Connection ID with seeded randomness (for testing only)
    ///
    /// This method uses a simple PRNG based on the seed for deterministic testing.
    /// DO NOT use this in production - use `generate()` instead.
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `seed` - A seed value to generate deterministic entropy
    ///
    /// # Returns
    /// A 20-byte array representing the Connection ID
    pub fn generate_with_seed(generation: u8, worker_idx: u8, seed: u32) -> [u8; CID_LENGTH] {
        // Simple PRNG for testing (NOT cryptographically secure)
        let mut entropy = [0u8; 17];
        let mut state = seed;

        for (i, entropy_byte) in entropy.iter_mut().enumerate() {
            // Simple LCG: state = (a * state + c) mod m
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *entropy_byte = (state >> (8 * (i % 4))) as u8;
        }

        Self::generate_with_entropy(generation, worker_idx, entropy)
    }

    /// Verify the SipHash protection byte of a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID to verify (must be exactly 20 bytes)
    ///
    /// # Returns
    /// `true` if the protection byte is valid, `false` otherwise
    pub fn verify_protection(cid: &[u8]) -> bool {
        if cid.len() != CID_LENGTH {
            return false;
        }

        let mut hasher = SipHasher13::new_with_keys(SIPHASH_KEY.0, SIPHASH_KEY.1);
        hasher.write(&cid[0..19]);
        let hash = hasher.finish();
        let expected = (hash & 0xFF) as u8;

        cid[19] == expected
    }

    /// Extract the cookie from a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID (must be at least 8 bytes)
    ///
    /// # Returns
    /// The extracted cookie value, or None if the CID is too short
    pub fn extract_cookie(cid: &[u8]) -> Option<u16> {
        if cid.len() < 8 {
            return None;
        }

        Some(u16::from_be_bytes([cid[6], cid[7]]))
    }

    /// Validate a Connection ID's cookie
    ///
    /// Note: This only validates the cookie checksum, not the SipHash protection byte.
    /// For full validation, also call `verify_protection()`.
    ///
    /// # Arguments
    /// * `cid` - The Connection ID to validate
    ///
    /// # Returns
    /// `true` if the cookie is valid, `false` otherwise
    pub fn validate_cookie(cid: &[u8]) -> bool {
        Self::extract_cookie(cid)
            .map(Cookie::validate)
            .unwrap_or(false)
    }

    /// Get the worker index from a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID
    ///
    /// # Returns
    /// The worker index, or None if extraction fails
    pub fn get_worker_idx(cid: &[u8]) -> Option<u8> {
        Self::extract_cookie(cid).map(Cookie::get_worker_idx)
    }

    /// Get the generation from a Connection ID
    ///
    /// # Arguments
    /// * `cid` - The Connection ID
    ///
    /// # Returns
    /// The generation, or None if extraction fails
    pub fn get_generation(cid: &[u8]) -> Option<u8> {
        Self::extract_cookie(cid).map(Cookie::get_generation)
    }
}

pub fn setup_rlimit() -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    Ok(())
}

pub fn load_ebpf() -> anyhow::Result<aya::Ebpf> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    Ok(aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/quicd-ebpf-router"
    )))?)
}

/// Get the expected cookie for a worker
/// Useful for debugging and verification
pub fn get_worker_cookie(generation: u8, worker_idx: u8) -> u16 {
    Cookie::generate(generation, worker_idx)
}

/// Check if a cookie corresponds to a valid worker
/// This is a local check - doesn't query the eBPF map
pub fn is_valid_worker_cookie(cookie: u16, current_generation: u8) -> bool {
    Cookie::validate(cookie) && Cookie::get_generation(cookie) == current_generation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation_and_validation() {
        // Test cookie generation
        let cookie = Cookie::generate(5, 42);

        // Validate the cookie
        assert!(Cookie::validate(cookie));

        // Extract components
        assert_eq!(Cookie::get_generation(cookie), 5);
        assert_eq!(Cookie::get_worker_idx(cookie), 42);
    }

    #[test]
    fn test_cookie_checksum() {
        // Valid cookie should validate
        let valid_cookie = Cookie::generate(0, 0);
        assert!(Cookie::validate(valid_cookie));

        // Manipulated cookie should fail validation
        let invalid_cookie = valid_cookie ^ 0x0001; // Flip checksum bit
        assert!(!Cookie::validate(invalid_cookie));
    }

    #[test]
    fn test_connection_id_creation() {
        let generation = 3;
        let worker_idx = 17;
        let entropy = [0xAAu8; 17];

        let cid = ConnectionId::generate_with_entropy(generation, worker_idx, entropy);

        // Check length
        assert_eq!(cid.len(), CID_LENGTH);

        // Check prefix is preserved (first 6 bytes of entropy)
        assert_eq!(&cid[0..6], &entropy[0..6]);

        // Validate cookie
        assert!(ConnectionId::validate_cookie(&cid));

        // Verify SipHash protection
        assert!(ConnectionId::verify_protection(&cid));

        // Extract components
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));
    }

    #[test]
    fn test_connection_id_with_seed() {
        let generation = 7;
        let worker_idx = 99;
        let seed = 0x12345678;

        let cid = ConnectionId::generate_with_seed(generation, worker_idx, seed);

        // Check length
        assert_eq!(cid.len(), CID_LENGTH);

        // Validate
        assert!(ConnectionId::validate_cookie(&cid));
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));

        // Verify SipHash protection
        assert!(ConnectionId::verify_protection(&cid));

        // Deterministic: same seed should produce same CID
        let cid2 = ConnectionId::generate_with_seed(generation, worker_idx, seed);
        assert_eq!(cid, cid2);
    }

    #[test]
    fn test_cookie_extraction() {
        let cid = ConnectionId::generate_with_seed(2, 50, 0xABCDEF);

        let cookie = ConnectionId::extract_cookie(&cid).unwrap();
        assert!(Cookie::validate(cookie));
        assert_eq!(Cookie::get_generation(cookie), 2);
        assert_eq!(Cookie::get_worker_idx(cookie), 50);

        // Also verify full CID
        assert!(ConnectionId::verify_protection(&cid));
    }

    #[test]
    fn test_connection_id_generate() {
        let generation = 5;
        let worker_idx = 123;

        let cid = ConnectionId::generate(generation, worker_idx).unwrap();

        // Check length
        assert_eq!(cid.len(), CID_LENGTH);

        // Validate cookie
        assert!(ConnectionId::validate_cookie(&cid));
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));

        // Verify SipHash protection
        assert!(ConnectionId::verify_protection(&cid));

        // Each call should produce different CID (due to randomness)
        let cid2 = ConnectionId::generate(generation, worker_idx).unwrap();
        assert_ne!(cid, cid2);
    }

    #[test]
    fn test_short_cid_handling() {
        let short_cid = [0x01, 0x02, 0x03]; // Too short

        assert_eq!(ConnectionId::extract_cookie(&short_cid), None);
        assert!(!ConnectionId::validate_cookie(&short_cid));
        assert_eq!(ConnectionId::get_worker_idx(&short_cid), None);
        assert_eq!(ConnectionId::get_generation(&short_cid), None);
    }

    #[test]
    fn test_generation_wrap() {
        // Test that generation is properly masked to 5 bits
        let cookie1 = Cookie::generate(31, 0); // Max generation (0b11111)
        let cookie2 = Cookie::generate(32, 0); // Should wrap to 0

        assert_eq!(Cookie::get_generation(cookie1), 31);
        assert_eq!(Cookie::get_generation(cookie2), 0);
    }

    #[test]
    fn test_all_workers() {
        // Test that all 256 worker indices work
        for worker_idx in 0..=255 {
            let cookie = Cookie::generate(0, worker_idx);
            assert!(Cookie::validate(cookie));
            assert_eq!(Cookie::get_worker_idx(cookie), worker_idx);
        }
    }

    #[test]
    fn test_worker_cookie_generation() {
        let generation = 5;
        let worker_idx = 42;

        let cookie = get_worker_cookie(generation, worker_idx);
        assert!(Cookie::validate(cookie));
        assert_eq!(Cookie::get_generation(cookie), generation);
        assert_eq!(Cookie::get_worker_idx(cookie), worker_idx);
    }

    #[test]
    fn test_valid_worker_cookie_check() {
        let generation = 3;
        let worker_idx = 17;

        let cookie = Cookie::generate(generation, worker_idx);
        assert!(is_valid_worker_cookie(cookie, generation));
        assert!(!is_valid_worker_cookie(cookie, generation + 1)); // Wrong generation

        let invalid_cookie = cookie ^ 0x0001; // Corrupt checksum
        assert!(!is_valid_worker_cookie(invalid_cookie, generation));
    }

    #[test]
    fn test_siphash_protection() {
        let generation = 2;
        let worker_idx = 50;
        let entropy = [0x42u8; 17];

        let cid = ConnectionId::generate_with_entropy(generation, worker_idx, entropy);

        // Valid CID should verify
        assert!(ConnectionId::verify_protection(&cid));

        // Tampering with any byte (except last) should break protection
        for i in 0..19 {
            let mut tampered = cid;
            tampered[i] ^= 0x01; // Flip one bit
            assert!(
                !ConnectionId::verify_protection(&tampered),
                "Tampering at byte {} should break protection",
                i
            );
        }

        // Tampering with the protection byte itself
        let mut tampered_protection = cid;
        tampered_protection[19] ^= 0x01;
        assert!(!ConnectionId::verify_protection(&tampered_protection));
    }

    #[test]
    fn test_siphash_uniqueness() {
        // Different inputs should produce different protection bytes
        let entropy1 = [0x11u8; 17];
        let entropy2 = [0x22u8; 17];

        let cid1 = ConnectionId::generate_with_entropy(0, 0, entropy1);
        let cid2 = ConnectionId::generate_with_entropy(0, 0, entropy2);

        // The protection bytes should be different
        assert_ne!(cid1[19], cid2[19]);
    }

    #[test]
    fn test_entropy_distribution() {
        // Verify that entropy is placed correctly
        let entropy = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // First 6 bytes -> prefix (0-5)
            0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, // Next 11 bytes -> suffix (8-18)
        ];

        let cid = ConnectionId::generate_with_entropy(0, 0, entropy);

        // Check prefix (bytes 0-5)
        assert_eq!(&cid[0..6], &entropy[0..6]);

        // Bytes 6-7 are the cookie (not from entropy)
        let cookie = u16::from_be_bytes([cid[6], cid[7]]);
        assert_eq!(cookie, Cookie::generate(0, 0));

        // Check suffix (bytes 8-18)
        assert_eq!(&cid[8..19], &entropy[6..17]);

        // Byte 19 is the protection byte (computed)
        assert!(ConnectionId::verify_protection(&cid));
    }

    #[test]
    fn test_backward_compatibility() {
        // Ensure extract_cookie still works with 20-byte CIDs
        let generation = 7;
        let worker_idx = 99;
        let cid = ConnectionId::generate_with_seed(generation, worker_idx, 0xDEADBEEF);

        // Old validation methods should still work
        assert!(ConnectionId::validate_cookie(&cid));
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));

        let cookie = ConnectionId::extract_cookie(&cid).unwrap();
        assert_eq!(Cookie::get_generation(cookie), generation);
        assert_eq!(Cookie::get_worker_idx(cookie), worker_idx);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_ebpf_cookie_routing() {
        // Setup eBPF program
        let _router = Router::new().expect("Failed to initialise router");

        let generation = 0;

        // Test cookie generation and validation (without actual socket insertion)
        let cookie0 = Cookie::generate(generation, 0);
        let cookie1 = Cookie::generate(generation, 1);
        let cookie2 = Cookie::generate(generation, 2);

        println!("Testing eBPF cookie routing:");
        println!("Cookie 0: {:#06x} (worker 0)", cookie0);
        println!("Cookie 1: {:#06x} (worker 1)", cookie1);
        println!("Cookie 2: {:#06x} (worker 2)", cookie2);

        // Test cookie generation and validation
        assert!(Cookie::validate(cookie0));
        assert!(Cookie::validate(cookie1));
        assert!(Cookie::validate(cookie2));

        assert_eq!(Cookie::get_worker_idx(cookie0), 0);
        assert_eq!(Cookie::get_worker_idx(cookie1), 1);
        assert_eq!(Cookie::get_worker_idx(cookie2), 2);

        assert_eq!(Cookie::get_generation(cookie0), generation);
        assert_eq!(Cookie::get_generation(cookie1), generation);
        assert_eq!(Cookie::get_generation(cookie2), generation);

        // Test Connection ID creation with cookies
        let entropy = [0xAAu8; 17];

        let cid0 = ConnectionId::generate_with_entropy(generation, 0, entropy);
        let cid1 = ConnectionId::generate_with_entropy(generation, 1, entropy);
        let cid2 = ConnectionId::generate_with_entropy(generation, 2, entropy);

        // Verify cookies are embedded correctly
        assert_eq!(ConnectionId::extract_cookie(&cid0), Some(cookie0));
        assert_eq!(ConnectionId::extract_cookie(&cid1), Some(cookie1));
        assert_eq!(ConnectionId::extract_cookie(&cid2), Some(cookie2));

        assert!(ConnectionId::validate_cookie(&cid0));
        assert!(ConnectionId::validate_cookie(&cid1));
        assert!(ConnectionId::validate_cookie(&cid2));

        // Test invalid cookie scenarios
        let mut invalid_cid = [0xAAu8; 20];
        invalid_cid[6] = 0x00; // Set invalid cookie at bytes 6-7
        invalid_cid[7] = 0x01;
        assert!(!ConnectionId::validate_cookie(&invalid_cid));

        // Test load distribution for new connections (no valid cookie)
        let new_connection_cid = [0x11u8; 20]; // Random DCID
        assert!(!ConnectionId::validate_cookie(&new_connection_cid));

        println!("eBPF cookie routing logic validation passed");
    }

    #[test]
    fn test_quic_packet_parsing() {
        // Test parsing of different QUIC packet types

        // Short header packet (1-RTT)
        let mut short_header_packet = vec![0x40]; // Short header flag
        short_header_packet.extend_from_slice(&[0u8; 20]); // 20-byte DCID placeholder
        short_header_packet.extend_from_slice(&[0x99, 0xAA, 0xBB]); // Rest of packet

        // Create a Connection ID and embed it
        let generation = 1;
        let worker_idx = 42;
        let entropy = [0x11u8; 17];
        let cid = ConnectionId::generate_with_entropy(generation, worker_idx, entropy);

        // Replace DCID in packet
        short_header_packet[1..21].copy_from_slice(&cid);

        // Extract cookie from packet (simulate what eBPF does)
        let extracted_cookie = extract_cookie_from_packet(&short_header_packet);
        assert_eq!(
            extracted_cookie,
            Some(Cookie::generate(generation, worker_idx))
        );
        assert!(extracted_cookie.map_or(false, |c| Cookie::validate(c)));

        // Long header packet (Initial)
        let mut long_header_packet = vec![0xC0]; // Long header flag
        long_header_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version
        long_header_packet.extend_from_slice(&[0x08]); // DCID length
        long_header_packet.extend_from_slice(&cid); // DCID
        long_header_packet.extend_from_slice(&[0x00]); // SCID length
        long_header_packet.extend_from_slice(&[0xCC, 0xDD]); // Rest of packet

        // Extract cookie from long header packet
        let extracted_cookie_long = extract_cookie_from_packet(&long_header_packet);
        assert_eq!(
            extracted_cookie_long,
            Some(Cookie::generate(generation, worker_idx))
        );
        assert!(extracted_cookie_long.map_or(false, |c| Cookie::validate(c)));

        println!("QUIC packet parsing validation passed");
    }

    #[test]
    fn test_load_distribution_hash() {
        // Test that the load distribution hash function works consistently

        let test_dcids = vec![[0x11u8; 20], [0xAAu8; 20], [0x12u8; 20]];

        // Test that the same DCID always produces the same hash
        for dcid in &test_dcids {
            let hash1 = compute_dcid_hash_simple(dcid);
            let hash2 = compute_dcid_hash_simple(dcid);
            assert_eq!(hash1, hash2, "Hash should be consistent for same DCID");

            // Hash should be in range 0-255 for load distribution (u8 is always < 256)
            // This assertion is redundant but kept for clarity
        }

        // Test that different DCIDs produce different hashes (most of the time)
        let hashes: Vec<u8> = test_dcids
            .iter()
            .map(|dcid| compute_dcid_hash_simple(dcid))
            .collect();
        let unique_hashes: std::collections::HashSet<_> = hashes.iter().collect();

        // At least 2 out of 3 should be different (allowing for hash collisions)
        assert!(
            unique_hashes.len() >= 2,
            "Load distribution should spread connections"
        );

        println!("Load distribution hash validation passed");
    }

    #[test]
    fn test_cookie_rotation() {
        // Test cookie rotation with generations
        let worker_idx = 100;
        let generations = [0, 1, 5, 15, 31]; // Test various generations

        for &generation in &generations {
            let cookie = Cookie::generate(generation, worker_idx);
            assert!(Cookie::validate(cookie));
            assert_eq!(Cookie::get_generation(cookie), generation);
            assert_eq!(Cookie::get_worker_idx(cookie), worker_idx);
        }

        // Test that different generations produce different cookies
        let cookie_gen0 = Cookie::generate(0, worker_idx);
        let cookie_gen1 = Cookie::generate(1, worker_idx);
        assert_ne!(cookie_gen0, cookie_gen1);

        // Test generation wraparound
        let cookie_wrap = Cookie::generate(32, worker_idx); // Should wrap to 0
        assert_eq!(Cookie::get_generation(cookie_wrap), 0);

        println!("Cookie rotation validation passed");
    }
}

// Helper functions for testing (simulating eBPF logic)
#[allow(dead_code)]
fn extract_cookie_from_packet(packet: &[u8]) -> Option<u16> {
    if packet.is_empty() {
        return None;
    }

    let first_byte = packet[0];

    if first_byte & 0x80 == 0 {
        // Short header - cookie at bytes 7-8 (offset 1 for header, then 6 bytes in)
        if packet.len() < 21 {
            return None;
        }
        Some(u16::from_be_bytes([packet[7], packet[8]]))
    } else {
        // Long header - cookie at DCID bytes 6-7
        if packet.len() < 26 {
            return None;
        }
        let dcid_start = 6; // flags(1) + version(4) + dcid_len(1)
        Some(u16::from_be_bytes([
            packet[dcid_start + 6],
            packet[dcid_start + 7],
        ]))
    }
}

#[allow(dead_code)]
fn compute_dcid_hash_simple(dcid: &[u8; 20]) -> u8 {
    // Simple hash for testing (matches eBPF logic)
    let mut hash: u32 = 0;
    for &byte in dcid {
        hash = hash.wrapping_add(byte as u32);
        hash = hash.wrapping_mul(31);
    }
    (hash % 256) as u8
}
