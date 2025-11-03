use aya::{
    maps::{MapData, SockHash},
    programs::SkMsg,
};
use common::SockKey;
#[rustfmt::skip]
use log::debug;
use std::os::fd::AsRawFd;

// Re-export Cookie utilities for applications
pub use common::Cookie;

/// Standard Connection ID length used by this router (8 bytes)
pub const CID_LENGTH: usize = 8;

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
///     // Use the cookie when building connection IDs for clients
///     let cid = ConnectionId::new_with_seed(0, 1, 0x1234_5678);
///     assert_eq!(ConnectionId::extract_cookie(&cid), Some(cookie));
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
/// # Cookie Format
///
/// The 16-bit cookie is embedded in bytes 6-7 of the 8-byte Connection ID:
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
/// // Option 1: Use a proper random number generator for the prefix
/// let mut random_prefix = [0u8; 6];
/// // Fill random_prefix with secure random bytes (e.g., from rand crate)
/// let server_cid = ConnectionId::generate(generation, worker_idx, random_prefix);
///
/// // Option 2: Use the simple seed-based method (less secure)
/// let prefix_seed = 0x12345678u32; // Could be derived from timestamp, etc.
/// let server_cid = ConnectionId::new_with_seed(generation, worker_idx, prefix_seed);
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

impl ConnectionId {
    /// Generate a new 8-byte Connection ID with an embedded cookie
    ///
    /// The cookie is embedded in bytes 6-7 (big-endian u16).
    /// Bytes 0-5 can be random or application-specific data.
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `random_prefix` - 6 bytes of random or application data for bytes 0-5
    ///
    /// # Returns
    /// An 8-byte array representing the Connection ID
    ///
    /// # Example
    /// ```
    /// use quicd_ebpf_router::ConnectionId;
    ///
    /// // Generate random prefix (in real code, use a CSPRNG)
    /// let random_prefix = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    /// let cid = ConnectionId::generate(0, 42, random_prefix);
    ///
    /// // This CID can now be used as SCID in server Initial packet
    /// // Client will echo it back as DCID, allowing eBPF routing
    /// ```
    pub fn generate(generation: u8, worker_idx: u8, random_prefix: [u8; 6]) -> [u8; CID_LENGTH] {
        let cookie = Cookie::generate(generation, worker_idx);
        let cookie_bytes = cookie.to_be_bytes();

        let mut cid = [0u8; CID_LENGTH];
        cid[0..6].copy_from_slice(&random_prefix);
        cid[6..8].copy_from_slice(&cookie_bytes);

        cid
    }

    /// Generate a new Connection ID with a simple random prefix
    ///
    /// This is a convenience method that generates a basic random-looking prefix.
    /// For production use, consider using a cryptographically secure random generator.
    ///
    /// # Arguments
    /// * `generation` - Generation counter (0-31)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `prefix_seed` - A seed value to generate the prefix (for simplicity)
    ///
    /// # Returns
    /// An 8-byte array representing the Connection ID
    pub fn new_with_seed(generation: u8, worker_idx: u8, prefix_seed: u32) -> [u8; CID_LENGTH] {
        // Simple pseudo-random prefix generation (not cryptographically secure)
        // In production, use a proper CSPRNG
        let prefix = [
            (prefix_seed >> 24) as u8,
            (prefix_seed >> 16) as u8,
            (prefix_seed >> 8) as u8,
            prefix_seed as u8,
            worker_idx.wrapping_mul(17).wrapping_add(generation),
            generation.wrapping_mul(31).wrapping_add(worker_idx),
        ];

        Self::generate(generation, worker_idx, prefix)
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
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let cid = ConnectionId::generate(generation, worker_idx, prefix);

        // Check length
        assert_eq!(cid.len(), CID_LENGTH);

        // Check prefix is preserved
        assert_eq!(&cid[0..6], &prefix);

        // Validate cookie
        assert!(ConnectionId::validate_cookie(&cid));

        // Extract components
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));
    }

    #[test]
    fn test_connection_id_with_seed() {
        let generation = 7;
        let worker_idx = 99;
        let seed = 0x12345678;

        let cid = ConnectionId::new_with_seed(generation, worker_idx, seed);

        // Validate
        assert!(ConnectionId::validate_cookie(&cid));
        assert_eq!(ConnectionId::get_generation(&cid), Some(generation));
        assert_eq!(ConnectionId::get_worker_idx(&cid), Some(worker_idx));
    }

    #[test]
    fn test_cookie_extraction() {
        let cid = ConnectionId::new_with_seed(2, 50, 0xABCDEF);

        let cookie = ConnectionId::extract_cookie(&cid).unwrap();
        assert!(Cookie::validate(cookie));
        assert_eq!(Cookie::get_generation(cookie), 2);
        assert_eq!(Cookie::get_worker_idx(cookie), 50);
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
        let prefix = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let cid0 = ConnectionId::generate(generation, 0, prefix);
        let cid1 = ConnectionId::generate(generation, 1, prefix);
        let cid2 = ConnectionId::generate(generation, 2, prefix);

        // Verify cookies are embedded correctly
        assert_eq!(ConnectionId::extract_cookie(&cid0), Some(cookie0));
        assert_eq!(ConnectionId::extract_cookie(&cid1), Some(cookie1));
        assert_eq!(ConnectionId::extract_cookie(&cid2), Some(cookie2));

        assert!(ConnectionId::validate_cookie(&cid0));
        assert!(ConnectionId::validate_cookie(&cid1));
        assert!(ConnectionId::validate_cookie(&cid2));

        // Test invalid cookie scenarios
        let invalid_cid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01]; // Invalid cookie
        assert!(!ConnectionId::validate_cookie(&invalid_cid));

        // Test load distribution for new connections (no valid cookie)
        let new_connection_cid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]; // Random DCID
        assert!(!ConnectionId::validate_cookie(&new_connection_cid));

        println!("eBPF cookie routing logic validation passed");
    }

    #[test]
    fn test_quic_packet_parsing() {
        // Test parsing of different QUIC packet types

        // Short header packet (1-RTT)
        let mut short_header_packet = vec![0x40]; // Short header flag
        short_header_packet.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // 8-byte DCID
        short_header_packet.extend_from_slice(&[0x99, 0xAA, 0xBB]); // Rest of packet

        // Create a Connection ID and embed it
        let generation = 1;
        let worker_idx = 42;
        let cid =
            ConnectionId::generate(generation, worker_idx, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        // Replace DCID in packet
        short_header_packet[1..9].copy_from_slice(&cid);

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

        let test_dcids = vec![
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
        ];

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
        // Short header
        if packet.len() < 9 {
            return None;
        }
        Some(u16::from_be_bytes([packet[7], packet[8]]))
    } else {
        // Long header
        if packet.len() < 14 {
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
fn compute_dcid_hash_simple(dcid: &[u8; 8]) -> u8 {
    // Simple hash for testing (matches eBPF logic)
    let mut hash: u32 = 0;
    for &byte in dcid {
        hash = hash.wrapping_add(byte as u32);
        hash = hash.wrapping_mul(31);
    }
    (hash % 256) as u8
}
