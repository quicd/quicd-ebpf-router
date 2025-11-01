#![no_std]

// Using u16 cookie as the key for routing QUIC connections
pub type SockKey = u16;

/// Cookie format:
/// - Bits 11-15 (5 bits): Generation counter (0-31)
/// - Bits 3-10 (8 bits): Worker/socket index (0-255)
/// - Bits 0-2 (3 bits): Checksum = (generation + index) & 0x7
///
/// This allows up to 256 workers with 32 generations each
pub struct Cookie;

impl Cookie {
    /// Generate a cookie from generation and worker index
    /// 
    /// # Arguments
    /// * `generation` - Generation counter (0-31, only lower 5 bits used)
    /// * `worker_idx` - Worker/socket index (0-255)
    /// 
    /// # Returns
    /// A 16-bit cookie value with embedded checksum
    /// 
    /// # Example
    /// ```
    /// let cookie = common::Cookie::generate(0, 42);
    /// assert!(common::Cookie::validate(cookie));
    /// ```
    #[inline]
    pub const fn generate(generation: u8, worker_idx: u8) -> u16 {
        let g = (generation & 0x1F) as u16; // 5 bits
        let idx = worker_idx as u16; // 8 bits
        let checksum = ((g + idx) & 0x7) as u16; // 3 bits
        
        (g << 11) | (idx << 3) | checksum
    }
    
    /// Validate a cookie's checksum
    /// 
    /// # Arguments
    /// * `cookie` - The 16-bit cookie value to validate
    /// 
    /// # Returns
    /// `true` if the checksum is valid, `false` otherwise
    #[inline]
    pub const fn validate(cookie: u16) -> bool {
        let generation = cookie >> 11;
        let idx = (cookie >> 3) & 0xff;
        let chksum = cookie & 0x7;
        let sum = generation + idx;
        
        chksum == (sum & 0x7)
    }
    
    /// Extract the generation from a cookie
    #[inline]
    pub const fn get_generation(cookie: u16) -> u8 {
        (cookie >> 11) as u8
    }
    
    /// Extract the worker index from a cookie
    #[inline]
    pub const fn get_worker_idx(cookie: u16) -> u8 {
        ((cookie >> 3) & 0xff) as u8
    }
}
