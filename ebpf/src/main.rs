#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, sk_msg},
    maps::SockHash,
    programs::SkMsgContext,
};
use aya_log_ebpf::info;
use common::SockKey;

#[map]
static QUICD_WORKERS: SockHash<SockKey> = SockHash::<SockKey>::with_max_entries(1024, 0);

#[sk_msg]
pub fn quicd_ebpf_router(ctx: SkMsgContext) -> u32 {
    match try_quicd_ebpf_router(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_quicd_ebpf_router(ctx: SkMsgContext) -> Result<u32, u32> {
    // Extract the cookie from the QUIC connection ID
    let cookie = match extract_cookie(&ctx) {
        Some(c) => c,
        None => {
            info!(&ctx, "failed to extract cookie, distributing load");
            // No cookie found, distribute load evenly using DCID hash
            return distribute_load(&ctx);
        }
    };

    // Validate the cookie checksum
    let generation = cookie >> 11;
    let idx = (cookie >> 3) & 0xff;
    let chksum = cookie & 0x7;
    let sum = generation + idx;
    
    if chksum != (sum & 0x7) {
        info!(&ctx, "invalid cookie checksum, distributing load");
        // Invalid cookie, distribute load evenly
        return distribute_load(&ctx);
    }

    info!(&ctx, "valid cookie found: {}, redirecting", cookie);

    // Redirect to the socket associated with this cookie
    let ret = QUICD_WORKERS.redirect_msg(&ctx, cookie, 0);

    if ret < 0 {
        info!(&ctx, "redirect failed, distributing load");
        // Redirect failed, fall back to load distribution
        return distribute_load(&ctx);
    } else {
        Ok(ret as u32) // SK_REDIRECT
    }
}

/// Distribute load evenly among available sockets when no valid route is found
/// Uses a simple hash of the DCID to ensure consistent routing for the same connection
fn distribute_load(ctx: &SkMsgContext) -> Result<u32, u32> {
    let dcid_hash = match compute_dcid_hash(ctx) {
        Some(hash) => hash,
        None => {
            info!(ctx, "failed to compute DCID hash, passing through");
            return Ok(0); // SK_PASS
        }
    };

    // Use the hash to select a socket index (0-255 range)
    // This ensures the same DCID always goes to the same worker
    let socket_idx = (dcid_hash % 256) as u16;

    info!(ctx, "distributing to socket index: {}", socket_idx);

    let ret = QUICD_WORKERS.redirect_msg(ctx, socket_idx, 0);

    if ret < 0 {
        info!(ctx, "load distribution redirect failed, passing through");
        Ok(0) // SK_PASS if redirect failed
    } else {
        Ok(ret as u32) // SK_REDIRECT
    }
}

/// Compute a simple hash of the DCID for load distribution
fn compute_dcid_hash(ctx: &SkMsgContext) -> Option<u32> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // Need at least 1 byte
    if unsafe { data.add(1) } > data_end {
        return None;
    }

    // Read first byte to determine packet type
    let first_byte = unsafe { *data };

    if first_byte & 0x80 == 0 {
        // Short header packet: DCID starts at offset 1, always 8 bytes
        if unsafe { data.add(1 + 8) } > data_end {
            return None;
        }

        // Hash the 8-byte DCID
        let dcid_start = unsafe { data.add(1) };
        let mut hash: u32 = 0;
        hash = hash.wrapping_add(unsafe { *dcid_start.add(0) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(1) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(2) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(3) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(4) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(5) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(6) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(7) } as u32);
        Some(hash)
    } else {
        // Long header packet: DCID starts after version + dcid_len byte
        if unsafe { data.add(6) } > data_end {
            return None;
        }

        // Read DCID length (byte 5)
        let dcid_len = unsafe { *data.add(5) } as usize;

        if dcid_len != 8 {
            return None;
        }

        // Check bounds for 8-byte DCID
        if unsafe { data.add(6 + 8) } > data_end {
            return None;
        }

        // Hash the 8-byte DCID
        let dcid_start = unsafe { data.add(6) };
        let mut hash: u32 = 0;
        hash = hash.wrapping_add(unsafe { *dcid_start.add(0) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(1) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(2) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(3) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(4) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(5) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(6) } as u32);
        hash = hash.wrapping_add(unsafe { *dcid_start.add(7) } as u32);
        Some(hash)
    }
}

/// Extract the 16-bit cookie from the QUIC connection ID (DCID)
fn extract_cookie(ctx: &SkMsgContext) -> Option<u16> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // Need at least 1 byte for header - check bounds explicitly for verifier
    if unsafe { data.add(1) } > data_end {
        return None;
    }

    // Read first byte to determine packet type
    let first_byte = unsafe { *data };

    if first_byte & 0x80 == 0 {
        // Short header packet: 1 byte flags + 8 byte DCID
        if unsafe { data.add(1 + 8) } > data_end {
            return None;
        }

        // Cookie is at offset 1 + 6 = 7 (bytes 6-7 of DCID)
        let cookie_ptr = unsafe { data.add(7) };
        let cookie = unsafe { u16::from_be_bytes([*cookie_ptr, *cookie_ptr.add(1)]) };
        Some(cookie)
    } else {
        // Long header packet: 1 byte flags + 4 bytes version + 1 byte DCID len + DCID
        if unsafe { data.add(6) } > data_end {
            return None;
        }

        // Read DCID length (byte 5)
        let dcid_len = unsafe { *data.add(5) } as usize;

        // We expect 8-byte DCID
        if dcid_len != 8 {
            return None;
        }

        // Check if we have the full DCID
        if unsafe { data.add(6 + 8) } > data_end {
            return None;
        }

        // Cookie is at offset 6 + 6 = 12 (bytes 6-7 of DCID)
        let cookie_ptr = unsafe { data.add(12) };
        let cookie = unsafe { u16::from_be_bytes([*cookie_ptr, *cookie_ptr.add(1)]) };
        Some(cookie)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
