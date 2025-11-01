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
            info!(&ctx, "failed to extract cookie, passing through");
            return Ok(0); // SK_PASS
        }
    };

    // Validate the cookie checksum
    let generation = cookie >> 11;
    let idx = (cookie >> 3) & 0xff;
    let chksum = cookie & 0x7;
    let sum = generation + idx;
    
    if chksum != (sum & 0x7) {
        info!(&ctx, "invalid cookie checksum, passing through");
        return Ok(0); // SK_PASS
    }

    info!(&ctx, "valid cookie found: {}, redirecting", cookie);

    // Redirect to the socket associated with this cookie
    let ret = QUICD_WORKERS.redirect_msg(&ctx, cookie, 0);

    if ret < 0 {
        info!(&ctx, "redirect failed, passing through");
        Ok(0) // SK_PASS
    } else {
        Ok(ret as u32) // SK_REDIRECT
    }
}
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
