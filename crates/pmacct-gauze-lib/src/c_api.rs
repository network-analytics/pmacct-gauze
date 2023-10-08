use libc;
use netgauze_bmp_pkt::BmpMessage;
use netgauze_parse_utils::{ReadablePdu, Span};
use nom::Offset;
use pmacct_gauze_bindings::bmp_common_hdr;
use std::slice;

#[no_mangle]
pub extern "C" fn netgauze_print_packet(buffer: *const libc::c_char, len: u32) -> u32 {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, len as usize) };
    let span = Span::new(s);
    if let Ok((end_span, msg)) = BmpMessage::from_wire(span) {
        println!("span: ptr: {:?} | value {:?}", span.as_ptr(), span);
        println!("msg: {:?}", msg);
        return span.offset(&end_span) as u32;
    }

    0
}

#[repr(C)]
pub struct ParseResult {
    read_bytes: u32,
    common_header: bmp_common_hdr,
}

// TODO find a way to tell cbindgen to use pmacct-gauze-bindings to find the original name
// TODO then rename use this in cbindgen.export.rename to avoid duplicating all types
// TODO for now: using the bindgen option to add struct_ in front of structs Builder::c_naming(true)
// TODO next: fork cbindgen, add a RenameRule to rename struct_X to struct X
// TODO       use cbindgen.toml [struct.rename]
// TODO profit?

#[no_mangle]
pub extern "C" fn netgauze_parse_packet(buffer: *const libc::c_char, len: u32) -> ParseResult {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, len as usize) };
    let span = Span::new(s);
    if let Ok((end_span, _msg)) = BmpMessage::from_wire(span) {
        let read_bytes = span.offset(&end_span) as u32;

        println!("netgauze {} bytes read", read_bytes);

        return ParseResult {
            read_bytes,
            common_header: bmp_common_hdr {
                version: 0,
                len,
                type_: 0,
            },
        };
    }

    ParseResult {
        read_bytes: 0,
        common_header: bmp_common_hdr {
            version: 0,
            len,
            type_: 0,
        },
    }
}

#[no_mangle]
pub extern "C" fn nonce8() {}
