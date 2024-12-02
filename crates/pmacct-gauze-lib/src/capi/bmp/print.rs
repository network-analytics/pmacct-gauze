use std::slice;

use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use nom::Offset;

use crate::opaque::Opaque;

#[no_mangle]
pub extern "C" fn netgauze_bmp_print_packet(buffer: *const libc::c_char, len: u32) -> u32 {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, len as usize) };
    let span = Span::new(s);
    if let Ok((end_span, msg)) = BmpMessage::from_wire(span, &mut Default::default()) {
        println!("span: ptr: {:?} | value {:?}", span.as_ptr(), span);
        println!("msg: {:?}", msg);
        return span.offset(&end_span) as u32;
    }

    0
}

/// Print a [BmpMessageValue]
///
/// # Safety
/// `bmp_message_value_opaque` should be not null and point to valid data
#[no_mangle]
pub unsafe extern "C" fn netgauze_bmp_print_message(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap() };
    println!("{:#?}", bmp_value);
}
