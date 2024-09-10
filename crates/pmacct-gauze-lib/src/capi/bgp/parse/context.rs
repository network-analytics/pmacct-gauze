use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;

use pmacct_gauze_bindings::{afi_t, cap_per_af, safi_t};

use crate::cresult::CResult;
use crate::extensions::add_path::AddPathCapability;
use crate::opaque::Opaque;
use crate::{free_rust_raw_box, make_rust_raw_box_pointer};

#[repr(C)]
pub struct UnsupportedAfiSafi {
    afi: afi_t,
    safi: safi_t,
}

/// This structure must be freed using [netgauze_free_OpaqueBgpParsingContext]
pub type BgpParsingContextResult = CResult<*mut Opaque<BgpParsingContext>, UnsupportedAfiSafi>;

free_rust_raw_box!(Opaque<BgpParsingContext>, OpaqueBgpParsingContext);

#[no_mangle]
pub extern "C" fn netgauze_make_bgp_parsing_context(
    asn4: bool,
    add_path: *const cap_per_af,
    fail_on_non_unicast_withdraw_nlri: bool,
    fail_on_non_unicast_update_nlri: bool,
    fail_on_capability_error: bool,
    fail_on_malformed_path_attr: bool,
) -> BgpParsingContextResult {
    let add_path = unsafe { add_path.as_ref().unwrap() };
    let add_path = add_path.get_receive_map();
    let add_path = if let Ok(map) = add_path {
        map
    } else {
        let (afi, safi) = add_path.err().unwrap();
        return Err(UnsupportedAfiSafi { afi, safi }).into();
    };

    Ok(make_rust_raw_box_pointer(Opaque::from(
        BgpParsingContext::new(
            asn4,
            Default::default(), // pmacct: this is not supported in pmacct
            add_path,
            fail_on_non_unicast_withdraw_nlri,
            fail_on_non_unicast_update_nlri,
            fail_on_capability_error,
            fail_on_malformed_path_attr,
        ),
    )))
    .into()
}
