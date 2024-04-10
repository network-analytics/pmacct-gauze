use netgauze_bmp_pkt::BmpMessageValue;

use pmacct_gauze_bindings::bmp_log_stats;

use crate::capi::bmp::WrongBmpMessageTypeError;
use crate::cresult::CResult;
use crate::cslice::CSlice;
use crate::cslice::RustFree;
use crate::extensions::bmp_statistics::ExtendBmpStatistics;
use crate::free_cslice_t;
use crate::log::{pmacct_log, LogPriority};
use crate::opaque::Opaque;

pub type BmpStatsResult = CResult<CSlice<bmp_log_stats>, WrongBmpMessageTypeError>;

free_cslice_t!(bmp_log_stats);

#[no_mangle]
pub extern "C" fn netgauze_bmp_stats_get_stats(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpStatsResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

    // Ensure passed value is a supported Bmp Message Type
    let stats = match bmp_value {
        BmpMessageValue::StatisticsReport(stats) => stats,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let mut result = Vec::with_capacity(stats.counters().len());

    for stat in stats.counters() {
        let cnt_type = match stat.get_type() {
            Ok(type_) => type_ as u16,
            Err(code) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! stat type {code} is not supported by NetGauze\n"
                    ),
                );
                continue;
            }
        };

        let (cnt_afi, cnt_safi) = match stat.get_afi_safi() {
            Ok(None) => (0, 0),
            Ok(Some(afi_safi)) => afi_safi,
            Err(address_type) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! address type {:?}(afi={}, safi={}) is not supported by NetGauze\n",
                        address_type,
                        address_type.address_family(),
                        address_type.subsequent_address_family()
                    ),
                );
                continue;
            }
        };

        // This error will only happen for experimental values since Unknown has already been filtered out in cnt_type
        let cnt_data = match stat.get_value_as_u64() {
            Ok(value) => value,
            Err(()) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! stat type {} is not supported by NetGauze\n",
                        cnt_type
                    ),
                );
                continue;
            }
        };

        result.push(bmp_log_stats {
            cnt_type,
            cnt_afi,
            cnt_safi,
            cnt_data,
        });
    }

    let slice = unsafe { CSlice::from_vec(result) };
    CResult::Ok(slice)
}
