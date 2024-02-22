use netgauze_bmp_pkt::StatisticsCounter;
use netgauze_iana::address_family::AddressType;
use pmacct_gauze_bindings::convert::TryConvertFrom;
use pmacct_gauze_bindings::{afi_t, safi_t};

pub trait ExtendBmpStatistics {
    fn get_afi_safi(&self) -> Result<Option<(afi_t, safi_t)>, AddressType>;
    fn get_value_as_u64(&self) -> Result<u64, ()>;
}

impl ExtendBmpStatistics for StatisticsCounter {
    fn get_afi_safi(&self) -> Result<Option<(afi_t, safi_t)>, AddressType> {
        return match self {
            StatisticsCounter::NumberOfPrefixesRejectedByInboundPolicy(_)
            | StatisticsCounter::NumberOfDuplicatePrefixAdvertisements(_)
            | StatisticsCounter::NumberOfDuplicateWithdraws(_)
            | StatisticsCounter::NumberOfUpdatesInvalidatedDueToClusterListLoop(_)
            | StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsPathLoop(_)
            | StatisticsCounter::NumberOfUpdatesInvalidatedDueToOriginatorId(_)
            | StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(_)
            | StatisticsCounter::NumberOfRoutesInAdjRibIn(_)
            | StatisticsCounter::NumberOfRoutesInLocRib(_)
            | StatisticsCounter::Experimental65531(_)
            | StatisticsCounter::Experimental65532(_)
            | StatisticsCounter::Experimental65533(_)
            | StatisticsCounter::Experimental65534(_)
            | StatisticsCounter::NumberOfUpdatesSubjectedToTreatAsWithdraw(_)
            | StatisticsCounter::NumberOfPrefixesSubjectedToTreatAsWithdraw(_)
            | StatisticsCounter::NumberOfDuplicateUpdateMessagesReceived(_)
            | StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibOut(_)
            | StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibOut(_)
            | StatisticsCounter::Unknown(_, _) => Ok(None),

            StatisticsCounter::NumberOfRoutesInPerAfiSafiAdjRibIn(address_type, _)
            | StatisticsCounter::NumberOfRoutesInPerAfiSafiLocRib(address_type, _)
            | StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(address_type, _)
            | StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(address_type, _) => {
                let afi = address_type.address_family();
                let safi = address_type.subsequent_address_family();

                let afi_t = afi_t::try_convert_from(afi);
                let afi_t = if afi_t.is_err() {
                    return Err(*address_type);
                } else {
                    afi_t.unwrap()
                };

                let safi_t = safi_t::try_convert_from(safi);
                let safi_t = if safi_t.is_err() {
                    return Err(*address_type);
                } else {
                    safi_t.unwrap()
                };

                Ok(Some((afi_t, safi_t)))
            }
        };
    }

    fn get_value_as_u64(&self) -> Result<u64, ()> {
        match self {
            StatisticsCounter::NumberOfPrefixesRejectedByInboundPolicy(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfDuplicatePrefixAdvertisements(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfDuplicateWithdraws(stat) => Ok(stat.value() as u64),
            StatisticsCounter::NumberOfUpdatesInvalidatedDueToClusterListLoop(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsPathLoop(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfUpdatesInvalidatedDueToOriginatorId(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfUpdatesInvalidatedDueToAsConfederationLoop(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfRoutesInAdjRibIn(stat) => Ok(stat.value()),
            StatisticsCounter::NumberOfRoutesInLocRib(stat) => Ok(stat.value()),
            StatisticsCounter::NumberOfRoutesInPerAfiSafiAdjRibIn(_, stat) => Ok(stat.value()),
            StatisticsCounter::NumberOfRoutesInPerAfiSafiLocRib(_, stat) => Ok(stat.value()),
            StatisticsCounter::NumberOfUpdatesSubjectedToTreatAsWithdraw(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfPrefixesSubjectedToTreatAsWithdraw(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfDuplicateUpdateMessagesReceived(stat) => {
                Ok(stat.value() as u64)
            }
            StatisticsCounter::NumberOfRoutesInPrePolicyAdjRibOut(stat) => Ok(stat.value()),
            StatisticsCounter::NumberOfRoutesInPostPolicyAdjRibOut(stat) => Ok(stat.value()),
            StatisticsCounter::NumberOfRoutesInPerAfiSafiPrePolicyAdjRibOut(_, stat) => {
                Ok(stat.value())
            }
            StatisticsCounter::NumberOfRoutesInPerAfiSafiPostPolicyAdjRibOut(_, stat) => {
                Ok(stat.value())
            }
            StatisticsCounter::Experimental65531(_)
            | StatisticsCounter::Experimental65532(_)
            | StatisticsCounter::Experimental65533(_)
            | StatisticsCounter::Experimental65534(_)
            | StatisticsCounter::Unknown(_, _) => Err(()),
        }
    }
}
