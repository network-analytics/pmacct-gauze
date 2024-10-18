use netgauze_bgp_pkt::iana::{
    BgpErrorNotificationCode, CeaseErrorSubCode, FiniteStateMachineErrorSubCode,
    MessageHeaderErrorSubCode, OpenMessageErrorSubCode, RouteRefreshMessageErrorSubCode,
    UpdateMessageErrorSubCode,
};
use netgauze_bgp_pkt::notification::{
    BgpNotificationMessage, CeaseError, FiniteStateMachineError, HoldTimerExpiredError,
    MessageHeaderError, OpenMessageError, RouteRefreshError, UpdateMessageError,
};

pub trait ExtendBgpNotificationMessage {
    fn code(&self) -> BgpErrorNotificationCode;
    fn raw_subcode(&self) -> u8;
    fn value_ptr(&self) -> &[u8];
}

impl ExtendBgpNotificationMessage for BgpNotificationMessage {
    fn code(&self) -> BgpErrorNotificationCode {
        match self {
            BgpNotificationMessage::MessageHeaderError(_) => {
                BgpErrorNotificationCode::MessageHeaderError
            }
            BgpNotificationMessage::OpenMessageError(_) => {
                BgpErrorNotificationCode::OpenMessageError
            }
            BgpNotificationMessage::UpdateMessageError(_) => {
                BgpErrorNotificationCode::UpdateMessageError
            }
            BgpNotificationMessage::HoldTimerExpiredError(_) => {
                BgpErrorNotificationCode::HoldTimerExpired
            }
            BgpNotificationMessage::FiniteStateMachineError(_) => {
                BgpErrorNotificationCode::FiniteStateMachineError
            }
            BgpNotificationMessage::CeaseError(_) => BgpErrorNotificationCode::Cease,
            BgpNotificationMessage::RouteRefreshError(_) => {
                BgpErrorNotificationCode::RouteRefreshMessageError
            }
        }
    }

    fn raw_subcode(&self) -> u8 {
        match self {
            BgpNotificationMessage::MessageHeaderError(error) => match error {
                MessageHeaderError::Unspecific { .. } => {
                    MessageHeaderErrorSubCode::Unspecific as u8
                }
                MessageHeaderError::ConnectionNotSynchronized { .. } => {
                    MessageHeaderErrorSubCode::ConnectionNotSynchronized as u8
                }
                MessageHeaderError::BadMessageLength { .. } => {
                    MessageHeaderErrorSubCode::BadMessageLength as u8
                }
                MessageHeaderError::BadMessageType { .. } => {
                    MessageHeaderErrorSubCode::BadMessageType as u8
                }
            },
            BgpNotificationMessage::OpenMessageError(error) => match error {
                OpenMessageError::Unspecific { .. } => OpenMessageErrorSubCode::Unspecific as u8,
                OpenMessageError::UnsupportedVersionNumber { .. } => {
                    OpenMessageErrorSubCode::UnsupportedVersionNumber as u8
                }
                OpenMessageError::BadPeerAs { .. } => OpenMessageErrorSubCode::BadPeerAs as u8,
                OpenMessageError::BadBgpIdentifier { .. } => {
                    OpenMessageErrorSubCode::BadBgpIdentifier as u8
                }
                OpenMessageError::UnsupportedOptionalParameter { .. } => {
                    OpenMessageErrorSubCode::UnsupportedOptionalParameter as u8
                }
                OpenMessageError::UnacceptableHoldTime { .. } => {
                    OpenMessageErrorSubCode::UnacceptableHoldTime as u8
                }
                OpenMessageError::UnsupportedCapability { .. } => {
                    OpenMessageErrorSubCode::UnsupportedCapability as u8
                }
                OpenMessageError::RoleMismatch { .. } => {
                    OpenMessageErrorSubCode::RoleMismatch as u8
                }
            },
            BgpNotificationMessage::UpdateMessageError(error) => match error {
                UpdateMessageError::Unspecific { .. } => {
                    UpdateMessageErrorSubCode::Unspecific as u8
                }
                UpdateMessageError::MalformedAttributeList { .. } => {
                    UpdateMessageErrorSubCode::MalformedAttributeList as u8
                }
                UpdateMessageError::UnrecognizedWellKnownAttribute { .. } => {
                    UpdateMessageErrorSubCode::UnrecognizedWellKnownAttribute as u8
                }
                UpdateMessageError::MissingWellKnownAttribute { .. } => {
                    UpdateMessageErrorSubCode::MissingWellKnownAttribute as u8
                }
                UpdateMessageError::AttributeFlagsError { .. } => {
                    UpdateMessageErrorSubCode::AttributeFlagsError as u8
                }
                UpdateMessageError::AttributeLengthError { .. } => {
                    UpdateMessageErrorSubCode::AttributeLengthError as u8
                }
                UpdateMessageError::InvalidOriginAttribute { .. } => {
                    UpdateMessageErrorSubCode::InvalidOriginAttribute as u8
                }
                UpdateMessageError::InvalidNextHopAttribute { .. } => {
                    UpdateMessageErrorSubCode::InvalidNextHopAttribute as u8
                }
                UpdateMessageError::OptionalAttributeError { .. } => {
                    UpdateMessageErrorSubCode::OptionalAttributeError as u8
                }
                UpdateMessageError::InvalidNetworkField { .. } => {
                    UpdateMessageErrorSubCode::InvalidNetworkField as u8
                }
                UpdateMessageError::MalformedAsPath { .. } => {
                    UpdateMessageErrorSubCode::MalformedAsPath as u8
                }
            },
            BgpNotificationMessage::HoldTimerExpiredError(error) => match error {
                HoldTimerExpiredError::Unspecific { .. } => 0,
            },
            BgpNotificationMessage::FiniteStateMachineError(error) => match error {
                FiniteStateMachineError::Unspecific { .. } => {
                    FiniteStateMachineErrorSubCode::UnspecifiedError as u8
                }
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState { .. } => {
                    FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenSentState as u8
                }
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState { .. } => {
                    FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInOpenConfirmState as u8
                }
                FiniteStateMachineError::ReceiveUnexpectedMessageInEstablishedState { .. } => {
                    FiniteStateMachineErrorSubCode::ReceiveUnexpectedMessageInEstablishedState as u8
                }
            },
            BgpNotificationMessage::CeaseError(error) => match error {
                CeaseError::MaximumNumberOfPrefixesReached { .. } => {
                    CeaseErrorSubCode::MaximumNumberOfPrefixesReached as u8
                }
                CeaseError::AdministrativeShutdown { .. } => {
                    CeaseErrorSubCode::AdministrativeShutdown as u8
                }
                CeaseError::PeerDeConfigured { .. } => CeaseErrorSubCode::PeerDeConfigured as u8,
                CeaseError::AdministrativeReset { .. } => {
                    CeaseErrorSubCode::AdministrativeReset as u8
                }
                CeaseError::ConnectionRejected { .. } => {
                    CeaseErrorSubCode::ConnectionRejected as u8
                }
                CeaseError::OtherConfigurationChange { .. } => {
                    CeaseErrorSubCode::OtherConfigurationChange as u8
                }
                CeaseError::ConnectionCollisionResolution { .. } => {
                    CeaseErrorSubCode::ConnectionCollisionResolution as u8
                }
                CeaseError::OutOfResources { .. } => CeaseErrorSubCode::OutOfResources as u8,
                CeaseError::HardReset { .. } => CeaseErrorSubCode::HardReset as u8,
                CeaseError::BfdDown { .. } => CeaseErrorSubCode::BfdDown as u8,
            },
            BgpNotificationMessage::RouteRefreshError(error) => match error {
                RouteRefreshError::InvalidMessageLength { .. } => {
                    RouteRefreshMessageErrorSubCode::InvalidMessageLength as u8
                }
            },
        }
    }

    fn value_ptr(&self) -> &[u8] {
        match self {
            BgpNotificationMessage::MessageHeaderError(error) => match error {
                MessageHeaderError::Unspecific { value, .. } => value,
                MessageHeaderError::ConnectionNotSynchronized { value, .. } => value,
                MessageHeaderError::BadMessageLength { value, .. } => value,
                MessageHeaderError::BadMessageType { value, .. } => value,
            },
            BgpNotificationMessage::OpenMessageError(error) => match error {
                OpenMessageError::Unspecific { value, .. } => value,
                OpenMessageError::UnsupportedVersionNumber { value, .. } => value,
                OpenMessageError::BadPeerAs { value, .. } => value,
                OpenMessageError::BadBgpIdentifier { value, .. } => value,
                OpenMessageError::UnsupportedOptionalParameter { value, .. } => value,
                OpenMessageError::UnacceptableHoldTime { value, .. } => value,
                OpenMessageError::UnsupportedCapability { value, .. } => value,
                OpenMessageError::RoleMismatch { value, .. } => value,
            },
            BgpNotificationMessage::UpdateMessageError(error) => match error {
                UpdateMessageError::Unspecific { value, .. } => value,
                UpdateMessageError::MalformedAttributeList { value, .. } => value,
                UpdateMessageError::UnrecognizedWellKnownAttribute { value, .. } => value,
                UpdateMessageError::MissingWellKnownAttribute { value, .. } => value,
                UpdateMessageError::AttributeFlagsError { value, .. } => value,
                UpdateMessageError::AttributeLengthError { value, .. } => value,
                UpdateMessageError::InvalidOriginAttribute { value, .. } => value,
                UpdateMessageError::InvalidNextHopAttribute { value, .. } => value,
                UpdateMessageError::OptionalAttributeError { value, .. } => value,
                UpdateMessageError::InvalidNetworkField { value, .. } => value,
                UpdateMessageError::MalformedAsPath { value, .. } => value,
            },
            BgpNotificationMessage::HoldTimerExpiredError(error) => match error {
                HoldTimerExpiredError::Unspecific { value, .. } => value,
            },
            BgpNotificationMessage::FiniteStateMachineError(error) => match error {
                FiniteStateMachineError::Unspecific { value, .. } => value,
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenSentState {
                    value, ..
                } => value,
                FiniteStateMachineError::ReceiveUnexpectedMessageInOpenConfirmState {
                    value,
                    ..
                } => value,
                FiniteStateMachineError::ReceiveUnexpectedMessageInEstablishedState {
                    value,
                    ..
                } => value,
            },
            BgpNotificationMessage::CeaseError(error) => match error {
                CeaseError::MaximumNumberOfPrefixesReached { value, .. } => value,
                CeaseError::AdministrativeShutdown { value, .. } => value,
                CeaseError::PeerDeConfigured { value, .. } => value,
                CeaseError::AdministrativeReset { value, .. } => value,
                CeaseError::ConnectionRejected { value, .. } => value,
                CeaseError::OtherConfigurationChange { value, .. } => value,
                CeaseError::ConnectionCollisionResolution { value, .. } => value,
                CeaseError::OutOfResources { value, .. } => value,
                CeaseError::HardReset { value, .. } => value,
                CeaseError::BfdDown { value, .. } => value,
            },
            BgpNotificationMessage::RouteRefreshError(error) => match error {
                RouteRefreshError::InvalidMessageLength { value, .. } => value,
            },
        }
    }
}
