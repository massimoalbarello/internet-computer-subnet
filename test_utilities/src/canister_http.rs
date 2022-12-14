use ic_base_types::NumBytes;
use ic_interfaces::canister_http::{
    CanisterHttpPayloadBuilder, CanisterHttpPayloadValidationError,
};
use ic_types::{
    batch::{CanisterHttpPayload, ValidationContext},
    canister_http::CanisterHttpResponseWithConsensus,
    CountBytes, Height,
};

// TODO: Allow for timeouts in payload builder
#[derive(Default)]
pub struct FakeCanisterHttpPayloadBuilder(Vec<CanisterHttpResponseWithConsensus>);

impl FakeCanisterHttpPayloadBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_responses(mut self, responses: Vec<CanisterHttpResponseWithConsensus>) -> Self {
        self.0 = responses;
        self
    }

    pub fn build(&self) -> CanisterHttpPayload {
        CanisterHttpPayload {
            responses: self.0.clone(),
            timeouts: vec![],
            divergence_responses: vec![],
        }
    }
}

impl CanisterHttpPayloadBuilder for FakeCanisterHttpPayloadBuilder {
    fn get_canister_http_payload(
        &self,
        _height: Height,
        _validation_context: &ValidationContext,
        _past_payloads: &[&CanisterHttpPayload],
        _byte_limit: NumBytes,
    ) -> CanisterHttpPayload {
        CanisterHttpPayload {
            responses: self.0.clone(),
            timeouts: vec![],
            divergence_responses: vec![],
        }
    }

    fn validate_canister_http_payload(
        &self,
        _height: Height,
        payload: &CanisterHttpPayload,
        _validation_context: &ValidationContext,
        _past_payloads: &[&CanisterHttpPayload],
    ) -> Result<NumBytes, CanisterHttpPayloadValidationError> {
        Ok(NumBytes::new(payload.count_bytes() as u64))
    }
}
