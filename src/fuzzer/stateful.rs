use bytes::Bytes;
use crate::fuzzer::strategies::{FuzzingStrategy, FuzzingResult};
use async_trait::async_trait;
use crate::core::ProtocolFSM;

pub struct StatefulFuzzingStrategy {
    state_machine: ProtocolFSM,
    max_depth: u32,
    current_depth: u32,
}

impl StatefulFuzzingStrategy {
    pub fn new(state_machine: ProtocolFSM, max_depth: u32) -> Self {
        Self {
            state_machine,
            max_depth,
            current_depth: 0,
        }
    }
}

#[async_trait]
impl FuzzingStrategy for StatefulFuzzingStrategy {
    fn name(&self) -> &str {
        "stateful"
    }

    async fn generate_input(&mut self) -> Bytes {
        // TODO: Generate input based on current state
        Bytes::from("test input")
    }

    async fn update_with_result(&mut self, _result: FuzzingResult) {
        // TODO: Update state machine based on result
        self.current_depth += 1;
    }
}
