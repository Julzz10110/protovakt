use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct State(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Event(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub from: State,
    pub to: State,
    pub event: Event,
    pub guard: Option<String>, // Condition expression
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub name: String,
    pub check: String, // Validation logic
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub name: String,
    pub condition: String, // Invariant expression
}

#[derive(Debug, Clone)]
pub struct ProtocolFSM {
    pub states: Vec<State>,
    pub initial_state: State,
    pub transitions: Vec<Transition>,
    pub validators: Vec<Validator>,
    pub invariants: Vec<Invariant>,
    pub current_state: State,
}

impl ProtocolFSM {
    pub fn new(initial_state: State) -> Self {
        Self {
            states: vec![initial_state.clone()],
            initial_state: initial_state.clone(),
            transitions: vec![],
            validators: vec![],
            invariants: vec![],
            current_state: initial_state,
        }
    }

    pub fn add_state(&mut self, state: State) {
        if !self.states.contains(&state) {
            self.states.push(state);
        }
    }

    pub fn add_transition(&mut self, transition: Transition) {
        self.transitions.push(transition);
    }

    pub fn can_transition(&self, event: &Event) -> Option<&Transition> {
        self.transitions
            .iter()
            .find(|t| t.from == self.current_state && t.event == *event)
    }

    pub fn transition(&mut self, event: &Event) -> Result<(), String> {
        if let Some(transition) = self.can_transition(event) {
            // TODO: Check guard condition
            self.current_state = transition.to.clone();
            Ok(())
        } else {
            Err(format!(
                "Invalid transition from {:?} on event {:?}",
                self.current_state, event
            ))
        }
    }

    pub fn reset(&mut self) {
        self.current_state = self.initial_state.clone();
    }
}
