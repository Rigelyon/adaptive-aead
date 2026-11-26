//! Security-constrained adaptive AEAD selector with relative hysteresis.

use crate::crypto::{Algorithm, CryptoError, SecurityPolicy};
use crate::profile::RuntimeProfile;

/// Selection strategy evaluated in experiments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SelectionPolicy {
    Static(Algorithm),
    Adaptive,
    AdaptiveHysteresis { delta: f64 },
}

impl SelectionPolicy {
    pub fn label(&self) -> String {
        match self {
            Self::Static(alg) => format!("Static({})", alg.name()),
            Self::Adaptive => "Adaptive(d=0.00)".to_string(),
            Self::AdaptiveHysteresis { delta } => format!("Adaptive+Hyst(d={delta:.2})"),
        }
    }

    pub const fn delta(&self) -> f64 {
        match self {
            Self::Static(_) | Self::Adaptive => 0.0,
            Self::AdaptiveHysteresis { delta } => *delta,
        }
    }
}

/// Explanation for why the selector kept or switched the active algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    Initial,
    AlreadyOptimal,
    HysteresisHeld,
    ThresholdExceeded,
    SecurityOverride,
    StaticFixed,
}

/// Result of a per-file selection step.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SelectionDecision {
    pub chosen: Algorithm,
    pub switched: bool,
    pub reason: SwitchReason,
    pub relative_gain: f64,
}

/// Stateful selector combining calibrated/EMA profiling, security gate, and hysteresis.
#[derive(Debug, Clone)]
pub struct AdaptiveSelector {
    policy: SelectionPolicy,
    profile: RuntimeProfile,
    active: Option<Algorithm>,
}

impl AdaptiveSelector {
    pub fn new(policy: SelectionPolicy, profile: RuntimeProfile) -> Self {
        Self {
            policy,
            profile,
            active: None,
        }
    }

    pub const fn active(&self) -> Option<Algorithm> {
        self.active
    }

    pub const fn policy(&self) -> SelectionPolicy {
        self.policy
    }

    /// Selects the algorithm for an upcoming file of `size_bytes` under `security`.
    pub fn select_for(
        &mut self,
        size_bytes: usize,
        security: &SecurityPolicy,
    ) -> Result<SelectionDecision, CryptoError> {
        if let SelectionPolicy::Static(fixed) = self.policy {
            security.validate(fixed)?;
            let switched = matches!(self.active, Some(prev) if prev != fixed);
            self.active = Some(fixed);
            return Ok(SelectionDecision {
                chosen: fixed,
                switched,
                reason: SwitchReason::StaticFixed,
                relative_gain: 0.0,
            });
        }

        let eligible = security.eligible_algorithms();
        if eligible.is_empty() {
            return Err(CryptoError::PolicyViolation("no eligible algorithms satisfy policy"));
        }

        let (best, best_cost) = eligible
            .iter()
            .copied()
            .map(|alg| (alg, self.profile.predicted_ns(alg, size_bytes)))
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .ok_or(CryptoError::PolicyViolation("no eligible algorithms satisfy policy"))?;

        let Some(current) = self.active else {
            self.active = Some(best);
            return Ok(SelectionDecision {
                chosen: best,
                switched: false,
                reason: SwitchReason::Initial,
                relative_gain: 0.0,
            });
        };

        if security.validate(current).is_err() {
            self.active = Some(best);
            return Ok(SelectionDecision {
                chosen: best,
                switched: current != best,
                reason: SwitchReason::SecurityOverride,
                relative_gain: 1.0,
            });
        }

        if best == current {
            return Ok(SelectionDecision {
                chosen: current,
                switched: false,
                reason: SwitchReason::AlreadyOptimal,
                relative_gain: 0.0,
            });
        }

        let current_cost = self.profile.predicted_ns(current, size_bytes);
        let relative_gain = if current_cost > 0.0 {
            (current_cost - best_cost) / current_cost
        } else {
            0.0
        };

        let delta = self.policy.delta();
        if relative_gain > delta {
            self.active = Some(best);
            Ok(SelectionDecision {
                chosen: best,
                switched: true,
                reason: SwitchReason::ThresholdExceeded,
                relative_gain,
            })
        } else {
            Ok(SelectionDecision {
                chosen: current,
                switched: false,
                reason: SwitchReason::HysteresisHeld,
                relative_gain,
            })
        }
    }

    /// Feeds real observed latency back into the online EMA profile.
    pub fn observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64) {
        self.profile.observe(alg, size_bytes, observed_ns);
    }
}
