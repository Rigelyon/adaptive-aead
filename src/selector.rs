//! Security-constrained adaptive AEAD selector with static-lookup vs online-EMA and hysteresis.

use crate::crypto::{Algorithm, CryptoError, SecurityPolicy};
use crate::profile::RuntimeProfile;

/// Selection strategy evaluated in experiments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SelectionPolicy {
    Static(Algorithm),
    Lookup,
    LookupHysteresis { delta: f64 },
    AdaptiveEma,
    AdaptiveEmaHysteresis { delta: f64 },
}

impl SelectionPolicy {
    pub fn label(&self) -> String {
        match self {
            Self::Static(alg) => format!("Static({})", alg.name()),
            Self::Lookup => "Lookup(d=0.00)".to_string(),
            Self::LookupHysteresis { delta } => format!("Lookup+Hyst(d={delta:.2})"),
            Self::AdaptiveEma => "AdaptiveEMA(d=0.00)".to_string(),
            Self::AdaptiveEmaHysteresis { delta } => format!("AdaptiveEMA+Hyst(d={delta:.2})"),
        }
    }

    pub fn key(&self) -> String {
        match self {
            Self::Static(alg) => format!("static:{}", alg.id()),
            Self::Lookup => "lookup:0.00".to_string(),
            Self::LookupHysteresis { delta } => format!("lookup:{delta:.2}"),
            Self::AdaptiveEma => "ema:0.00".to_string(),
            Self::AdaptiveEmaHysteresis { delta } => format!("ema:{delta:.2}"),
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        let (kind, val) = key.split_once(':')?;
        match kind {
            "static" => {
                let id: u8 = val.parse().ok()?;
                Some(Self::Static(Algorithm::from_id(id).ok()?))
            }
            "lookup" => {
                let d: f64 = val.parse().ok()?;
                if d <= 0.0 {
                    Some(Self::Lookup)
                } else {
                    Some(Self::LookupHysteresis { delta: d })
                }
            }
            "ema" => {
                let d: f64 = val.parse().ok()?;
                if d <= 0.0 {
                    Some(Self::AdaptiveEma)
                } else {
                    Some(Self::AdaptiveEmaHysteresis { delta: d })
                }
            }
            _ => None,
        }
    }

    pub const fn delta(&self) -> f64 {
        match self {
            Self::Static(_) | Self::Lookup | Self::AdaptiveEma => 0.0,
            Self::LookupHysteresis { delta } | Self::AdaptiveEmaHysteresis { delta } => *delta,
        }
    }

    pub const fn uses_ema(&self) -> bool {
        matches!(self, Self::AdaptiveEma | Self::AdaptiveEmaHysteresis { .. })
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

    /// Selects the algorithm for an upcoming file/batch item of `size_bytes` under `security`.
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

    /// Updates online EMA telemetry only if the policy uses online EMA feedback.
    pub fn observe(&mut self, alg: Algorithm, size_bytes: usize, observed_ns: f64) {
        if self.policy.uses_ema() {
            self.profile.observe(alg, size_bytes, observed_ns);
        }
    }
}
