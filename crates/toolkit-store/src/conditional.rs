//! Conditional writes over participating records in the same physical backend.
//! These are storage predicates, not policy decisions or authority credentials.

use crate::{
    AdmissionOutcome, AdmissionRequest, EffectLease, RecordLease, StoreKey, StoreResult,
    ToolkitStore,
};
use async_trait::async_trait;

/// The application has read and authorized this exact owner record. Every
/// relevant writer must update this same record in this same store. A copy of
/// policy held by another owner does not fence that owner's changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordCondition {
    pub key: StoreKey,
    pub revision: u64,
    pub content_digest: String,
    pub claim: Option<RecordLease>,
    /// When publication originates from a claimed effect, its actual current
    /// Dispatch lease must also participate. Reconciliation never permits a
    /// new publication.
    pub dispatch_claim: Option<EffectLease>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalAdmission {
    pub admission: AdmissionRequest,
    pub conditions: Vec<RecordCondition>,
    /// Exclusive deadline checked with a fresh backend time after the final
    /// condition scan, before COMMIT. Disk sync and response delivery may finish
    /// later; this is a serialized admission decision, not a completion deadline.
    pub before_ms: i64,
}

/// Required extension for compositions that publish an immutable obligation
/// conditional on other owners' records. There is no preflight-then-write
/// default. A backend that lacks an equivalent atomic boundary cannot supply
/// this feature. The ordinary ToolkitStore remains useful without it.
#[async_trait]
pub trait ConditionalAdmissionStore: ToolkitStore {
    /// A new write checks all conditions atomically with record/events/effects.
    /// Exact replay returns Existing with the current record projection even
    /// after conditions expire. It proves matching initial admission identity,
    /// not which API created it or that these predicates held at that write.
    /// Both admission APIs share identity; replay may follow later record CAS.
    /// It neither restores permission nor starts another effect. The domain
    /// must authorize observation, validate the recovered record and own every
    /// writer for its namespace. Immutable conditional publication requires the
    /// domain to prevent ordinary creation and unauthorized later mutation.
    async fn admit_conditionally(
        &self,
        request: ConditionalAdmission,
    ) -> StoreResult<AdmissionOutcome>;
}
