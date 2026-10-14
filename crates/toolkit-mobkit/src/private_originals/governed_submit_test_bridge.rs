//! Faults surround actual native delivery. Helper controls also hold before
//! native lookup; all ordinary bridge operations and results are delegated.

use super::*;
use meerkat_core::types::HandlingMode;
use meerkat_mob::ids::AgentIdentity as MobAgentIdentity;
use meerkat_mobkit::actor_loop_health::ActorLoopHealth;
use meerkat_mobkit::identity_first::*;

pub(super) struct ObservedBridge {
    pub inner: MobSessionBridge,
    pub fault: Arc<DeliveryFault>,
    pub publication: meerkat_authorization::publication::LocalAuthorizationPublication,
}

impl ObservedBridge {
    async fn observe_governed_delivery(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &SessionId,
        input: meerkat_runtime::Input,
        custody: GovernedDeliveryCustody,
        internal: bool,
    ) -> Result<GovernedDelivery, BridgeAdmissionError> {
        if matches!(self.fault.mode, DeliveryMode::RefuseSecondBeforeLookup)
            && self.fault.accepted.load(Ordering::SeqCst) >= 1
        {
            // The real B binder and evidence write completed, but the actual
            // native bridge has not been called for B. No admission is invented.
            return Err(BridgeAdmissionError::GovernedInput(GovernedInputError::AdmissionUnresolved {
                detail: "injected refusal before second native lookup".into(),
            }));
        }
        let helper_control = matches!(self.fault.mode,
            DeliveryMode::HoldHelperBeforeLookup | DeliveryMode::HoldHelperAcceptedReply);
        if helper_control {
            if self.fault.helper_session.get() != Some(session_id) {
                return self.delegate_governed_delivery(runtime_id, session_id, input, custody, internal).await;
            }
            // The production helper binder already returned its real input and
            // fence. Preserve both, and hold just before the native bridge's
            // member lookups; the native bridge performs those lookups itself.
            {
                let mut captured = self.fault.helper_input.lock().unwrap();
                assert!(captured.replace(input.id().clone()).is_none(),
                    "one actual helper delivery at this boundary");
            }
            if matches!(self.fault.mode, DeliveryMode::HoldHelperBeforeLookup) {
                self.fault.entered.notify_one();
                self.fault.release.acquire().await.unwrap().forget();
            }
        }
        let real = self
            .delegate_governed_delivery(runtime_id, session_id, input, custody, internal)
            .await;
        if helper_control {
            self.fault.helper_returns.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(&real, Err(BridgeAdmissionError::GovernedInput(GovernedInputError::Mob(error)))
            if matches!(**error, meerkat_mob::MobError::MemberInputRefused { .. }))
        {
            self.fault.refused.fetch_add(1, Ordering::SeqCst);
        }
        if !matches!(&real, Ok(GovernedDelivery { admission: Some(a), .. }) if !a.deduplicated) {
            return real;
        }
        let accepted = self.fault.accepted.fetch_add(1, Ordering::SeqCst) + 1;
        match self.fault.mode {
            DeliveryMode::Normal | DeliveryMode::HoldHelperBeforeLookup | DeliveryMode::RefuseSecondBeforeLookup => {}
            DeliveryMode::HoldAccepted | DeliveryMode::HoldHelperAcceptedReply => {
                // Native admission is real and its reply is retained unchanged.
                // IdentityRuntime owns the entry permit and finishes it only
                // after this bridge await returns and it observes settlement.
                self.fault.entered.notify_one();
                self.fault.release.acquire().await.unwrap().forget();
            }
            DeliveryMode::LoseAcceptedAnswer | DeliveryMode::LoseSecondAcceptedAnswer if accepted >= 2
                || matches!(self.fault.mode, DeliveryMode::LoseAcceptedAnswer) => {
                return Err(BridgeAdmissionError::GovernedInput(
                    GovernedInputError::AdmissionUnresolved {
                        detail: "injected loss after native fresh acceptance".into(),
                    },
                ));
            }
            DeliveryMode::PoisonPublicationAfterAcceptance | DeliveryMode::PoisonPublicationAfterSecondAcceptance
                if accepted >= 2 || matches!(self.fault.mode, DeliveryMode::PoisonPublicationAfterAcceptance) => {
                // Poison this real publication only after native accepted.
                // Its ordinary source-publication path must report failure;
                // this adapter never manufactures an admission or settlement.
                let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _guard = self.publication.begin_owner_change().unwrap();
                    panic!("injected shared publication failure after native acceptance");
                }));
                assert!(poisoned.is_err());
            }
            DeliveryMode::LoseAcceptedAnswer | DeliveryMode::LoseSecondAcceptedAnswer
                | DeliveryMode::PoisonPublicationAfterAcceptance | DeliveryMode::PoisonPublicationAfterSecondAcceptance => {}
        }
        real
    }

    async fn delegate_governed_delivery(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &SessionId,
        input: meerkat_runtime::Input,
        custody: GovernedDeliveryCustody,
        internal: bool,
    ) -> Result<GovernedDelivery, BridgeAdmissionError> {
        if internal {
            self.inner
                .begin_internal_governed_delivery(runtime_id, session_id, input, custody)
                .await
        } else {
            self.inner
                .begin_governed_delivery(runtime_id, session_id, input, custody)
                .await
        }
    }
}

#[async_trait]
impl SessionBridge for ObservedBridge {
    async fn begin_governed_delivery(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &SessionId,
        input: meerkat_runtime::Input,
        custody: GovernedDeliveryCustody,
    ) -> Result<GovernedDelivery, BridgeAdmissionError> {
        self.observe_governed_delivery(runtime_id, session_id, input, custody, false)
            .await
    }

    async fn begin_internal_governed_delivery(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &SessionId,
        input: meerkat_runtime::Input,
        custody: GovernedDeliveryCustody,
    ) -> Result<GovernedDelivery, BridgeAdmissionError> {
        self.observe_governed_delivery(runtime_id, session_id, input, custody, true)
            .await
    }

    fn observe_actor_loop_health(&self, health: Arc<ActorLoopHealth>) {
        self.inner.observe_actor_loop_health(health);
    }

    async fn reload_member_registration(
        &self,
        runtime_id: &AgentRuntimeId,
    ) -> Result<Option<BridgeMemberReload>, BridgeError> {
        self.inner.reload_member_registration(runtime_id).await
    }

    async fn release_member_run_starts_for_published_tools(
        &self,
        member_id: &MobAgentIdentity,
    ) -> Result<(), BridgeError> {
        self.inner
            .release_member_run_starts_for_published_tools(member_id)
            .await
    }

    async fn member_durability(
        &self,
        session_id: &meerkat_core::types::SessionId,
    ) -> Option<MemberDurability> {
        self.inner.member_durability(session_id).await
    }

    async fn raw_member_alias_exists(&self, alias: &str) -> Result<bool, BridgeError> {
        self.inner.raw_member_alias_exists(alias).await
    }

    fn requires_resume_snapshot(&self) -> bool {
        self.inner.requires_resume_snapshot()
    }

    async fn recover_committed_boundary(
        &self,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<CommittedBoundaryRepair, BridgeError> {
        self.inner.recover_committed_boundary(session_id).await
    }

    async fn reset_member_to_successor(
        &self,
        identity: &AgentIdentity,
        spec: &DurableAgentSpec,
        draft: &AgentBuildDraft,
    ) -> Result<ResetSuccessorBinding, BridgeError> {
        self.inner
            .reset_member_to_successor(identity, spec, draft)
            .await
    }

    async fn create_session(
        &self,
        identity: &AgentIdentity,
        runtime_id: &AgentRuntimeId,
        spec: &DurableAgentSpec,
        draft: &AgentBuildDraft,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<meerkat_core::types::SessionId, BridgeError> {
        self.inner
            .create_session(identity, runtime_id, spec, draft, session_id)
            .await
    }

    async fn resume_session(
        &self,
        identity: &AgentIdentity,
        runtime_id: &AgentRuntimeId,
        spec: &DurableAgentSpec,
        draft: &AgentBuildDraft,
        session_id: &meerkat_core::types::SessionId,
        snapshot: &SessionSnapshot,
    ) -> Result<ResumeSessionOutcome, BridgeError> {
        self.inner
            .resume_session(identity, runtime_id, spec, draft, session_id, snapshot)
            .await
    }

    async fn deliver_admitted(
        &self,
        runtime_id: &AgentRuntimeId,
        delivery: BridgeDelivery,
    ) -> Result<meerkat_core::types::SessionId, BridgeError> {
        self.inner.deliver_admitted(runtime_id, delivery).await
    }

    async fn deliver_host_human_input(
        &self,
        runtime_id: &AgentRuntimeId,
        expected_session: &meerkat_core::SessionId,
        delivery: BridgeDelivery,
    ) -> Result<meerkat_core::SessionId, BridgeError> {
        self.inner
            .deliver_host_human_input(runtime_id, expected_session, delivery)
            .await
    }

    async fn begin_awaiting_commit(
        &self,
        runtime_id: &AgentRuntimeId,
        content: &meerkat_core::ContentInput,
        system_prompt: Option<&str>,
        injected_context: &[meerkat_core::ContentInput],
        handling_mode: HandlingMode,
        interaction_id: Option<&str>,
    ) -> Result<BridgeTurnReceipt, BridgeAdmissionError> {
        self.inner
            .begin_awaiting_commit(
                runtime_id,
                content,
                system_prompt,
                injected_context,
                handling_mode,
                interaction_id,
            )
            .await
    }

    fn tracks_turn_output(&self) -> bool {
        self.inner.tracks_turn_output()
    }

    async fn governed_controller(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<meerkat_core::ControllerModelClient, BridgeAdmissionError> {
        self.inner.governed_controller(runtime_id, session_id).await
    }

    async fn begin_delivery_with_output(
        &self,
        runtime_id: &AgentRuntimeId,
        delivery: BridgeDelivery,
    ) -> Result<BridgeTurnReceipt, BridgeAdmissionError> {
        self.inner
            .begin_delivery_with_output(runtime_id, delivery)
            .await
    }

    async fn checkpoint_session(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<SessionSnapshot, BridgeError> {
        self.inner.checkpoint_session(runtime_id, session_id).await
    }

    async fn retire_member(&self, runtime_id: &AgentRuntimeId) -> Result<(), BridgeError> {
        self.inner.retire_member(runtime_id).await
    }

    async fn retire_reset_superseded_member(
        &self,
        runtime_id: &AgentRuntimeId,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<(), BridgeError> {
        self.inner
            .retire_reset_superseded_member(runtime_id, session_id)
            .await
    }

    async fn wire_peer(&self, a: &AgentRuntimeId, b: &AgentRuntimeId) -> Result<(), BridgeError> {
        self.inner.wire_peer(a, b).await
    }

    async fn wire_peers_batch(
        &self,
        edges: &[(AgentRuntimeId, AgentRuntimeId)],
    ) -> Result<(), BridgeError> {
        self.inner.wire_peers_batch(edges).await
    }

    async fn current_member_wires(
        &self,
    ) -> Result<Vec<(AgentRuntimeId, AgentRuntimeId)>, BridgeError> {
        self.inner.current_member_wires().await
    }

    async fn current_member_wires_any_half(
        &self,
    ) -> Result<Vec<(AgentRuntimeId, AgentRuntimeId)>, BridgeError> {
        self.inner.current_member_wires_any_half().await
    }

    async fn unwire_peer(&self, a: &AgentRuntimeId, b: &AgentRuntimeId) -> Result<(), BridgeError> {
        self.inner.unwire_peer(a, b).await
    }

    async fn inspect_member(
        &self,
        runtime_id: &AgentRuntimeId,
    ) -> Result<MemberInspection, BridgeError> {
        self.inner.inspect_member(runtime_id).await
    }

    async fn register_session_runtime_state(
        &self,
        session_id: &meerkat_core::types::SessionId,
        identity: &AgentIdentity,
        generation: ContinuityGeneration,
        checkpoint_version: CheckpointVersion,
        fencing_token: FencingToken,
    ) -> Result<CheckpointVersion, BridgeError> {
        self.inner
            .register_session_runtime_state(
                session_id,
                identity,
                generation,
                checkpoint_version,
                fencing_token,
            )
            .await
    }

    async fn suspend_session_runtime_state(
        &self,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<(), BridgeError> {
        self.inner.suspend_session_runtime_state(session_id).await
    }

    async fn unregister_session_runtime_state(
        &self,
        session_id: &meerkat_core::types::SessionId,
    ) -> Result<(), BridgeError> {
        self.inner
            .unregister_session_runtime_state(session_id)
            .await
    }
}
