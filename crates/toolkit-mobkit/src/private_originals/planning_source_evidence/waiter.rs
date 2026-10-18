//! Explicit configured A evidence and historical source custody for one cohort.
//! This does not create the A-to-G delegation required by waiter effect custody.
use super::*;
use meerkat_core::MobMemberBinding;
use meerkat_toolkit::setup::SetupWorkflowRef;

impl PrivateOriginals {
    pub(in crate::private_originals) async fn check_workflow_waiter_binding(
        &self, record: &SourceRecord, reference: &PrivateOriginalRef,
    ) -> Result<(), PrivateOriginalError> {
        let Some(PlanningSourceEvidence::Waiter { planning, .. }) = &record.planning_source_evidence else { return Ok(()); };
        let member = record.configured_setup.as_ref().and_then(|saved| saved.capability.helper.as_ref())
            .ok_or(PrivateOriginalError::Conflict)?;
        self.check_workflow_waiter_profile(record, reference, planning, member).await?;
        self.check_historical_setup_selection(record, reference).await
    }

    pub(in crate::private_originals) async fn select_workflow_waiter_evidence(
        &self, workflow: &SetupWorkflowRef, planning: &PrivateOriginalRef,
        member: &MobMemberBinding, reference: &PrivateOriginalRef,
    ) -> Result<(), PrivateOriginalError> {
        let row = self.store.get(&self.key(reference)?).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let record = self.decode_record(&row, reference)?;
        self.check_workflow_waiter_profile(&record, reference, planning, member).await?;
        self.select_planning_source_evidence(reference, PlanningSourceEvidence::Waiter {
            workflow: workflow.clone(), planning: planning.clone(),
        }).await
    }

    async fn check_workflow_waiter_profile(
        &self, record: &SourceRecord, reference: &PrivateOriginalRef,
        planning: &PrivateOriginalRef, member: &MobMemberBinding,
    ) -> Result<(), PrivateOriginalError> {
        self.check_planning_evidence_source(record, reference)?;
        if reference == planning || !record.event.contributors.is_empty()
            || record.approved_task.is_some() || record.service_admission.is_some()
            || record.setup_request.is_some()
        { return Err(PrivateOriginalError::Denied); }
        let lifetime = self.host_lifetime.get().and_then(Weak::upgrade).ok_or(PrivateOriginalError::Unavailable)?;
        let selected = lifetime.selected_policy();
        let native = selected.native_host.as_ref().ok_or(PrivateOriginalError::Unavailable)?;
        let route = native.routes.iter().find(|row| row.id == reference.route).ok_or(PrivateOriginalError::Denied)?;
        let binding = route.source_binding(selected).map_err(|_| PrivateOriginalError::Denied)?.0;
        let capability = native.members.iter().find(|row| &row.member == binding)
            .and_then(|row| row.setup_capability.as_ref()).ok_or(PrivateOriginalError::Unavailable)?;
        // This first profile matches the actual SDK cohort. A configured Find
        // child has no helper effect targets and cannot delegate another child.
        if capability.route != reference.route || capability.helper.as_ref() != Some(member)
            || !capability.helper_targets.is_empty()
            || record.configured_setup.as_ref().is_some_and(|saved| &saved.capability != capability)
        { return Err(PrivateOriginalError::Conflict); }
        let row = self.store.get(&self.key(planning)?).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let lead = self.decode_record(&row, planning)?;
        self.check_planning_evidence_source(&lead, planning)?;
        let lead_route = native.routes.iter().find(|row| row.id == planning.route).ok_or(PrivateOriginalError::Denied)?;
        if lead_route.source_binding(selected).map_err(|_| PrivateOriginalError::Denied)?.0 != member
            || lead.event.contributors.len() != 1 || lead.source.requester != record.source.requester
            || lead.source.realm != record.source.realm || lead.source.source_authority != record.source.source_authority
        { return Err(PrivateOriginalError::Conflict); }
        Ok(())
    }

    pub(in crate::private_originals) async fn restore_workflow_waiter_source(
        &self, workflow: &SetupWorkflowRef, planning: &PrivateOriginalRef,
        member: &MobMemberBinding, reference: &PrivateOriginalRef,
    ) -> Result<(), PrivateOriginalError> {
        let writer = self.owner.try_source_writer().map_err(writer_error)?;
        let (_, stamp) = self.owner.publication().observe(|| ()).map_err(|_| PrivateOriginalError::Unavailable)?;
        let row = self.store.get(&self.key(reference)?).await.map_err(store_error)?
            .ok_or(PrivateOriginalError::Unavailable)?;
        let record = self.decode_record(&row, reference)?;
        if record.planning_source_evidence != Some(PlanningSourceEvidence::Waiter {
            workflow: workflow.clone(), planning: planning.clone(),
        }) { return Err(PrivateOriginalError::Unavailable); }
        self.check_workflow_waiter_profile(&record, reference, planning, member).await?;
        if record.operation_cancelled { return Err(PrivateOriginalError::Denied); }
        let snapshot = self.workflow_store()?.load_setup_workflow(workflow).await.map_err(|_| PrivateOriginalError::Unavailable)?;
        let terms = snapshot.terms();
        if terms.planning_source != self.key(planning)? || &terms.lead != member
            || terms.requester != record.source.requester || terms.realm != record.source.realm
        { return Err(PrivateOriginalError::Conflict); }
        // No canonical waiter count is treated as a currentness fence. This
        // restores only A custody; G's incomplete attachment remains restricted.
        self.check_historical_setup_selection(&record, reference).await?;
        let association = record.final_association.as_ref().ok_or(PrivateOriginalError::Unavailable)?;
        let input = record.bound_service_input.as_ref().ok_or(PrivateOriginalError::Unavailable)?.decode()?;
        if input.header().authority_association.as_ref() != Some(association) { return Err(PrivateOriginalError::Conflict); }
        let claims = association.candidate();
        let WorkAuthorityBasis::GrantLineage { lineage } = &claims.authority_basis else { return Err(PrivateOriginalError::Conflict); };
        let grants = self.owner.grants();
        let operation = grants.resolve_lineage(lineage, &claims.logical_executor, claims.represented_subject.as_ref())
            .map_err(|error| writer_error(OriginalWriterError::Grant(error)))?;
        let controller = grants.resolve_controller_lineage(&claims.controller_grant_lineage,
            &claims.logical_executor, claims.represented_subject.as_ref())
            .map_err(|error| writer_error(OriginalWriterError::Grant(error)))?;
        let session = meerkat_core::SessionId::parse(claims.target.context.as_str()).map_err(|_| PrivateOriginalError::Conflict)?;
        let sources = [OriginalCancellationSource { realm: record.source.realm.clone(), original: claims.original_work.clone(),
            record: Arc::new(row), association: Some(association.clone()) }];
        stamp.check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
        drop(writer);
        let machine = self.machine()?;
        let pins = self.controller_pin_source.get().and_then(Weak::upgrade).ok_or(PrivateOriginalError::Unavailable)?;
        let registration = machine.current_session_registration_witness(&session).await.ok_or(PrivateOriginalError::Unavailable)?;
        let attachment = machine.current_executor_attachment_witness(&session).await.ok_or(PrivateOriginalError::Unavailable)?;
        let actor = pins.live_actor(&session).await.ok_or(PrivateOriginalError::Unavailable)?;
        let custody = AuthenticatedOriginal {
            original_work: claims.original_work.clone(), occurrence_scope: claims.ingress_namespace.occurrence_scope.clone(),
            original_authentication: claims.original_authentication.clone(), root_event: claims.root_event.clone(),
            contributing_work: claims.contributing_work.clone(), target: claims.target.clone(), authority_basis: claims.authority_basis.clone(),
        };
        let observed = machine.with_admitted_original(&registration, &attachment, &actor.executor_actor_identity(), &input, |admitted| {
            let _writer = self.owner.try_source_writer().map_err(writer_error)?;
            stamp.check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
            operation.check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
            controller.check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
            if admitted.input_id() != input.id() { return Err(PrivateOriginalError::Conflict); }
            self.owner.promote_historical_task(association, custody, &sources, admitted).map_err(writer_error)
        }).await;
        let retained = match observed {
            Ok(result) => result?,
            Err(AdmittedOriginalRefusal::Conflict) => return Err(PrivateOriginalError::Conflict),
            Err(AdmittedOriginalRefusal::NotAdmitted | AdmittedOriginalRefusal::Unavailable) => return Err(PrivateOriginalError::Unavailable),
        };
        self.hold_binding(reference.clone(), retained).await
    }
}
