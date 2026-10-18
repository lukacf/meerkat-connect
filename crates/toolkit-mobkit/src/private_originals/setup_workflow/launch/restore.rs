//! Reattach a canonical launch/delivery interest to actual restored A/P/G.
//! No request body leaves its owner and no Find, input or effect grant is made.
use super::*;
use crate::private_originals::{cold_service_admission::writer_error,
    planning_source_evidence::PlanningSourceEvidence};
use meerkat_authorization_contracts::work_association::WorkAuthorityBasis;
use meerkat_runtime::meerkat_machine::AdmittedOriginalRefusal;

#[cfg(test)]
tokio::task_local! {
    // Same-crate control only: pause after the real canonical reads and before
    // the native observation, with the source writer already released.
    pub(super) static AFTER_MEMBERSHIP_READ: Arc<(tokio::sync::Notify, tokio::sync::Notify)>;
}

impl PrivateOriginals {
    pub(in crate::private_originals) async fn restore_workflow_interest(
        self: &Arc<Self>, reference: &SetupWorkflowRef, lead: &PrivateOriginalRef,
        member: &MobMemberBinding, waiter: &PrivateOriginalRef, membership: &SetupWorkflowWaiter,
    ) -> Result<Arc<InstalledWorkflowPlanning>, PrivateOriginalError> {
        self.service_input_host_current()?;
        if membership.workflow() != reference || membership.source() != &self.key(waiter)? {
            return Err(PrivateOriginalError::Denied);
        }
        let (a, g) = {
            let held = self.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?;
            (held.iter().find(|held| &held.reference == waiter).cloned().ok_or(PrivateOriginalError::Unavailable)?,
             held.iter().find(|held| &held.reference == lead).cloned().ok_or(PrivateOriginalError::Unavailable)?)
        };
        // These are exact selected source records, not a reconstructed user
        // request. G's retained native Input supplies its already-admitted body.
        let g_row = self.store.get(&self.key(lead)?).await.map_err(store_error)?.ok_or(PrivateOriginalError::Unavailable)?;
        let g_record = self.decode_record(&g_row, lead)?;
        let Some(PlanningSourceEvidence::Lead { parent }) = &g_record.planning_source_evidence else {
            return Err(PrivateOriginalError::Unavailable);
        };
        let p = self.retained.lock().map_err(|_| PrivateOriginalError::Unavailable)?.iter()
            .find(|held| &held.reference == parent).cloned().ok_or(PrivateOriginalError::Unavailable)?;
        let input = g_record.bound_service_input.as_ref().ok_or(PrivateOriginalError::Unavailable)?.decode()?;
        let Input::Prompt(prompt) = &input else { return Err(PrivateOriginalError::Conflict); };
        let meerkat_core::ContentInput::Text(content) = &prompt.content else { return Err(PrivateOriginalError::Conflict); };
        if g_record.final_association.as_ref() != Some(g.original.association())
            || input.header().authority_association.as_ref() != Some(g.original.association())
            || g_record.operation_cancelled
        { return Err(PrivateOriginalError::Denied); }
        let snapshot = self.workflow_store()?.load_setup_workflow(reference).await.map_err(|_| PrivateOriginalError::Unavailable)?;
        if &snapshot.terms().lead != member { return Err(PrivateOriginalError::Conflict); }
        let WorkAuthorityBasis::GrantLineage { lineage } = &g.original.association().candidate().authority_basis else {
            return Err(PrivateOriginalError::Conflict);
        };
        let planning = self.prepare_workflow_planning(parent, PrivateOriginalSubmit {
            original: lead.clone(), content: content.clone(),
            // Retained historical source evidence, not a new transport login.
            // This method never binds or submits this reconstructed holder.
            transport_authentication: g_record.event.original_authentication.clone(),
        }, snapshot.terms().clone(), lineage.clone()).await?;
        if !Arc::ptr_eq(&planning.parent, &p.original) { return Err(PrivateOriginalError::Conflict); }

        // Normal departure and cancellation use this same writer. Read canonical
        // membership/phase under it, then use its publication stamp across the
        // native await. A winning departure leaves a tombstone in this interned
        // planning owner even when the local interest was not published yet.
        let writer = self.owner.source_writer().await;
        let publication = self.owner.publication();
        let (_, stamp) = publication.observe(|| ()).map_err(|_| PrivateOriginalError::Unavailable)?;
        let current_g = self.store.get(&g_row.key).await.map_err(store_error)?.ok_or(PrivateOriginalError::Unavailable)?;
        if current_g != g_row { return Err(PrivateOriginalError::Conflict); }
        let p_row = self.store.get(&self.key(parent)?).await.map_err(store_error)?.ok_or(PrivateOriginalError::Unavailable)?;
        let p_record = self.decode_record(&p_row, parent)?;
        if p_record.planning_source_evidence != Some(PlanningSourceEvidence::Parent)
            || p_record.final_association.as_ref() != Some(p.original.association())
            || p_record.bound_service_input.is_none() || p_record.operation_cancelled
        { return Err(PrivateOriginalError::Denied); }
        self.check_planning_evidence_source(&p_record, parent)?;
        let a_row = self.store.get(&self.key(waiter)?).await.map_err(store_error)?.ok_or(PrivateOriginalError::Unavailable)?;
        let a_record = self.decode_record(&a_row, waiter)?;
        if a_record.planning_source_evidence != Some(PlanningSourceEvidence::Waiter {
            workflow: reference.clone(), planning: lead.clone(),
        }) || a_record.final_association.as_ref() != Some(a.original.association())
            || a_record.bound_service_input.is_none() || a_record.operation_cancelled
        { return Err(PrivateOriginalError::Denied); }
        self.check_workflow_waiter_binding(&a_record, waiter).await?;
        let (current, correlation) = self.workflow_store()?.workflow_waiter_recovery_snapshot(membership, a.original.association())
            .await.map_err(|error| match error {
                meerkat_toolkit::setup::SetupError::Denied => PrivateOriginalError::Denied,
                _ => PrivateOriginalError::Unavailable,
            })?;
        if current.terms() != &planning.terms { return Err(PrivateOriginalError::Conflict); }
        let now = self.owner.clock().now().map_err(|_| PrivateOriginalError::Unavailable)?.unix_ms;
        if now >= membership.deadline_ms() || now >= planning.terms.deadline_ms { return Err(PrivateOriginalError::Denied); }
        // Resolve outside the native callback. Under B/M/D only atomic checks
        // and nonwaiting source/attachment publication are permitted.
        let mut authorities = Vec::new();
        for held in [&a, &p, &g] {
            if !self.owner.has_admitted_source(held.original.association()).map_err(writer_error)? {
                return Err(PrivateOriginalError::Unavailable);
            }
            let claims = held.original.association().candidate();
            for lineage in claims.authority_basis.grant_lineages() {
                authorities.push(self.owner.grants().resolve_lineage(lineage, &claims.logical_executor,
                    claims.represented_subject.as_ref()).map_err(|_| PrivateOriginalError::Denied)?);
            }
            authorities.push(self.owner.grants().resolve_controller_lineage(&claims.controller_grant_lineage,
                &claims.logical_executor, claims.represented_subject.as_ref()).map_err(|_| PrivateOriginalError::Denied)?);
        }
        let controller = self.owner.workflow_controller(&g.original).map_err(writer_error)?;
        let route = controller.plain_facts().map_err(|_| PrivateOriginalError::Unavailable)?.route_key();
        let session = meerkat_core::SessionId::parse(g.original.association().candidate().target.context.as_str())
            .map_err(|_| PrivateOriginalError::Conflict)?;
        stamp.check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
        drop(writer);
        #[cfg(test)]
        if let Ok(pause) = AFTER_MEMBERSHIP_READ.try_with(Arc::clone) {
            pause.0.notify_one();
            pause.1.notified().await;
        }
        let machine = self.machine()?;
        let pins = self.controller_pin_source.get().and_then(Weak::upgrade).ok_or(PrivateOriginalError::Unavailable)?;
        let registration = machine.current_session_registration_witness(&session).await.ok_or(PrivateOriginalError::Unavailable)?;
        let attachment = machine.current_executor_attachment_witness(&session).await.ok_or(PrivateOriginalError::Unavailable)?;
        let actor = pins.live_actor(&session).await.ok_or(PrivateOriginalError::Unavailable)?;
        let candidate = Arc::new(HeldSetupWorkflow {
            source: Arc::downgrade(self), planning: g.original.clone(), reference: reference.clone(),
            member: member.clone(), session: session.clone(), controller_route: route.clone(),
            accepted: AtomicBool::new(true), deadline_ms: planning.terms.deadline_ms,
            waiters: Mutex::new(Vec::new()),
        });
        let observed = machine.with_admitted_original(&registration, &attachment, &actor.executor_actor_identity(), &input, |admitted| {
            let _writer = self.owner.try_source_writer().map_err(writer_error)?;
            stamp.check_current().map_err(|_| PrivateOriginalError::Unavailable)?;
            for authority in &authorities { authority.check_current().map_err(|_| PrivateOriginalError::Unavailable)?; }
            for held in [&a, &p, &g] {
                if !self.owner.has_admitted_source(held.original.association()).map_err(writer_error)? {
                    return Err(PrivateOriginalError::Unavailable);
                }
            }
            let now = self.owner.clock().now().map_err(|_| PrivateOriginalError::Unavailable)?.unix_ms;
            if now >= membership.deadline_ms() || now >= planning.terms.deadline_ms { return Err(PrivateOriginalError::Denied); }
            if admitted.input_id() != input.id() { return Err(PrivateOriginalError::Conflict); }
            self.owner.complete_restored_workflow_member(reference, member, g.original.association(), admitted,
                &route, |apply| {
                    let mut interests = planning.interests.try_lock().map_err(|_| OriginalWriterError::Unavailable)?;
                    let mut selections = a.workflow_selections.try_lock().map_err(|_| OriginalWriterError::Unavailable)?;
                    let prior_interest = interests.iter().find(|interest| interest.membership.acquisition() == membership.acquisition());
                    if let Some(prior) = prior_interest {
                        if prior.membership != *membership || prior.closed
                            || !prior.original.as_ref().is_some_and(|held| Arc::ptr_eq(held, &a.original))
                        { return Err(OriginalWriterError::Conflict); }
                    } else if interests.len() >= usize::from(planning.terms.max_waiters) { return Err(OriginalWriterError::Unavailable); }
                    let prior_selection = selections.iter().find(|selected| selected.correlation == correlation);
                    if let Some(prior) = prior_selection {
                        if !same_optional(prior.selection.as_ref(), Some(&planning)) { return Err(OriginalWriterError::Conflict); }
                        // An existing host-owned transfer selection stays owned.
                    } else if selections.len() >= 128 { return Err(OriginalWriterError::Unavailable); }
                    if let Some(prior) = g.setup_workflow.get() {
                        if prior.reference != *reference || prior.member != *member || prior.session != session
                            || !Arc::ptr_eq(&prior.planning, &g.original)
                            || prior.controller_route != route
                            || !prior.accepted.load(Ordering::Acquire)
                        { return Err(OriginalWriterError::Conflict); }
                    }
                    // No fallible step follows these owner mutations. The
                    // controller gate is still closed until the outer commit.
                    let add_interest = prior_interest.is_none();
                    let add_selection = prior_selection.is_none();
                    let changed = g.setup_workflow.get().is_none() || add_interest || add_selection;
                    if !apply { return Ok(changed); }
                    g.setup_workflow.get_or_init(|| candidate.clone());
                    if add_interest { interests.push(LaunchInterest { membership: membership.clone(),
                        original: Some(a.original.clone()), closed: false, entries: Vec::new() }); }
                    if add_selection { selections.push(InvocationPlanning { correlation: correlation.clone(),
                        selection: Some(planning.clone()), context_transfer: None }); }
                    Ok(changed)
                }).map_err(writer_error)
        }).await;
        match observed {
            Ok(result) => result?,
            Err(AdmittedOriginalRefusal::Conflict) => return Err(PrivateOriginalError::Conflict),
            Err(AdmittedOriginalRefusal::NotAdmitted | AdmittedOriginalRefusal::Unavailable) => return Err(PrivateOriginalError::Unavailable),
        }
        Ok(planning)
    }
}
