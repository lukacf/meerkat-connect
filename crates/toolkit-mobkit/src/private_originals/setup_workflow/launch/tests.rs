//! One actual host-selected G route through native Original admission. The
//! model transport is scripted. These controls do not qualify waiter disclosure,
//! shared SDK discovery, approval/activation or dynamic member creation.
use super::*;
use crate::{
    original_ingress::tests::private_event,
    private_originals::governed_submit::tests::first_input_tests::FirstFixture,
};
use futures::FutureExt;
use meerkat_authorization_contracts::constraints::{ExecutionRestrictions, LifetimeRestriction};
use meerkat_core::{ToolDispatchContext, exact_operation::OperationExecutionScope};
use meerkat_toolkit::{
    authority::{
        Action, ActionPermission, Ceiling, SetupProposalConstraints, SetupRequestEvidence,
        SetupUseContext,
    },
    request::{
        ContextReference, ContextReferenceOwner, FindAndInstallRequest, HostSetupRequest,
        NativeOriginalTask, RequestError, SetupLimits, TaskContinuation, validate_request,
    },
    setup::{SetupWorkBackend, SetupWorkContext},
};
use meerkat_workgraph::{
    ClaimWorkItemRequest, CreateWorkItemRequest, LinkWorkItemsRequest, SqliteWorkGraphStore,
    WorkEdgeKind, WorkGraphService, WorkItem, WorkItemRef, WorkNamespace, WorkOwner, WorkOwnerKey,
};
use std::{collections::BTreeSet, panic::AssertUnwindSafe, time::Duration};
use toolkit_package::Revision;
use toolkit_store::ToolkitStore;

const GUARD: Duration = Duration::from_secs(30);
const CYCLE: &str = "planning-launch-control";
fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}
fn revision(value: &str) -> Revision {
    Revision::new(value).unwrap()
}
fn native(observation: WorkflowLaunchObservation) -> PrivateOriginalSubmission {
    match observation {
        WorkflowLaunchObservation::Native { observation } => observation,
        WorkflowLaunchObservation::NotAdmitted => {
            panic!("unexpected definitive native nonadmission")
        }
    }
}
struct Inline;
impl ContextReferenceOwner for Inline {
    fn verify_access(
        &self,
        _: &ContextReference,
        _: &SetupRequestEvidence,
        _: &SetupUseContext<'_>,
    ) -> Result<(), RequestError> {
        Err(RequestError::ContextUnavailable)
    }
}
fn work_ref(item: &WorkItem) -> WorkItemRef {
    WorkItemRef {
        realm_id: item.realm_id.clone(),
        namespace: item.namespace.clone(),
        item_id: item.id.clone(),
    }
}
async fn claim(service: &WorkGraphService, name: &str) -> WorkItem {
    let item = service
        .create(CreateWorkItemRequest {
            title: name.into(),
            labels: [CYCLE.into()].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    service
        .claim(ClaimWorkItemRequest {
            id: item.id,
            realm_id: None,
            namespace: None,
            expected_revision: item.revision,
            owner: WorkOwner {
                key: WorkOwnerKey::agent(name).unwrap(),
                display_name: None,
            },
            lease_seconds: Some(300),
            lease_expires_at: None,
        })
        .await
        .unwrap()
}
async fn event(
    f: &FirstFixture,
    label: &str,
    contributors: Vec<EvidenceId>,
) -> PrivateOriginalSubmit {
    let mut event = private_event(label);
    event.route = f.original_reference().route.clone();
    event.content_sha256 = digest(label.as_bytes());
    event.contributors = contributors;
    let authentication = event.original_authentication.clone();
    let reference = f.source.retain_event(event).await.unwrap();
    PrivateOriginalSubmit {
        original: reference,
        content: label.into(),
        transport_authentication: authentication,
    }
}

struct Case {
    planning: Arc<InstalledWorkflowPlanning>,
    membership: SetupWorkflowWaiter,
    snapshot: SetupWorkflowSnapshot,
    a: crate::private_originals::acquisition::AcquisitionOriginal,
    a_dispatch: ToolDispatchContext,
    work: SetupWorkContext,
    _backend: SetupWorkBackend,
}

async fn prepare(f: &FirstFixture) -> Case {
    let a = f.submit().await;
    f.finish(&a).await.unwrap();
    let dispatch = f.probe.as_ref().unwrap().captured();
    let original = f.source.acquisition_original(&dispatch).await.unwrap();
    // P is a separate actual admitted input. A is never G's parent and its
    // cancellation cannot revoke the independently selected planning lineage.
    let parent = event(f, "planning-parent", vec![]).await;
    let admitted_parent = f
        .source
        .submit_authenticated_original(parent.clone())
        .await
        .unwrap();
    f.finish(&Ok::<_, String>(admitted_parent)).await.unwrap();
    let parent_binding = f
        .source
        .binding_evidence(&parent.original)
        .await
        .unwrap()
        .unwrap();
    let submission = event(
        f,
        "planning-lead",
        vec![parent_binding.candidate().original_work.work.clone()],
    )
    .await;
    let route = f.source.route(&submission.original.route).unwrap();
    let native = f.lifetime().selected_policy().native_host.as_ref().unwrap();
    let now = u64::try_from(f.store.now_ms().await.unwrap()).unwrap();
    let deadline = now + 60_000;
    let grants = f.source.owner.grants();
    let bounds = ExecutionRestrictions {
        delegation_depth: DelegationDepth::remaining(1),
        lifetime: LifetimeRestriction::window(now, deadline + 60_000),
        ..ExecutionRestrictions::unrestricted()
    };
    let root_authority = meerkat_core::auth::PrincipalRef::in_domain(
        meerkat_core::auth::PrincipalKind::ServiceAccount,
        "admin",
        meerkat_core::auth::TrustDomainId::new("factory-test").unwrap(),
    )
    .unwrap();
    let root = grants
        .issue_root(
            &root_authority,
            EvidenceId::new("planning-operation-parent").unwrap(),
            native.grant_administrator.clone(),
            route.represented_subject.clone(),
            bounds.clone(),
        )
        .unwrap();
    let leaf_bounds = bounds
        .for_child(&ExecutionRestrictions {
            delegation_depth: DelegationDepth::remaining(0),
            ..ExecutionRestrictions::unrestricted()
        })
        .unwrap();
    let leaf = grants
        .issue_child(
            &native.grant_administrator,
            &root,
            EvidenceId::new("planning-operation-leaf").unwrap(),
            route.logical_executor.clone(),
            leaf_bounds.clone(),
        )
        .unwrap();
    let lineage = vec![root, leaf];
    let service = WorkGraphService::with_scope(
        Arc::new(
            SqliteWorkGraphStore::open(f.source_path.with_extension("planning-work.sqlite"))
                .unwrap(),
        ),
        f.scope.realm.clone(),
        WorkNamespace::new("planning-control").unwrap(),
    );
    let parent_work = claim(&service, "parent").await;
    let child_work = claim(&service, "waiter-a").await;
    service
        .link(LinkWorkItemsRequest {
            realm_id: None,
            namespace: None,
            kind: WorkEdgeKind::Parent,
            from_id: child_work.id.clone(),
            to_id: parent_work.id.clone(),
        })
        .await
        .unwrap();
    let backend = SetupWorkBackend::new(
        service,
        "sqlite-planning-control".into(),
        id("generation-one"),
        &[meerkat_core::DurabilityDeclaration::durable(
            "workgraph",
            meerkat_core::DurabilityResolution::Persistent,
        )],
    )
    .unwrap();
    let work = SetupWorkContext::from_owner(
        backend.pin().clone(),
        work_ref(&parent_work),
        work_ref(&child_work),
        parent_work.owner.as_ref().unwrap().key.clone(),
        child_work.owner.as_ref().unwrap().key.clone(),
        CYCLE.into(),
    )
    .unwrap();
    let terms = SetupWorkflowTerms {
        key: id("planning-workflow"),
        backend: backend.pin().clone(),
        parent: work_ref(&parent_work),
        parent_owner: parent_work.owner.as_ref().unwrap().key.clone(),
        cycle_label: CYCLE.into(),
        requester: route.requester.clone(),
        realm: route.realm.clone(),
        authority_revision: revision("planning-policy"),
        planning_source: f.source.key(&submission.original).unwrap(),
        lead: native.members[0].member.clone(),
        envelope_digest: ContentDigest::of_bytes(&canonical_json(&leaf_bounds).unwrap()),
        deadline_ms: deadline,
        max_waiters: 8,
    };
    let planning = f
        .source
        .prepare_workflow_planning(
            &parent.original,
            submission.clone(),
            terms.clone(),
            lineage.clone(),
        )
        .await
        .unwrap();
    let replay = f
        .source
        .prepare_workflow_planning(&parent.original, submission, terms.clone(), lineage)
        .await
        .unwrap();
    assert!(
        Arc::ptr_eq(&planning, &replay),
        "same actual P retains one planning owner"
    );
    let (membership, snapshot) = join_waiter(
        f, &planning, &original, &dispatch, &backend, &work, "waiter-a",
    )
    .await;
    Case {
        planning,
        membership,
        snapshot,
        a: original,
        a_dispatch: dispatch,
        work,
        _backend: backend,
    }
}

async fn join_waiter(
    f: &FirstFixture,
    planning: &Arc<InstalledWorkflowPlanning>,
    original: &crate::private_originals::acquisition::AcquisitionOriginal,
    dispatch: &ToolDispatchContext,
    backend: &SetupWorkBackend,
    work: &SetupWorkContext,
    label: &str,
) -> (SetupWorkflowWaiter, SetupWorkflowSnapshot) {
    let terms = &planning.terms;
    let deadline = terms.deadline_ms;
    let now = u64::try_from(f.store.now_ms().await.unwrap()).unwrap();
    let route = f.source.route(&planning.submission.original.route).unwrap();
    let tenant = id(&f.scope.realm);
    let deployment = id(&f.scope.owner);
    let receiver = id("agent");
    let audience = BTreeSet::from([id(label)]);
    let evidence = SetupRequestEvidence::new(
        original.original.association().clone(),
        SetupProposalConstraints {
            tenant: tenant.clone(),
            deployment: deployment.clone(),
            policy_revision: terms.authority_revision.clone(),
            issued_at_ms: now,
            expires_at_ms: deadline,
            ceiling: Ceiling {
                actions: [ActionPermission {
                    action: Action::FindAndInstall,
                    resource: receiver.clone(),
                }]
                .into(),
                services: BTreeSet::new(),
                frontends: BTreeSet::new(),
                output_audiences: audience.clone(),
            },
        },
    )
    .unwrap();
    let target = evidence.association().candidate().target.clone();
    let authorization = dispatch.work_authorization().unwrap();
    let context = SetupUseContext {
        tenant: &tenant,
        deployment: &deployment,
        realm: &route.realm,
        target: &target,
        policy_revision: &terms.authority_revision,
        now_ms: now,
        authorization,
    };
    let OperationExecutionScope::RuntimeInput {
        canonical_input_id, ..
    } = authorization.execution_scope()
    else {
        panic!("actual waiter input scope required")
    };
    let retained = dispatch.retained_work().unwrap().clone();
    let request = validate_request(
        FindAndInstallRequest {
            request: format!("Prepare a bounded integration for {label}"),
            user_context: vec![],
            caller_observations: vec![],
        },
        HostSetupRequest {
            setup_helper: None,
            work_context: Some(work.clone()),
            target: receiver,
            correlation: id(&format!("{label}-call")),
            parent_operation: None,
            continuation: TaskContinuation {
                owner: id("planning-test"),
                task: id(&retained.run_id().to_string()),
                revision: revision(&canonical_input_id.to_string()),
                delivery_key: id(&format!("planning-test:{label}")),
                audience,
                native_original: Some(NativeOriginalTask {
                    origin_session_id: f.session.clone(),
                    retained_work: retained,
                    member: None,
                }),
            },
            environment_revision: revision("planning-environment"),
            limits: SetupLimits {
                deadline_ms: deadline,
                max_workers: 1,
                max_effect_attempts: 2,
            },
        },
        &evidence,
        &context,
        &Inline,
    )
    .unwrap();
    let store = f.source.workflow_store().unwrap();
    let acquisition = store
        .admit(&request, &evidence, &context, &Inline)
        .await
        .unwrap()
        .snapshot;
    let membership = store
        .workflow_waiter(terms, &acquisition, original.source_record.key.clone())
        .unwrap();
    let joined = store
        .join_setup_workflow(
            terms,
            &membership,
            SetupAccess {
                evidence: &evidence,
                context: &context,
                references: &Inline,
            },
            backend,
        )
        .await
        .unwrap();
    planning
        .retain_launch_interest(&joined.snapshot, &membership, original)
        .await
        .unwrap();
    (membership, joined.snapshot)
}

struct DepartAfterBind {
    inner: Arc<WorkflowBinder>,
    planning: Arc<InstalledWorkflowPlanning>,
    membership: SetupWorkflowWaiter,
    pending_seen: AtomicBool,
}
#[async_trait::async_trait]
impl GovernedInputBinder for DepartAfterBind {
    async fn bind(
        &self,
        context: &GovernedBindContext,
        input: Input,
    ) -> Result<BoundGovernedInput, String> {
        let bound = self.inner.bind(context, input).await?;
        let source = self
            .planning
            .source
            .upgrade()
            .ok_or("fixture source unavailable")?;
        let pending = source
            .retained
            .lock()
            .map_err(|_| "fixture owner unavailable")?
            .iter()
            .find(|held| held.reference == self.planning.submission.original)
            .cloned()
            .and_then(|held| held.setup_workflow.get().cloned())
            .is_some_and(|workflow| {
                !workflow.accepted.load(Ordering::Acquire) && workflow.current_source().is_err()
            });
        self.pending_seen.store(pending, Ordering::Release);
        self.planning
            .depart_waiter(&self.membership)
            .await
            .map_err(|error| error.to_string())?;
        // Return the actual bound input, source guard and production fence.
        // Native still makes its real final admission decision.
        Ok(bound)
    }
    fn retain_unresolved(&self, settlement: Box<dyn GovernedSettlement>, detail: &str) {
        self.inner.retain_unresolved(settlement, detail);
    }
}

async fn exercise(case: u8) {
    let f = FirstFixture::for_continuation().await;
    let result = AssertUnwindSafe(tokio::time::timeout(GUARD, async {
        let mut c = prepare(&f).await;
        assert_eq!(
            f.inputs().await.unwrap(),
            2,
            "A and independent P admitted before G"
        );
        let before_delivery = f
            .store
            .get_effect(&c.membership.delivery_effect().unwrap())
            .await
            .unwrap()
            .unwrap();
        if case == 0 {
            // Explicit seal prevents new members but preserves existing A.
            c.snapshot = f
                .source
                .workflow_store()
                .unwrap()
                .seal_setup_workflow(c.snapshot.reference())
                .await
                .unwrap();
            assert!(c.snapshot.sealed());
            c.planning
                .retain_launch_interest(&c.snapshot, &c.membership, &c.a)
                .await
                .unwrap();
            let admitted = native(c.planning.launch(&c.snapshot).await.unwrap());
            assert!(matches!(
                &admitted,
                PrivateOriginalSubmission::Admitted {
                    source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted,
                    ..
                }
            ));
            f.finish(&Ok::<_, String>(admitted)).await.unwrap();
            assert_eq!(f.inputs().await.unwrap(), 3);
            let held = f
                .source
                .retained
                .lock()
                .unwrap()
                .iter()
                .find(|held| held.reference == c.planning.submission.original)
                .cloned()
                .unwrap();
            assert!(
                held.setup_workflow.get().unwrap().current_source().is_ok(),
                "actual accepted callback promoted the staged G attachment"
            );
            let observed = native(c.planning.launch(&c.snapshot).await.unwrap());
            assert!(matches!(
                observed,
                PrivateOriginalSubmission::Admitted { .. }
            ));
            assert_eq!(
                f.inputs().await.unwrap(),
                3,
                "exact replay observed G without submitting another native input"
            );
            let launch = f
                .store
                .get_effect(&c.snapshot.reference().launch_effect())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(launch.status, EffectStatus::Succeeded);
            assert_eq!(launch.attempt, 1);
        } else if case == 1 {
            // Real dispatch succeeded but the outbox owner never receives its
            // acknowledgment. Its expired Some(lease) must reconcile, not send.
            let EffectClaimOutcome::Claimed(claimed) = f
                .store
                .claim_effect(
                    &c.snapshot.reference().launch_effect(),
                    c.snapshot.revision(),
                    "lost-ack-control",
                    1,
                )
                .await
                .unwrap()
            else {
                panic!("first launch effect claimed")
            };
            let expires = claimed.lease.as_ref().unwrap().expires_at_ms;
            let prepared = Arc::new(PreparedWorkflowLaunch {
                selection: c.planning.clone(),
                reference: c.snapshot.reference().clone(),
            });
            let admitted = native(prepared.submit(&f.source).await.unwrap());
            assert!(matches!(
                &admitted,
                PrivateOriginalSubmission::Admitted {
                    source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted,
                    ..
                }
            ));
            f.finish(&Ok::<_, String>(admitted)).await.unwrap();
            tokio::time::timeout(GUARD, async {
                while f.store.now_ms().await.unwrap() < expires {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            let lost = f.store.get_effect(&claimed.key).await.unwrap().unwrap();
            assert_eq!(lost.status, EffectStatus::InFlight);
            assert!(lost.lease.is_some());
            let observed = native(c.planning.launch(&c.snapshot).await.unwrap());
            assert!(matches!(
                observed,
                PrivateOriginalSubmission::Admitted { .. }
            ));
            let reconciled = f.store.get_effect(&claimed.key).await.unwrap().unwrap();
            assert_eq!(reconciled.status, EffectStatus::Succeeded);
            assert!(reconciled.lease.is_none());
            assert_eq!(reconciled.attempt, 1);
            assert_eq!(f.inputs().await.unwrap(), 3);
        } else if case == 2 {
            // Claim first, then close the actual reservation before native's
            // final protected entry. Durable departure is not the entry fence.
            let EffectClaimOutcome::Claimed(claimed) = f
                .store
                .claim_effect(
                    &c.snapshot.reference().launch_effect(),
                    c.snapshot.revision(),
                    "departure-control",
                    60_000,
                )
                .await
                .unwrap()
            else {
                panic!("first launch effect claimed")
            };
            let prepared = Arc::new(PreparedWorkflowLaunch {
                selection: c.planning.clone(),
                reference: c.snapshot.reference().clone(),
            });
            let route = f
                .source
                .route(&c.planning.submission.original.route)
                .unwrap();
            let binder = Arc::new(DepartAfterBind {
                inner: prepared.binder(&f.source, &route).await.unwrap(),
                planning: c.planning.clone(),
                membership: c.membership.clone(),
                pending_seen: AtomicBool::new(false),
            });
            let refused = prepared
                .submit_with_binder(&f.source, binder.clone())
                .await
                .unwrap();
            assert!(
                binder.pending_seen.load(Ordering::Acquire),
                "actual G binder staged fenced pending custody before departure"
            );
            let departed = f
                .source
                .workflow_store()
                .unwrap()
                .load_setup_workflow(c.snapshot.reference())
                .await
                .unwrap();
            assert_eq!(departed.active_waiters(), 0);
            assert!(matches!(refused, WorkflowLaunchObservation::NotAdmitted));
            assert_eq!(
                f.inputs().await.unwrap(),
                2,
                "closed final entry cannot admit G"
            );
            c.planning
                .record_launch_observation(&f.source, claimed.lease.as_ref().unwrap(), &refused)
                .await
                .unwrap();
            let retained = f.store.get_effect(&claimed.key).await.unwrap().unwrap();
            assert_eq!(retained.status, EffectStatus::Failed);
            assert!(retained.lease.is_none());
            let observed = c.planning.launch(&c.snapshot).await.unwrap();
            assert!(
                matches!(observed, WorkflowLaunchObservation::NotAdmitted),
                "later observation retains the exact failed launch decision"
            );
            assert_eq!(retained.attempt, 1);
            assert_eq!(
                f.inputs().await.unwrap(),
                2,
                "known nonadmission does not replay G"
            );
        } else if case == 3 {
            // Cancel the actual dispatch future after its store claim and
            // before constructing/handing a binder to the native runtime.
            let (claimed_tx, claimed_rx) = tokio::sync::oneshot::channel();
            let source = f.source.clone();
            let planning = c.planning.clone();
            let reference = c.snapshot.reference().clone();
            let revision = c.snapshot.revision();
            let mut dispatch = Box::pin(async move {
                let claimed = source
                    .store
                    .claim_effect(
                        &reference.launch_effect(),
                        revision,
                        "cancel-before-handoff",
                        60_000,
                    )
                    .await
                    .unwrap();
                let _ = claimed_tx.send(claimed);
                std::future::pending::<()>().await;
                let prepared = Arc::new(PreparedWorkflowLaunch {
                    selection: planning,
                    reference,
                });
                prepared.submit(&source).await
            });
            let claimed = tokio::select! {
                claimed = claimed_rx => claimed.unwrap(),
                _ = &mut dispatch => panic!("held dispatch cannot finish"),
            };
            drop(dispatch);
            let EffectClaimOutcome::Claimed(claimed) = claimed else {
                panic!("launch claim required")
            };
            c.planning.depart_waiter(&c.membership).await.unwrap();
            // This real source cancellation drains its owned SharedEntries.
            // The old eager reservation cannot settle and would hit its 30 s
            // drain bound; no native decision exists to wait for in this case.
            tokio::time::timeout(
                Duration::from_secs(5),
                f.source.cancel_original_operation(&c.a.reference),
            )
            .await
            .expect("no native reservation before handoff")
            .unwrap();
            assert_eq!(f.inputs().await.unwrap(), 2);
            let retained = f.store.get_effect(&claimed.key).await.unwrap().unwrap();
            assert_eq!(retained.status, EffectStatus::InFlight);
            assert!(retained.lease.is_some());
            assert_eq!(
                retained.attempt, 1,
                "local cleanup does not fabricate an outbox admission decision"
            );
        } else if case == 4 {
            // Both producer invocations observe no retained choice. Keep
            // them live concurrently, then order None's publication first.
            // Some must not replace it even before a durable CAS is available.
            let correlation = id("divergent-first-producer");
            let barrier = std::sync::Barrier::new(3);
            let (none_done, after_none) = std::sync::mpsc::channel();
            let ((none_before, none_result), (some_before, some_result)) =
                std::thread::scope(|threads| {
                    let source = &f.source;
                    let original = &c.a;
                    let work = &c.work;
                    let planning = &c.planning;
                    let correlation = &correlation;
                    let gate = &barrier;
                    let none = threads.spawn(move || {
                        let before =
                            source.retained_workflow_selection(&original.original, correlation);
                        gate.wait();
                        let result = source.retain_workflow_selection(
                            original,
                            correlation,
                            None,
                            Some(work),
                        );
                        let _ = none_done.send(());
                        (before, result)
                    });
                    let some = threads.spawn(move || {
                        let before =
                            source.retained_workflow_selection(&original.original, correlation);
                        gate.wait();
                        let _ = after_none.recv();
                        let result = source.retain_workflow_selection(
                            original,
                            correlation,
                            Some(planning),
                            Some(work),
                        );
                        (before, result)
                    });
                    barrier.wait();
                    let none = none.join();
                    let some = some.join();
                    (none.unwrap(), some.unwrap())
                });
            assert!(none_before.unwrap().is_none() && some_before.unwrap().is_none());
            assert!(none_result.is_ok());
            assert!(matches!(some_result, Err(PrivateOriginalError::Conflict)));
            assert!(
                f.source
                    .retained_workflow_selection(&c.a.original, &correlation)
                    .unwrap()
                    .is_none()
            );
            f.source
                .retain_workflow_selection(&c.a, &correlation, None, Some(&c.work))
                .unwrap();
            assert_eq!(f.inputs().await.unwrap(), 2);
        } else {
            // A's actual cancellation owner fences it Pending before the
            // deliberately failed persistence callback releases the writer.
            let a_claims = c.a.original.association().candidate();
            let expected = c.a.original.association().clone();
            let record = c.a.source_record.clone();
            let cancelled = f
                .source
                .owner
                .record_operation_cancelled(
                    &a_claims.ingress_namespace.realm,
                    &a_claims.original_work,
                    move |binding, _| async move {
                        if binding.as_ref() != Some(&expected) {
                            return Err(crate::original_ingress::OriginalWriterError::Conflict);
                        }
                        Ok(record)
                    },
                    |_| async { Err(crate::original_ingress::OriginalWriterError::Unavailable) },
                )
                .await;
            assert!(matches!(
                cancelled,
                Err(crate::original_ingress::OriginalWriterError::Unavailable)
            ));
            assert!(matches!(
                f.source.owner.workflow_controller(&c.a.original),
                Err(crate::original_ingress::OriginalWriterError::Unavailable)
            ));
            let fence = LaunchFence {
                planning: c.planning.clone(),
            };
            assert!(
                matches!(fence.enter(), Err(GovernedEntryRefusal::Unavailable(_))),
                "A alone stays unavailable after its failed cancellation write"
            );
            assert!(c.planning.interests.lock().unwrap()[0].entries.is_empty());

            // Preserve A's actual context before rearming the existing probe.
            // B is a new authenticated native input, not another A correlation.
            let a_scope = c
                .a_dispatch
                .work_authorization()
                .unwrap()
                .execution_scope()
                .clone();
            f.probe.as_ref().unwrap().arm_next_input();
            let b_submission = event(&f, "planning-waiter-b", vec![]).await;
            let admitted_b = f
                .source
                .submit_authenticated_original(b_submission)
                .await
                .unwrap();
            f.finish(&Ok::<_, String>(admitted_b)).await.unwrap();
            let b_dispatch = f.probe.as_ref().unwrap().captured();
            let b = f.source.acquisition_original(&b_dispatch).await.unwrap();
            assert_ne!(
                &a_scope,
                b_dispatch.work_authorization().unwrap().execution_scope()
            );
            assert!(c.a.reference != b.reference);
            assert_ne!(c.a.source_record.key, b.source_record.key);
            f.source.owner.workflow_controller(&b.original).unwrap();
            let child = claim(c._backend.service(), "waiter-b").await;
            c._backend
                .service()
                .link(LinkWorkItemsRequest {
                    realm_id: None,
                    namespace: None,
                    kind: WorkEdgeKind::Parent,
                    from_id: child.id.clone(),
                    to_id: c.work.parent().item_id.clone(),
                })
                .await
                .unwrap();
            let work = SetupWorkContext::from_owner(
                c._backend.pin().clone(),
                c.work.parent().clone(),
                work_ref(&child),
                c.planning.terms.parent_owner.clone(),
                child.owner.as_ref().unwrap().key.clone(),
                CYCLE.into(),
            )
            .unwrap();
            let (membership, snapshot) = join_waiter(
                &f,
                &c.planning,
                &b,
                &b_dispatch,
                &c._backend,
                &work,
                "waiter-b",
            )
            .await;
            assert_ne!(c.membership.acquisition(), membership.acquisition());
            assert_ne!(c.work.child(), work.child());
            assert_eq!(snapshot.active_waiters(), 2);
            c.snapshot = snapshot;
            let b_delivery = f
                .store
                .get_effect(&membership.delivery_effect().unwrap())
                .await
                .unwrap()
                .unwrap();
            let admitted = native(c.planning.launch(&c.snapshot).await.unwrap());
            assert!(matches!(
                &admitted,
                PrivateOriginalSubmission::Admitted {
                    source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted,
                    ..
                }
            ));
            f.finish(&Ok::<_, String>(admitted)).await.unwrap();
            assert_eq!(
                f.inputs().await.unwrap(),
                4,
                "A, P, independent B and exactly one G"
            );
            {
                let interests = c.planning.interests.lock().unwrap();
                assert_eq!(interests.len(), 2);
                assert!(
                    interests[0].entries.is_empty(),
                    "pending A supplies no entry"
                );
                assert_eq!(
                    interests[1].entries.len(),
                    1,
                    "the actual B entry admitted G"
                );
            }
            let observed = native(c.planning.launch(&c.snapshot).await.unwrap());
            assert!(matches!(
                observed,
                PrivateOriginalSubmission::Admitted { .. }
            ));
            assert_eq!(
                f.inputs().await.unwrap(),
                4,
                "observation does not submit another G"
            );
            let effect = f
                .store
                .get_effect(&c.snapshot.reference().launch_effect())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(effect.status, EffectStatus::Succeeded);
            assert_eq!(effect.attempt, 1);
            assert_eq!(
                f.store
                    .get_effect(&membership.delivery_effect().unwrap())
                    .await
                    .unwrap()
                    .unwrap(),
                b_delivery,
                "launch never acknowledges B context delivery"
            );
            assert!(
                matches!(
                    f.source.owner.workflow_controller(&c.a.original),
                    Err(crate::original_ingress::OriginalWriterError::Unavailable)
                ),
                "successful B launch cannot reopen A"
            );
        }
        assert_eq!(
            f.store
                .get_effect(&c.membership.delivery_effect().unwrap())
                .await
                .unwrap()
                .unwrap(),
            before_delivery,
            "G admission never acknowledges A context delivery"
        );
        assert!(c.a_dispatch.work_authorization().is_some());
    }))
    .catch_unwind()
    .await;
    let cleanup = f.shutdown().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    match result {
        Ok(result) => result.expect("bounded planning launch control"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_planning_input_promotes_once_and_preserves_sealed_waiter_delivery() {
    exercise(0).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_inflight_launch_reconciles_actual_native_acceptance_without_resubmit() {
    exercise(1).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_departure_after_claim_refuses_actual_planning_admission() {
    exercise(2).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_before_native_handoff_leaves_no_pending_source_reservation() {
    exercise(3).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_producers_cannot_replace_retained_none_with_planning() {
    exercise(4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_a_cancellation_preserves_unavailable_without_b_and_admits_from_live_b() {
    exercise(5).await;
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn planning_binding_refuses_distinct_issued_root_without_source_or_native_change() {
    let f = FirstFixture::for_continuation().await;
    let result = AssertUnwindSafe(tokio::time::timeout(GUARD, async {
        let c = prepare(&f).await;
        let reference = &c.planning.submission.original;
        let unbound_row = f.store.get(&f.source.key(reference).unwrap()).await.unwrap().unwrap();
        let unbound = f.source.decode_record(&unbound_row, reference).unwrap();
        assert!(unbound.final_association.is_none());
        c.planning.retain_launch_interest(&c.snapshot, &c.membership, &c.a).await.unwrap();
        let admitted = native(c.planning.launch(&c.snapshot).await.unwrap());
        assert!(matches!(&admitted, PrivateOriginalSubmission::Admitted {
            source_settlement: PrivateSourceSettlement::FreshAcceptancePromoted, ..
        }));
        f.finish(&Ok::<_, String>(admitted)).await.unwrap();
        let association = f.source.binding_evidence(reference).await.unwrap().unwrap();
        let key = f.source.key(reference).unwrap();
        let before = f.store.get(&key).await.unwrap().unwrap();
        let input_count = f.inputs().await.unwrap();
        assert_eq!(input_count, 3);
        let route = f.source.route(&reference.route).unwrap();
        let native = f.lifetime().selected_policy().native_host.as_ref().unwrap();
        let grants = f.source.owner.grants();
        let bounds = grants.resolve_lineage(&c.planning.lineage, &route.logical_executor,
            route.represented_subject.as_ref()).unwrap().restrictions().clone();
        let other_root = grants.issue_root(
            &c.planning.lineage[0].root_authority,
            EvidenceId::new("different-planning-root").unwrap(),
            native.grant_administrator.clone(), route.represented_subject.clone(), bounds,
        ).unwrap();
        assert!(other_root != c.planning.lineage[0]);
        let mut candidate = association.candidate().clone();
        let meerkat_authorization_contracts::work_association::WorkAuthorityBasis::GrantLineage { lineage }
            = &mut candidate.authority_basis else { panic!("expected exact planning lineage") };
        lineage[0] = other_root;
        let changed = meerkat_authorization_contracts::work_association::InputAuthorityAssociation::new(candidate).unwrap();
        // Use the actual pre-binding source row to distinguish planning
        // validation from the shared replay-equality refusal on a bound row.
        c.planning.check_persistence_binding(&f.source, reference, &unbound, &association).unwrap();
        assert!(matches!(c.planning.check_persistence_binding(&f.source, reference, &unbound, &changed),
            Err(OriginalWriterError::Conflict)));
        assert!(matches!(f.source.persist_or_observe_workflow_binding(reference, &changed, &c.planning).await,
            Err(OriginalWriterError::Conflict)));
        assert_eq!(f.store.get(&key).await.unwrap().unwrap(), before);
        assert_eq!(f.inputs().await.unwrap(), input_count);
        assert_eq!(f.source.binding_evidence(reference).await.unwrap(), Some(association));
    })).catch_unwind().await;
    let closed = f.shutdown().await;
    assert!(closed.is_ok(), "{closed:?}");
    match result {
        Ok(result) => result.expect("planning binding control completes within guard"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
