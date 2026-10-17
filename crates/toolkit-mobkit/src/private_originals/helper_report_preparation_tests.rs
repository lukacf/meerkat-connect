//! The real configured helper context exercises the shared preparation APIs.
//! The model is mechanical; there is no account/provider I/O or service grant.
use super::*;
use crate::installed_host::acquisition::{AcquisitionBootstrap, InstalledServiceTaskSource};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn software_authenticated_and_report_only_public_capture_keep_legacy_preparation() {
    let script = acquisition_denial::Script::for_approved();
    let report = Report::new(script.tools().result_tool());
    let (fixture, _runtime_store) =
        Fixture::for_configured_helper_report(script.clone(), report.clone()).await;
    let checked = std::panic::AssertUnwindSafe(tokio::time::timeout(
        WAIT,
        Box::pin(async {
            let first = fixture.submit().await;
            fixture.finish(&first).await.unwrap();
            let feedback = script.observations().0;
            assert_eq!(feedback.len(), 1);
            assert!(!feedback[0].is_error, "{feedback:?}");
            let context = report.take_context().await;
            let native = fixture
                .lifetime()
                .selected_policy()
                .native_host
                .as_ref()
                .unwrap();
            let configured = native
                .members
                .iter()
                .find(|member| member.member.member == MEMBER)
                .unwrap()
                .setup_capability
                .as_ref()
                .unwrap();
            assert_eq!(configured.helper_targets.len(), 3);
            assert!(
                configured
                    .helper_targets
                    .iter()
                    .all(|target| target.target.is_some()),
                "this actual legacy configured selection has no catalog opt-in"
            );

            // Reuse the actual installed acquisition owner; this bootstrap view
            // opens no runtime/store and creates no replacement helper custody.
            let owner = script.installed_owner();
            let mut bootstrap = AcquisitionBootstrap::selected(owner.clone());
            assert!(Arc::ptr_eq(
                &bootstrap.prepare(None, None).unwrap().unwrap(),
                &owner
            ));
            let bootstrap = Arc::new(Mutex::new(bootstrap));
            let tasks = InstalledServiceTaskSource::new(&bootstrap);
            let source = fixture
                .source
                .setup_result_source(&context, report.selection.get().unwrap())
                .await
                .unwrap();
            let acquisition_key = source.operation.acquisition.clone();
            let original_key = fixture.source.key(&fixture.submission.original).unwrap();
            let acquisition_before = fixture.store.get(&acquisition_key).await.unwrap().unwrap();
            let original_before = fixture.store.get(&original_key).await.unwrap().unwrap();
            let journal = fixture.source_path.with_file_name("grants.jsonl");
            let grants_before = std::fs::read(&journal).unwrap();
            let software = report
                .prepare_task(&tasks, ReportPreparation::Software)
                .await
                .unwrap();
            let authenticated = report
                .prepare_task(&tasks, ReportPreparation::CapturedConsumer)
                .await
                .unwrap();
            let explicit = report
                .prepare_task(&tasks, ReportPreparation::ExplicitConsumer)
                .await
                .unwrap();
            let public = report
                .prepare_task(&tasks, ReportPreparation::PublicService)
                .await
                .unwrap();
            for task in [&software, &authenticated, &explicit, &public] {
                assert_eq!(task.consumer_member(), Some(MEMBER));
                assert_eq!(task.deadline_ms(), software.deadline_ms());
                assert!(!task.has_configured_setup());
                task.check_setup_current().await.unwrap();
            }
            assert_eq!(
                fixture.store.get(&acquisition_key).await.unwrap().unwrap(),
                acquisition_before
            );
            assert_eq!(
                fixture.store.get(&original_key).await.unwrap().unwrap(),
                original_before
            );
            assert_eq!(std::fs::read(journal).unwrap(), grants_before);
        }),
    ))
    .catch_unwind()
    .await;
    report.release();
    report.leaf.context.lock().unwrap().take();
    let cleanup = fixture.shutdown().await;
    assert!(cleanup.is_ok(), "{cleanup:?}");
    match checked {
        Ok(Ok(())) => (),
        Ok(Err(_)) => panic!("legacy task preparation did not settle before the fixture deadline"),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_executor_legacy_helper_prepares_public_without_warm_selection() {
    use crate::installed_host::controller_first_input_fixture::WarmHelperProfile;
    legacy_helper_preparation(&[WarmHelperProfile::SameExecutor]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_audience_legacy_helper_prepares_public_without_warm_selection() {
    use crate::installed_host::controller_first_input_fixture::WarmHelperProfile;
    legacy_helper_preparation(&[WarmHelperProfile::CrossAudience]).await;
}

async fn legacy_helper_preparation(
    profiles: &[crate::installed_host::controller_first_input_fixture::WarmHelperProfile],
) {
    use crate::installed_host::controller_first_input_fixture::WarmHelperProfile;
    use meerkat_authorization_contracts::constraints::{ExactRestriction, ProcessorRef};
    for &profile in profiles {
        let script = acquisition_denial::Script::for_approved();
        let report = Report::new(script.tools().result_tool());
        let (fixture, _) =
            Fixture::for_warm_helper_profile(script.clone(), report.clone(), profile).await;
        let checked = std::panic::AssertUnwindSafe(tokio::time::timeout(
            WAIT,
            Box::pin(async {
                let first = fixture.submit().await;
                fixture.finish(&first).await.unwrap();
                let feedback = script.observations().0;
                assert_eq!(feedback.len(), 1);
                assert!(!feedback[0].is_error, "{feedback:?}");
                let context = report.take_context().await;
                let native = fixture
                    .lifetime()
                    .selected_policy()
                    .native_host
                    .as_ref()
                    .unwrap();
                let original = &native.members[0];
                let helper = &native.members[1];
                assert!(
                    original
                        .setup_capability
                        .as_ref()
                        .unwrap()
                        .helper_targets
                        .iter()
                        .any(|target| target.target.is_none()),
                    "catalog capability is genuinely configured"
                );
                match profile {
                    WarmHelperProfile::SameExecutor => {
                        assert!(original.audience == helper.audience);
                        assert!(original.logical_owner == helper.logical_owner);
                    }
                    WarmHelperProfile::CrossAudience => {
                        assert!(original.audience != helper.audience);
                        assert!(original.logical_owner != helper.logical_owner);
                    }
                    WarmHelperProfile::Standard => unreachable!(),
                }
                for target in &original.setup_capability.as_ref().unwrap().helper_targets {
                    assert!(
                        target.restrictions.processors
                            == ExactRestriction::exact([ProcessorRef::Principal {
                                principal: helper.logical_owner.clone()
                            },])
                    );
                    assert!(
                        target.restrictions.audiences
                            == ExactRestriction::exact([helper.audience.clone()])
                    );
                }
                let owner = script.installed_owner();
                let mut bootstrap = AcquisitionBootstrap::selected(owner.clone());
                assert!(Arc::ptr_eq(
                    &bootstrap.prepare(None, None).unwrap().unwrap(),
                    &owner
                ));
                let bootstrap = Arc::new(Mutex::new(bootstrap));
                let tasks = InstalledServiceTaskSource::new(&bootstrap);
                let key = fixture.source.key(fixture.original_reference()).unwrap();
                let before = fixture.store.get(&key).await.unwrap().unwrap();
                let journal = fixture.source_path.with_file_name("grants.jsonl");
                let grants_before = std::fs::read(&journal).unwrap();
                let public = report
                    .prepare_task(&tasks, ReportPreparation::PublicService)
                    .await
                    .unwrap();
                assert!(
                    !public.has_configured_setup(),
                    "valid legacy profiles do not acquire broader metadata scope"
                );
                assert_eq!(public.consumer_member(), Some(MEMBER));
                public.check_setup_current().await.unwrap();
                if matches!(profile, WarmHelperProfile::CrossAudience) {
                    // Optional fallback cannot hide contradictory helper facts.
                    // This negative owner lookup changes no retained policy or
                    // grants; positive preparation above uses the actual call.
                    let mut contradictory = helper.clone();
                    contradictory.audience = original.audience.clone();
                    assert!(matches!(
                        fixture.source.select_service_setup(
                            fixture.original_reference(),
                            &fixture.session,
                            public.deadline_ms(),
                            report.selection.get().unwrap(),
                            &contradictory,
                            context.origin_session_id().unwrap(),
                        ),
                        Err(PrivateOriginalError::Conflict)
                    ));
                }
                for task in [
                    report
                        .prepare_task(&tasks, ReportPreparation::Software)
                        .await
                        .unwrap(),
                    report
                        .prepare_task(&tasks, ReportPreparation::CapturedConsumer)
                        .await
                        .unwrap(),
                ] {
                    assert!(!task.has_configured_setup());
                    assert_eq!(task.deadline_ms(), public.deadline_ms());
                    task.check_setup_current().await.unwrap();
                }
                assert_eq!(fixture.store.get(&key).await.unwrap().unwrap(), before);
                assert_eq!(std::fs::read(&journal).unwrap(), grants_before);
            }),
        ))
        .catch_unwind()
        .await;
        report.release();
        report.leaf.context.lock().unwrap().take();
        let cleanup = fixture.shutdown().await;
        assert!(cleanup.is_ok(), "{cleanup:?}");
        match checked {
            Ok(Ok(())) => (),
            Ok(Err(_)) => panic!("legacy profile preparation exceeded its bounded deadline"),
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}
