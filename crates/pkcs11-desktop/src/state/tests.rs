// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn object_entry(id: u64, label: &str) -> ObjectEntry {
    ObjectEntry {
        id: ResourceId(id),
        class: Some(pkcs11_client::ObjectClass::PUBLIC_KEY),
        label: label.into(),
        identifier: "00FF".into(),
        uri: Some(format!("pkcs11:serial=A;object={label};type=public")),
        ambiguous: false,
        fields: Vec::new(),
    }
}
fn browsing() -> UiState {
    let mut state = ready();
    state.loaded_modules = vec![module(1, vec![token(2, "A"), token(3, "B")])];
    state.select_token(ResourceId(1), ResourceId(2));
    state
}
fn complete(id: RequestId, result: BackendResult) -> BackendEvent {
    BackendEvent::Completed {
        id,
        result: Ok(result),
    }
}
fn objects_result(token: u64, objects: Vec<ObjectEntry>) -> BackendResult {
    BackendResult::Objects {
        module: ResourceId(1),
        token: ResourceId(token),
        objects,
    }
}
fn details_result(object: u64, value: &str) -> BackendResult {
    BackendResult::ObjectDetails {
        module: ResourceId(1),
        token: ResourceId(2),
        object: ResourceId(object),
        fields: vec![MetadataField {
            name: "Key type",
            status: "available",
            value: Some(value.into()),
        }],
    }
}
#[test]
fn token_and_page_changes_reject_pending_lists() {
    let mut state = browsing();
    let old = state.show_page(TokenPage::Objects).unwrap().id();
    state.select_token(ResourceId(1), ResourceId(3));
    let current = state.show_page(TokenPage::Objects).unwrap().id();
    state.event(complete(
        old,
        objects_result(2, vec![object_entry(4, "old")]),
    ));
    assert_eq!(state.current_operation, Some(current));
    state.event(complete(
        current,
        objects_result(3, vec![object_entry(5, "new")]),
    ));
    assert_eq!(state.objects[0].label, "new");
    let old = state.show_page(TokenPage::Mechanisms).unwrap().id();
    state.show_page(TokenPage::Overview);
    state.event(complete(
        old,
        BackendResult::Mechanisms {
            module: ResourceId(1),
            token: ResourceId(3),
            mechanisms: Vec::new(),
        },
    ));
    assert!(!state.mechanisms_loaded);
    assert!(state.read_objects().is_none());
}
#[test]
fn object_details_are_lazy_and_latest_selection_wins() {
    let mut state = browsing();
    let list = state.show_page(TokenPage::Objects).unwrap().id();
    state.event(complete(
        list,
        objects_result(2, vec![object_entry(4, "A"), object_entry(5, "B")]),
    ));
    assert!(state.object_details.is_none());
    let a = state.select_object(ResourceId(4)).unwrap().id();
    let b = state.select_object(ResourceId(5)).unwrap().id();
    state.event(complete(b, details_result(5, "B")));
    state.event(complete(a, details_result(4, "A")));
    assert_eq!(state.selected_object, Some(ResourceId(5)));
    assert_eq!(
        state.object_details.as_ref().unwrap()[0].value.as_deref(),
        Some("B")
    );
    state.show_page(TokenPage::Overview);
    assert!(state.selected_object.is_none());
    assert!(state.object_details.is_none());
}
#[test]
fn filtering_and_refresh_invalidate_old_object_details() {
    let mut state = browsing();
    let list = state.show_page(TokenPage::Objects).unwrap().id();
    state.event(complete(
        list,
        objects_result(2, vec![object_entry(4, "key")]),
    ));
    let detail = state.select_object(ResourceId(4)).unwrap().id();
    state.edit_object_filter("nomatch".into());
    state.event(complete(detail, details_result(4, "hidden")));
    assert!(state.object_details.is_none());
    assert!(state.selected_object.is_none());
    state.edit_object_filter("  public KEY  ".into());
    let detail = state.select_object(ResourceId(4)).unwrap().id();
    let refresh = state.read_objects().unwrap().id();
    state.event(complete(detail, details_result(4, "old")));
    assert_eq!(state.current_operation, Some(refresh));
    state.cancel();
    state.event(complete(
        refresh,
        objects_result(2, vec![object_entry(9, "late")]),
    ));
    assert!(state.objects.is_empty());
    assert!(!state.objects_loaded);
}
#[test]
fn unsupported_and_ambiguous_objects_keep_summary_without_an_inspect_request() {
    let mut state = browsing();
    let list = state.show_page(TokenPage::Objects).unwrap().id();
    let mut ambiguous = object_entry(4, "duplicate");
    ambiguous.ambiguous = true;
    let mut unsupported = object_entry(5, "unsupported");
    unsupported.uri = None;
    state.event(complete(
        list,
        objects_result(2, vec![ambiguous, unsupported]),
    ));
    assert!(state.select_object(ResourceId(4)).is_none());
    assert_eq!(state.object().unwrap().label, "duplicate");
    assert!(state.select_object(ResourceId(5)).is_none());
    assert_eq!(state.object().unwrap().label, "unsupported");
    assert!(state.current_operation.is_none());
}
#[test]
fn mechanism_filters_use_names_identifiers_and_flags_without_backend_work() {
    let mut state = browsing();
    let request = state.show_page(TokenPage::Mechanisms).unwrap().id();
    let entry = MechanismEntry {
        id: MechanismType::RSA_PKCS,
        name: "RSA_PKCS".into(),
        identifier: "0x1".into(),
        minimum: 1024,
        maximum: 4096,
        flags: vec!["Sign", "Verify"],
    };
    for filter in ["rsa", "0X1", "verify"] {
        assert!(entry.matches(filter));
    }
    state.event(complete(
        request,
        BackendResult::Mechanisms {
            module: ResourceId(1),
            token: ResourceId(2),
            mechanisms: vec![entry],
        },
    ));
    state.select_mechanism(MechanismType::RSA_PKCS);
    state.edit_mechanism_filter("derive".into());
    assert!(state.selected_mechanism.is_none());
    assert!(state.current_operation.is_none());
    state.refresh();
    assert!(state.mechanisms.is_empty());
    assert_eq!(state.token_page, TokenPage::Overview);
}
#[test]
fn matching_request_id_cannot_apply_another_token_or_object_result() {
    let mut state = browsing();
    let request = state.show_page(TokenPage::Objects).unwrap().id();
    state.event(complete(
        request,
        objects_result(3, vec![object_entry(9, "foreign")]),
    ));
    assert_eq!(state.current_operation, Some(request));
    assert!(state.objects.is_empty());
    state.event(complete(
        request,
        objects_result(2, vec![object_entry(4, "key")]),
    ));
    let request = state.select_object(ResourceId(4)).unwrap().id();
    state.event(complete(request, details_result(5, "foreign")));
    assert_eq!(state.current_operation, Some(request));
    assert!(state.object_details.is_none());
}

fn ready() -> UiState {
    UiState {
        worker_available: true,
        ..UiState::default()
    }
}
fn request(state: &mut UiState) -> RequestId {
    match state.start(SyntheticOutcome::Success).unwrap() {
        BackendCommand::Synthetic { id, .. } => id,
        _ => unreachable!(),
    }
}

#[test]
fn latest_request_wins_even_if_responses_arrive_out_of_order() {
    let mut state = ready();
    let a = request(&mut state);
    let b = request(&mut state);
    assert_ne!(a, b);
    state.event(BackendEvent::Completed {
        id: b,
        result: Ok(BackendResult::Synthetic),
    });
    state.event(BackendEvent::Completed {
        id: a,
        result: Err(BackendError::Synthetic),
    });
    assert_eq!(state.notification, Some(Notification::Completed));
    assert_eq!(state.current_operation, None);
}

#[test]
fn stale_result_does_not_clear_an_active_request() {
    let mut state = ready();
    let a = request(&mut state);
    let b = request(&mut state);
    state.event(BackendEvent::Completed {
        id: a,
        result: Ok(BackendResult::Synthetic),
    });
    assert_eq!(state.current_operation, Some(b));
    assert_eq!(state.notification, None);
}

#[test]
fn cancel_and_navigation_ignore_eventual_results() {
    let mut state = ready();
    let cancelled = request(&mut state);
    state.cancel();
    state.event(BackendEvent::Completed {
        id: cancelled,
        result: Ok(BackendResult::Synthetic),
    });
    assert_eq!(state.notification, Some(Notification::Cancelled));
    let navigated = request(&mut state);
    state.navigate(Screen::Modules);
    state.event(BackendEvent::Completed {
        id: navigated,
        result: Ok(BackendResult::Synthetic),
    });
    assert_eq!(state.screen, Screen::Modules);
    assert_eq!(state.current_operation, None);
    assert_eq!(state.notification, Some(Notification::Cancelled));
}

#[test]
fn shutdown_is_idempotent_and_rejects_new_work_and_late_results() {
    let mut state = ready();
    let old = request(&mut state);
    let shutdown = state.begin_shutdown().unwrap();
    assert_ne!(shutdown, old);
    assert!(state.begin_shutdown().is_none());
    assert!(state.start(SyntheticOutcome::Success).is_none());
    state.event(BackendEvent::Completed {
        id: old,
        result: Ok(BackendResult::Synthetic),
    });
    state.event(BackendEvent::Stopped {
        id: old,
        result: Ok(()),
    });
    assert!(state.worker_available);
    state.event(BackendEvent::Stopped {
        id: shutdown,
        result: Ok(()),
    });
    assert!(!state.worker_available);
    assert_eq!(state.notification, None);
}

#[test]
fn failures_and_disconnects_are_visible() {
    let mut state = ready();
    let id = request(&mut state);
    state.event(BackendEvent::Completed {
        id,
        result: Err(BackendError::Synthetic),
    });
    assert_eq!(
        state.notification,
        Some(Notification::Error(BackendError::Synthetic))
    );
    state.event(BackendEvent::Disconnected);
    assert!(!state.worker_available);
    assert!(state.start(SyntheticOutcome::Success).is_none());
}

#[test]
fn request_ids_do_not_wrap_and_shutdown_keeps_its_reserved_id() {
    let mut state = ready();
    state.next_request = u64::MAX - 2;
    assert_eq!(request(&mut state), RequestId(u64::MAX - 1));
    state.cancel();
    assert!(state.start(SyntheticOutcome::Success).is_none());
    assert_eq!(state.begin_shutdown(), Some(RequestId(u64::MAX)));
}
fn token(id: u64, serial: &str) -> TokenEntry {
    TokenEntry {
        id: ResourceId(id),
        slot_id: 10,
        label: "Token".into(),
        manufacturer: "Maker".into(),
        model: "Model".into(),
        serial: serial.into(),
        uri: Some(format!("pkcs11:serial={serial}")),
        details: Vec::new(),
    }
}
fn module(id: u64, tokens: Vec<TokenEntry>) -> ModuleEntry {
    ModuleEntry {
        id: ResourceId(id),
        path: PathBuf::from("module.so"),
        description: "Module".into(),
        manufacturer: "Maker".into(),
        library_version: "1.0".into(),
        cryptoki_version: "2.40".into(),
        slots: Vec::new(),
        tokens,
        discovery_error: None,
    }
}
fn modules(
    id: RequestId,
    entries: Vec<ModuleEntry>,
    loaded: Option<ResourceId>,
    error: Option<BackendError>,
) -> BackendEvent {
    BackendEvent::Completed {
        id,
        result: Ok(BackendResult::Modules {
            modules: entries,
            loaded,
            error,
        }),
    }
}
#[test]
fn loading_survives_navigation_and_cannot_be_cancelled_or_superseded() {
    let mut state = ready();
    state.edit_path("module.so".into());
    let id = state.load().unwrap().id();
    assert!(!state.can_cancel());
    state.cancel();
    state.navigate(Screen::Welcome);
    assert_eq!(state.current_operation, Some(id));
    assert!(state.load().is_none());
    state.event(modules(
        id,
        vec![module(1, vec![token(2, "1")])],
        Some(ResourceId(1)),
        None,
    ));
    assert_eq!(state.loaded_modules.len(), 1);
    assert_eq!(state.screen, Screen::Welcome);
    assert!(state.selected_module.is_none());
    assert!(state.can_submit());
}
#[test]
fn load_selects_module_and_failure_keeps_existing_inventory() {
    let mut state = ready();
    state.edit_path("module.so".into());
    let id = state.load().unwrap().id();
    state.event(modules(
        id,
        vec![module(1, vec![token(2, "1")])],
        Some(ResourceId(1)),
        None,
    ));
    assert_eq!(state.selected_module, Some(ResourceId(1)));
    state.select_token(ResourceId(1), ResourceId(2));
    let id = state.load().unwrap().id();
    state.event(modules(
        id,
        state.loaded_modules.clone(),
        None,
        Some(BackendError::AlreadyLoaded),
    ));
    assert_eq!(state.selected_token, Some(ResourceId(2)));
    assert_eq!(
        state.notification,
        Some(Notification::Error(BackendError::AlreadyLoaded))
    );
}
#[test]
fn refresh_preserves_live_selection_and_rejects_a_late_snapshot() {
    let mut state = ready();
    state.loaded_modules = vec![module(1, vec![token(2, "A"), token(3, "B")])];
    state.select_token(ResourceId(1), ResourceId(2));
    let a = state.refresh().unwrap().id();
    state.select_token(ResourceId(1), ResourceId(3));
    let b = state.refresh().unwrap().id();
    let mut latest = state.loaded_modules.clone();
    latest[0].tokens[1]
        .details
        .push(("Current".into(), "B".into()));
    state.event(modules(b, latest, None, None));
    state.event(modules(a, vec![module(1, vec![token(2, "A")])], None, None));
    assert_eq!(state.selected_token, Some(ResourceId(3)));
    assert_eq!(state.token().unwrap().serial, "B");
    assert_eq!(state.token().unwrap().details.len(), 1);
}
#[test]
fn removal_replacement_and_unload_clear_only_invalid_selections() {
    let mut state = ready();
    state.loaded_modules = vec![module(1, vec![token(2, "A")])];
    state.select_token(ResourceId(1), ResourceId(2));
    state.selected_object = Some(ResourceId(99));
    let id = state.refresh().unwrap().id();
    state.event(modules(
        id,
        vec![module(1, vec![token(3, "B")])],
        None,
        None,
    ));
    assert_eq!(state.selected_module, Some(ResourceId(1)));
    assert!(state.selected_token.is_none());
    assert!(state.selected_object.is_none());
    state.select_token(ResourceId(1), ResourceId(3));
    let id = state.unload().unwrap().id();
    state.cancel();
    assert_eq!(state.current_operation, Some(id));
    state.event(modules(
        id,
        Vec::new(),
        None,
        Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
    ));
    assert!(state.selected_module.is_none());
    assert!(state.selected_token.is_none());
    assert!(state.loaded_modules.is_empty());
    assert!(matches!(state.notification, Some(Notification::Error(_))));
}
#[test]
fn cancelled_refresh_and_invalid_selection_cannot_restore_stale_resources() {
    let mut state = ready();
    state.loaded_modules = vec![module(1, vec![token(2, "A")])];
    state.select_token(ResourceId(1), ResourceId(2));
    let id = state.refresh().unwrap().id();
    state.cancel();
    state.event(modules(id, Vec::new(), None, None));
    assert_eq!(state.token().unwrap().serial, "A");
    state.select_token(ResourceId(9), ResourceId(2));
    assert_eq!(state.selected_module, Some(ResourceId(1)));
    state.event(BackendEvent::Disconnected);
    assert!(state.loaded_modules.is_empty());
    assert!(state.refresh().is_none());
}
#[test]
fn picker_cancellation_editing_navigation_and_shutdown_reject_late_paths() {
    let mut state = ready();
    state.edit_path("manual.so".into());
    let id = state.begin_picker().unwrap();
    state.picked(id, None);
    assert_eq!(state.module_path, "manual.so");
    let id = state.begin_picker().unwrap();
    state.edit_path("new.so".into());
    state.picked(id, Some(PathBuf::from("stale.so")));
    assert_eq!(state.module_path, "new.so");
    let id = state.begin_picker().unwrap();
    state.navigate(Screen::Modules);
    state.picked(id, Some(PathBuf::from("other-screen.so")));
    assert_eq!(state.module_path, "new.so");
    let id = state.begin_picker().unwrap();
    state.begin_shutdown();
    state.picked(id, Some(PathBuf::from("late.so")));
    assert_eq!(state.module_path, "new.so");
}
#[cfg(unix)]
#[test]
fn selected_non_utf8_path_survives_display_conversion() {
    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"module-\xff.so".to_vec()));
    let mut state = ready();
    let id = state.begin_picker().unwrap();
    state.picked(id, Some(path.clone()));
    assert!(
        matches!(state.load(), Some(BackendCommand::Load { path: selected, .. }) if selected == path)
    );
}
