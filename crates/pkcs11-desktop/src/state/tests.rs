// SPDX-License-Identifier: MIT OR Apache-2.0
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
        initialization: pkcs11_client::TokenInitializationTarget {
            slot_id: 10,
            label: "Token".into(),
            manufacturer: "Maker".into(),
            model: "Model".into(),
            serial: serial.into(),
            initialized: true,
            minimum_pin_length: 4,
            maximum_pin_length: 32,
        },
        id: ResourceId(id),
        slot_id: 10,
        label: "Token".into(),
        manufacturer: "Maker".into(),
        model: "Model".into(),
        serial: serial.into(),
        uri: Some(format!("pkcs11:serial={serial}")),
        details: Vec::new(),
        login: crate::backend::LoginState::Public,
        initialized: true,
        user_pin_initialized: true,
        user_pin_locked: false,
        so_pin_locked: false,
        write_protected: false,
        protected_path: false,
        rng: true,
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

#[test]
fn authentication_form_rejects_stale_input_and_clears_on_navigation() {
    use secrecy::ExposeSecret;
    let mut state = browsing();
    state.open_login(LoginRole::User);
    let old = state.login_form.as_ref().unwrap().id;
    state.edit_pin(old, "secret-canary".into());
    state.select_token(ResourceId(1), ResourceId(3));
    assert!(state.login_form.is_none());
    state.open_login(LoginRole::User);
    let new = state.login_form.as_ref().unwrap().id;
    assert_ne!(old, new);
    state.edit_pin(old, "late-canary".into());
    assert!(
        state
            .login_form
            .as_ref()
            .unwrap()
            .pin
            .expose_secret()
            .is_empty()
    );
    assert!(state.login(old).is_none());
    state.edit_pin(new, "current".into());
    state.begin_shutdown();
    assert!(state.login_form.is_none());
}
#[test]
fn login_submission_moves_secret_and_preserves_lifecycle_result_across_navigation() {
    use secrecy::ExposeSecret;
    let mut state = browsing();
    state.objects = vec![object_entry(4, "old-private")];
    state.open_login(LoginRole::User);
    let form = state.login_form.as_ref().unwrap().id;
    state.edit_pin(form, "secret-canary".into());
    let request = match state.login(form).unwrap() {
        BackendCommand::Login {
            id,
            module,
            token,
            role,
            pin: SecretInput::Value(pin),
        } => {
            assert_eq!(module, ResourceId(1));
            assert_eq!(token, ResourceId(2));
            assert_eq!(role, LoginRole::User);
            assert_eq!(pin.expose_secret(), "secret-canary");
            id
        }
        _ => panic!("expected host login"),
    };
    assert!(state.login_form.is_none());
    assert!(state.objects.is_empty());
    assert!(!state.can_cancel());
    assert!(!state.can_submit());
    state.cancel();
    state.select_token(ResourceId(1), ResourceId(3));
    assert_eq!(state.current_operation, Some(request));
    assert!(state.refresh().is_none());
    let mut modules = state.loaded_modules.clone();
    modules[0].tokens[0].login = LoginState::User;
    state.event(complete(RequestId(request.0 - 1), BackendResult::Synthetic));
    assert_eq!(state.current_operation, Some(request));
    state.event(complete(
        request,
        BackendResult::Modules {
            modules,
            loaded: None,
            error: None,
        },
    ));
    assert_eq!(state.selected_token, Some(ResourceId(3)));
    assert_eq!(state.loaded_modules[0].tokens[0].login, LoginState::User);
    assert!(state.can_submit());
}
#[test]
fn protected_path_clears_host_pin_and_is_capability_gated() {
    use secrecy::ExposeSecret;
    let mut state = browsing();
    state.open_login(LoginRole::User);
    let id = state.login_form.as_ref().unwrap().id;
    state.edit_pin(id, "canary".into());
    state.use_protected_path(id, true);
    assert!(!state.login_form.as_ref().unwrap().protected_path);
    state.loaded_modules[0].tokens[0].protected_path = true;
    state.use_protected_path(id, true);
    assert!(
        state
            .login_form
            .as_ref()
            .unwrap()
            .pin
            .expose_secret()
            .is_empty()
    );
    state.edit_pin(id, "ignored".into());
    assert!(
        state
            .login_form
            .as_ref()
            .unwrap()
            .pin
            .expose_secret()
            .is_empty()
    );
    assert!(matches!(
        state.login(id),
        Some(BackendCommand::Login {
            pin: SecretInput::ProtectedPath,
            ..
        })
    ));
}
#[test]
fn logout_clears_private_metadata_and_cannot_be_cancelled() {
    let mut state = browsing();
    state.loaded_modules[0].tokens[0].login = LoginState::User;
    state.objects = vec![object_entry(4, "private")];
    state.selected_object = Some(ResourceId(4));
    state.object_details = Some(Vec::new());
    let id = state.logout().unwrap().id();
    assert!(state.objects.is_empty());
    assert!(state.object_details.is_none());
    assert!(state.selected_object.is_none());
    state.navigate(Screen::Welcome);
    state.cancel();
    assert_eq!(state.current_operation, Some(id));
    assert!(!state.can_cancel());
}
#[test]
fn authentication_roles_obey_initialization_lock_and_write_flags() {
    let mut entry = token(2, "A");
    assert!(entry.can_login(LoginRole::User));
    assert!(entry.can_login(LoginRole::SecurityOfficer));
    entry.user_pin_locked = true;
    assert!(!entry.can_login(LoginRole::User));
    assert!(entry.can_login(LoginRole::SecurityOfficer));
    entry.user_pin_locked = false;
    entry.user_pin_initialized = false;
    assert!(!entry.can_login(LoginRole::User));
    entry.write_protected = true;
    assert!(!entry.can_login(LoginRole::SecurityOfficer));
    entry.write_protected = false;
    entry.so_pin_locked = true;
    assert!(!entry.can_login(LoginRole::SecurityOfficer));
    entry.login = LoginState::User;
    assert!(!entry.can_login(LoginRole::User));
    entry.initialized = false;
    entry.login = LoginState::Public;
    assert!(!entry.can_login(LoginRole::User));
    assert!(!entry.can_login(LoginRole::SecurityOfficer));
}

fn managing() -> UiState {
    let mut state = browsing();
    state.loaded_modules[0].tokens[0].login = LoginState::User;
    state
}
#[test]
fn generation_choices_are_scoped_and_invalid_forms_do_not_enqueue_mutations() {
    let mut state = managing();
    let request = state.show_page(TokenPage::Operations).unwrap().id();
    let kind = crate::backend::GenerationKind::Signing(pkcs11_client::KeyKind::Rsa { bits: 2048 });
    state.event(complete(
        request,
        BackendResult::Capabilities {
            module: ResourceId(1),
            token: ResourceId(3),
            keys: vec![kind],
        },
    ));
    assert!(state.management.keys.is_empty());
    state.event(complete(
        request,
        BackendResult::Capabilities {
            module: ResourceId(1),
            token: ResourceId(2),
            keys: vec![kind],
        },
    ));
    state.management.key_label = "test".into();
    state.management.key_id = "0FF".into();
    assert!(state.generate().is_none());
    state.management.key_id = "00FF".into();
    let request = state.generate().unwrap();
    assert!(
        matches!(request, BackendCommand::Manage { action: crate::backend::ManagementAction::Generate { kind: returned, id, .. }, .. } if returned == kind && id == vec![0, 255])
    );
    assert!(!state.can_cancel());
    assert!(!state.can_submit());
    assert!(state.management.key_label.is_empty());
}
#[test]
fn deletion_confirmation_cannot_target_another_selection_and_refreshes_even_on_failure() {
    let mut state = managing();
    state.token_page = TokenPage::Objects;
    state.objects = vec![object_entry(4, "old"), object_entry(5, "new")];
    state.selected_object = Some(ResourceId(4));
    state.request_delete();
    let first = state.management.confirmation.as_ref().unwrap().id;
    assert_eq!(state.dialog, Some(Dialog::Delete(first)));
    assert!(state.current_operation.is_none());
    state.select_object(ResourceId(5));
    assert!(state.dialog.is_none());
    assert!(state.confirm_delete(first).is_none());
    state.request_delete();
    let second = state.management.confirmation.as_ref().unwrap().id;
    assert!(state.confirm_delete(first).is_none());
    let request = state.confirm_delete(second).unwrap().id();
    assert!(state.objects.is_empty());
    assert!(state.dialog.is_none());
    assert!(!state.can_cancel());
    state.event(complete(
        request,
        BackendResult::Managed {
            module: ResourceId(1),
            token: ResourceId(2),
            modules: state.loaded_modules.clone(),
            objects: Some(vec![object_entry(6, "still present")]),
            error: Some(BackendError::Client(pkcs11_client::ErrorKind::Runtime)),
        },
    ));
    assert_eq!(state.objects[0].id, ResourceId(6));
    assert!(state.selected_object.is_none());
    assert_eq!(state.token_page, TokenPage::Objects);
    assert!(matches!(state.notification, Some(Notification::Error(_))));
}
#[test]
fn late_file_picker_and_management_results_cannot_restore_an_old_token() {
    let mut state = managing();
    let request = state.show_page(TokenPage::Operations).unwrap().id();
    state.event(complete(
        request,
        BackendResult::Capabilities {
            module: ResourceId(1),
            token: ResourceId(2),
            keys: Vec::new(),
        },
    ));
    let (picker, _) = state.begin_object_file(false).unwrap();
    state.select_token(ResourceId(1), ResourceId(3));
    assert!(
        state
            .object_file_picked(picker, Some(PathBuf::from("old.der")))
            .is_none()
    );
    assert!(state.management.certificate_path.is_empty());
    state.select_token(ResourceId(1), ResourceId(2));
    state.token_page = TokenPage::Objects;
    state.objects = vec![object_entry(4, "public")];
    state.selected_object = Some(ResourceId(4));
    state.object_details = Some(vec![MetadataField {
        name: "Private",
        status: "available",
        value: Some("false".into()),
    }]);
    let (picker, _) = state.begin_object_file(true).unwrap();
    let operation = state
        .object_file_picked(picker, Some(PathBuf::from("new.der")))
        .unwrap()
        .id();
    state.select_token(ResourceId(1), ResourceId(3));
    state.event(complete(
        operation,
        BackendResult::Managed {
            module: ResourceId(1),
            token: ResourceId(2),
            modules: state.loaded_modules.clone(),
            objects: Some(vec![object_entry(8, "foreign")]),
            error: None,
        },
    ));
    assert_eq!(state.selected_token, Some(ResourceId(3)));
    assert!(state.objects.is_empty());
    assert_eq!(state.token_page, TokenPage::Overview);
}
#[test]
fn private_or_ambiguous_objects_never_offer_export_and_import_validation_is_local() {
    let mut state = managing();
    state.token_page = TokenPage::Objects;
    let mut entry = object_entry(4, "private");
    entry.class = Some(pkcs11_client::ObjectClass::PRIVATE_KEY);
    state.objects = vec![entry];
    state.selected_object = Some(ResourceId(4));
    state.object_details = Some(vec![MetadataField {
        name: "Private",
        status: "available",
        value: Some("false".into()),
    }]);
    assert!(!state.can_export());
    state.objects[0].class = Some(pkcs11_client::ObjectClass::DATA);
    state.objects[0].ambiguous = true;
    assert!(!state.can_export());
    state.request_delete();
    assert!(state.dialog.is_none());
    state.objects[0].ambiguous = false;
    state.object_details.as_mut().unwrap()[0].value = Some("true".into());
    assert!(!state.can_export());
    state.show_page(TokenPage::Operations);
    state.management.certificate_id = "01".into();
    state.management.certificate_label = "certificate".into();
    assert!(state.import_certificate().is_none());
    state.management.certificate_path = "fixture.der".into();
    assert!(matches!(
        state.import_certificate(),
        Some(BackendCommand::Manage {
            action: crate::backend::ManagementAction::ImportCertificate { .. },
            ..
        })
    ));
}

#[test]
fn pqc_public_export_picker_is_scoped_to_the_selected_object_without_login() {
    for family in ["CKK_ML_DSA", "CKK_ML_KEM"] {
        let mut state = browsing();
        state.token_page = TokenPage::Objects;
        state.objects = vec![object_entry(4, "PQC public key"), object_entry(5, "other")];
        state.selected_object = Some(ResourceId(4));
        state.object_details = Some(vec![
            MetadataField {
                name: "Key type",
                status: "available",
                value: Some(family.into()),
            },
            MetadataField {
                name: "Private",
                status: "available",
                value: Some("false".into()),
            },
        ]);
        assert_eq!(state.token().unwrap().login, LoginState::Public);
        assert!(state.can_export());
        let (picker, _) = state.begin_object_file(true).unwrap();
        state.select_object(ResourceId(5));
        assert!(
            state
                .object_file_picked(picker, Some(PathBuf::from("obsolete.der")))
                .is_none()
        );
        assert_eq!(state.selected_object, Some(ResourceId(5)));
        assert!(!state.can_export());
    }
}

fn crypto_state(
    mode: crate::backend::CryptoMode,
) -> (UiState, RequestId, crate::backend::CryptoScope) {
    use crate::backend::{CryptoMode, SignatureOption};
    let mut state = browsing();
    state.loaded_modules[0].tokens[0].login = LoginState::User;
    let list = state.show_page(TokenPage::Objects).unwrap().id();
    let mut object = object_entry(4, "crypto");
    object.class = Some(if mode == CryptoMode::Sign {
        pkcs11_client::ObjectClass::PRIVATE_KEY
    } else {
        pkcs11_client::ObjectClass::CERTIFICATE
    });
    state.event(complete(list, objects_result(2, vec![object])));
    let detail = state.select_object(ResourceId(4)).unwrap().id();
    state.event(complete(detail, details_result(4, "crypto")));
    let command = state.open_crypto(mode).unwrap();
    let BackendCommand::CryptoOptions { id, scope, .. } = command else {
        panic!("options command");
    };
    state.event(complete(
        id,
        BackendResult::CryptoOptions {
            scope,
            context: mode == CryptoMode::Sign,
            options: vec![SignatureOption {
                parameters: pkcs11_client::SignatureParameters {
                    algorithm: pkcs11_client::SignatureAlgorithm::RsaPkcs1,
                    digest: pkcs11_client::DigestAlgorithm::Sha256,
                    pss: None,
                },
                plan: None,
            }],
        },
    ));
    (state, id, scope)
}
#[test]
fn crypto_pin_moves_once_and_signing_cannot_be_superseded() {
    use crate::backend::{CryptoJob, CryptoMode};
    use CryptoField::*;
    let (mut state, form, scope) = crypto_state(CryptoMode::Sign);
    state.crypto_pin(form, "redaction-canary".into());
    assert!(state.submit_crypto(form).is_none());
    assert!(
        secrecy::ExposeSecret::expose_secret(&state.crypto_form.as_ref().unwrap().pin).is_empty()
    );
    state.crypto_edit(form, Input, "message.bin".into());
    state.crypto_edit(form, Signature, "new.sig".into());
    state.crypto_pin(form, "redaction-canary".into());
    let BackendCommand::Crypto {
        id,
        scope: actual,
        job:
            CryptoJob {
                context: Some(SecretInput::Value(pin)),
                ..
            },
    } = state.submit_crypto(form).unwrap()
    else {
        panic!("one-shot sign command");
    };
    assert_eq!(actual, scope);
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(&pin),
        "redaction-canary"
    );
    assert!(state.crypto_form.is_none());
    assert!(!state.can_submit());
    assert!(!state.can_cancel());
    state.cancel();
    assert_eq!(state.current_operation, Some(id));
    assert!(state.submit_crypto(form).is_none());
    state.select_token(ResourceId(1), ResourceId(3));
    state.event(complete(
        id,
        BackendResult::Managed {
            module: scope.module,
            token: scope.token,
            modules: state.loaded_modules.clone(),
            objects: Some(vec![object_entry(8, "old")]),
            error: None,
        },
    ));
    assert_eq!(state.selected_token, Some(ResourceId(3)));
    assert!(state.objects.is_empty());
}
#[test]
fn verification_edits_and_navigation_reject_old_success() {
    use crate::backend::CryptoMode;
    let (mut state, form, scope) = crypto_state(CryptoMode::Verify);
    state.crypto_edit(form, CryptoField::Input, "input".into());
    state.crypto_edit(form, CryptoField::Signature, "signature".into());
    let pending = state.submit_crypto(form).unwrap().id();
    state.crypto_edit(form, CryptoField::Input, "changed".into());
    state.event(complete(pending, BackendResult::Verified { scope }));
    assert_ne!(state.notification, Some(Notification::SignatureVerified));
    let current = state.submit_crypto(form).unwrap().id();
    state.event(complete(current, BackendResult::Verified { scope }));
    assert_eq!(state.notification, Some(Notification::SignatureVerified));
    state.crypto_edit(form, CryptoField::Signature, "changed-signature".into());
    assert!(state.notification.is_none());
    let pending = state.submit_crypto(form).unwrap().id();
    state.select_token(ResourceId(1), ResourceId(3));
    state.event(complete(pending, BackendResult::Verified { scope }));
    assert!(state.crypto_form.is_none());
    assert_ne!(state.notification, Some(Notification::SignatureVerified));
}
#[test]
fn crypto_policy_picker_and_secret_messages_are_scoped() {
    use crate::backend::CryptoMode;
    let (mut state, old, scope) = crypto_state(CryptoMode::Sign);
    state.crypto_pin(old, "canary".into());
    let (picker, _) = state.crypto_picker(old, CryptoField::Input).unwrap();
    let command = state.crypto_policy(old, true).unwrap();
    let current = command.id();
    assert_ne!(old, current);
    state.crypto_pin(old, "late-canary".into());
    state.crypto_pin(current, "during-capability-query-canary".into());
    state.crypto_picked(picker, Some("stale-input".into()));
    let form = state.crypto_form.as_ref().unwrap();
    assert_eq!(form.id, current);
    assert!(form.input.is_empty());
    assert!(secrecy::ExposeSecret::expose_secret(&form.pin).is_empty());
    state.event(complete(
        old,
        BackendResult::CryptoOptions {
            scope,
            options: Vec::new(),
            context: false,
        },
    ));
    assert_eq!(state.current_operation, Some(current));
    state.dismiss_crypto(current);
    state.crypto_pin(current, "late-canary".into());
    assert!(state.crypto_form.is_none());
    let (mut state, id, _) = crypto_state(CryptoMode::Sign);
    state.loaded_modules[0].tokens[0].protected_path = true;
    state.crypto_pin(id, "canary".into());
    state.crypto_protected(id, true);
    assert!(
        secrecy::ExposeSecret::expose_secret(&state.crypto_form.as_ref().unwrap().pin).is_empty()
    );
    state.crypto_pin(id, "ignored-canary".into());
    assert!(
        secrecy::ExposeSecret::expose_secret(&state.crypto_form.as_ref().unwrap().pin).is_empty()
    );
    state.begin_shutdown();
    assert!(state.crypto_form.is_none());
}
#[test]
fn ambiguous_or_wrong_class_objects_do_not_open_crypto_forms() {
    use crate::backend::CryptoMode;
    let (mut state, _, _) = crypto_state(CryptoMode::Sign);
    state.objects[0].ambiguous = true;
    assert!(state.open_crypto(CryptoMode::Sign).is_none());
    state.objects[0].ambiguous = false;
    state.objects[0].class = Some(pkcs11_client::ObjectClass::PUBLIC_KEY);
    assert!(state.open_crypto(CryptoMode::Sign).is_none());
    assert!(state.open_crypto(CryptoMode::Verify).is_none());
}

#[cfg(unix)]
#[test]
fn repeated_verification_preserves_native_non_utf8_paths() {
    use crate::backend::CryptoMode;
    use std::os::unix::ffi::OsStringExt;
    let (mut state, id, scope) = crypto_state(CryptoMode::Verify);
    let input = PathBuf::from(std::ffi::OsString::from_vec(b"input-\xff".to_vec()));
    let signature = PathBuf::from(std::ffi::OsString::from_vec(b"sig-\xff".to_vec()));
    let (picker, save) = state.crypto_picker(id, CryptoField::Input).unwrap();
    assert!(!save);
    state.crypto_picked(picker, Some(input.clone()));
    let (picker, save) = state.crypto_picker(id, CryptoField::Signature).unwrap();
    assert!(!save);
    state.crypto_picked(picker, Some(signature.clone()));
    for _ in 0..2 {
        let command = state.submit_crypto(id).unwrap();
        let request = command.id();
        let BackendCommand::Crypto { job, .. } = command else {
            panic!("verification command");
        };
        assert_eq!(job.input, input);
        assert_eq!(job.signature, signature);
        state.event(complete(request, BackendResult::Verified { scope }));
    }
    let pending = state.submit_crypto(id).unwrap().id();
    state.edit_object_filter("no matches".into());
    state.event(complete(pending, BackendResult::Verified { scope }));
    assert!(state.current_operation.is_none());
    assert!(state.crypto_form.is_none());
    assert_ne!(state.notification, Some(Notification::SignatureVerified));
}

#[test]
fn random_requests_validate_length_and_keep_file_writes_unsuperseded() {
    let mut state = browsing();
    state.show_page(TokenPage::Operations);
    assert!(state.can_random());
    state.random_edit(RandomField::Path, "new-random.bin".into());
    for value in ["0", "1048577", "-1", "", "184467440737095516160", "1.5"] {
        state.random_edit(RandomField::Length, value.into());
        assert!(state.generate_random().is_none());
        assert_eq!(
            state.notification,
            Some(Notification::Error(BackendError::RandomLength))
        );
    }
    state.random_edit(RandomField::Length, "1024".into());
    let BackendCommand::Random {
        id,
        module,
        token,
        request,
        path,
    } = state.generate_random().unwrap()
    else {
        panic!("random command");
    };
    assert_eq!(module, ResourceId(1));
    assert_eq!(token, ResourceId(2));
    assert_eq!(request.length(), 1024);
    assert_eq!(path, PathBuf::from("new-random.bin"));
    assert!(!state.can_submit());
    assert!(!state.can_cancel());
    state.cancel();
    assert_eq!(state.current_operation, Some(id));
    assert!(state.generate_random().is_none());
    state.select_token(ResourceId(1), ResourceId(3));
    state.event(complete(
        RequestId(id.0 - 1),
        BackendResult::RandomWritten { length: 99 },
    ));
    assert_eq!(state.current_operation, Some(id));
    state.event(complete(id, BackendResult::RandomWritten { length: 1024 }));
    assert_eq!(state.selected_token, Some(ResourceId(3)));
    assert!(state.objects.is_empty());
    assert_eq!(state.notification, Some(Notification::RandomSaved(1024)));
    assert!(state.current_operation.is_none());
}
#[test]
fn random_capability_and_picker_results_are_scoped() {
    let mut state = browsing();
    state.show_page(TokenPage::Operations);
    let picker = state.random_picker().unwrap();
    state.random_edit(RandomField::Path, "typed-path".into());
    state.random_picked(picker, Some("old-dialog-path".into()));
    assert_eq!(state.random.path, "typed-path");
    let picker = state.random_picker().unwrap();
    state.select_token(ResourceId(1), ResourceId(3));
    state.show_page(TokenPage::Operations);
    state.random_picked(picker, Some("token-A-path".into()));
    assert!(state.random.path.is_empty());
    state.loaded_modules[0].tokens[1].rng = false;
    assert!(!state.can_random());
    assert!(state.random_picker().is_none());
    assert!(state.generate_random().is_none());
    state.loaded_modules[0].tokens[1].rng = true;
    state.loaded_modules[0].tokens[1].initialized = false;
    assert!(!state.can_random());
    state.loaded_modules[0].tokens[1].initialized = true;
    let picker = state.random_picker().unwrap();
    state.begin_shutdown();
    state.random_picked(picker, Some("late-path".into()));
    assert!(state.random.path.is_empty());
}
#[cfg(unix)]
#[test]
fn random_generation_keeps_native_non_utf8_picker_path() {
    use std::os::unix::ffi::OsStringExt;
    let mut state = browsing();
    state.show_page(TokenPage::Operations);
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"random-\xff.bin".to_vec()));
    let picker = state.random_picker().unwrap();
    state.random_picked(picker, Some(path.clone()));
    let BackendCommand::Random { path: native, .. } = state.generate_random().unwrap() else {
        panic!("random command");
    };
    assert_eq!(native, path);
    assert!(state.random.path.is_empty());
    assert!(state.random.picker.is_none());
}

fn cipher_state(
    mode: crate::backend::CryptoMode,
) -> (UiState, RequestId, crate::backend::CryptoScope) {
    use crate::backend::CryptoMode;
    let mut state = browsing();
    state.loaded_modules[0].tokens[0].login = LoginState::User;
    let list = state.show_page(TokenPage::Objects).unwrap().id();
    let mut object = object_entry(4, "cipher");
    object.class = Some(if mode == CryptoMode::Encrypt {
        pkcs11_client::ObjectClass::PUBLIC_KEY
    } else {
        pkcs11_client::ObjectClass::PRIVATE_KEY
    });
    state.event(complete(list, objects_result(2, vec![object])));
    state.select_object(ResourceId(4));
    let BackendCommand::CryptoOptions { id, scope, .. } = state.open_cipher(mode).unwrap() else {
        panic!("cipher options");
    };
    state.event(complete(
        id,
        BackendResult::CipherOptions {
            scope,
            choices: vec![crate::backend::CipherParameters::Oaep(
                pkcs11_client::OaepChoice {
                    digest: pkcs11_client::DigestAlgorithm::Sha256,
                    maximum_plaintext: 190,
                    ciphertext_length: 256,
                },
            )],
        },
    ));
    (state, id, scope)
}
#[test]
fn cipher_forms_validate_and_submit_once_without_restoring_a_navigated_token() {
    let (mut state, id, scope) = cipher_state(crate::backend::CryptoMode::Decrypt);
    assert!(state.submit_cipher(id).is_none());
    state.cipher_edit(id, CipherField::Input, "cipher.bin".into());
    state.cipher_edit(id, CipherField::Output, "new-plain.bin".into());
    let command = state.submit_cipher(id).unwrap();
    let request = command.id();
    let BackendCommand::Cipher {
        scope: actual, job, ..
    } = command
    else {
        panic!("cipher command");
    };
    assert_eq!(actual, scope);
    assert_eq!(job.input, PathBuf::from("cipher.bin"));
    assert!(
        matches!(job.choice,crate::backend::CipherParameters::Oaep(choice) if choice.maximum_plaintext == 190)
    );
    assert!(state.cipher_form.is_none());
    assert!(!state.can_cancel());
    assert!(!state.can_submit());
    state.cancel();
    assert_eq!(state.current_operation, Some(request));
    state.select_token(ResourceId(1), ResourceId(3));
    state.event(complete(
        request,
        BackendResult::Managed {
            module: scope.module,
            token: scope.token,
            modules: state.loaded_modules.clone(),
            objects: Some(vec![object_entry(7, "old")]),
            error: None,
        },
    ));
    assert_eq!(state.selected_token, Some(ResourceId(3)));
    assert!(state.objects.is_empty());
}
#[test]
fn cipher_options_picker_and_message_scopes_reject_old_results() {
    let (mut state, id, scope) = cipher_state(crate::backend::CryptoMode::Encrypt);
    let (picker, save) = state.cipher_picker(id, CipherField::Output).unwrap();
    assert!(save);
    state.cipher_edit(id, CipherField::Output, "typed".into());
    state.cipher_picked(picker, Some("stale".into()));
    assert_eq!(state.cipher_form.as_ref().unwrap().output, "typed");
    state.dismiss_cipher(id);
    state.cipher_edit(id, CipherField::Input, "old-input".into());
    assert!(state.cipher_form.is_none());
    let current = state
        .open_cipher(crate::backend::CryptoMode::Encrypt)
        .unwrap()
        .id();
    state.event(complete(
        id,
        BackendResult::CipherOptions {
            scope,
            choices: Vec::new(),
        },
    ));
    assert_eq!(state.current_operation, Some(current));
    let (picker, _) = state.cipher_picker(current, CipherField::Input).unwrap();
    state.select_token(ResourceId(1), ResourceId(3));
    state.cipher_picked(picker, Some("old-token".into()));
    assert!(state.cipher_form.is_none());
    let (mut state, id, _) = cipher_state(crate::backend::CryptoMode::Decrypt);
    state.loaded_modules[0].tokens[0].login = LoginState::Public;
    assert!(state.submit_cipher(id).is_none());
}
#[cfg(unix)]
#[test]
fn cipher_paths_preserve_native_non_utf8_names_and_shutdown_clears_forms() {
    use std::os::unix::ffi::OsStringExt;
    let (mut state, id, _) = cipher_state(crate::backend::CryptoMode::Encrypt);
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"cipher-\xff".to_vec()));
    let (picker, _) = state.cipher_picker(id, CipherField::Input).unwrap();
    state.cipher_picked(picker, Some(path.clone()));
    state.cipher_edit(id, CipherField::Output, "new.bin".into());
    let BackendCommand::Cipher { job, .. } = state.submit_cipher(id).unwrap() else {
        panic!("cipher command");
    };
    assert_eq!(job.input, path);
    state.begin_shutdown();
    assert!(state.cipher_form.is_none());
}

#[test]
fn failed_cipher_choice_loading_stops_and_clears_on_form_changes() {
    let (mut state, id, _) = cipher_state(crate::backend::CryptoMode::Encrypt);
    state.dismiss_cipher(id);
    let request = state
        .open_cipher(crate::backend::CryptoMode::Encrypt)
        .unwrap()
        .id();
    state.event(BackendEvent::Completed {
        id: request,
        result: Err(BackendError::CipherUnavailable),
    });
    assert!(state.cipher_form.as_ref().unwrap().loaded);
    assert!(state.cipher_form.as_ref().unwrap().choices.is_empty());
    assert!(state.current_operation.is_none());
    state.select_object(ResourceId(4));
    state.objects[0].class = Some(pkcs11_client::ObjectClass::PRIVATE_KEY);
    state.open_crypto(crate::backend::CryptoMode::Sign);
    assert!(state.cipher_form.is_none());
}

fn key_state(
    mode: crate::backend::CryptoMode,
) -> (UiState, RequestId, crate::backend::CryptoScope) {
    use crate::backend::CryptoMode;
    let (mut state, _, _) = cipher_state(CryptoMode::Decrypt);
    state.objects[0].class = Some(if mode == CryptoMode::Derive {
        pkcs11_client::ObjectClass::PRIVATE_KEY
    } else {
        pkcs11_client::ObjectClass::SECRET_KEY
    });
    let mut target = object_entry(5, "target");
    target.class = Some(pkcs11_client::ObjectClass::SECRET_KEY);
    state.objects.push(target);
    let BackendCommand::CryptoOptions { id, scope, .. } = state.open_key_operation(mode).unwrap()
    else {
        panic!("options");
    };
    let profile = if mode == CryptoMode::Derive {
        pkcs11_client::KeyOperationProfile::EcdhRaw(pkcs11_client::NamedCurve::P256)
    } else {
        pkcs11_client::KeyOperationProfile::AesKeyWrap(32)
    };
    state.event(complete(id, BackendResult::KeyOptions { scope, profile }));
    (state, id, scope)
}
#[test]
fn key_operations_validate_forms_and_cannot_cancel_or_supersede_mutations() {
    use crate::backend::CryptoMode;
    for mode in [CryptoMode::Derive, CryptoMode::Unwrap, CryptoMode::Wrap] {
        let (mut state, id, scope) = key_state(mode);
        assert!(state.submit_key_operation(id).is_none());
        assert_eq!(
            state.notification,
            Some(Notification::Error(BackendError::KeyOperationInput))
        );
        if mode == CryptoMode::Wrap {
            let target = state.key_form.as_ref().unwrap().targets[0].clone();
            state.key_target(id, target);
            state.key_edit(id, KeyField::Output, "new-output".into());
        } else {
            state.key_edit(id, KeyField::Input, "peer-or-wrapped".into());
            state.key_edit(id, KeyField::Label, "new-key".into());
            state.key_edit(id, KeyField::Id, "ABCD".into());
        }
        assert!(state.submit_key_operation(RequestId(id.0 + 99)).is_none());
        let command = state.submit_key_operation(id).unwrap();
        assert!(!state.can_cancel());
        assert!(!state.can_submit());
        assert!(state.key_form.is_none());
        state.select_token(ResourceId(1), ResourceId(3));
        state.event(complete(
            command.id(),
            BackendResult::Managed {
                module: scope.module,
                token: scope.token,
                modules: state.loaded_modules.clone(),
                objects: Some(vec![object_entry(99, "late-created")]),
                error: None,
            },
        ));
        assert_eq!(state.selected_token, Some(ResourceId(3)));
        assert!(state.objects.is_empty());
    }
}
#[test]
fn key_profiles_picker_and_errors_are_scoped_to_the_current_form() {
    use crate::backend::CryptoMode;
    let (mut state, id, scope) = key_state(CryptoMode::Derive);
    let (picker, _) = state.key_picker(id, KeyField::Input).unwrap();
    state.key_edit(id, KeyField::Input, "typed".into());
    state.key_picked(picker, Some("stale".into()));
    assert_eq!(state.key_form.as_ref().unwrap().input, "typed");
    state.select_token(ResourceId(1), ResourceId(3));
    state.event(complete(
        id,
        BackendResult::KeyOptions {
            scope,
            profile: pkcs11_client::KeyOperationProfile::EcdhRaw(pkcs11_client::NamedCurve::P256),
        },
    ));
    state.key_picked(picker, Some("late".into()));
    assert!(state.key_form.is_none());
    let (mut state, id, _) = key_state(CryptoMode::Unwrap);
    state.dismiss_key_operation(id);
    let command = state.open_key_operation(CryptoMode::Unwrap).unwrap();
    state.event(BackendEvent::Completed {
        id: command.id(),
        result: Err(BackendError::KeyOperationUnavailable),
    });
    assert!(state.key_form.as_ref().unwrap().loaded);
    assert!(state.key_form.as_ref().unwrap().profile.is_none());
    state.loaded_modules[0].tokens[0].login = LoginState::Public;
    assert!(state.submit_key_operation(command.id()).is_none());
}
#[cfg(unix)]
#[test]
fn key_file_pickers_preserve_native_paths_and_shutdown_clears_forms() {
    use crate::backend::{CryptoMode, KeyJob};
    use std::os::unix::ffi::OsStringExt;
    let (mut state, id, _) = key_state(CryptoMode::Derive);
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"peer-\xff.der".to_vec()));
    let (picker, _) = state.key_picker(id, KeyField::Input).unwrap();
    state.key_picked(picker, Some(path.clone()));
    state.key_edit(id, KeyField::Id, "01".into());
    state.key_edit(id, KeyField::Label, "secret".into());
    let BackendCommand::KeyOperation {
        job: KeyJob::Derive { peer, .. },
        ..
    } = state.submit_key_operation(id).unwrap()
    else {
        panic!("derive");
    };
    assert_eq!(peer, path);
    let (mut state, id, _) = key_state(CryptoMode::Wrap);
    let (picker, _) = state.key_picker(id, KeyField::Output).unwrap();
    state.begin_shutdown();
    state.key_picked(picker, Some(path));
    assert!(state.key_form.is_none());
}

fn administration_state(kind: crate::backend::AdministrationKind) -> (UiState, RequestId) {
    use crate::backend::AdministrationKind;
    let mut state = browsing();
    state.loaded_modules[0].tokens[0].login = if kind == AdministrationKind::InitializeUserPin {
        LoginState::SecurityOfficer
    } else {
        LoginState::User
    };
    state.show_page(TokenPage::Administration);
    state.open_administration(kind);
    let id = state.administration_form.as_ref().unwrap().id;
    (state, id)
}
fn fill_administration(state: &mut UiState, id: RequestId) {
    state.administration_pin(id, AdministrationPinField::Current, "12345678".into());
    state.administration_pin(id, AdministrationPinField::New, "23456789".into());
    state.administration_pin(id, AdministrationPinField::Confirm, "23456789".into());
    state.administration_edit(id, AdministrationField::Label, "new-label".into());
}
#[test]
fn administration_requires_review_and_exact_confirmation_and_never_retains_submitted_pins() {
    use crate::backend::AdministrationKind;
    for kind in [
        AdministrationKind::InitializeToken,
        AdministrationKind::InitializeUserPin,
        AdministrationKind::ChangePin,
    ] {
        let (mut state, id) = administration_state(kind);
        fill_administration(&mut state, id);
        assert!(state.submit_administration(id).is_none());
        state.review_administration(id);
        assert!(state.administration_form.as_ref().unwrap().reviewing);
        state.administration_edit(id, AdministrationField::Confirmation, "wrong".into());
        assert!(state.submit_administration(id).is_none());
        state.administration_edit(
            id,
            AdministrationField::Confirmation,
            if kind == AdministrationKind::InitializeToken {
                "ERASE"
            } else {
                "CHANGE"
            }
            .into(),
        );
        let command = state.submit_administration(id).unwrap();
        assert!(state.administration_form.is_none());
        assert!(!state.can_cancel());
        assert!(!state.can_submit());
        state.cancel();
        assert_eq!(state.current_operation, Some(command.id()));
        state.select_token(ResourceId(1), ResourceId(3));
        state.event(complete(
            command.id(),
            BackendResult::Modules {
                modules: state.loaded_modules.clone(),
                loaded: None,
                error: None,
            },
        ));
        assert_eq!(state.selected_token, Some(ResourceId(3)));
        assert!(state.administration_form.is_none());
    }
}
#[test]
fn administration_clears_secrets_on_invalid_review_navigation_login_and_shutdown() {
    use crate::backend::AdministrationKind;
    use secrecy::ExposeSecret;
    let (mut state, id) = administration_state(AdministrationKind::ChangePin);
    fill_administration(&mut state, id);
    state.administration_pin(id, AdministrationPinField::Confirm, "different".into());
    state.review_administration(id);
    let form = state.administration_form.as_ref().unwrap();
    assert!(form.old_pin.expose_secret().is_empty());
    assert!(form.new_pin.expose_secret().is_empty());
    assert!(form.confirm_pin.expose_secret().is_empty());
    assert!(!form.reviewing);
    for action in 0..4 {
        let (mut state, id) = administration_state(AdministrationKind::InitializeToken);
        fill_administration(&mut state, id);
        match action {
            0 => {
                state.show_page(TokenPage::Overview);
            }
            1 => state.select_token(ResourceId(1), ResourceId(3)),
            2 => {
                state.loaded_modules[0].tokens[0].login = LoginState::Public;
                state.open_login(LoginRole::User);
            }
            _ => {
                state.begin_shutdown();
            }
        }
        assert!(state.administration_form.is_none());
        state.review_administration(id);
        assert!(state.submit_administration(id).is_none());
    }
}
#[test]
fn administration_rejects_role_identity_and_capability_changes_after_review() {
    use crate::backend::AdministrationKind;
    for change in 0..5 {
        let (mut state, id) = administration_state(AdministrationKind::ChangePin);
        fill_administration(&mut state, id);
        state.review_administration(id);
        state.administration_edit(id, AdministrationField::Confirmation, "CHANGE".into());
        let token = &mut state.loaded_modules[0].tokens[0];
        match change {
            0 => token.login = LoginState::Public,
            1 => token.initialization.serial.push('x'),
            2 => token.write_protected = true,
            3 => token.protected_path = true,
            _ => token.user_pin_locked = true,
        }
        assert!(state.submit_administration(id).is_none());
    }
    let (mut state, id) = administration_state(AdministrationKind::InitializeUserPin);
    state.loaded_modules[0].tokens[0].login = LoginState::User;
    assert!(state.submit_administration(id).is_none());
}
#[test]
fn uninitialized_token_requires_confirmed_new_so_pin_and_byte_bounded_label() {
    use crate::backend::{AdministrationAction, AdministrationKind};
    let mut state = browsing();
    state.loaded_modules[0].tokens[0].initialized = false;
    state.loaded_modules[0].tokens[0].initialization.initialized = false;
    state.loaded_modules[0].tokens[0].so_pin_locked = true;
    state.show_page(TokenPage::Administration);
    state.open_administration(AdministrationKind::InitializeToken);
    let id = state.administration_form.as_ref().unwrap().id;
    state.administration_edit(id, AdministrationField::Label, "é".repeat(17));
    fill_administration(&mut state, id);
    state.administration_edit(id, AdministrationField::Label, "é".repeat(17));
    state.review_administration(id);
    assert!(!state.administration_form.as_ref().unwrap().reviewing);
    fill_administration(&mut state, id);
    state.review_administration(id);
    state.administration_edit(id, AdministrationField::Confirmation, "ERASE".into());
    assert!(matches!(
        state.submit_administration(id),
        Some(BackendCommand::Administer {
            action: AdministrationAction::InitializeToken { .. },
            ..
        })
    ));
}

#[test]
fn cancelled_read_still_invalidates_a_module_after_cleanup_failure() {
    let mut state = browsing();
    let old = state.show_page(TokenPage::Objects).unwrap().id();
    state.cancel();
    state.open_login(LoginRole::User);
    let mut disabled = module(1, Vec::new());
    disabled.discovery_error = Some(BackendError::SessionCleanup);
    state.event(complete(
        old,
        BackendResult::Modules {
            modules: vec![disabled],
            loaded: None,
            error: Some(BackendError::SessionCleanup),
        },
    ));
    assert!(state.loaded_modules[0].tokens.is_empty());
    assert!(state.login_form.is_none());
    assert!(state.selected_token.is_none());
    assert_eq!(state.selected_module, Some(ResourceId(1)));
    assert!(state.read_objects().is_none());
    assert!(state.unload().is_some());
}

#[test]
fn stale_cleanup_inventory_preserves_other_modules_and_newer_work() {
    let mut state = browsing();
    let old = state.show_page(TokenPage::Objects).unwrap().id();
    state.loaded_modules.push(module(4, vec![token(5, "C")]));
    state.select_token(ResourceId(4), ResourceId(5));
    let current = state.show_page(TokenPage::Objects).unwrap().id();
    let mut disabled = module(1, Vec::new());
    disabled.discovery_error = Some(BackendError::SessionCleanup);
    state.event(complete(
        old,
        BackendResult::Modules {
            modules: vec![disabled],
            loaded: None,
            error: Some(BackendError::SessionCleanup),
        },
    ));
    assert_eq!(state.loaded_modules.len(), 2);
    assert_eq!(state.current_operation, Some(current));
    assert_eq!(state.selected_module, Some(ResourceId(4)));
    assert_eq!(state.selected_token, Some(ResourceId(5)));
    state.event(complete(
        current,
        BackendResult::Objects {
            module: ResourceId(4),
            token: ResourceId(5),
            objects: vec![object_entry(6, "current")],
        },
    ));
    assert_eq!(state.objects[0].label, "current");
    // A disabled module removed by a newer unload must never be restored.
    state
        .loaded_modules
        .retain(|module| module.id != ResourceId(1));
    let mut disabled = module(1, Vec::new());
    disabled.discovery_error = Some(BackendError::SessionCleanup);
    state.event(complete(
        old,
        BackendResult::Modules {
            modules: vec![disabled],
            loaded: None,
            error: Some(BackendError::SessionCleanup),
        },
    ));
    assert_eq!(state.loaded_modules.len(), 1);
    assert_eq!(state.objects[0].label, "current");
}

#[test]
fn non_signing_generation_rejects_stale_authentication_and_bounds_before_enqueue() {
    use crate::backend::GenerationKind;
    use pkcs11_client::{AesKeyPurpose, AesKeySize, NamedCurve};
    for kind in [
        GenerationKind::Ecdh(NamedCurve::P384),
        GenerationKind::Aes(AesKeySize::Bits256, AesKeyPurpose::Wrapping),
    ] {
        let mut state = managing();
        state.management.always_authenticate = true;
        let request = state.show_page(TokenPage::Operations).unwrap().id();
        state.event(complete(
            request,
            BackendResult::Capabilities {
                module: ResourceId(1),
                token: ResourceId(2),
                keys: vec![kind],
            },
        ));
        assert!(!state.management.always_authenticate);
        state.management.key_id = "01".into();
        state.management.key_label = "x".repeat(129);
        assert!(state.generate().is_none());
        state.management.key_label = "key".into();
        state.management.always_authenticate = true;
        assert!(state.generate().is_none());
        state.management.always_authenticate = false;
        let request = state.generate().unwrap();
        assert!(
            matches!(request, BackendCommand::Manage { action: crate::backend::ManagementAction::Generate { kind: actual, always_authenticate: false, .. }, .. } if actual == kind)
        );
        assert!(!state.can_cancel());
    }
}

#[test]
fn pqc_generation_checks_identity_and_authentication_before_enqueue() {
    use crate::backend::{GenerationKind, ManagementAction};
    use pkcs11_client::{MlDsaParameterSet, MlKemParameterSet};
    for kind in [
        GenerationKind::MlDsa(MlDsaParameterSet::MlDsa44),
        GenerationKind::MlDsa(MlDsaParameterSet::MlDsa65),
        GenerationKind::MlDsa(MlDsaParameterSet::MlDsa87),
        GenerationKind::MlKem(MlKemParameterSet::MlKem512),
        GenerationKind::MlKem(MlKemParameterSet::MlKem768),
        GenerationKind::MlKem(MlKemParameterSet::MlKem1024),
    ] {
        let mut state = managing();
        let request = state.show_page(TokenPage::Operations).unwrap().id();
        state.event(complete(
            request,
            BackendResult::Capabilities {
                module: ResourceId(1),
                token: ResourceId(2),
                keys: vec![kind],
            },
        ));
        state.management.key_id = "01".into();
        assert!(state.generate().is_none());
        state.management.key_label = "PQC key".into();
        state.management.key_id = "zz".into();
        assert!(state.generate().is_none());
        state.management.key_id = "01".into();
        state.management.always_authenticate = true;
        if !kind.supports_context_authentication() {
            assert!(state.generate().is_none());
            state.management.always_authenticate = false;
        }
        state.loaded_modules[0].tokens[0].login = LoginState::SecurityOfficer;
        assert!(state.generate().is_none());
        state.loaded_modules[0].tokens[0].login = LoginState::User;
        state.loaded_modules[0].tokens[0].write_protected = true;
        assert!(state.generate().is_none());
        state.loaded_modules[0].tokens[0].write_protected = false;
        let command = state.generate().unwrap();
        assert!(matches!(command, BackendCommand::Manage {
            action: ManagementAction::Generate { kind: selected, id, label, always_authenticate }, ..
        } if selected == kind && id == [1] && label == b"PQC key"
            && always_authenticate == kind.supports_context_authentication()));
        assert!(state.management.key_label.is_empty());
        assert!(state.management.key_id.is_empty());
        assert!(!state.can_cancel());
    }
}

#[test]
fn late_pqc_choices_cannot_replace_refreshed_classical_choices() {
    use crate::backend::GenerationKind;
    let mut state = managing();
    let old = state.show_page(TokenPage::Operations).unwrap().id();
    state.cancel();
    let fresh = state.read_capabilities().unwrap().id();
    let classical = GenerationKind::Signing(pkcs11_client::KeyKind::Rsa { bits: 2048 });
    state.event(complete(
        fresh,
        BackendResult::Capabilities {
            module: ResourceId(1),
            token: ResourceId(2),
            keys: vec![classical],
        },
    ));
    state.event(complete(
        old,
        BackendResult::Capabilities {
            module: ResourceId(1),
            token: ResourceId(2),
            keys: vec![GenerationKind::MlKem(
                pkcs11_client::MlKemParameterSet::MlKem768,
            )],
        },
    ));
    assert_eq!(
        state.management.keys,
        vec![crate::state::KeyChoice(classical)]
    );
}

fn aes_cipher_state() -> (UiState, RequestId, crate::backend::CryptoScope) {
    use crate::backend::{CipherParameters, CryptoMode};
    let (mut state, id, _) = cipher_state(CryptoMode::Encrypt);
    state.dismiss_cipher(id);
    state.objects[0].class = Some(pkcs11_client::ObjectClass::SECRET_KEY);
    let BackendCommand::CryptoOptions { id, scope, .. } =
        state.open_cipher(CryptoMode::Encrypt).unwrap()
    else {
        panic!("options")
    };
    state.event(complete(
        id,
        BackendResult::CipherOptions {
            scope,
            choices: vec![CipherParameters::AesGcm(
                pkcs11_client::AesGcmCapabilities {
                    key_size: pkcs11_client::AesKeySize::Bits256,
                },
            )],
        },
    ));
    (state, id, scope)
}
#[test]
fn aes_gcm_forms_validate_nonce_and_clear_parameters_after_submission() {
    let (mut state, id, scope) = aes_cipher_state();
    state.cipher_edit(id, CipherField::Input, "plain".into());
    state.cipher_edit(id, CipherField::Output, "encrypted".into());
    for nonce in [
        "",
        "00",
        "zzzzzzzzzzzzzzzzzzzzzzzz",
        " 010101010101010101010101 ",
    ] {
        state.cipher_edit(id, CipherField::Nonce, nonce.into());
        assert!(state.submit_cipher(id).is_none());
    }
    assert!(state.cipher_picker(id, CipherField::Nonce).is_none());
    let (picker, save) = state.cipher_picker(id, CipherField::Aad).unwrap();
    assert!(!save);
    state.cipher_picked(picker, Some(PathBuf::from("context")));
    state.cipher_edit(id, CipherField::Nonce, "010101010101010101010101".into());
    let BackendCommand::Cipher {
        job, scope: actual, ..
    } = state.submit_cipher(id).unwrap()
    else {
        panic!("cipher")
    };
    assert_eq!(actual, scope);
    let gcm = job.aes_gcm.unwrap();
    assert_eq!(gcm.nonce, [1; 12]);
    assert_eq!(gcm.aad, Some("context".into()));
    assert!(state.cipher_form.is_none());
    assert!(!state.can_cancel());
}
#[test]
fn aes_gcm_forms_reject_late_choices_and_aad_pickers_after_navigation() {
    let (mut state, id, scope) = aes_cipher_state();
    let (picker, _) = state.cipher_picker(id, CipherField::Aad).unwrap();
    state.cipher_edit(id, CipherField::Nonce, "010101010101010101010101".into());
    state.select_token(ResourceId(1), ResourceId(3));
    state.cipher_picked(picker, Some("obsolete-context".into()));
    assert!(state.cipher_form.is_none());
    state.event(complete(
        id,
        BackendResult::CipherOptions {
            scope,
            choices: vec![],
        },
    ));
    assert!(state.cipher_form.is_none());
    assert!(state.submit_cipher(id).is_none());
}

#[test]
fn aes_gcm_secret_key_operations_require_user_login() {
    let (mut state, id, _) = aes_cipher_state();
    state.loaded_modules[0].tokens[0].login = LoginState::Public;
    assert!(!state.can_open_cipher(crate::backend::CryptoMode::Encrypt));
    assert!(!state.can_open_cipher(crate::backend::CryptoMode::Decrypt));
    assert!(state.submit_cipher(id).is_none());
}
