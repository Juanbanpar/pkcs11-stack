// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use iced::futures::executor::block_on;

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_objects_mechanisms_and_scoped_detail_reads() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
    let (worker, source) = Worker::spawn().unwrap();
    let mut events = source.stream();
    worker
        .submit(BackendCommand::Load {
            id: RequestId(1),
            path,
        })
        .unwrap();
    let (modules, module, error) = inventory(block_on(events.next()).unwrap());
    assert!(error.is_none());
    let module = module.unwrap();
    let mut next_request = 2;
    let mut selected = None;
    for token in modules[0]
        .tokens
        .iter()
        .filter(|token| token.label == "runtime-test")
    {
        worker
            .submit(BackendCommand::Objects {
                id: RequestId(next_request),
                module,
                token: token.id,
            })
            .unwrap();
        next_request += 1;
        match block_on(events.next()).unwrap() {
            BackendEvent::Completed {
                result: Ok(BackendResult::Objects { objects, .. }),
                ..
            } => {
                if objects.iter().any(|object| object.label == "unique") {
                    selected = Some((token.id, objects));
                    break;
                }
            }
            other => panic!("unexpected object list: {other:?}"),
        }
    }
    let (token, objects) = selected.expect("public runtime fixtures");
    assert!(objects.iter().all(|object| object.label != "private"));
    let unique = objects
        .iter()
        .find(|object| object.label == "unique")
        .unwrap();
    assert!(unique.uri.as_ref().unwrap().contains("type=data"));
    let duplicate = objects
        .iter()
        .find(|object| object.label == "duplicate")
        .unwrap();
    assert!(duplicate.ambiguous);
    assert!(!format!("{objects:?}").contains("fixture-canary"));
    worker
        .submit(BackendCommand::Inspect {
            id: RequestId(next_request),
            module,
            token,
            object: unique.id,
        })
        .unwrap();
    next_request += 1;
    match block_on(events.next()).unwrap() {
        BackendEvent::Completed {
            result: Ok(BackendResult::ObjectDetails { fields, .. }),
            ..
        } => {
            assert!(fields.iter().any(|field| field.name == "Private" && field.value.as_deref() == Some("false")));
            assert!(!format!("{fields:?}").contains("fixture-canary"));
            assert!(fields.iter().all(|field| field.name != "Value"));
        }
        other => panic!("unexpected detail result: {other:?}"),
    }
    worker
        .submit(BackendCommand::Inspect {
            id: RequestId(next_request),
            module,
            token,
            object: duplicate.id,
        })
        .unwrap();
    next_request += 1;
    assert!(matches!(
        block_on(events.next()).unwrap(),
        BackendEvent::Completed {
            result: Err(BackendError::AmbiguousObject),
            ..
        }
    ));
    worker
        .submit(BackendCommand::Mechanisms {
            id: RequestId(next_request),
            module,
            token,
        })
        .unwrap();
    next_request += 1;
    match block_on(events.next()).unwrap() {
        BackendEvent::Completed {
            result: Ok(BackendResult::Mechanisms { mechanisms, .. }),
            ..
        } => {
            assert!(!mechanisms.is_empty());
            assert!(
                mechanisms
                    .iter()
                    .any(|entry| entry.id == pkcs11_client::MechanismType::RSA_PKCS
                        && entry.flags.contains(&"Sign"))
            );
        }
        other => panic!("unexpected mechanism result: {other:?}"),
    }
    worker
        .submit(BackendCommand::Objects {
            id: RequestId(next_request),
            module,
            token,
        })
        .unwrap();
    next_request += 1;
    let refreshed_object = match block_on(events.next()).unwrap() {
        BackendEvent::Completed {
            result: Ok(BackendResult::Objects { objects, .. }),
            ..
        } => {
            assert!(objects.iter().all(|object| object.id != unique.id));
            objects
                .iter()
                .find(|object| object.label == "unique")
                .unwrap()
                .id
        }
        other => panic!("unexpected refresh: {other:?}"),
    };
    worker
        .submit(BackendCommand::Inspect {
            id: RequestId(next_request),
            module,
            token,
            object: unique.id,
        })
        .unwrap();
    next_request += 1;
    assert!(matches!(
        block_on(events.next()).unwrap(),
        BackendEvent::Completed {
            result: Err(BackendError::UnknownObject),
            ..
        }
    ));
    worker
        .submit(BackendCommand::Refresh {
            id: RequestId(next_request),
            module,
        })
        .unwrap();
    next_request += 1;
    assert!(inventory(block_on(events.next()).unwrap()).2.is_none());
    worker
        .submit(BackendCommand::Inspect {
            id: RequestId(next_request),
            module,
            token,
            object: refreshed_object,
        })
        .unwrap();
    next_request += 1;
    assert!(matches!(
        block_on(events.next()).unwrap(),
        BackendEvent::Completed {
            result: Err(BackendError::UnknownObject),
            ..
        }
    ));
    block_on(worker.shutdown(RequestId(next_request))).unwrap();
}

#[test]
fn command_round_trip_failure_and_shutdown_are_ordered() {
    let (worker, source) = Worker::spawn().unwrap();
    worker
        .submit(BackendCommand::Synthetic {
            id: RequestId(1),
            outcome: SyntheticOutcome::Success,
        })
        .unwrap();
    worker
        .submit(BackendCommand::Synthetic {
            id: RequestId(2),
            outcome: SyntheticOutcome::Failure,
        })
        .unwrap();
    block_on(worker.shutdown(RequestId(3))).unwrap();
    let events: Vec<_> = block_on(source.stream().collect());
    assert!(matches!(
        events.as_slice(),
        [
            BackendEvent::Completed {
                id: RequestId(1),
                result: Ok(BackendResult::Synthetic)
            },
            BackendEvent::Completed {
                id: RequestId(2),
                result: Err(BackendError::Synthetic)
            },
            BackendEvent::Stopped {
                id: RequestId(3),
                result: Ok(())
            },
            BackendEvent::Disconnected
        ]
    ));
}

#[test]
fn dropping_worker_disconnects_and_terminates_it() {
    let (mut worker, source) = Worker::spawn().unwrap();
    let handle = worker.thread.take().unwrap();
    drop(worker);
    handle.join().unwrap().unwrap();
    assert!(matches!(
        block_on(source.stream().next()),
        Some(BackendEvent::Disconnected)
    ));
}

#[test]
fn queue_full_and_disconnected_are_typed_failures() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = Worker {
        commands: Some(sender),
        thread: None,
    };
    let command = || BackendCommand::Synthetic {
        id: RequestId(1),
        outcome: SyntheticOutcome::Success,
    };
    worker.submit(command()).unwrap();
    assert_eq!(worker.submit(command()), Err(BackendError::Busy));
    drop(receiver);
    assert_eq!(worker.submit(command()), Err(BackendError::Disconnected));
}

#[test]
fn worker_panic_is_reported_at_join_and_stream_closure() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let (events, output) = asynchronous::unbounded();
    let worker = Worker {
        commands: Some(sender),
        thread: Some(thread::spawn(move || {
            let _keep_channels_alive = (receiver, events);
            panic!("synthetic worker panic");
        })),
    };
    assert_eq!(
        block_on(worker.shutdown(RequestId(1))),
        Err(BackendError::Panicked)
    );
    let source = EventSource(Arc::new(Mutex::new(Some(output))));
    assert!(matches!(
        block_on(source.stream().next()),
        Some(BackendEvent::Disconnected)
    ));
}

#[test]
fn cleanup_failure_is_returned_after_the_worker_is_joined() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let failure = BackendError::Client(ErrorKind::Runtime);
    let worker = Worker {
        commands: Some(sender),
        thread: Some(thread::spawn(move || {
            assert!(matches!(
                receiver.recv().unwrap(),
                BackendCommand::Shutdown { .. }
            ));
            Err(failure)
        })),
    };
    assert_eq!(block_on(worker.shutdown(RequestId(1))), Err(failure));
}

#[test]
fn client_ownership_traits_support_worker_local_use() {
    fn send<T: Send>() {}
    fn share<T: Send + Sync>() {}
    share::<pkcs11_client::Provider>();
    share::<pkcs11_client::Client<'static>>();
    send::<pkcs11_client::ManagementSession<'static>>();
}
fn inventory(event: BackendEvent) -> (Vec<ModuleEntry>, Option<ResourceId>, Option<BackendError>) {
    match event {
        BackendEvent::Completed {
            result:
                Ok(BackendResult::Modules {
                    modules,
                    loaded,
                    error,
                }),
            ..
        } => (modules, loaded, error),
        other => panic!("unexpected event: {other:?}"),
    }
}
#[test]
fn invalid_paths_and_unknown_modules_return_inventory_with_fixed_errors() {
    let mut registry = Registry::default();
    let path = std::env::temp_dir().join("missing-directory-desktop-test/module-pin-canary.so");
    let (modules, loaded, error) = inventory(registry.execute(BackendCommand::Load {
        id: RequestId(1),
        path,
    }));
    assert!(modules.is_empty());
    assert!(loaded.is_none());
    assert_eq!(error, Some(BackendError::ModulePath));
    assert!(!format!("{error:?} {}", error.unwrap().message()).contains("pin-canary"));
    for command in [
        BackendCommand::Refresh {
            id: RequestId(2),
            module: ResourceId(9),
        },
        BackendCommand::Unload {
            id: RequestId(3),
            module: ResourceId(9),
        },
    ] {
        assert_eq!(
            inventory(registry.execute(command)).2,
            Some(BackendError::UnknownModule)
        );
    }
    registry.next_resource = u64::MAX;
    assert_eq!(registry.allocate(), Err(BackendError::ResourceExhausted));
}
#[test]
fn backend_failure_reaches_ui_without_loading_vendor_code() {
    let (worker, source) = Worker::spawn().unwrap();
    worker
        .submit(BackendCommand::Refresh {
            id: RequestId(1),
            module: ResourceId(44),
        })
        .unwrap();
    let event = block_on(source.stream().next()).unwrap();
    assert_eq!(inventory(event).2, Some(BackendError::UnknownModule));
    block_on(worker.shutdown(RequestId(2))).unwrap();
}
#[test]
fn public_token_identity_distinguishes_replacement_in_the_same_slot() {
    let a = TokenEntry {
        id: ResourceId(1),
        slot_id: 2,
        label: String::new(),
        manufacturer: "Maker".into(),
        model: "Model".into(),
        serial: "A".into(),
        uri: None,
        details: Vec::new(),
        login: crate::backend::LoginState::Public,
        initialized: true,
        user_pin_initialized: true,
        user_pin_locked: false,
        so_pin_locked: false,
        write_protected: false,
        protected_path: false,
    };
    let mut b = a.clone();
    b.details.push(("Initialized".into(), "true".into()));
    assert!(a.same_resource(&b));
    b.serial = "B".into();
    assert!(!a.same_resource(&b));
    b.serial = "A".into();
    b.slot_id = 3;
    assert!(!a.same_resource(&b));
}

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_browser_load_refresh_unload_and_shutdown() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
    let (worker, source) = Worker::spawn().unwrap();
    let mut events = source.stream();
    worker
        .submit(BackendCommand::Load {
            id: RequestId(1),
            path: path.clone(),
        })
        .unwrap();
    let (modules, loaded, error) = inventory(block_on(events.next()).unwrap());
    assert!(error.is_none());
    assert_eq!(modules.len(), 1);
    let module = &modules[0];
    let module_id = loaded.unwrap();
    assert_eq!(module.id, module_id);
    assert_eq!(module.path, path.canonicalize().unwrap());
    assert!(!module.description.is_empty());
    assert!(!module.slots.is_empty());
    assert!(
        module
            .tokens
            .iter()
            .filter(|t| t.label == "runtime-test")
            .count()
            >= 2
    );
    let mut identities: Vec<_> = module
        .tokens
        .iter()
        .map(|t| (t.id, t.serial.clone()))
        .collect();
    identities.sort_by_key(|(id, _)| id.0);
    let distinct: std::collections::HashSet<_> = module.tokens.iter().map(|t| t.id.0).collect();
    assert_eq!(distinct.len(), module.tokens.len());
    for token in &module.tokens {
        let uri: pkcs11_client::Pkcs11Uri = token.uri.as_ref().unwrap().parse().unwrap();
        pkcs11_client::validate_token_uri(&uri).unwrap();
        assert!(!uri.to_string().contains("pin-value"));
    }
    // Dot components resolve to the same owner; a duplicate must not finalize it.
    let alias = path
        .parent()
        .unwrap()
        .join(".")
        .join(path.file_name().unwrap());
    worker
        .submit(BackendCommand::Load {
            id: RequestId(2),
            path: alias,
        })
        .unwrap();
    let (duplicates, _, error) = inventory(block_on(events.next()).unwrap());
    assert_eq!(error, Some(BackendError::AlreadyLoaded));
    assert_eq!(duplicates.len(), 1);
    worker
        .submit(BackendCommand::Refresh {
            id: RequestId(3),
            module: module_id,
        })
        .unwrap();
    let (refreshed, _, error) = inventory(block_on(events.next()).unwrap());
    assert!(error.is_none());
    let mut refreshed_identities: Vec<_> = refreshed[0]
        .tokens
        .iter()
        .map(|t| (t.id, t.serial.clone()))
        .collect();
    refreshed_identities.sort_by_key(|(id, _)| id.0);
    assert_eq!(identities, refreshed_identities);
    worker
        .submit(BackendCommand::Unload {
            id: RequestId(4),
            module: module_id,
        })
        .unwrap();
    let (modules, _, error) = inventory(block_on(events.next()).unwrap());
    assert!(modules.is_empty());
    assert!(error.is_none());
    worker
        .submit(BackendCommand::Load {
            id: RequestId(5),
            path: path.clone(),
        })
        .unwrap();
    let (modules, reloaded, error) = inventory(block_on(events.next()).unwrap());
    assert!(error.is_none());
    assert_eq!(modules.len(), 1);
    assert_ne!(reloaded, Some(module_id));
    // Successful reloading proves both explicit unload and shutdown finalized the owner.
    block_on(worker.shutdown(RequestId(6))).unwrap();
    drop(events);
    let provider = Provider::load(path).unwrap();
    assert!(!provider.tokens().unwrap().is_empty());
    provider.finalize().unwrap();
}

#[test]
fn unknown_authentication_targets_return_fixed_errors_without_echoing_pin() {
    let mut registry = Registry::default();
    let (_, _, error) = inventory(registry.execute(BackendCommand::Login {
        id: RequestId(1),
        module: ResourceId(2),
        token: ResourceId(3),
        role: LoginRole::User,
        pin: SecretInput::Value("redaction-canary".into()),
    }));
    assert_eq!(error, Some(BackendError::UnknownModule));
    assert!(!format!("{error:?}").contains("canary"));
    assert_eq!(
        inventory(registry.execute(BackendCommand::Logout {
            id: RequestId(2),
            module: ResourceId(2),
            token: ResourceId(3),
        }))
        .2,
        Some(BackendError::UnknownModule)
    );
}

#[test]
#[ignore = "requires the isolated SoftHSM runner"]
fn software_token_authentication_visibility_roles_and_cleanup() {
    assert_eq!(std::env::var("PKCS11_TEST_ISOLATED").as_deref(), Ok("1"));
    let path = PathBuf::from(std::env::var_os("PKCS11_TEST_MODULE").unwrap());
    let (worker, source) = Worker::spawn().unwrap();
    let mut events = source.stream();
    let mut next = 0;
    let mut send = |make: &dyn Fn(RequestId) -> BackendCommand| {
        next += 1;
        let id = RequestId(next);
        worker.submit(make(id)).unwrap();
        let event = block_on(events.next()).unwrap();
        assert!(matches!(&event, BackendEvent::Completed { id: returned, .. } if *returned == id));
        event
    };
    let (modules, module, error) = inventory(send(&|id| BackendCommand::Load {
        id,
        path: path.clone(),
    }));
    assert!(error.is_none());
    let module = module.unwrap();
    let mut selected = None;
    for token in modules[0]
        .tokens
        .iter()
        .filter(|token| token.label == "runtime-test")
    {
        let event = send(&|id| BackendCommand::Objects {
            id,
            module,
            token: token.id,
        });
        if let BackendEvent::Completed {
            result: Ok(BackendResult::Objects { objects, .. }),
            ..
        } = event
            && objects.iter().any(|object| object.label == "unique")
        {
            assert!(objects.iter().all(|object| object.label != "private"));
            selected = Some(token.id);
            break;
        }
    }
    let token = selected.expect("public fixtures");
    let serial = modules[0]
        .tokens
        .iter()
        .find(|entry| entry.id == token)
        .unwrap()
        .serial
        .clone();
    let login = |id, role, pin: &str| BackendCommand::Login {
        id,
        module,
        token,
        role,
        pin: SecretInput::Value(pin.into()),
    };
    let (modules, _, error) = inventory(send(&|id| BackendCommand::Login {
        id,
        module,
        token,
        role: LoginRole::User,
        pin: SecretInput::ProtectedPath,
    }));
    assert_eq!(error, Some(BackendError::AuthenticationUnavailable));
    assert_eq!(
        modules[0]
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .unwrap()
            .login,
        LoginState::Public
    );
    let (modules, _, error) = inventory(send(&|id| {
        login(id, LoginRole::User, "incorrect-desktop-canary")
    }));
    assert_eq!(error, Some(BackendError::AuthenticationFailed));
    assert!(!format!("{modules:?} {error:?}").contains("incorrect-desktop-canary"));
    assert_eq!(
        modules[0]
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .unwrap()
            .login,
        LoginState::Public
    );
    assert!(
        inventory(send(&|id| login(id, LoginRole::User, "12345678")))
            .2
            .is_none()
    );
    let objects = match send(&|id| BackendCommand::Objects { id, module, token }) {
        BackendEvent::Completed {
            result: Ok(BackendResult::Objects { objects, .. }),
            ..
        } => objects,
        event => panic!("unexpected objects: {event:?}"),
    };
    let private = objects
        .iter()
        .find(|object| object.label == "private")
        .unwrap()
        .id;
    match send(&|id| BackendCommand::Inspect {
        id,
        module,
        token,
        object: private,
    }) {
        BackendEvent::Completed {
            result: Ok(BackendResult::ObjectDetails { fields, .. }),
            ..
        } => {
            assert!(
                fields
                    .iter()
                    .any(|field| field.name == "Private" && field.value.as_deref() == Some("true"))
            );
            assert!(!format!("{fields:?}").contains("fixture-canary"));
        }
        event => panic!("unexpected private metadata: {event:?}"),
    }
    // Reading and refreshing must not close the last authenticated session.
    let (modules, _, error) = inventory(send(&|id| BackendCommand::Refresh { id, module }));
    assert!(error.is_none());
    assert_eq!(
        modules[0]
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .unwrap()
            .login,
        LoginState::User
    );
    assert_eq!(
        inventory(send(&|id| login(
            id,
            LoginRole::SecurityOfficer,
            "87654321"
        )))
        .2,
        Some(BackendError::AuthenticationUnavailable)
    );
    let (modules, _, error) = inventory(send(&|id| BackendCommand::Logout { id, module, token }));
    assert!(error.is_none());
    assert_eq!(
        modules[0]
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .unwrap()
            .login,
        LoginState::Public
    );
    assert!(matches!(
        send(&|id| BackendCommand::Inspect {
            id,
            module,
            token,
            object: private
        }),
        BackendEvent::Completed {
            result: Err(BackendError::UnknownObject),
            ..
        }
    ));
    assert!(
        matches!(send(&|id| BackendCommand::Objects { id, module, token }), BackendEvent::Completed { result: Ok(BackendResult::Objects { objects, .. }), .. } if objects.iter().all(|object| object.label != "private"))
    );
    let (modules, _, error) = inventory(send(&|id| {
        login(id, LoginRole::SecurityOfficer, "87654321")
    }));
    assert!(error.is_none());
    assert_eq!(
        modules[0]
            .tokens
            .iter()
            .find(|entry| entry.id == token)
            .unwrap()
            .login,
        LoginState::SecurityOfficer
    );
    // SO state rejects RO sessions; browsing must select RW without another login.
    assert!(matches!(
        send(&|id| BackendCommand::Objects { id, module, token }),
        BackendEvent::Completed {
            result: Ok(BackendResult::Objects { .. }),
            ..
        }
    ));
    assert!(
        inventory(send(&|id| BackendCommand::Logout { id, module, token }))
            .2
            .is_none()
    );
    assert!(
        inventory(send(&|id| login(id, LoginRole::User, "12345678")))
            .2
            .is_none()
    );
    assert!(
        inventory(send(&|id| BackendCommand::Unload { id, module }))
            .2
            .is_none()
    );
    let (modules, module, error) = inventory(send(&|id| BackendCommand::Load {
        id,
        path: path.clone(),
    }));
    assert!(error.is_none());
    let module = module.unwrap();
    let token = modules[0]
        .tokens
        .iter()
        .find(|entry| entry.serial == serial)
        .unwrap()
        .id;
    assert!(
        inventory(send(&|id| BackendCommand::Login {
            id,
            module,
            token,
            role: LoginRole::User,
            pin: SecretInput::Value("12345678".into())
        }))
        .2
        .is_none()
    );
    // Shutdown closes the retained session before finalizing the provider.
    block_on(worker.shutdown(RequestId(next + 1))).unwrap();
    let provider = pkcs11_client::Provider::load(path).unwrap();
    let token = provider
        .tokens()
        .unwrap()
        .into_iter()
        .find(|entry| entry.info.serial_number() == serial)
        .unwrap();
    let session = provider
        .management(
            &token.uri().unwrap(),
            pkcs11_client::SessionMode::ReadOnly,
            pkcs11_client::Authentication::None,
        )
        .unwrap();
    assert_eq!(
        session.state().unwrap(),
        pkcs11_client::SessionState::RoPublic
    );
    session.close().unwrap();
    provider.finalize().unwrap();
}
