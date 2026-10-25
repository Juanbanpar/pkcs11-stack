// SPDX-License-Identifier: MIT OR Apache-2.0
use super::*;
use crate::{
    app::{App, Message},
    backend::{LoginState, ModuleEntry, ObjectEntry, RequestId, ResourceId, TokenEntry},
    state::{Screen, TokenPage, UiState},
};
use iced::futures::{StreamExt, channel::mpsc};
use iced::{
    Size,
    keyboard::{self, key::Named},
};
use iced_test::{
    Instruction,
    emulator::{Emulator, Event, Mode},
    program::Program,
};

fn state() -> UiState {
    let token = TokenEntry {
        initialization: pkcs11_client::TokenInitializationTarget {
            slot_id: 10,
            label: "Test Token".into(),
            manufacturer: "Maker".into(),
            model: "Model".into(),
            serial: "A".into(),
            initialized: true,
            minimum_pin_length: 4,
            maximum_pin_length: 32,
        },
        id: ResourceId(2),
        slot_id: 10,
        label: "Test Token".into(),
        manufacturer: "Maker".into(),
        model: "Model".into(),
        serial: "A".into(),
        uri: Some("pkcs11:serial=A".into()),
        details: vec![],
        login: LoginState::Public,
        initialized: true,
        user_pin_initialized: true,
        user_pin_locked: false,
        so_pin_locked: false,
        write_protected: false,
        protected_path: false,
        rng: true,
    };
    let mut state = UiState::default();
    state.worker_available = true;
    state.loaded_modules.push(ModuleEntry {
        id: ResourceId(1),
        path: "module.so".into(),
        description: "Module".into(),
        manufacturer: "Maker".into(),
        library_version: "1.0".into(),
        cryptoki_version: "2.40".into(),
        slots: vec![],
        tokens: vec![token],
        discovery_error: None,
    });
    state.select_token(ResourceId(1), ResourceId(2));
    state
}
fn object(id: u64, label: &str) -> ObjectEntry {
    ObjectEntry {
        id: ResourceId(id),
        class: Some(pkcs11_client::ObjectClass::PUBLIC_KEY),
        label: label.into(),
        identifier: format!("{id:02X}"),
        uri: None,
        ambiguous: false,
        fields: vec![],
    }
}
async fn settle<P: Program + 'static>(
    emulator: &mut Emulator<P>,
    program: &P,
    receiver: &mut mpsc::Receiver<Event<P>>,
) {
    while let Some(event) = receiver.next().await {
        match event {
            Event::Action(action) => emulator.perform(program, action),
            Event::Ready => return,
            Event::Failed(_) => panic!("UI interaction failed"),
        }
    }
    panic!("UI event stream disconnected");
}
fn run(initial: fn() -> UiState, steps: &[&str]) -> App {
    run_focused(initial, steps, None)
}
fn run_focused(initial: fn() -> UiState, steps: &[&str], focus: Option<&'static str>) -> App {
    let program = iced::application(
        move || {
            (
                App::without_worker(initial()),
                focus.map_or_else(iced::Task::none, crate::ui::focus::focus),
            )
        },
        App::update,
        App::view,
    )
    .font(iced_fonts::LUCIDE_FONT_BYTES)
    .subscription(App::subscription)
    .theme(App::theme);
    let (sender, mut receiver) = mpsc::channel(100);
    let mut emulator = Emulator::new(sender, &program, Mode::Zen, Size::new(1060.0, 720.0));
    iced::futures::executor::block_on(settle(&mut emulator, &program, &mut receiver));
    for step in steps {
        emulator.run(
            &program,
            Instruction::parse(step).expect("valid UI instruction"),
        );
        iced::futures::executor::block_on(settle(&mut emulator, &program, &mut receiver));
    }
    emulator.into_state().0
}

#[test]
fn keyboard_opens_and_closes_module_dialog_without_loading() {
    let app = run(
        state,
        &[
            "type tab",
            "type enter",
            "expect \"Add Module\"",
            "type escape",
        ],
    );
    assert!(app.state.presentation.overlay.is_none());
    assert_eq!(app.state.loaded_modules.len(), 1);
    assert!(app.state.current_operation.is_none());
}
#[test]
fn modal_tab_traversal_cannot_activate_background_navigation() {
    let app = run(state, &["click \"About\"", "type tab", "type enter"]);
    assert!(app.state.dialog.is_none());
    assert_eq!(app.state.selected_token, Some(ResourceId(2)));
}
#[test]
fn appearance_buttons_work_with_keyboard_and_keep_resource_selection() {
    let app = run(
        state,
        &[
            "click \"Appearance\"",
            "type tab",
            "type tab",
            "type enter",
            "type escape",
        ],
    );
    assert_eq!(app.state.presentation.appearance, theme::Appearance::Dark);
    assert_eq!(app.state.selected_token, Some(ResourceId(2)));
}
#[test]
fn login_cancel_clears_pin_and_restores_resource_context() {
    use secrecy::ExposeSecret;
    let mut app = run(
        state,
        &["click \"USER login\"", "type tab", "type \"secret-canary\""],
    );
    assert!(
        app.state
            .login_form
            .as_ref()
            .is_some_and(|form| form.pin.expose_secret() == "secret-canary"),
        "PIN input must receive keyboard text"
    );
    let _ = app.update(Message::Ui(Action::Escape));
    assert!(app.state.login_form.is_none());
    assert_eq!(app.state.selected_token, Some(ResourceId(2)));
    assert!(app.state.current_operation.is_none());
}

#[test]
fn sorting_changes_only_presentation_and_keeps_selected_object() {
    let mut state = state();
    state.token_page = TokenPage::Objects;
    state.objects = vec![object(4, "Zulu"), object(3, "Alpha")];
    state.selected_object = Some(ResourceId(4));
    let mut app = App::without_worker(state);
    assert_eq!(sorted_objects(&app.state)[0].id, ResourceId(3));
    let _ = app.update(Message::Ui(Action::SortObjects(ObjectSort::Label)));
    assert_eq!(sorted_objects(&app.state)[0].id, ResourceId(4));
    assert_eq!(app.state.selected_object, Some(ResourceId(4)));
    assert!(app.state.current_operation.is_none());
}
#[test]
fn escape_clears_task_picker_and_rejects_late_result() {
    let mut app = App::without_worker(state());
    app.state.token_page = TokenPage::Operations;
    let _ = app.update(Message::Ui(Action::Task(Some(ManagementTask::Random))));
    app.state.random.picker = Some((RequestId(9), ResourceId(1), ResourceId(2)));
    let _ = app.update(Message::Ui(Action::Escape));
    let _ = app.update(Message::RandomPicked {
        id: RequestId(9),
        path: Some("late.bin".into()),
    });
    assert!(app.state.presentation.task.is_none());
    assert!(app.state.random.path.is_empty());
}
#[test]
fn system_appearance_changes_only_apply_in_system_mode() {
    let mut app = App::without_worker(state());
    let _ = app.update(Message::Ui(Action::SystemTheme(iced::theme::Mode::Dark)));
    assert!(app.state.presentation.dark());
    let _ = app.update(Message::Ui(Action::SetAppearance(theme::Appearance::Light)));
    assert!(!app.state.presentation.dark());
    let _ = app.update(Message::Ui(Action::SystemTheme(iced::theme::Mode::Dark)));
    assert!(!app.state.presentation.dark());
}
#[test]
fn disabled_button_and_checkbox_never_publish_actions() {
    let view = iced::widget::column![button("Disabled"), checkbox(false).label("Disabled toggle")];
    let mut ui = iced_test::simulator(view);
    ui.click("Disabled").unwrap();
    ui.click("Disabled toggle").unwrap();
    ui.tap_key(Named::Enter);
    assert_eq!(ui.into_messages().count(), 0);
}
#[test]
fn focused_button_sends_one_action_per_press_even_with_repeat() {
    let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
    let view: iced::Element<'_, Message> =
        button("Run").id("run").on_press(Message::Refresh).into();
    let mut ui = iced_test::runtime::UserInterface::build(
        view,
        Size::new(400.0, 200.0),
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    ui.operate(
        &renderer,
        &mut iced::advanced::widget::operation::focusable::focus(iced::widget::Id::new("run")),
    );
    let mut repeat = iced_test::simulator::press_key(Named::Enter, None);
    if let iced::Event::Keyboard(keyboard::Event::KeyPressed { repeat, .. }) = &mut repeat {
        *repeat = true;
    }
    let mut messages = vec![];
    ui.update(
        &[
            iced_test::simulator::press_key(Named::Enter, None),
            repeat,
            iced_test::simulator::release_key(Named::Enter),
        ],
        iced::mouse::Cursor::Unavailable,
        &mut renderer,
        &mut iced::advanced::clipboard::Null,
        &mut messages,
    );
    assert_eq!(
        messages
            .iter()
            .filter(|message| matches!(message, Message::Refresh))
            .count(),
        1
    );
}
#[test]
fn all_pages_render_at_supported_sizes_with_long_metadata() {
    let mut state = state();
    state.module_path = "/long/".repeat(40);
    state.objects = vec![object(3, &"Long Label ".repeat(20))];
    state.objects_loaded = true;
    for (width, height) in [(900, 600), (1060, 720), (1440, 900)] {
        state.presentation.width = width as f32;
        for page in [
            TokenPage::Overview,
            TokenPage::Objects,
            TokenPage::Mechanisms,
            TokenPage::Operations,
            TokenPage::Administration,
        ] {
            state.token_page = page;
            for dark in [false, true] {
                let view = crate::views::main::view(&state);
                let mut ui = iced_test::Simulator::with_size(
                    iced::Settings::default(),
                    Size::new(width as f32, height as f32),
                    view,
                );
                assert!(ui.snapshot(&theme::theme(dark)).is_ok());
            }
        }
    }
    state.navigate(Screen::Welcome);
    assert!(state.presentation.task.is_none());
}

#[test]
fn closing_a_dialog_restores_keyboard_focus_to_its_opener() {
    let app = run(state, &["type tab", "type enter", "type escape"]);
    assert_eq!(
        app.state.presentation.focused,
        Some(iced::widget::Id::new("add-module"))
    );
    let app = run(state, &["click \"USER login\"", "type escape"]);
    assert_eq!(
        app.state.presentation.focused,
        Some(iced::widget::Id::new("login-User"))
    );
}

#[test]
fn object_tab_navigation_moves_focus_without_requesting_metadata() {
    fn objects() -> UiState {
        let mut state = state();
        state.token_page = TokenPage::Objects;
        state.objects = vec![object(4, "Zulu"), object(3, "Alpha")];
        state.objects_loaded = true;
        state
    }
    let app = run(objects, &["click \"ID\"", "type tab", "type tab"]);
    assert_eq!(
        app.state.presentation.focused,
        Some(iced::widget::Id::new("object-ResourceId(4)"))
    );
    assert!(app.state.selected_object.is_none());
    assert!(app.state.current_operation.is_none());
}

#[test]
fn choice_keyboard_navigation_selects_typed_client_parameters() {
    fn generation() -> UiState {
        let mut state = state();
        state.loaded_modules[0].tokens[0].login = LoginState::User;
        state.token_page = TokenPage::Operations;
        state.presentation.task = Some(ManagementTask::Generate);
        state.management.capabilities_loaded = true;
        state.management.keys = vec![
            crate::state::KeyChoice(crate::backend::GenerationKind::Signing(
                pkcs11_client::KeyKind::Rsa { bits: 2048 },
            )),
            crate::state::KeyChoice(crate::backend::GenerationKind::Signing(
                pkcs11_client::KeyKind::Rsa { bits: 4096 },
            )),
        ];
        state
    }
    let app = run(
        generation,
        &["click \"Key type\"", "type tab", "type enter"],
    );
    assert_eq!(
        app.state.management.key,
        Some(crate::state::KeyChoice(
            crate::backend::GenerationKind::Signing(pkcs11_client::KeyKind::Rsa { bits: 4096 })
        ))
    );
    assert!(app.state.presentation.choice.is_none());
    assert_eq!(
        app.state.presentation.focused,
        Some(iced::widget::Id::new("choice-Key type"))
    );
    assert!(app.state.current_operation.is_none());
}

#[test]
fn disappeared_focus_target_falls_back_to_a_visible_control() {
    fn missing_opener() -> UiState {
        let mut state = state();
        state.presentation.overlay = Some(Overlay::KeyboardHelp);
        state.presentation.restore_focus = Some(iced::widget::Id::new("removed-control"));
        state
    }
    let app = run(missing_opener, &["type escape"]);
    assert_eq!(
        app.state.presentation.focused,
        Some(iced::widget::Id::new("add-module"))
    );
}

#[test]
fn file_picker_controls_have_distinct_focus_targets() {
    use crate::state::CryptoField;
    use iced::advanced::widget::{Id, Operation, operation::Focusable};
    struct Ids(Vec<Id>);
    impl Operation for Ids {
        fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
            operate(self);
        }
        fn focusable(&mut self, id: Option<&Id>, _: iced::Rectangle, _: &mut dyn Focusable) {
            self.0.extend(id.cloned());
        }
    }
    let id = RequestId(5);
    let view = iced::widget::column![
        button("Browse message").on_press(Message::CryptoBrowse {
            id,
            field: CryptoField::Input
        }),
        button("Browse signature").on_press(Message::CryptoBrowse {
            id,
            field: CryptoField::Signature
        }),
    ];
    let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
    let mut ui = iced_test::runtime::UserInterface::build(
        view,
        Size::new(400.0, 200.0),
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    let mut ids = Ids(vec![]);
    ui.operate(&renderer, &mut ids);
    assert_eq!(ids.0.len(), 2);
    assert_ne!(ids.0[0], ids.0[1]);
}

#[test]
fn long_resource_names_keep_toolbar_actions_inside_the_window() {
    use iced::advanced::widget::{Id, Operation, operation::Focusable};
    struct Bounds(Vec<(Id, iced::Rectangle)>);
    impl Operation for Bounds {
        fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
            operate(self);
        }
        fn focusable(&mut self, id: Option<&Id>, bounds: iced::Rectangle, _: &mut dyn Focusable) {
            if let Some(id) = id {
                self.0.push((id.clone(), bounds));
            }
        }
    }
    let mut state = state();
    state.loaded_modules[0].tokens[0].label = "Very Long Token Name ".repeat(20);
    for width in [900.0, 1060.0, 1440.0] {
        state.presentation.width = width;
        let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
        let mut ui = iced_test::runtime::UserInterface::build(
            crate::views::main::view(&state),
            Size::new(width, 600.0),
            iced_test::runtime::user_interface::Cache::default(),
            &mut renderer,
        );
        let mut bounds = Bounds(vec![]);
        ui.operate(&renderer, &mut bounds);
        for name in [
            "add-module",
            "refresh",
            "appearance",
            "keyboard-help",
            "About",
        ] {
            let (_, area) = bounds
                .0
                .iter()
                .find(|(id, _)| id == &Id::new(name))
                .expect("toolbar action");
            assert!(
                area.x >= 0.0 && area.x + area.width <= width && area.y + area.height <= 70.0,
                "toolbar action must remain visible"
            );
        }
        for (index, (id, _)) in bounds.0.iter().enumerate() {
            assert!(
                !bounds.0[index + 1..].iter().any(|(other, _)| other == id),
                "enabled focus targets must be unique"
            );
        }
    }
}

#[test]
fn disabled_inputs_are_excluded_from_keyboard_focus() {
    use iced::advanced::widget::{Id, Operation, operation::Focusable};
    struct Ids(Vec<Id>);
    impl Operation for Ids {
        fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
            operate(self);
        }
        fn focusable(&mut self, id: Option<&Id>, _: iced::Rectangle, _: &mut dyn Focusable) {
            self.0.extend(id.cloned());
        }
    }
    let view = iced::widget::column![
        text_input("Disabled", ""),
        text_input("Enabled", "").on_input(Message::EditPath),
        button("Continue").id("continue").on_press(Message::Refresh),
    ];
    let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
    let mut ui = iced_test::runtime::UserInterface::build(
        view,
        Size::new(400.0, 300.0),
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    let mut ids = Ids(vec![]);
    ui.operate(&renderer, &mut ids);
    assert_eq!(ids.0, vec![Id::new("input-Enabled"), Id::new("continue")]);
}

fn populated_state() -> UiState {
    use crate::backend::MetadataField;
    let mut state = state();
    let module = &mut state.loaded_modules[0];
    module.path = "/usr/lib/pkcs11/vendor-pkcs11.so".into();
    module.description = "PKCS#11 Provider".into();
    module.slots = vec![crate::backend::SlotEntry {
        id: 10,
        description: "Security Token Reader".into(),
        manufacturer: "Example Devices".into(),
        token_present: true,
    }];
    let token = &mut module.tokens[0];
    token.label = "Development Token".into();
    token.manufacturer = "Example Devices".into();
    token.model = "Security Token".into();
    token.serial = "DEV-0248".into();
    token.login = LoginState::User;
    token.initialization.label = token.label.clone();
    token.initialization.manufacturer = token.manufacturer.clone();
    token.initialization.model = token.model.clone();
    token.initialization.serial = token.serial.clone();
    token.uri = Some("pkcs11:token=Development%20Token;serial=DEV-0248".into());
    token.details = vec![
        ("Initialized".into(), "true".into()),
        ("Login required".into(), "true".into()),
        ("USER PIN initialized".into(), "true".into()),
        ("USER PIN locked".into(), "false".into()),
        ("Write protected".into(), "false".into()),
        ("Random generator".into(), "true".into()),
    ];
    state.objects = [
        (3, "Signing key", pkcs11_client::ObjectClass::PRIVATE_KEY),
        (4, "Signing key", pkcs11_client::ObjectClass::PUBLIC_KEY),
        (
            5,
            "Client certificate",
            pkcs11_client::ObjectClass::CERTIFICATE,
        ),
        (6, "Transport key", pkcs11_client::ObjectClass::SECRET_KEY),
    ]
    .into_iter()
    .map(|(id, label, class)| {
        let mut object = object(id, label);
        object.class = Some(class);
        object.uri = Some(format!(
            "pkcs11:token=Development%20Token;serial=DEV-0248;object={};type={}",
            label.replace(' ', "%20"),
            match class {
                pkcs11_client::ObjectClass::PRIVATE_KEY => "private",
                pkcs11_client::ObjectClass::PUBLIC_KEY => "public",
                pkcs11_client::ObjectClass::CERTIFICATE => "cert",
                _ => "secret-key",
            }
        ));
        object.fields = vec![
            MetadataField {
                name: "Class",
                status: "available",
                value: Some(class.to_string()),
            },
            MetadataField {
                name: "Label",
                status: "available",
                value: Some(label.into()),
            },
            MetadataField {
                name: "ID (hex)",
                status: "available",
                value: Some(format!("{id:02X}")),
            },
        ];
        object
    })
    .collect();
    state.objects_loaded = true;
    state.mechanisms = vec![crate::backend::MechanismEntry {
        id: pkcs11_client::MechanismType::SHA256_RSA_PKCS,
        name: "CKM_SHA256_RSA_PKCS".into(),
        identifier: "0x00000040".into(),
        minimum: 1024,
        maximum: 4096,
        flags: vec!["SIGN", "VERIFY"],
    }];
    state.mechanisms_loaded = true;
    state.selected_object = Some(ResourceId(3));
    state.object_details = Some(vec![
        MetadataField {
            name: "Key type",
            status: "available",
            value: Some("CKK_RSA".into()),
        },
        MetadataField {
            name: "Sign",
            status: "available",
            value: Some("true".into()),
        },
        MetadataField {
            name: "Sensitive",
            status: "available",
            value: Some("true".into()),
        },
    ]);
    state
}

#[test]
fn representative_screens_render_without_a_provider() {
    let mut state = populated_state();
    for (width, height) in [(900, 600), (1440, 900)] {
        state.presentation.width = width as f32;
        for (name, page) in [
            ("overview", TokenPage::Overview),
            ("objects", TokenPage::Objects),
            ("mechanisms", TokenPage::Mechanisms),
            ("operations", TokenPage::Operations),
            ("administration", TokenPage::Administration),
        ] {
            state.token_page = page;
            state.selected_object = (page == TokenPage::Objects).then_some(ResourceId(3));
            state.selected_mechanism = (page == TokenPage::Mechanisms)
                .then_some(pkcs11_client::MechanismType::SHA256_RSA_PKCS);
            for dark in [false, true] {
                render_screen(&state, name, width, height, dark);
            }
        }
    }
}

fn render_screen(state: &UiState, name: &str, width: u32, height: u32, dark: bool) {
    let mut ui = iced_test::Simulator::with_size(
        iced::Settings {
            default_text_size: iced::Pixels(16.0),
            fonts: vec![iced_fonts::LUCIDE_FONT_BYTES.into()],
            ..Default::default()
        },
        Size::new(width as f32, height as f32),
        crate::views::main::view(state),
    );
    let snapshot = ui
        .snapshot(&theme::theme(dark))
        .expect("rendered interface");
    if let Some(directory) = std::env::var_os("PKCS11_DESKTOP_SNAPSHOT_DIR") {
        assert!(
            snapshot
                .matches_image(std::path::PathBuf::from(directory).join(format!(
                    "{name}-{width}-{}",
                    if dark { "dark" } else { "light" }
                )))
                .expect("write UI snapshot"),
            "snapshot differs from the supplied baseline"
        );
    }
}

#[test]
fn workflow_screens_render_without_a_provider() {
    use crate::backend::{
        BackendCommand, BackendEvent, BackendResult, CryptoMode, LoginRole, SignatureOption,
    };
    let mut welcome = UiState::default();
    welcome.worker_available = true;
    render_screen(&welcome, "welcome", 900, 600, false);

    let mut module = populated_state();
    module.select_module(ResourceId(1));
    render_screen(&module, "module", 1060, 720, false);

    let mut login = populated_state();
    login.loaded_modules[0].tokens[0].login = LoginState::Public;
    login.open_login(LoginRole::User);
    assert!(login.login_form.is_some());
    render_screen(&login, "login", 900, 600, true);

    let mut object = populated_state();
    object.token_page = TokenPage::Objects;
    object.presentation.width = 900.0;
    object.presentation.show_detail = true;
    render_screen(&object, "object-detail", 900, 600, false);
    object.request_delete();
    assert!(object.management.confirmation.is_some());
    render_screen(&object, "delete", 900, 600, false);

    let mut sign = populated_state();
    sign.token_page = TokenPage::Objects;
    let BackendCommand::CryptoOptions { id, scope, .. } =
        sign.open_crypto(CryptoMode::Sign).expect("signing form")
    else {
        panic!("signature choices request");
    };
    sign.event(BackendEvent::Completed {
        id,
        result: Ok(BackendResult::CryptoOptions {
            scope,
            context: false,
            options: vec![SignatureOption {
                parameters: pkcs11_client::SignatureParameters {
                    algorithm: pkcs11_client::SignatureAlgorithm::RsaPkcs1,
                    digest: pkcs11_client::DigestAlgorithm::Sha256,
                    pss: None,
                },
                plan: Some((
                    pkcs11_client::MechanismType::SHA256_RSA_PKCS,
                    pkcs11_client::HashLocation::Token,
                )),
            }],
        }),
    });
    render_screen(&sign, "sign", 1060, 720, true);
}

#[test]
fn filtering_out_a_selection_returns_the_narrow_browser_to_the_list() {
    let mut state = populated_state();
    state.token_page = TokenPage::Objects;
    state.presentation.width = 900.0;
    state.presentation.show_detail = true;
    let mut app = App::without_worker(state);
    let _ = app.update(Message::ObjectFilter("no matching object".into()));
    assert!(app.state.selected_object.is_none());
    assert!(app.state.object_details.is_none());
    assert!(!app.state.presentation.show_detail);
    assert!(app.state.current_operation.is_none());
}

#[test]
fn back_to_list_restores_the_selected_rows_keyboard_focus() {
    fn narrow() -> UiState {
        let mut state = populated_state();
        state.token_page = TokenPage::Objects;
        state.presentation.width = 900.0;
        state.presentation.show_detail = true;
        state
    }
    let app = run(narrow, &["click \"Back to List\""]);
    assert!(!app.state.presentation.show_detail);
    assert_eq!(app.state.selected_object, Some(ResourceId(3)));
    assert_eq!(
        app.state.presentation.focused,
        Some(iced::widget::Id::new("object-ResourceId(3)"))
    );
    assert!(app.state.current_operation.is_none());
}

#[test]
fn showing_a_locator_does_not_read_or_change_the_selected_object() {
    fn objects() -> UiState {
        let mut state = populated_state();
        state.token_page = TokenPage::Objects;
        state
    }
    let mut app = run(objects, &["click \"Show PKCS#11 locator\""]);
    assert!(app.state.presentation.locator_expanded);
    assert_eq!(app.state.selected_object, Some(ResourceId(3)));
    assert!(app.state.current_operation.is_none());
    let _ = app.update(Message::SelectModule(ResourceId(1)));
    assert!(!app.state.presentation.locator_expanded);
}

#[test]
fn a_stale_selection_cannot_open_an_empty_detail_view() {
    let mut state = state();
    state.token_page = TokenPage::Objects;
    let mut app = App::without_worker(state);
    let _ = app.update(Message::SelectObject(ResourceId(999)));
    assert!(!app.state.presentation.show_detail);
    assert!(app.state.selected_object.is_none());
    assert!(app.state.current_operation.is_none());
}

#[test]
fn secondary_text_and_status_badges_keep_readable_contrast() {
    for dark in [false, true] {
        let theme = theme::theme(dark);
        let palette = theme.extended_palette();
        let secondary = theme::muted(&theme).color.expect("secondary text color");
        for background in [
            palette.background.base.color,
            palette.background.weak.color,
            palette.background.weaker.color,
        ] {
            assert!(
                secondary.relative_contrast(background) >= 4.5,
                "secondary text contrast"
            );
        }
        for pair in [
            palette.primary.weak,
            palette.success.weak,
            palette.warning.weak,
        ] {
            assert!(
                pair.text.relative_contrast(pair.color) >= 4.5,
                "status label contrast"
            );
        }
    }
}

#[test]
fn identity_read_failures_remain_distinguishable_in_the_inspector() {
    let mut state = populated_state();
    state.objects[0].uri = None;
    state.objects[0].fields = vec![
        crate::backend::MetadataField {
            name: "Label",
            status: "sensitive",
            value: None,
        },
        crate::backend::MetadataField {
            name: "ID",
            status: "unsupported",
            value: None,
        },
    ];
    let mut ui = iced_test::simulator(crate::views::object::detail(&state));
    assert!(ui.find("sensitive").is_ok());
    assert!(ui.find("unsupported").is_ok());
}

#[test]
fn text_attributes_are_displayed_verbatim() {
    let mut state = populated_state();
    state.object_details = Some(vec![crate::backend::MetadataField {
        name: "Application",
        status: "available",
        value: Some("true".into()),
    }]);
    let mut ui = iced_test::simulator(crate::views::object::detail(&state));
    assert!(ui.find("true").is_ok());
    assert!(ui.find("Yes").is_err());
}

#[test]
fn primary_actions_stay_visible_at_supported_window_sizes() {
    use iced::advanced::widget::{Id, Operation, operation::Focusable};
    struct Bounds(Vec<(Id, iced::Rectangle)>);
    impl Operation for Bounds {
        fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
            operate(self);
        }
        fn focusable(&mut self, id: Option<&Id>, bounds: iced::Rectangle, _: &mut dyn Focusable) {
            if let Some(id) = id {
                self.0.push((id.clone(), bounds));
            }
        }
    }
    for (width, height) in [(900.0, 600.0), (1060.0, 720.0), (1440.0, 900.0)] {
        for page in [TokenPage::Objects, TokenPage::Operations] {
            let mut state = populated_state();
            state.token_page = page;
            state.presentation.width = width;
            state.presentation.show_detail = true;
            let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
            let mut ui = iced_test::runtime::UserInterface::build(
                crate::views::main::view(&state),
                Size::new(width, height),
                iced_test::runtime::user_interface::Cache::default(),
                &mut renderer,
            );
            let mut bounds = Bounds(vec![]);
            ui.operate(&renderer, &mut bounds);
            let names: &[&str] = if page == TokenPage::Objects {
                &["crypto-Sign"]
            } else {
                &[
                    "task-Some(Generate)",
                    "task-Some(Import)",
                    "task-Some(Random)",
                ]
            };
            for name in names {
                let (_, area) = bounds
                    .0
                    .iter()
                    .find(|(id, _)| id == &Id::new(name))
                    .expect("primary action is enabled");
                assert!(
                    area.y >= 0.0
                        && area.y + area.height <= height - 24.0
                        && area.x + area.width <= width,
                    "primary action must be visible without scrolling: {name}"
                );
            }
        }
    }
}

#[test]
fn refreshing_resources_closes_the_obsolete_narrow_detail_view() {
    let mut state = populated_state();
    state.token_page = TokenPage::Objects;
    state.presentation.show_detail = true;
    state.presentation.locator_expanded = true;
    assert!(state.read_objects().is_some());
    assert!(!state.presentation.show_detail);
    assert!(!state.presentation.locator_expanded);
    assert!(state.selected_object.is_none());
    state.cancel();
    state.token_page = TokenPage::Mechanisms;
    state.selected_mechanism = Some(pkcs11_client::MechanismType::SHA256_RSA_PKCS);
    state.presentation.show_detail = true;
    assert!(state.read_mechanisms().is_some());
    assert!(!state.presentation.show_detail);
    assert!(state.selected_mechanism.is_none());
}

#[test]
fn refreshing_objects_drops_the_old_operation_form_and_rejects_late_choices() {
    use crate::backend::{BackendCommand, BackendEvent, BackendResult, CryptoMode};
    let mut state = populated_state();
    state.token_page = TokenPage::Objects;
    let BackendCommand::CryptoOptions { id, scope, .. } = state
        .open_crypto(CryptoMode::Sign)
        .expect("open signing form")
    else {
        panic!("crypto choices request");
    };
    assert!(state.crypto_form.is_some());
    let refresh = state.read_objects().expect("refresh inventory").id();
    assert!(state.crypto_form.is_none());
    state.event(BackendEvent::Completed {
        id,
        result: Ok(BackendResult::CryptoOptions {
            scope,
            context: false,
            options: vec![],
        }),
    });
    assert!(state.crypto_form.is_none());
    assert_eq!(state.current_operation, Some(refresh));
}

#[test]
fn selecting_aes_clears_signing_authentication_and_disables_its_control() {
    use crate::backend::GenerationKind;
    use crate::state::KeyChoice;
    use pkcs11_client::{AesKeyPurpose, AesKeySize, KeyKind};
    fn generation() -> UiState {
        let mut state = state();
        state.loaded_modules[0].tokens[0].login = LoginState::User;
        state.token_page = TokenPage::Operations;
        state.presentation.task = Some(ManagementTask::Generate);
        let signing = KeyChoice(GenerationKind::Signing(KeyKind::Rsa { bits: 2048 }));
        let aes = KeyChoice(GenerationKind::Aes(
            AesKeySize::Bits256,
            AesKeyPurpose::Wrapping,
        ));
        state.management.keys = vec![signing, aes];
        state.management.key = Some(signing);
        state.management.always_authenticate = true;
        state
    }
    let app = run(
        generation,
        &[
            "click \"RSA 2048 — signing\"",
            "type tab",
            "type enter",
            "click \"Require authentication for every signature\"",
        ],
    );
    assert!(matches!(
        app.state.management.key,
        Some(KeyChoice(GenerationKind::Aes(_, _)))
    ));
    assert!(!app.state.management.always_authenticate);
    assert!(app.state.current_operation.is_none());
    for dark in [false, true] {
        render_screen(&app.state, "generate-aes", 900, 600, dark);
    }
}

#[test]
fn aes_gcm_file_form_accepts_nonce_and_aad_without_running_crypto() {
    fn gcm() -> UiState {
        use crate::backend::{
            BackendCommand, BackendEvent, BackendResult, CipherParameters, CryptoMode,
        };
        let mut state = state();
        state.loaded_modules[0].tokens[0].login = LoginState::User;
        state.token_page = TokenPage::Objects;
        let mut key = object(4, "AES encryption key");
        key.class = Some(pkcs11_client::ObjectClass::SECRET_KEY);
        key.uri = Some("pkcs11:serial=A;id=%04;type=secret-key".into());
        state.objects = vec![key];
        state.selected_object = Some(ResourceId(4));
        let BackendCommand::CryptoOptions { id, scope, .. } =
            state.open_cipher(CryptoMode::Encrypt).unwrap()
        else {
            panic!("options")
        };
        state.event(BackendEvent::Completed {
            id,
            result: Ok(BackendResult::CipherOptions {
                scope,
                choices: vec![CipherParameters::AesGcm(
                    pkcs11_client::AesGcmCapabilities {
                        key_size: pkcs11_client::AesKeySize::Bits256,
                    },
                )],
            }),
        });
        state
    }
    let app = run_focused(
        gcm,
        &[
            "type \"0102030405060708090a0b0c\"",
            "type tab",
            "type \"context.bin\"",
        ],
        Some("input-Nonce (24 hexadecimal digits)"),
    );
    let form = app.state.cipher_form.as_ref().unwrap();
    assert_eq!(form.nonce, "0102030405060708090a0b0c");
    assert_eq!(form.aad, "context.bin");
    assert!(app.state.current_operation.is_none());
    for dark in [false, true] {
        render_screen(&app.state, "aes-gcm-encrypt", 1060, 720, dark);
    }
}
