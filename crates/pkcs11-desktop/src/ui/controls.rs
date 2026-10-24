// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{Action, theme};
use crate::app::Message;
use iced::advanced::{
    self, Clipboard, Layout, Shell, Widget, layout, renderer,
    widget::{Operation, Tree, operation::Focusable, tree},
};
use iced::widget;
use iced::{
    Element, Event, Length, Padding, Rectangle, Renderer, Size, Theme, Vector, keyboard, mouse,
};

/// Adds keyboard focus to controls whose upstream implementation handles only pointers.
struct Focus<'a> {
    content: Element<'a, Message>,
    action: Option<Message>,
    id: String,
    group: Option<super::focus::Group>,
    inert: bool,
    root: bool,
}
#[derive(Default)]
struct FocusState {
    focused: bool,
    pressed: bool,
    id: String,
}
impl Focusable for FocusState {
    fn is_focused(&self) -> bool {
        self.focused
    }
    fn focus(&mut self) {
        self.focused = true;
    }
    fn unfocus(&mut self) {
        self.focused = false;
        self.pressed = false;
    }
}
impl Widget<Message, Theme, Renderer> for Focus<'_> {
    fn size(&self) -> Size<Length> {
        self.content.as_widget().size()
    }
    fn size_hint(&self) -> Size<Length> {
        self.content.as_widget().size_hint()
    }
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<FocusState>()
    }
    fn state(&self) -> tree::State {
        tree::State::new(FocusState {
            id: self.id.clone(),
            ..Default::default()
        })
    }
    fn children(&self) -> Vec<Tree> {
        vec![Tree::new(&self.content)]
    }
    fn diff(&self, tree: &mut Tree) {
        let state = tree.state.downcast_mut::<FocusState>();
        if state.id != self.id {
            *state = FocusState {
                id: self.id.clone(),
                ..Default::default()
            };
        }
        if self.action.is_none() {
            state.unfocus();
        }
        tree.diff_children(std::slice::from_ref(&self.content));
    }
    fn layout(
        &mut self,
        tree: &mut Tree,
        renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        self.content
            .as_widget_mut()
            .layout(&mut tree.children[0], renderer, limits)
    }
    fn operate(
        &mut self,
        tree: &mut Tree,
        layout: Layout<'_>,
        renderer: &Renderer,
        operation: &mut dyn Operation,
    ) {
        if self.inert {
            return;
        }
        if self.action.is_some() {
            operation.focusable(
                Some(&widget::Id::from(self.id.clone())),
                layout.bounds(),
                tree.state.downcast_mut::<FocusState>(),
            );
        }
        self.content
            .as_widget_mut()
            .operate(&mut tree.children[0], layout, renderer, operation);
    }
    fn update(
        &mut self,
        tree: &mut Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        renderer: &Renderer,
        clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        if self.inert {
            return;
        }
        if self.root {
            self.content.as_widget_mut().update(
                &mut tree.children[0],
                event,
                layout,
                cursor,
                renderer,
                clipboard,
                shell,
                viewport,
            );
            if matches!(
                event,
                Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left))
            ) {
                shell.publish(Message::Ui(Action::RecordFocus));
            }
            if let Event::Keyboard(keyboard::Event::KeyPressed {
                key,
                modifiers,
                repeat,
                ..
            }) = event
                && !repeat
            {
                let message = crate::app::shortcut(key, *modifiers).or_else(|| {
                    (!shell.is_event_captured())
                        .then(|| crate::app::focus_navigation(key.clone(), *modifiers))
                        .flatten()
                });
                if let Some(message) = message {
                    shell.publish(message);
                    shell.capture_event();
                }
            }
            return;
        }
        let state = tree.state.downcast_mut::<FocusState>();
        if let Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) = event
            && cursor.is_over(layout.bounds())
            && self.action.is_some()
        {
            shell.publish(Message::Ui(Action::Focus(self.id.clone())));
        }
        if state.focused
            && let Some(action) = &self.action
        {
            match event {
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key:
                        keyboard::Key::Named(keyboard::key::Named::Enter | keyboard::key::Named::Space),
                    repeat,
                    modifiers,
                    ..
                }) if modifiers.is_empty() => {
                    if !repeat && !state.pressed {
                        state.pressed = true;
                        shell.publish(action.clone());
                    }
                    shell.capture_event();
                    return;
                }
                Event::Keyboard(keyboard::Event::KeyReleased {
                    key:
                        keyboard::Key::Named(keyboard::key::Named::Enter | keyboard::key::Named::Space),
                    ..
                }) => {
                    state.pressed = false;
                    shell.capture_event();
                    return;
                }
                Event::Keyboard(keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(named),
                    modifiers,
                    ..
                }) if self.group.is_some() && modifiers.is_empty() => {
                    use super::focus::Movement;
                    let movement = match named {
                        keyboard::key::Named::ArrowUp | keyboard::key::Named::ArrowLeft => {
                            Some(Movement::Previous)
                        }
                        keyboard::key::Named::ArrowDown | keyboard::key::Named::ArrowRight => {
                            Some(Movement::Next)
                        }
                        keyboard::key::Named::Home => Some(Movement::First),
                        keyboard::key::Named::End => Some(Movement::Last),
                        _ => None,
                    };
                    let action = movement
                        .map(|movement| Message::Ui(Action::MoveIn(self.group.unwrap(), movement)));
                    if let Some(action) = action {
                        shell.publish(action);
                        shell.capture_event();
                        return;
                    }
                }
                _ => {}
            }
        }
        self.content.as_widget_mut().update(
            &mut tree.children[0],
            event,
            layout,
            cursor,
            renderer,
            clipboard,
            shell,
            viewport,
        );
    }
    fn draw(
        &self,
        tree: &Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        self.content.as_widget().draw(
            &tree.children[0],
            renderer,
            theme,
            style,
            layout,
            cursor,
            viewport,
        );
        if tree.state.downcast_ref::<FocusState>().focused && self.action.is_some() && !self.inert {
            use advanced::Renderer as _;
            renderer.fill_quad(
                renderer::Quad {
                    bounds: layout.bounds(),
                    border: iced::Border {
                        width: 2.0,
                        radius: 8.0.into(),
                        color: theme.palette().primary,
                    },
                    ..Default::default()
                },
                iced::Color::TRANSPARENT,
            );
        }
    }
    fn mouse_interaction(
        &self,
        tree: &Tree,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &Renderer,
    ) -> mouse::Interaction {
        if self.inert {
            mouse::Interaction::None
        } else {
            self.content.as_widget().mouse_interaction(
                &tree.children[0],
                layout,
                cursor,
                viewport,
                renderer,
            )
        }
    }
    fn overlay<'b>(
        &'b mut self,
        tree: &'b mut Tree,
        layout: Layout<'b>,
        renderer: &Renderer,
        viewport: &Rectangle,
        translation: Vector,
    ) -> Option<advanced::overlay::Element<'b, Message, Theme, Renderer>> {
        if self.inert {
            None
        } else {
            self.content.as_widget_mut().overlay(
                &mut tree.children[0],
                layout,
                renderer,
                viewport,
                translation,
            )
        }
    }
}
pub fn inert(content: Element<'_, Message>) -> Element<'_, Message> {
    Element::new(Focus {
        content,
        action: None,
        id: String::new(),
        group: None,
        inert: true,
        root: false,
    })
}

pub fn root(content: Element<'_, Message>) -> Element<'_, Message> {
    Element::new(Focus {
        content,
        action: None,
        id: "root".into(),
        group: None,
        inert: false,
        root: true,
    })
}

pub struct Button<'a> {
    inner: widget::Button<'a, Message>,
    action: Option<Message>,
    id: Option<String>,
    arrows: bool,
}
pub fn button<'a>(content: impl Into<Element<'a, Message>>) -> Button<'a> {
    Button {
        inner: widget::button(content)
            .padding([8, 12])
            .style(theme::secondary),
        action: None,
        id: None,
        arrows: false,
    }
}
impl<'a> Button<'a> {
    pub fn width(mut self, value: impl Into<Length>) -> Self {
        self.inner = self.inner.width(value);
        self
    }
    pub fn padding(mut self, value: impl Into<Padding>) -> Self {
        self.inner = self.inner.padding(value);
        self
    }
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
    pub fn arrows(mut self) -> Self {
        self.arrows = true;
        self
    }
    pub fn style(
        mut self,
        style: impl Fn(&Theme, widget::button::Status) -> widget::button::Style + 'a,
    ) -> Self {
        self.inner = self.inner.style(style);
        self
    }
    pub fn on_press(self, message: Message) -> Self {
        self.on_press_maybe(Some(message))
    }
    pub fn on_press_maybe(mut self, message: Option<Message>) -> Self {
        self.action = message.clone();
        self.inner = self.inner.on_press_maybe(message);
        self
    }
}
impl<'a> From<Button<'a>> for Element<'a, Message> {
    fn from(button: Button<'a>) -> Self {
        let id = button.id.unwrap_or_else(|| {
            button
                .action
                .as_ref()
                .map(action_id)
                .unwrap_or_else(|| "disabled".into())
        });
        let group = if button.arrows {
            use super::focus::Group;
            Some(match &button.action {
                Some(Message::SelectObject(_)) => Group::Objects,
                Some(Message::SelectMechanism(_)) => Group::Mechanisms,
                Some(Message::ShowPage(_)) => Group::Pages,
                Some(Message::Ui(Action::Choose(_))) => Group::Choices,
                _ => Group::Navigation,
            })
        } else {
            None
        };
        Element::new(Focus {
            content: button.inner.into(),
            action: button.action,
            id,
            group,
            inert: false,
            root: false,
        })
    }
}
fn action_id(message: &Message) -> String {
    match message {
        Message::SelectModule(id) => format!("module-{id:?}"),
        Message::SelectToken { token, .. } => format!("token-{token:?}"),
        Message::SelectObject(id) => format!("object-{id:?}"),
        Message::SelectMechanism(id) => format!("mechanism-{id:?}"),
        Message::CryptoBrowse { id, field } => format!("crypto-file-{id:?}-{field:?}"),
        Message::CipherBrowse { id, field } => format!("cipher-file-{id:?}-{field:?}"),
        Message::KeyBrowse { id, field } => format!("key-file-{id:?}-{field:?}"),
        Message::ShowPage(page) => format!("page-{page:?}"),
        Message::Navigate(screen) => format!("screen-{screen:?}"),
        Message::OpenLogin(role) => format!("login-{role:?}"),
        Message::Ui(Action::Refresh) => "refresh".into(),
        Message::Ui(Action::BackToList) => "back-to-list".into(),
        Message::Ui(Action::Close) => "close-overlay".into(),
        Message::Ui(Action::ToggleModule(id)) => format!("expand-{id:?}"),
        Message::Ui(Action::Task(task)) => format!("task-{task:?}"),
        Message::Ui(Action::SetAppearance(appearance)) => format!("appearance-{appearance:?}"),
        Message::Ui(Action::SortObjects(sort)) => format!("sort-object-{sort:?}"),
        Message::Ui(Action::SortMechanisms(sort)) => format!("sort-mechanism-{sort:?}"),
        Message::OpenCrypto(mode) | Message::OpenCipher(mode) | Message::OpenKeyOperation(mode) => {
            format!("crypto-{mode:?}")
        }
        Message::OpenAdministration(kind) => format!("admin-{kind:?}"),
        _ => format!("{message:?}"),
    }
}

pub mod button {
    pub use super::super::theme::{danger, primary};
}

pub struct Checkbox<'a> {
    inner: widget::Checkbox<'a, Message>,
    checked: bool,
    action: Option<Message>,
    label: String,
}
pub fn checkbox<'a>(checked: bool) -> Checkbox<'a> {
    Checkbox {
        inner: widget::checkbox(checked),
        checked,
        action: None,
        label: String::new(),
    }
}
impl<'a> Checkbox<'a> {
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self.inner = self.inner.label(self.label.clone());
        self
    }
    pub fn on_toggle(self, callback: impl Fn(bool) -> Message + 'a) -> Self {
        self.on_toggle_maybe(Some(callback))
    }
    pub fn on_toggle_maybe<F: Fn(bool) -> Message + 'a>(mut self, callback: Option<F>) -> Self {
        self.action = callback.as_ref().map(|callback| callback(!self.checked));
        self.inner = self.inner.on_toggle_maybe(callback);
        self
    }
}
impl<'a> From<Checkbox<'a>> for Element<'a, Message> {
    fn from(checkbox: Checkbox<'a>) -> Self {
        Element::new(Focus {
            content: checkbox.inner.into(),
            action: checkbox.action,
            id: format!("check-{}", checkbox.label),
            group: None,
            inert: false,
            root: false,
        })
    }
}

pub struct Choice<'a> {
    enabled: bool,
    options: Vec<(String, Message)>,
    value: Option<String>,
    placeholder: String,
    marker: std::marker::PhantomData<&'a ()>,
}
pub fn pick_list<'a, T, L, V>(
    options: L,
    selected: Option<V>,
    callback: impl Fn(T) -> Message,
) -> Choice<'a>
where
    T: ToString + Clone,
    L: std::borrow::Borrow<[T]>,
    V: std::borrow::Borrow<T>,
{
    Choice {
        enabled: true,
        options: options
            .borrow()
            .iter()
            .map(|value| (value.to_string(), callback(value.clone())))
            .collect(),
        value: selected.map(|value| value.borrow().to_string()),
        placeholder: "Choose…".into(),
        marker: std::marker::PhantomData,
    }
}
impl Choice<'_> {
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
    pub fn placeholder(mut self, value: impl Into<String>) -> Self {
        self.placeholder = value.into();
        self
    }
}
impl<'a> From<Choice<'a>> for Element<'a, Message> {
    fn from(choice: Choice<'a>) -> Self {
        let id = format!("choice-{}", choice.placeholder);
        let label = choice.value.unwrap_or_else(|| choice.placeholder.clone());
        let enabled = choice.enabled && !choice.options.is_empty();
        button(widget::text(label))
            .id(id.clone())
            .on_press_maybe(enabled.then_some(Message::Ui(Action::Choice {
                id,
                title: choice.placeholder,
                options: choice.options,
            })))
            .into()
    }
}

/// A persistent label; placeholders remain hints rather than the only field name.
pub fn text_input<'a>(label: &'a str, value: &'a str) -> LabeledInput<'a> {
    LabeledInput {
        label,
        enabled: false,
        input: widget::text_input("", value).id(format!("input-{label}")),
    }
}
pub struct LabeledInput<'a> {
    label: &'a str,
    input: widget::TextInput<'a, Message>,
    enabled: bool,
}
impl<'a> LabeledInput<'a> {
    pub fn id(mut self, id: impl Into<widget::Id>) -> Self {
        self.input = self.input.id(id);
        self
    }
    pub fn secure(mut self, secure: bool) -> Self {
        self.input = self.input.secure(secure);
        self
    }
    pub fn on_input(mut self, action: impl Fn(String) -> Message + 'a) -> Self {
        self.enabled = true;
        self.input = self.input.on_input(action);
        self
    }
    pub fn on_input_maybe(mut self, action: Option<impl Fn(String) -> Message + 'a>) -> Self {
        self.enabled = action.is_some();
        self.input = self.input.on_input_maybe(action);
        self
    }
    pub fn on_submit(mut self, action: Message) -> Self {
        self.input = self.input.on_submit(action);
        self
    }
    pub fn on_submit_maybe(mut self, action: Option<Message>) -> Self {
        self.input = self.input.on_submit_maybe(action);
        self
    }
}
impl<'a> From<LabeledInput<'a>> for Element<'a, Message> {
    fn from(input: LabeledInput<'a>) -> Self {
        let content = widget::column![widget::text(input.label).size(14), input.input.padding(8)]
            .spacing(4)
            .into();
        if input.enabled {
            content
        } else {
            inert(content)
        }
    }
}
