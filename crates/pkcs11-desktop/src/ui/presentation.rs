// SPDX-License-Identifier: MIT OR Apache-2.0
use super::theme::Appearance;
use crate::{app::Message, backend::ResourceId};
use std::collections::HashSet;

#[derive(Clone)]
pub enum Action {
    Focus(String),
    RecordFocus,
    Focused(iced::widget::Id),
    MoveIn(super::focus::Group, super::focus::Movement),
    AddModule,
    Appearance,
    KeyboardHelp,
    SetAppearance(Appearance),
    SystemTheme(iced::theme::Mode),
    ToggleModule(ResourceId),
    Close,
    Escape,
    BackToList,
    ToggleLocator,
    SortObjects(ObjectSort),
    SortMechanisms(MechanismSort),
    Task(Option<ManagementTask>),
    Choice {
        id: String,
        title: String,
        options: Vec<(String, Message)>,
    },
    Choose(Box<Message>),
    Refresh,
    Filter,
    Resize(iced::Size),
}
impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UiAction")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementTask {
    Generate,
    Import,
    Random,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectSort {
    #[default]
    Label,
    Class,
    Identifier,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MechanismSort {
    #[default]
    Name,
    Identifier,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overlay {
    AddModule,
    Appearance,
    KeyboardHelp,
}
pub struct ChoiceMenu {
    pub title: String,
    pub options: Vec<(String, Message)>,
}

pub struct Presentation {
    pub appearance: Appearance,
    pub system_dark: bool,
    pub collapsed: HashSet<u64>,
    pub overlay: Option<Overlay>,
    pub choice: Option<ChoiceMenu>,
    pub restore_focus: Option<iced::widget::Id>,
    pub focused: Option<iced::widget::Id>,
    pub task: Option<ManagementTask>,
    pub object_sort: ObjectSort,
    pub object_descending: bool,
    pub mechanism_sort: MechanismSort,
    pub mechanism_descending: bool,
    pub show_detail: bool,
    pub locator_expanded: bool,
    pub width: f32,
}
impl Default for Presentation {
    fn default() -> Self {
        Self {
            appearance: Appearance::System,
            system_dark: false,
            collapsed: HashSet::new(),
            overlay: None,
            choice: None,
            restore_focus: None,
            focused: None,
            task: None,
            object_sort: ObjectSort::Label,
            object_descending: false,
            mechanism_sort: MechanismSort::Name,
            mechanism_descending: false,
            show_detail: false,
            locator_expanded: false,
            width: 1060.0,
        }
    }
}
impl Presentation {
    pub fn dark(&self) -> bool {
        match self.appearance {
            Appearance::System => self.system_dark,
            Appearance::Light => false,
            Appearance::Dark => true,
        }
    }
}
