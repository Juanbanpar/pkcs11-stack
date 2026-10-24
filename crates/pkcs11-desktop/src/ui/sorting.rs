// SPDX-License-Identifier: MIT OR Apache-2.0
use super::{MechanismSort, ObjectSort};
use crate::{
    backend::{MechanismEntry, ObjectEntry},
    state::UiState,
};
pub fn sorted_objects(state: &UiState) -> Vec<&ObjectEntry> {
    let mut entries: Vec<_> = state
        .objects
        .iter()
        .filter(|entry| entry.matches(&state.object_filter))
        .collect();
    entries.sort_by(|a, b| {
        let order = match state.presentation.object_sort {
            ObjectSort::Label => a.label.to_lowercase().cmp(&b.label.to_lowercase()),
            ObjectSort::Class => a.class_name().cmp(&b.class_name()),
            ObjectSort::Identifier => a.identifier.cmp(&b.identifier),
        }
        .then(a.identifier.cmp(&b.identifier))
        .then(a.id.0.cmp(&b.id.0));
        if state.presentation.object_descending {
            order.reverse()
        } else {
            order
        }
    });
    entries
}
pub fn sorted_mechanisms(state: &UiState) -> Vec<&MechanismEntry> {
    let mut entries: Vec<_> = state
        .mechanisms
        .iter()
        .filter(|entry| entry.matches(&state.mechanism_filter))
        .collect();
    entries.sort_by(|a, b| {
        let order = match state.presentation.mechanism_sort {
            MechanismSort::Name => a.name.cmp(&b.name),
            MechanismSort::Identifier => a.id.cmp(&b.id),
        }
        .then(a.id.cmp(&b.id));
        if state.presentation.mechanism_descending {
            order.reverse()
        } else {
            order
        }
    });
    entries
}
