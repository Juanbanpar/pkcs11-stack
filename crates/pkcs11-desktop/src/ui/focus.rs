// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::app::Message;
use iced::{
    Rectangle, Task, Vector,
    advanced::widget::{
        self, Id, Operation,
        operation::{Focusable, Outcome, Scrollable, scrollable::AbsoluteOffset},
    },
};

#[derive(Clone, Copy, Debug)]
pub enum Movement {
    Previous,
    Next,
    First,
    Last,
}
#[derive(Clone, Copy, Debug)]
pub enum Group {
    Navigation,
    Objects,
    Mechanisms,
    Pages,
    Choices,
}
#[derive(Clone)]
struct Entry {
    id: Id,
    bounds: Rectangle,
    parents: Vec<usize>,
    focused: bool,
}
#[derive(Clone)]
struct Scroll {
    bounds: Rectangle,
    translation: Vector,
}
#[derive(Clone, Default)]
struct Snapshot {
    entries: Vec<Entry>,
    scrolls: Vec<Scroll>,
    parents: Vec<usize>,
    pending: Option<usize>,
}
impl Operation<Snapshot> for Snapshot {
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation<Snapshot>)) {
        let scroll = self.pending.take();
        if let Some(index) = scroll {
            self.parents.push(index);
        }
        operate(self);
        if scroll.is_some() {
            self.parents.pop();
        }
    }
    fn focusable(&mut self, id: Option<&Id>, bounds: Rectangle, state: &mut dyn Focusable) {
        if let Some(id) = id {
            self.entries.push(Entry {
                id: id.clone(),
                bounds,
                parents: self.parents.clone(),
                focused: state.is_focused(),
            });
        }
    }
    fn scrollable(
        &mut self,
        _: Option<&Id>,
        bounds: Rectangle,
        _: Rectangle,
        translation: Vector,
        _: &mut dyn Scrollable,
    ) {
        self.pending = Some(self.scrolls.len());
        self.scrolls.push(Scroll {
            bounds,
            translation,
        });
    }
    fn finish(&self) -> Outcome<Snapshot> {
        Outcome::Some(self.clone())
    }
}
struct Apply {
    target: Id,
    offsets: Vec<(usize, f32)>,
    index: usize,
}
impl Operation for Apply {
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation)) {
        operate(self);
    }
    fn focusable(&mut self, id: Option<&Id>, _: Rectangle, state: &mut dyn Focusable) {
        if id == Some(&self.target) {
            state.focus();
        } else {
            state.unfocus();
        }
    }
    fn scrollable(
        &mut self,
        _: Option<&Id>,
        _: Rectangle,
        _: Rectangle,
        _: Vector,
        state: &mut dyn Scrollable,
    ) {
        if let Some((_, y)) = self.offsets.iter().find(|(index, _)| *index == self.index) {
            state.scroll_to(AbsoluteOffset {
                x: None,
                y: Some(*y),
            });
        }
        self.index += 1;
    }
    fn finish(&self) -> Outcome<()> {
        Outcome::Some(())
    }
}
fn reveal(snapshot: &Snapshot, entry: &Entry) -> Vec<(usize, f32)> {
    let mut bounds = entry.bounds;
    let mut offsets = Vec::new();
    for index in entry.parents.iter().rev() {
        let scroll = &snapshot.scrolls[*index];
        let top = bounds.y - scroll.translation.y;
        let bottom = top + bounds.height;
        let delta = if top < scroll.bounds.y {
            top - scroll.bounds.y
        } else if bottom > scroll.bounds.y + scroll.bounds.height {
            bottom - scroll.bounds.y - scroll.bounds.height
        } else {
            0.0
        };
        let offset = (scroll.translation.y + delta).max(0.0);
        if delta != 0.0 {
            offsets.push((*index, offset));
        }
        bounds.y -= offset;
    }
    offsets
}
pub fn record() -> Task<Message> {
    widget::operate(Snapshot::default()).then(|snapshot| {
        snapshot
            .entries
            .into_iter()
            .find(|entry| entry.focused)
            .map_or_else(Task::none, |entry| {
                Task::done(Message::Ui(super::Action::Focused(entry.id)))
            })
    })
}
pub fn focus(id: impl Into<Id>) -> Task<Message> {
    walk_ids(Some(vec![id.into()]), Movement::First, true)
}
pub fn walk(ids: Option<Vec<String>>, movement: Movement) -> Task<Message> {
    walk_ids(
        ids.map(|ids| ids.into_iter().map(Id::from).collect()),
        movement,
        false,
    )
}
fn walk_ids(allowed: Option<Vec<Id>>, movement: Movement, fallback: bool) -> Task<Message> {
    widget::operate(Snapshot::default()).then(move |snapshot| {
        let mut entries: Vec<_> = snapshot
            .entries
            .iter()
            .filter(|entry| allowed.as_ref().is_none_or(|ids| ids.contains(&entry.id)))
            .collect();
        if entries.is_empty() && fallback {
            entries.extend(snapshot.entries.iter());
        }
        if entries.is_empty() {
            return Task::none();
        }
        let current = entries.iter().position(|entry| entry.focused);
        let index = match movement {
            Movement::First => 0,
            Movement::Last => entries.len() - 1,
            Movement::Next => current.map_or(0, |index| (index + 1) % entries.len()),
            Movement::Previous => current.map_or(entries.len() - 1, |index| {
                (index + entries.len() - 1) % entries.len()
            }),
        };
        let entry = entries[index];
        let id = entry.id.clone();
        widget::operate(Apply {
            target: id.clone(),
            offsets: reveal(&snapshot, entry),
            index: 0,
        })
        .map(move |()| Message::Ui(super::Action::Focused(id.clone())))
    })
}
