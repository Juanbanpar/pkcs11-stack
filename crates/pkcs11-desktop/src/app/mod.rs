// SPDX-License-Identifier: MIT OR Apache-2.0
mod core;
mod keyboard;
mod message;
mod update;

pub use core::App;
pub(crate) use keyboard::{focus_navigation, shortcut};
pub use message::Message;

#[cfg(test)]
mod tests;
