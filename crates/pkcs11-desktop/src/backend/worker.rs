// SPDX-License-Identifier: MIT OR Apache-2.0
use iced::futures::{Stream, StreamExt, channel::mpsc as asynchronous};
use std::{
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
};

use super::{BackendCommand, BackendError, BackendEvent, RequestId, registry::Registry};

/// One receiver per application; clones preserve the subscription's identity.
#[derive(Clone)]
pub struct EventSource(Arc<Mutex<Option<asynchronous::UnboundedReceiver<BackendEvent>>>>);
impl Hash for EventSource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}
impl EventSource {
    pub fn stream(&self) -> impl Stream<Item = BackendEvent> + Unpin + use<> {
        let receiver = self.0.lock().expect("event source lock poisoned").take();
        // Report closure (including worker panic), instead of silently hanging UI state.
        iced::futures::stream::iter(receiver)
            .flatten()
            .chain(iced::futures::stream::once(iced::futures::future::ready(
                BackendEvent::Disconnected,
            )))
    }
}

/// Providers are created, used and finalized on the worker thread.
pub struct Worker {
    commands: Option<mpsc::SyncSender<BackendCommand>>,
    thread: Option<JoinHandle<Result<(), BackendError>>>,
}
impl Worker {
    pub fn spawn() -> Result<(Self, EventSource), BackendError> {
        let (commands, receiver) = mpsc::sync_channel(8);
        let (events, output) = asynchronous::unbounded();
        let thread = thread::Builder::new()
            .name("pkcs11-desktop-backend".into())
            .spawn(move || run(receiver, events))
            .map_err(|_| BackendError::Start)?;
        Ok((
            Self {
                commands: Some(commands),
                thread: Some(thread),
            },
            EventSource(Arc::new(Mutex::new(Some(output)))),
        ))
    }

    pub fn submit(&self, command: BackendCommand) -> Result<(), BackendError> {
        self.commands
            .as_ref()
            .ok_or(BackendError::Disconnected)?
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => BackendError::Busy,
                mpsc::TrySendError::Disconnected(_) => BackendError::Disconnected,
            })
    }

    /// Called ONLY by an Iced Task on its thread-pool executor, never update/view.
    /// Drains queued commands, asks the worker to stop, and joins it before exit.
    pub async fn shutdown(mut self, id: RequestId) -> Result<(), BackendError> {
        if let Some(sender) = self.commands.take() {
            // A full queue can block here; this future runs off the UI thread.
            let _ = sender.send(BackendCommand::Shutdown { id });
        }
        self.thread
            .take()
            .expect("worker join handle missing")
            .join()
            .map_err(|_| BackendError::Panicked)?
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Exceptional application teardown also disconnects the worker. Normal
        // window closure uses shutdown/join; Drop must never block the UI thread.
        self.commands.take();
    }
}

fn run(
    commands: mpsc::Receiver<BackendCommand>,
    events: asynchronous::UnboundedSender<BackendEvent>,
) -> Result<(), BackendError> {
    let mut registry = Registry::default();
    while let Ok(command) = commands.recv() {
        if let BackendCommand::Shutdown { id } = command {
            let result = registry.close();
            let _ = events.unbounded_send(BackendEvent::Stopped { id, result });
            return result;
        }
        if events.unbounded_send(registry.execute(command)).is_err() {
            break;
        }
    }
    registry.close()
}

#[cfg(test)]
mod tests {
    use super::super::SyntheticOutcome;
    use super::*;
    use iced::futures::executor::block_on;
    use pkcs11_client::ErrorKind;

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
}
