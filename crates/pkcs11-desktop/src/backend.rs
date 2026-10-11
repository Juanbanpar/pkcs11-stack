// SPDX-License-Identifier: GPL-3.0-or-later
use iced::futures::{Stream, StreamExt, channel::mpsc as asynchronous};
use pkcs11_client::ErrorKind;
use std::{
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

/// Never reused during an application's lifetime, including after cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId(pub u64);

#[derive(Clone, Copy, Debug)]
pub enum SyntheticOutcome {
    Success,
    Failure,
}

// Command payloads are excluded from diagnostics.
pub enum BackendCommand {
    Synthetic {
        id: RequestId,
        outcome: SyntheticOutcome,
    },
    Shutdown {
        id: RequestId,
    },
}

/// Presentation data contains a category and fixed text, never raw diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendError {
    Start,
    Busy,
    Disconnected,
    Panicked,
    Synthetic,
    RequestExhausted,
    Client(ErrorKind),
}
impl BackendError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Start => "Could not start the background worker.",
            Self::Busy => "The worker queue is full. Wait before trying again.",
            Self::Disconnected => "The background worker is unavailable.",
            Self::Panicked => "The background worker stopped unexpectedly.",
            Self::Synthetic => "The synthetic operation reported a test failure.",
            Self::RequestExhausted => "No more request IDs are available. Restart the application.",
            Self::Client(_) => "The client operation failed.",
        }
    }
}
impl From<&pkcs11_client::Error> for BackendError {
    fn from(error: &pkcs11_client::Error) -> Self {
        Self::Client(error.kind())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BackendEvent {
    Completed {
        id: RequestId,
        result: Result<(), BackendError>,
    },
    Stopped {
        id: RequestId,
    },
    Disconnected,
}

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

/// Backend ownership stays outside UI state. Only this thread will own providers.
pub struct Worker {
    commands: Option<mpsc::SyncSender<BackendCommand>>,
    thread: Option<JoinHandle<()>>,
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
            .map_err(|_| BackendError::Panicked)
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
) {
    while let Ok(command) = commands.recv() {
        let event = match command {
            BackendCommand::Synthetic { id, outcome } => {
                // Prove that a blocking operation does not stall the UI. No client
                // or PKCS#11 calls occur at this milestone.
                thread::sleep(Duration::from_millis(350));
                BackendEvent::Completed {
                    id,
                    result: match outcome {
                        SyntheticOutcome::Success => Ok(()),
                        SyntheticOutcome::Failure => Err(BackendError::Synthetic),
                    },
                }
            }
            BackendCommand::Shutdown { id } => {
                let _ = events.unbounded_send(BackendEvent::Stopped { id });
                break;
            }
        };
        if events.unbounded_send(event).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced::futures::executor::block_on;

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
                    result: Ok(())
                },
                BackendEvent::Completed {
                    id: RequestId(2),
                    result: Err(BackendError::Synthetic)
                },
                BackendEvent::Stopped { id: RequestId(3) },
                BackendEvent::Disconnected
            ]
        ));
    }

    #[test]
    fn dropping_worker_disconnects_and_terminates_it() {
        let (mut worker, source) = Worker::spawn().unwrap();
        let handle = worker.thread.take().unwrap();
        drop(worker);
        handle.join().unwrap();
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
    fn client_ownership_traits_support_worker_local_use() {
        fn send<T: Send>() {}
        fn share<T: Send + Sync>() {}
        share::<pkcs11_client::Provider>();
        share::<pkcs11_client::Client<'static>>();
        send::<pkcs11_client::ManagementSession<'static>>();
    }
}
