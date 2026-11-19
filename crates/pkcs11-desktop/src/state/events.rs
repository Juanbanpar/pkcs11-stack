// SPDX-License-Identifier: MIT OR Apache-2.0
use pkcs11_client::SecretText;

use crate::backend::{BackendError, BackendEvent, BackendResult};

use super::{
    CipherChoice, KeyChoice, Notification, OperationKind, SignatureChoice, TokenPage, UiState,
};

impl UiState {
    pub fn event(&mut self, event: BackendEvent) {
        // Cancellation discards read results, not a module's cleanup failure.
        // Merge only disabled modules; an old inventory must not restore other
        // modules, selections or forms belonging to a newer request.
        if self.shutdown_request.is_none()
            && let BackendEvent::Completed {
                id,
                result:
                    Ok(BackendResult::Modules {
                        modules,
                        error: Some(BackendError::SessionCleanup),
                        ..
                    }),
            } = &event
            && self.current_operation != Some(*id)
        {
            let mut invalidated = false;
            let mut selected_invalidated = false;
            for disabled in modules
                .iter()
                .filter(|module| module.discovery_error == Some(BackendError::SessionCleanup))
            {
                if let Some(module) = self
                    .loaded_modules
                    .iter_mut()
                    .find(|module| module.id == disabled.id)
                {
                    *module = disabled.clone();
                    selected_invalidated |= self.selected_module == Some(module.id);
                    invalidated = true;
                }
            }
            if selected_invalidated {
                self.cancel();
                self.selected_token = None;
                self.reset_browser();
            }
            if invalidated {
                self.notification = Some(Notification::Error(BackendError::SessionCleanup));
            }
            return;
        }
        match event {
            BackendEvent::Completed { id, result }
                if self.shutdown_request.is_none() && self.current_operation == Some(id) =>
            {
                let in_scope = match &result {
                    Ok(
                        BackendResult::CryptoOptions { scope, .. }
                        | BackendResult::Verified { scope },
                    ) => {
                        self.crypto_form
                            .as_ref()
                            .is_some_and(|form| form.scope == *scope)
                            && self.selected_module == Some(scope.module)
                            && self.selected_token == Some(scope.token)
                            && self.selected_object == Some(scope.object)
                    }
                    Ok(BackendResult::KeyOptions { scope, .. }) => {
                        self.key_form
                            .as_ref()
                            .is_some_and(|form| form.scope == *scope)
                            && self.selected_module == Some(scope.module)
                            && self.selected_token == Some(scope.token)
                            && self.selected_object == Some(scope.object)
                    }
                    Ok(BackendResult::CipherOptions { scope, .. }) => {
                        self.cipher_form
                            .as_ref()
                            .is_some_and(|form| form.scope == *scope)
                            && self.selected_module == Some(scope.module)
                            && self.selected_token == Some(scope.token)
                            && self.selected_object == Some(scope.object)
                    }
                    Ok(
                        BackendResult::Objects { module, token, .. }
                        | BackendResult::Capabilities { module, token, .. }
                        | BackendResult::Mechanisms { module, token, .. },
                    ) => {
                        self.selected_module == Some(*module) && self.selected_token == Some(*token)
                    }
                    Ok(BackendResult::ObjectDetails {
                        module,
                        token,
                        object,
                        ..
                    }) => {
                        self.selected_module == Some(*module)
                            && self.selected_token == Some(*token)
                            && self.selected_object == Some(*object)
                    }
                    _ => true,
                };
                if !in_scope {
                    return;
                }
                let reading_choices = self.operation_kind == Some(OperationKind::CryptoOptions);
                self.current_operation = None;
                self.operation_kind = None;
                let error = match result {
                    Ok(BackendResult::KeyOptions { profile, .. }) => {
                        if let Some(form) = &mut self.key_form {
                            form.profile = Some(profile);
                            form.loaded = true;
                        }
                        None
                    }
                    Ok(BackendResult::CipherOptions { choices, .. }) => {
                        if let Some(form) = &mut self.cipher_form {
                            form.choices = choices.into_iter().map(CipherChoice).collect();
                            form.choice = form.choices.first().copied();
                            form.loaded = true;
                        }
                        None
                    }
                    Ok(BackendResult::RandomWritten { length }) => {
                        self.notification = Some(Notification::RandomSaved(length));
                        return;
                    }
                    Ok(BackendResult::CryptoOptions {
                        options, context, ..
                    }) => {
                        if let Some(form) = &mut self.crypto_form {
                            form.options = options.into_iter().map(SignatureChoice).collect();
                            form.choice = form.options.first().copied();
                            form.context_required = context;
                            form.pin = SecretText::default();
                            form.loaded = true;
                        }
                        None
                    }
                    Ok(BackendResult::Verified { .. }) => {
                        self.notification = Some(Notification::SignatureVerified);
                        return;
                    }
                    Ok(BackendResult::Capabilities { keys, .. }) => {
                        self.management.keys = keys.into_iter().map(KeyChoice).collect();
                        self.management.key = self.management.keys.first().copied();
                        if !self
                            .management
                            .key
                            .is_some_and(|key| key.0.supports_context_authentication())
                        {
                            self.management.always_authenticate = false;
                        }
                        self.management.capabilities_loaded = true;
                        None
                    }
                    Ok(BackendResult::Managed {
                        module,
                        token,
                        modules,
                        objects,
                        error,
                    }) => {
                        self.loaded_modules = modules;
                        if self.module().is_none() {
                            self.selected_module = None;
                            self.selected_token = None;
                        } else if self.token().is_none() {
                            self.selected_token = None;
                        }
                        self.reset_browser();
                        if self.selected_module == Some(module)
                            && self.selected_token == Some(token)
                        {
                            self.token_page = TokenPage::Objects;
                            if let Some(objects) = objects {
                                self.objects = objects;
                                self.objects_loaded = true;
                            }
                        }
                        error
                    }
                    Ok(BackendResult::Modules {
                        modules,
                        loaded,
                        error,
                    }) => {
                        self.loaded_modules = modules;
                        if self.select_loaded
                            && let Some(module) = loaded
                        {
                            self.selected_module = Some(module);
                            self.selected_token = None;
                            self.selected_object = None;
                        }
                        self.select_loaded = false;
                        if self.module().is_none() {
                            self.selected_module = None;
                            self.selected_token = None;
                            self.selected_object = None;
                        } else if self.token().is_none() {
                            self.selected_token = None;
                            self.selected_object = None;
                        }
                        self.reset_browser();
                        error
                    }
                    Ok(BackendResult::Objects { objects, .. }) => {
                        self.objects = objects;
                        self.objects_loaded = true;
                        None
                    }
                    Ok(BackendResult::Mechanisms { mechanisms, .. }) => {
                        self.mechanisms = mechanisms;
                        self.mechanisms_loaded = true;
                        None
                    }
                    Ok(BackendResult::ObjectDetails { details, .. }) => {
                        self.object_details = Some(details);
                        None
                    }
                    #[cfg(test)]
                    Ok(BackendResult::Synthetic) => None,
                    Err(error) => {
                        if reading_choices {
                            if let Some(form) = &mut self.key_form {
                                form.loaded = true;
                            }
                            if let Some(form) = &mut self.cipher_form {
                                form.loaded = true;
                            }
                            if let Some(form) = &mut self.crypto_form {
                                form.loaded = true;
                            }
                        }
                        Some(error)
                    }
                };
                self.select_loaded = false;
                self.notification =
                    Some(error.map_or(Notification::Completed, Notification::Error));
            }
            BackendEvent::Disconnected if self.shutdown_request.is_none() => {
                self.worker_available = false;
                self.current_operation = None;
                self.operation_kind = None;
                self.picker_request = None;
                // These snapshots no longer represent providers available for operations.
                self.loaded_modules.clear();
                self.selected_module = None;
                self.selected_token = None;
                self.selected_object = None;
                self.reset_browser();
                self.notification = Some(Notification::Error(BackendError::Disconnected));
            }
            BackendEvent::Stopped { id, result } if self.shutdown_request == Some(id) => {
                self.worker_available = false;
                if let Err(error) = result {
                    self.notification = Some(Notification::Error(error));
                }
            }
            _ => {} // Cancelled and superseded results cannot replace UI state.
        }
    }
}
