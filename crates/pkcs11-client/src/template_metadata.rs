// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Error, ManagementSession, ObjectRef, PUBLIC_METADATA_MAX_ATTRIBUTE, TemplateAttribute,
    TemplateMetadata,
};

impl ManagementSession<'_> {
    /// Inspect one object's wrap/unwrap/derive template structure. Selection
    /// requires a unique RFC 7512 object and bounds identity reads. Leaf values
    /// are never read; this report cannot be used as an operation template.
    ///
    /// The runtime limits depth, total entries and native array allocation.
    /// Unknown member IDs and unavailable lengths remain inspectable. Sensitive
    /// and invalid roots are distinct; unavailable members cannot be attributed
    /// to either cause because the native return code covers the whole request.
    pub fn template_metadata(
        &mut self,
        reference: &ObjectRef,
        kind: TemplateAttribute,
    ) -> Result<TemplateMetadata, Error> {
        Ok(self
            .session
            .resolve_bounded(reference, PUBLIC_METADATA_MAX_ATTRIBUTE)?
            .template_metadata(kind)?)
    }
}
