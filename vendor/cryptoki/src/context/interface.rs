// SPDX-License-Identifier: Apache-2.0
//! Selection of known standard function-table layouts before initialization.
use super::{v2tov3, v30tov32, Function, FunctionList};
use crate::error::{Error, Result, Rv};
use cryptoki_sys::*;
use std::{ffi::CStr, fmt, ptr};

/// Standard versions whose function-table layouts this binding understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceVersion {
    /// PKCS #11 2.40, including Errata 01.
    V2_40,
    /// PKCS #11 3.0.
    V3_0,
    /// PKCS #11 3.1 (uses the 3.0 function-table layout).
    V3_1,
    /// PKCS #11 3.2.
    V3_2,
}
impl InterfaceVersion {
    /// Major version number.
    pub fn major(self) -> u8 {
        match self {
            Self::V2_40 => 2,
            _ => 3,
        }
    }
    /// Minor version number, in decimal (40 means 2.40).
    pub fn minor(self) -> u8 {
        match self {
            Self::V2_40 => 40,
            Self::V3_0 => 0,
            Self::V3_1 => 1,
            Self::V3_2 => 2,
        }
    }
}
impl fmt::Display for InterfaceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major(), self.minor())
    }
}

/// Selection is independent of the provider's preferred/default interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InterfaceSelection {
    /// Try standard 3.2, 3.1 and 3.0, then the legacy 2.40 function list.
    #[default]
    Auto,
    /// Require this exact version; never silently choose another version.
    Exact(InterfaceVersion),
}

/// Metadata for the selected function table, not the provider's library version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Selected standard interface version.
    pub version: InterfaceVersion,
    /// Provider's table version field. Some providers report a known 3.x version
    /// through C_GetFunctionList; only its legacy prefix is used in that case.
    pub reported_version: crate::types::Version,
    /// Interface flags, or zero for the legacy function-list entry point.
    pub flags: CK_FLAGS,
    /// Whether selection used C_GetFunctionList instead of C_GetInterface.
    pub legacy: bool,
}

pub(super) unsafe fn select(
    library: &Pkcs11,
    selection: InterfaceSelection,
) -> Result<(FunctionList, InterfaceInfo)> {
    let versions: &[InterfaceVersion] = match selection {
        InterfaceSelection::Auto => &[
            InterfaceVersion::V3_2,
            InterfaceVersion::V3_1,
            InterfaceVersion::V3_0,
        ],
        InterfaceSelection::Exact(InterfaceVersion::V2_40) => &[],
        InterfaceSelection::Exact(ref version) => std::slice::from_ref(version),
    };
    if library.C_GetInterface.is_ok() {
        for &version in versions {
            let mut requested = CK_VERSION {
                major: version.major(),
                minor: version.minor(),
            };
            let mut interface: CK_INTERFACE_PTR = ptr::null_mut();
            let rv = library.C_GetInterface(
                b"PKCS 11\0".as_ptr() as CK_UTF8CHAR_PTR,
                &mut requested,
                &mut interface,
                0,
            );
            // C_GetInterface uses FUNCTION_FAILED for an unavailable interface.
            // Do not mask host-memory, device, or general failures by downgrading.
            if rv == CKR_FUNCTION_FAILED || rv == CKR_FUNCTION_NOT_SUPPORTED {
                continue;
            }
            Rv::from(rv).into_result(Function::GetInterface)?;
            if interface.is_null() {
                return Err(Error::InvalidInterface("NULL interface"));
            }
            let interface = &*interface;
            if interface.pInterfaceName.is_null() || interface.pFunctionList.is_null() {
                return Err(Error::InvalidInterface("NULL name or function list"));
            }
            if CStr::from_ptr(interface.pInterfaceName.cast()).to_bytes() != b"PKCS 11" {
                return Err(Error::InvalidInterface("unexpected interface name"));
            }
            // Read only CK_VERSION until the layout is established. In particular,
            // never interpret a future major version as a known larger structure.
            let actual = ptr::read_unaligned(interface.pFunctionList.cast::<CK_VERSION>());
            if actual.major != version.major() || actual.minor != version.minor() {
                return Err(Error::InvalidInterface("requested version does not match"));
            }
            let list = match version {
                InterfaceVersion::V3_2 => FunctionList::V3_2(ptr::read_unaligned(
                    interface.pFunctionList.cast::<CK_FUNCTION_LIST_3_2>(),
                )),
                InterfaceVersion::V3_0 | InterfaceVersion::V3_1 => FunctionList::V3_0(v30tov32(
                    ptr::read_unaligned(interface.pFunctionList.cast::<CK_FUNCTION_LIST_3_0>()),
                )),
                InterfaceVersion::V2_40 => unreachable!(),
            };
            return Ok((
                list,
                InterfaceInfo {
                    version,
                    reported_version: actual.into(),
                    flags: interface.flags,
                    legacy: false,
                },
            ));
        }
    }
    if matches!(selection, InterfaceSelection::Exact(v) if v != InterfaceVersion::V2_40) {
        return Err(Error::InterfaceUnavailable);
    }
    if library.C_GetFunctionList.is_err() {
        return Err(Error::InterfaceUnavailable);
    }
    let mut list: CK_FUNCTION_LIST_PTR = ptr::null_mut();
    Rv::from(library.C_GetFunctionList(&mut list)).into_result(Function::GetFunctionList)?;
    if list.is_null() {
        return Err(Error::InvalidInterface("NULL legacy function list"));
    }
    let version = ptr::read_unaligned(list.cast::<CK_VERSION>());
    if !matches!((version.major, version.minor), (2, 40) | (3, 0..=2)) {
        return Err(Error::InvalidInterface(
            "unknown legacy function-list version",
        ));
    }
    // The entry point's ABI determines the read size. Known 3.x version fields
    // are tolerated here, but never authorize reading a 3.x tail from this pointer.
    Ok((
        FunctionList::V2(v2tov3(ptr::read_unaligned(list))),
        InterfaceInfo {
            version: InterfaceVersion::V2_40,
            reported_version: version.into(),
            flags: 0,
            legacy: true,
        },
    ))
}
