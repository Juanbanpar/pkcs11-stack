/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent ABI/state fixture; digest bytes are synthetic. */
enum { cancel_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "digest.c"
#undef C_GetFunctionList

#ifndef API_MINOR
#define API_MINOR 2
#endif
static CK_FLAGS operations[32], last_cancel;
static CK_ULONG cancellations, legacy_cancellations, opened;
static CK_RV cancel_open(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    (void)slot; (void)flags; (void)app; (void)notify;
    if (cancel_fault == 13 && opened >= 2) return CKR_SESSION_COUNT;
    if (opened >= 31) return CKR_SESSION_COUNT;
    *out = ++opened; operations[*out] = 0; return CKR_OK;
}
static CK_RV cancel_close(CK_SESSION_HANDLE s) {
    operations[s] = 0; return CKR_OK;
}
static CK_RV cancel_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    /* State/count diagnostics let tests observe calls from a separate session. */
    out->ulDeviceError = cancellations * 0x10000UL + last_cancel;
    if (legacy_cancellations) return CKR_GENERAL_ERROR;
    return rv;
}
static CK_RV cancel_digest_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m) {
    if (operations[s] & CKF_DIGEST) return CKR_OPERATION_ACTIVE;
    if (m->mechanism != CKM_SHA256 || m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    operations[s] |= CKF_DIGEST; return CKR_OK;
}
static CK_RV cancel_digest_update(CK_SESSION_HANDLE s, CK_BYTE_PTR in, CK_ULONG n) {
    (void)in; (void)n;
    if (!(operations[s] & CKF_DIGEST)) return CKR_OPERATION_NOT_INITIALIZED;
    return cancel_fault == 9 ? CKR_DEVICE_ERROR : CKR_OK;
}
static CK_RV cancel_digest_final(CK_SESSION_HANDLE s, CK_BYTE_PTR out, CK_ULONG_PTR n) {
    if (!(operations[s] & CKF_DIGEST)) return CKR_OPERATION_NOT_INITIALIZED;
    if (cancel_fault == 10) return CKR_DEVICE_ERROR;
    if (!out || *n != 32) return CKR_ARGUMENTS_BAD;
    memset(out,0xAB,32); *n = 32; operations[s] &= ~CKF_DIGEST; return CKR_OK;
}
static CK_RV cancel_digest(CK_SESSION_HANDLE s, CK_BYTE_PTR in, CK_ULONG size, CK_BYTE_PTR out, CK_ULONG_PTR n) {
    (void)in; (void)size; return cancel_digest_final(s,out,n);
}
static CK_RV legacy_cancel(CK_SESSION_HANDLE s) {
    (void)s; ++legacy_cancellations; return CKR_GENERAL_ERROR;
}
static CK_RV legacy_status(CK_SESSION_HANDLE s) {
    return legacy_cancel(s);
}
#if API_MAJOR >= 3
static CK_RV session_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    ++cancellations; last_cancel = flags;
    if (flags & ~(CKF_FIND_OBJECTS|CKF_ENCRYPT|CKF_DECRYPT|CKF_DIGEST|CKF_SIGN|CKF_VERIFY)) return CKR_ARGUMENTS_BAD;
    if (cancel_fault == 2) return CKR_FUNCTION_NOT_SUPPORTED;
    if (cancel_fault == 3) return CKR_OPERATION_CANCEL_FAILED;
    if (cancel_fault == 4) return CKR_DEVICE_ERROR;
    if (cancel_fault == 5) return CKR_FUNCTION_FAILED;
    if (cancel_fault == 6) return CKR_OPERATION_ACTIVE;
    if (cancel_fault == 7) return (CK_RV)0x204; /* CKR_PENDING, introduced in 3.2. */
    if (cancel_fault == 8) return CKR_GENERAL_ERROR;
    if (cancel_fault == 11) {
        operations[s] &= ~CKF_DIGEST;
        return CKR_OPERATION_CANCEL_FAILED;
    }
    operations[s] &= ~flags; return CKR_OK;
}
#if API_MINOR >= 2
static CK_FUNCTION_LIST_3_2 current = {
#else
static CK_FUNCTION_LIST_3_0 current = {
#endif
    .version = {3,API_MINOR}, .C_Initialize = initialize, .C_Finalize = finalize,
    .C_GetInfo = info, .C_GetSlotList = slots, .C_GetSlotInfo = slot_info, .C_GetTokenInfo = token,
    .C_GetMechanismList = mechanisms, .C_GetMechanismInfo = mechanism_info,
    .C_OpenSession = cancel_open, .C_CloseSession = cancel_close, .C_GetSessionInfo = cancel_info,
    .C_DigestInit = cancel_digest_init, .C_Digest = cancel_digest,
    .C_DigestUpdate = cancel_digest_update, .C_DigestFinal = cancel_digest_final,
    .C_SessionCancel = session_cancel, .C_CancelFunction = legacy_cancel, .C_GetFunctionStatus = legacy_status,
};
static CK_INTERFACE standard = {.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11", .pFunctionList = &current};
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if (!name || strcmp((char *)name,"PKCS 11") || !version || version->major != 3 || version->minor != API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    if (cancel_fault == 1) current.C_SessionCancel = NULL;
    *out = &standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_OpenSession = cancel_open; functions.C_CloseSession = cancel_close;
    functions.C_GetSessionInfo = cancel_info; functions.C_DigestInit = cancel_digest_init;
    functions.C_Digest = cancel_digest; functions.C_DigestUpdate = cancel_digest_update;
    functions.C_DigestFinal = cancel_digest_final; functions.C_CancelFunction = legacy_cancel;
    functions.C_GetFunctionStatus = legacy_status;
    if (cancel_fault == 12) { functions.version.major = 3; functions.version.minor = 2; }
    *out = &functions; return CKR_OK;
}
