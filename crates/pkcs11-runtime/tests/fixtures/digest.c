/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Lifecycle/error fixture; hash bytes are deliberately synthetic. */
#include <stddef.h>
#include <string.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define NULL_PTR 0
#include "pkcs11.h"
#ifndef FAULT
#define FAULT 0
#endif
static int initialized, active;
static CK_RV initialize(CK_VOID_PTR args) {
    (void)args;
    if (initialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    initialized = 1; return CKR_OK;
}
static CK_RV finalize(CK_VOID_PTR reserved) {
    (void)reserved; initialized = 0; return CKR_OK;
}
static CK_RV info(CK_INFO_PTR out) {
    memset(out, 0, sizeof(*out));
    memset(out->manufacturerID, ' ', sizeof(out->manufacturerID));
    memset(out->libraryDescription, ' ', sizeof(out->libraryDescription));
    out->cryptokiVersion.major = 2; out->cryptokiVersion.minor = 40;
    return CKR_OK;
}
static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR list, CK_ULONG_PTR count) {
    (void)present; if (list) list[0] = 1; *count = 1; return CKR_OK;
}
static CK_RV slot_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR out) {
    (void)slot; memset(out, 0, sizeof(*out));
    memset(out->slotDescription, ' ', sizeof(out->slotDescription));
    memset(out->manufacturerID, ' ', sizeof(out->manufacturerID));
    out->flags = CKF_TOKEN_PRESENT; return CKR_OK;
}
static CK_RV token(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR out) {
    (void)slot; memset(out, 0, sizeof(*out));
    memset(out->label, ' ', sizeof(out->label)); memcpy(out->label, "digest", 6);
    memset(out->manufacturerID, ' ', sizeof(out->manufacturerID));
    memset(out->model, ' ', sizeof(out->model));
    memset(out->serialNumber, ' ', sizeof(out->serialNumber));
    memset(out->utcTime, ' ', sizeof(out->utcTime));
    out->flags = CKF_TOKEN_INITIALIZED; return CKR_OK;
}
static CK_RV mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot; if (list) list[0] = CKM_SHA256; *count = 1; return CKR_OK;
}
static CK_RV mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)slot; (void)mechanism; memset(out, 0, sizeof(*out));
    out->flags = FAULT == 1 ? 0 : CKF_DIGEST; return CKR_OK;
}
static CK_RV open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    (void)slot; (void)flags; (void)app; (void)notify; *out = 1; active = 0; return CKR_OK;
}
static CK_RV close_session(CK_SESSION_HANDLE session) {
    (void)session; active = 0; return CKR_OK;
}
static CK_RV session_info(CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR out) {
    (void)session; memset(out, 0, sizeof(*out)); out->slotID = 1;
    out->flags = CKF_SERIAL_SESSION; out->state = CKS_RO_PUBLIC_SESSION; return CKR_OK;
}
static CK_RV digest_init(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism) {
    (void)session;
    if (active) return CKR_OPERATION_ACTIVE;
    if (mechanism->mechanism != CKM_SHA256 || mechanism->ulParameterLen || mechanism->pParameter) return CKR_MECHANISM_PARAM_INVALID;
    if (FAULT == 3) return CKR_DEVICE_ERROR;
    active = 1; return CKR_OK;
}
static CK_RV digest_update(CK_SESSION_HANDLE session, CK_BYTE_PTR input, CK_ULONG length) {
    (void)session; (void)input; (void)length;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    return FAULT == 4 ? CKR_DEVICE_ERROR : CKR_OK;
}
static CK_RV digest_final(CK_SESSION_HANDLE session, CK_BYTE_PTR output, CK_ULONG_PTR length) {
    (void)session;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    /* These tests require bounded completion, never a provider-length query. */
    if (!output) return CKR_FUNCTION_FAILED;
    if (*length != 32) return CKR_ARGUMENTS_BAD;
    if (FAULT == 6) { *length = 33; return CKR_BUFFER_TOO_SMALL; }
    if (FAULT == 7) return CKR_DEVICE_ERROR;
    memset(output, 0xAB, 32); *length = FAULT == 5 ? 31 : FAULT == 8 ? 33 : 32;
    active = 0; return CKR_OK;
}
static CK_RV digest(CK_SESSION_HANDLE session, CK_BYTE_PTR input, CK_ULONG size, CK_BYTE_PTR output, CK_ULONG_PTR length) {
    (void)input; (void)size; return digest_final(session, output, length);
}
static CK_FUNCTION_LIST functions = {
    .version = {2,40}, .C_Initialize = initialize, .C_Finalize = finalize,
    .C_GetInfo = info, .C_GetSlotList = slots, .C_GetSlotInfo = slot_info, .C_GetTokenInfo = token,
    .C_GetMechanismList = mechanisms, .C_GetMechanismInfo = mechanism_info,
    .C_OpenSession = open_session, .C_CloseSession = close_session,
    .C_GetSessionInfo = session_info, .C_DigestInit = digest_init,
    .C_Digest = digest, .C_DigestUpdate = FAULT == 2 ? NULL : digest_update,
    .C_DigestFinal = digest_final,
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) { *out = &functions; return CKR_OK; }
