/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Lifecycle/error fixture; MAC bytes are deliberately synthetic. */
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
    memset(out->label, ' ', sizeof(out->label)); memcpy(out->label, "cmac", 4);
    memset(out->manufacturerID, ' ', sizeof(out->manufacturerID));
    memset(out->model, ' ', sizeof(out->model));
    memset(out->serialNumber, ' ', sizeof(out->serialNumber));
    memset(out->utcTime, ' ', sizeof(out->utcTime));
    out->flags = CKF_TOKEN_INITIALIZED; return CKR_OK;
}
static CK_RV mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot; if (list) list[0] = CKM_AES_CMAC; *count = 1; return CKR_OK;
}
static CK_RV mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)slot; (void)mechanism; memset(out, 0, sizeof(*out));
    out->ulMinKeySize = 16; out->ulMaxKeySize = 32;
    out->flags = (FAULT == 1 ? 0 : CKF_SIGN) | (FAULT == 11 ? 0 : CKF_VERIFY); return CKR_OK;
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

static CK_RV find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR a, CK_ULONG n) { (void)s; (void)a; (void)n; active = 0; return CKR_OK; }
static CK_RV find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR h, CK_ULONG n, CK_ULONG_PTR count) {
    (void)s; (void)n; *count = active ? 0 : 1; if (!active) h[0] = 1; active = 1; return CKR_OK;
}
static CK_RV find_final(CK_SESSION_HANDLE s) { (void)s; active = 0; return CKR_OK; }
static CK_RV attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR a, CK_ULONG count) {
    (void)s; (void)h;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ULONG value = 0; CK_ULONG length = sizeof(value);
        switch (a[i].type) {
            case CKA_LABEL: a[i].ulValueLen = 0; continue;
            case CKA_ID: length = 1; value = 1; break;
            case CKA_CLASS: value = CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: value = CKK_AES; break;
            case CKA_VALUE_LEN: value = 16; break;
            case CKA_ALLOWED_MECHANISMS: value = CKM_AES_CMAC; break;
            case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE: case CKA_SIGN: case CKA_VERIFY:
                length = sizeof(CK_BBOOL);
                value = !((FAULT == 12 && a[i].type == CKA_SIGN) || (FAULT == 13 && a[i].type == CKA_VERIFY)); break;
            case CKA_EXTRACTABLE: length = sizeof(CK_BBOOL); break;
            default: return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        if (a[i].pValue) {
            if (a[i].ulValueLen < length) return CKR_BUFFER_TOO_SMALL;
            if (length == sizeof(CK_BBOOL)) *(CK_BBOOL *)a[i].pValue = (CK_BBOOL)value;
            else memcpy(a[i].pValue, &value, length);
        }
        a[i].ulValueLen = length;
    }
    return CKR_OK;
}
static CK_RV sign_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h;
    if (m->mechanism != CKM_AES_CMAC || m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    if (FAULT == 3) return CKR_DEVICE_ERROR;
    active = 1; return CKR_OK;
}
static CK_RV sign(CK_SESSION_HANDLE s, CK_BYTE_PTR d, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR length) {
    (void)s; (void)d; (void)n;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    if (!out || *length != 16) return CKR_ARGUMENTS_BAD;
    if (FAULT == 4) return CKR_DEVICE_ERROR;
    if (FAULT == 6) { *length = 17; return CKR_BUFFER_TOO_SMALL; }
    memset(out, 0xAB, 16); *length = FAULT == 5 ? 15 : FAULT == 7 ? 17 : 16;
    active = 0; return CKR_OK;
}
static CK_RV verify_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    if (FAULT == 9) return CKR_SIGNATURE_INVALID;
    return sign_init(s, m, h);
}
static CK_RV verify(CK_SESSION_HANDLE s, CK_BYTE_PTR d, CK_ULONG n, CK_BYTE_PTR tag, CK_ULONG length) {
    (void)s; (void)d; (void)n; active = 0;
    if (FAULT == 8) return CKR_DEVICE_ERROR;
    for (CK_ULONG i = 0; i < length; ++i) if (tag[i] != 0xAB) return CKR_SIGNATURE_INVALID;
    return length == 16 ? CKR_OK : CKR_SIGNATURE_LEN_RANGE;
}
static CK_FUNCTION_LIST functions = {
    .version = {2,40}, .C_Initialize = initialize, .C_Finalize = finalize,
    .C_GetInfo = info, .C_GetSlotList = slots, .C_GetSlotInfo = slot_info, .C_GetTokenInfo = token,
    .C_GetMechanismList = mechanisms, .C_GetMechanismInfo = mechanism_info,
    .C_OpenSession = open_session, .C_CloseSession = close_session, .C_GetSessionInfo = session_info,
    .C_FindObjectsInit = find_init, .C_FindObjects = find, .C_FindObjectsFinal = find_final,
    .C_GetAttributeValue = attributes, .C_SignInit = FAULT == 14 ? NULL : sign_init, .C_Sign = FAULT == 2 ? NULL : sign,
    .C_VerifyInit = FAULT == 15 ? NULL : verify_init, .C_Verify = FAULT == 10 ? NULL : verify,
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) { *out = &functions; return CKR_OK; }
