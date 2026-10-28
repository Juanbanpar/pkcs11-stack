/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent ABI and lifecycle checks. Synthetic MACs, not a crypto oracle. */
#ifndef API_MAJOR
#define API_MAJOR 2
#define API_MINOR 40
#endif
#if HMAC
#if GENERAL
#define MAC_MECHANISM CKM_SHA256_HMAC_GENERAL
#define MAC_TAG_LENGTH 16
#else
#define MAC_MECHANISM CKM_SHA256_HMAC
#define MAC_TAG_LENGTH 32
#endif
#define MAC_KEY_TYPE CKK_GENERIC_SECRET
#else
#if GENERAL
#define MAC_MECHANISM CKM_AES_CMAC_GENERAL
#define MAC_TAG_LENGTH 8
#else
#define MAC_MECHANISM CKM_AES_CMAC
#define MAC_TAG_LENGTH 16
#endif
#define MAC_KEY_TYPE CKK_AES
#endif
#define C_GetFunctionList unused_get_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_ULONG inits, updates, finals, cancels;
static CK_FLAGS direction;
static CK_RV stream_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s, out);
    out->ulDeviceError = inits * 1000000UL + updates * 10000UL + finals * 100UL + cancels;
    return rv;
}
static CK_RV stream_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR a, CK_ULONG n) {
    CK_RV rv = attributes(s,h,a,n);
    if (rv != CKR_OK) return rv;
    for (CK_ULONG i = 0; i < n; ++i) {
        if (a[i].type == CKA_VALUE_LEN && a[i].pValue) {
            *(CK_ULONG *)a[i].pValue = HMAC ? 32 : 16;
        }
    }
    return CKR_OK;
}
static CK_RV stream_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits;
    if (active) return CKR_OPERATION_ACTIVE;
    if (m->mechanism != MAC_MECHANISM) return CKR_MECHANISM_INVALID;
#if GENERAL
    if (!m->pParameter || m->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
        *(CK_MAC_GENERAL_PARAMS *)m->pParameter != MAC_TAG_LENGTH) return CKR_MECHANISM_PARAM_INVALID;
#else
    if (m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
#endif
    if (FAULT == 20) return CKR_DEVICE_ERROR;
    active = 1; return CKR_OK;
}
static CK_RV stream_sign_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    direction = 0x800; return stream_init(s,m,h);
}
static CK_RV stream_verify_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    direction = 0x2000; return stream_init(s,m,h);
}
static CK_RV stream_update(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n) {
    (void)s; (void)bytes; (void)n; ++updates;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    if (FAULT == 21) return CKR_DEVICE_ERROR;
    if (FAULT == 22) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
static CK_RV stream_sign_final(CK_SESSION_HANDLE s, CK_BYTE_PTR out, CK_ULONG_PTR n) {
    (void)s; ++finals;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    if (!out || *n != MAC_TAG_LENGTH) return CKR_ARGUMENTS_BAD;
    if (FAULT == 23) return CKR_DEVICE_ERROR;
    if (FAULT == 26) { *n = MAC_TAG_LENGTH + 1; return CKR_BUFFER_TOO_SMALL; }
    active = 0; memset(out,0xAB,MAC_TAG_LENGTH);
    *n = FAULT == 24 ? MAC_TAG_LENGTH - 1 : FAULT == 25 ? MAC_TAG_LENGTH + 1 : MAC_TAG_LENGTH;
    return CKR_OK;
}
static CK_RV stream_verify_final(CK_SESSION_HANDLE s, CK_BYTE_PTR tag, CK_ULONG n) {
    (void)s; ++finals;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    active = 0;
    if (FAULT == 23) return CKR_DEVICE_ERROR;
    if (FAULT == 36) return CKR_OK;
    if (FAULT == 27) return CKR_SIGNATURE_INVALID;
    if (FAULT == 28 || n != MAC_TAG_LENGTH) return CKR_SIGNATURE_LEN_RANGE;
    for (CK_ULONG i = 0; i < n; ++i) if (tag[i] != 0xAB) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
#if API_MAJOR >= 3
static CK_RV stream_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    (void)s; ++cancels;
    if (flags != direction) return CKR_ARGUMENTS_BAD;
    if (FAULT == 33) return CKR_OPERATION_CANCEL_FAILED;
    active = 0; return CKR_OK;
}
#if API_MINOR >= 2
static CK_FUNCTION_LIST_3_2 current;
#else
static CK_FUNCTION_LIST_3_0 current;
#endif
static CK_INTERFACE standard = {.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11", .pFunctionList = &current};
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if (!name || strcmp((char *)name,"PKCS 11") || !version || version->major != 3 || version->minor != API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    /* The common 2.40 prefix is copied only within this C translation unit. */
    CK_FUNCTION_LIST_PTR prefix;
    C_GetFunctionList(&prefix);
    *out = &standard; return CKR_OK;
}
#endif
static CK_RV legacy_called(CK_SESSION_HANDLE s) { (void)s; cancels += 99; return CKR_GENERAL_ERROR; }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetSessionInfo = stream_info;
    functions.C_GetAttributeValue = stream_attributes;
    functions.C_Sign = NULL; functions.C_Verify = NULL;
    functions.C_SignInit = FAULT == 14 ? NULL : stream_sign_init;
    functions.C_VerifyInit = FAULT == 15 ? NULL : stream_verify_init;
    functions.C_SignUpdate = FAULT == 29 ? NULL : stream_update;
    functions.C_SignFinal = FAULT == 30 ? NULL : stream_sign_final;
    functions.C_VerifyUpdate = FAULT == 31 ? NULL : stream_update;
    functions.C_VerifyFinal = FAULT == 32 ? NULL : stream_verify_final;
    functions.C_CancelFunction = legacy_called; functions.C_GetFunctionStatus = legacy_called;
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions)); current.version.major = 3; current.version.minor = API_MINOR;
    current.C_SessionCancel = FAULT == 34 ? NULL : stream_cancel;
#endif
    *out = &functions; return CKR_OK;
}
