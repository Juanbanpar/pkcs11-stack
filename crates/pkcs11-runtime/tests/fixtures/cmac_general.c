/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent 2.40 headers check the byte-length parameter and bounded outputs. */
#define MAC_MECHANISM CKM_AES_CMAC_GENERAL
#define MAC_KEY_TYPE CKK_AES
#define MAC_TAG_LENGTH 16
#define C_GetFunctionList full_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_ULONG tag_length;
static CK_RV general_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h;
    if (m->mechanism != CKM_AES_CMAC_GENERAL || !m->pParameter || m->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)) return CKR_MECHANISM_PARAM_INVALID;
    tag_length = *(CK_MAC_GENERAL_PARAMS *)m->pParameter;
    if (tag_length < 8 || tag_length > 16) return CKR_MECHANISM_PARAM_INVALID;
    if (FAULT == 3) return CKR_DEVICE_ERROR;
    active = 1; return CKR_OK;
}
static CK_RV general_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR d, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR length) {
    (void)s; (void)d; (void)n;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    if (!out || *length != tag_length) return CKR_ARGUMENTS_BAD;
    if (FAULT == 4) return CKR_DEVICE_ERROR;
    if (FAULT == 6) { *length = tag_length + 1; return CKR_BUFFER_TOO_SMALL; }
    memset(out, 0xAB, tag_length);
    *length = FAULT == 5 ? tag_length - 1 : FAULT == 7 ? tag_length + 1 : tag_length;
    active = 0; return CKR_OK;
}
static CK_RV general_verify_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    if (FAULT == 9) return CKR_SIGNATURE_INVALID;
    return general_init(s, m, h);
}
static CK_RV general_verify(CK_SESSION_HANDLE s, CK_BYTE_PTR d, CK_ULONG n, CK_BYTE_PTR tag, CK_ULONG length) {
    (void)s; (void)d; (void)n; active = 0;
    if (FAULT == 8) return CKR_DEVICE_ERROR;
    if (length != tag_length) return CKR_SIGNATURE_LEN_RANGE;
    for (CK_ULONG i = 0; i < length; ++i) if (tag[i] != 0xAB) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_SignInit = FAULT == 14 ? NULL : general_init;
    functions.C_Sign = FAULT == 2 ? NULL : general_sign;
    functions.C_VerifyInit = FAULT == 15 ? NULL : general_verify_init;
    functions.C_Verify = FAULT == 10 ? NULL : general_verify;
    *out = &functions; return CKR_OK;
}
