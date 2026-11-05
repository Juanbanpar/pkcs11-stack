/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Validate PARAMS2 against official headers, without a derive or HMAC API. */
#define C_GetFunctionList lifecycle_function_list
#include "cmac.c"
#undef C_GetFunctionList
#ifndef EXPECTED_PRF
#define EXPECTED_PRF CKP_PKCS5_PBKD2_HMAC_SHA256
#endif
static CK_RV pbkdf2_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot; if (list) list[0] = FAULT == 3 ? CKM_AES_KEY_GEN : CKM_PKCS5_PBKD2;
    *count = 1; return CKR_OK;
}
static CK_RV pbkdf2_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)slot; (void)m; if (FAULT == 8) return CKR_DEVICE_ERROR;
    memset(out, 0, sizeof(*out)); out->ulMaxKeySize = 0xFFFFFFFF;
    out->flags = FAULT == 1 ? 0 : CKF_GENERATE; return CKR_OK;
}
static CK_RV pbkdf2_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR h, CK_ULONG n, CK_ULONG_PTR count) {
    (void)s; (void)n; *count = FAULT == 4 && !active ? 1 : 0;
    if (*count) h[0] = 1;
    active = 1; return CKR_OK;
}
static CK_RV pbkdf2_generate(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR a, CK_ULONG n, CK_OBJECT_HANDLE_PTR result) {
    (void)s;
    if (m->mechanism != CKM_PKCS5_PBKD2 || !m->pParameter || m->ulParameterLen != sizeof(CK_PKCS5_PBKD2_PARAMS2)) return CKR_ARGUMENTS_BAD;
    CK_PKCS5_PBKD2_PARAMS2 *p = m->pParameter;
    static const CK_BYTE password[] = {'p', 0, 0xFF, '\n'};
    if (p->saltSource != CKZ_SALT_SPECIFIED || !p->pSaltSourceData || p->ulSaltSourceDataLen != 4 || memcmp(p->pSaltSourceData, "salt", 4)) return CKR_MECHANISM_PARAM_INVALID;
    if (p->iterations != 2 || p->prf != EXPECTED_PRF || p->pPrfData != NULL || p->ulPrfDataLen != 0 || p->ulPasswordLen != sizeof(password) || !p->pPassword || memcmp(p->pPassword, password, sizeof(password))) return CKR_MECHANISM_PARAM_INVALID;
    int fields = 0; CK_ULONG kind = CKK_VENDOR_DEFINED;
    for (CK_ULONG i = 0; i < n; ++i) if (a[i].type == CKA_KEY_TYPE && a[i].ulValueLen == sizeof(kind)) memcpy(&kind, a[i].pValue, sizeof(kind));
    if (kind != CKK_AES && kind != CKK_GENERIC_SECRET) return CKR_TEMPLATE_INCONSISTENT;
    for (CK_ULONG i = 0; i < n; ++i) {
        CK_ULONG expected = 0; int boolean = 0;
        switch (a[i].type) {
            case CKA_CLASS: expected = CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: expected = kind; break;
            case CKA_VALUE_LEN: expected = 32; break;
            case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE: expected = CK_TRUE; boolean = 1; break;
            case CKA_EXTRACTABLE: case CKA_SIGN: case CKA_VERIFY: case CKA_WRAP: case CKA_UNWRAP: boolean = 1; break;
            case CKA_ENCRYPT: case CKA_DECRYPT: expected = kind == CKK_AES; boolean = 1; break;
            case CKA_DERIVE: expected = kind == CKK_GENERIC_SECRET; boolean = 1; break;
            case CKA_ID: if (a[i].ulValueLen != 1 || *(CK_BYTE *)a[i].pValue != 3) return CKR_TEMPLATE_INCONSISTENT; ++fields; continue;
            case CKA_LABEL: if (a[i].ulValueLen != 6 || memcmp(a[i].pValue, "output", 6)) return CKR_TEMPLATE_INCONSISTENT; ++fields; continue;
            default: return CKR_TEMPLATE_INCONSISTENT;
        }
        if (!a[i].pValue || a[i].ulValueLen != (boolean ? sizeof(CK_BBOOL) : sizeof(CK_ULONG))) return CKR_TEMPLATE_INCONSISTENT;
        CK_ULONG value = 0;
        if (boolean) value = *(CK_BBOOL *)a[i].pValue; else memcpy(&value, a[i].pValue, sizeof(value));
        if (value != expected) return CKR_TEMPLATE_INCONSISTENT;
        ++fields;
    }
    if (fields != 16) return CKR_TEMPLATE_INCONSISTENT;
    if (FAULT == 5) return CKR_DEVICE_ERROR;
    *result = 3; return CKR_OK;
}
static CK_RV pbkdf2_login(CK_SESSION_HANDLE s, CK_USER_TYPE role, CK_UTF8CHAR_PTR pin, CK_ULONG n) {
    (void)s; (void)role; (void)pin; (void)n; return CKR_OK;
}
static CK_RV pbkdf2_logout(CK_SESSION_HANDLE s) { (void)s; return CKR_OK; }
static CK_RV pbkdf2_close(CK_SESSION_HANDLE s) { return FAULT == 6 ? CKR_DEVICE_ERROR : close_session(s); }
static CK_RV pbkdf2_finalize(CK_VOID_PTR p) { return FAULT == 7 ? CKR_DEVICE_ERROR : finalize(p); }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetMechanismList = pbkdf2_mechanisms; functions.C_GetMechanismInfo = pbkdf2_info;
    functions.C_FindObjects = pbkdf2_find;
    functions.C_GenerateKey = FAULT == 2 ? NULL : pbkdf2_generate;
    functions.C_Login = pbkdf2_login; functions.C_Logout = pbkdf2_logout;
    functions.C_SignInit = NULL; functions.C_Sign = NULL; functions.C_VerifyInit = NULL; functions.C_Verify = NULL;
    functions.C_DeriveKey = NULL; functions.C_GetAttributeValue = NULL;
    functions.C_CloseSession = pbkdf2_close; functions.C_Finalize = pbkdf2_finalize;
    *out = &functions; return CKR_OK;
}
