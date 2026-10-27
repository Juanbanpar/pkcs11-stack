/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Reuse lifecycle stubs; key attributes and derivation use independent headers. */
#define C_GetFunctionList lifecycle_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_OBJECT_HANDLE selected;
static CK_RV hkdf_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot; if (list) list[0] = CKM_HKDF_DERIVE; *count = 1; return CKR_OK;
}
static CK_RV hkdf_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)slot; (void)mechanism; memset(out, 0, sizeof(*out));
    out->flags = FAULT == 5 ? 0 : CKF_DERIVE; return CKR_OK;
}
static CK_RV hkdf_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s; selected = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        if (attrs[i].type == CKA_ID && attrs[i].ulValueLen == 1) {
            CK_BYTE id = *(CK_BYTE *)attrs[i].pValue;
            if (id == 1 || id == 2) selected = id;
        }
    }
    return CKR_OK;
}
static CK_RV hkdf_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR handles, CK_ULONG maximum, CK_ULONG_PTR count) {
    (void)s; (void)maximum; *count = selected ? 1 : 0;
    if (selected) handles[0] = selected;
    selected = 0; return CKR_OK;
}
static CK_RV hkdf_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ULONG value = 0, length = sizeof(value);
        switch (attrs[i].type) {
            case CKA_LABEL: attrs[i].ulValueLen = 0; continue;
            case CKA_ID: value = handle; length = 1; break;
            case CKA_CLASS: value = CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: value = handle == 2 && FAULT == 7 ? CKK_AES : CKK_GENERIC_SECRET; break;
            case CKA_VALUE_LEN: value = handle == 1 ? 32 : FAULT == 6 ? 4097 : FAULT == 8 ? 0 : 131; break;
            case CKA_ALLOWED_MECHANISMS: value = handle == 2 && FAULT == 3 ? CKM_AES_GCM : CKM_HKDF_DERIVE; break;
            case CKA_DERIVE: value = !(handle == 2 && FAULT == 2); length = sizeof(CK_BBOOL); break;
            case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE: value = 1; length = sizeof(CK_BBOOL); break;
            case CKA_EXTRACTABLE: length = sizeof(CK_BBOOL); break;
            /* Reading CKA_VALUE is deliberately unsupported. */
            default: return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        if (attrs[i].pValue) {
            if (attrs[i].ulValueLen < length) return CKR_BUFFER_TOO_SMALL;
            if (length == sizeof(CK_BBOOL)) *(CK_BBOOL *)attrs[i].pValue = (CK_BBOOL)value;
            else memcpy(attrs[i].pValue, &value, length);
        }
        attrs[i].ulValueLen = length;
    }
    return CKR_OK;
}
static CK_RV hkdf_derive(CK_SESSION_HANDLE s, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE base, CK_ATTRIBUTE_PTR attrs, CK_ULONG count, CK_OBJECT_HANDLE_PTR result) {
    (void)s;
    if (mechanism->mechanism != CKM_HKDF_DERIVE || base != 1 || !mechanism->pParameter || mechanism->ulParameterLen != sizeof(CK_HKDF_PARAMS)) return CKR_ARGUMENTS_BAD;
    CK_HKDF_PARAMS *p = (CK_HKDF_PARAMS *)mechanism->pParameter;
    if (p->bExtract != CK_TRUE || p->prfHashMechanism != CKM_SHA256 || p->ulSaltType != CKF_HKDF_SALT_KEY || p->hSaltKey != 2 || p->pSalt != NULL || p->ulSaltLen != 0) return CKR_MECHANISM_PARAM_INVALID;
    if (p->bExpand) {
        if (p->ulInfoLen != 3 || !p->pInfo || memcmp(p->pInfo, "ctx", 3)) return CKR_MECHANISM_PARAM_INVALID;
    } else if (p->ulInfoLen != 0 || p->pInfo != NULL) return CKR_MECHANISM_PARAM_INVALID;
    int sensitive = 0, nonextractable = 0, length = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        if (attrs[i].type == CKA_SENSITIVE) sensitive = *(CK_BBOOL *)attrs[i].pValue;
        if (attrs[i].type == CKA_EXTRACTABLE) nonextractable = !*(CK_BBOOL *)attrs[i].pValue;
        if (attrs[i].type == CKA_VALUE_LEN) length = *(CK_ULONG *)attrs[i].pValue == 32;
    }
    if (!sensitive || !nonextractable || !length) return CKR_TEMPLATE_INCONSISTENT;
    if (FAULT == 1) return CKR_DEVICE_ERROR;
    *result = 3; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetMechanismList = hkdf_mechanisms;
    functions.C_GetMechanismInfo = hkdf_info;
    functions.C_FindObjectsInit = hkdf_find_init;
    functions.C_FindObjects = hkdf_find;
    functions.C_GetAttributeValue = hkdf_attributes;
    functions.C_DeriveKey = FAULT == 4 ? NULL : hkdf_derive;
    *out = &functions; return CKR_OK;
}
