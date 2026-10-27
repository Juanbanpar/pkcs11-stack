/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Reuse lifecycle stubs; key attributes and derivation use independent headers. */
#define C_GetFunctionList lifecycle_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_OBJECT_HANDLE selected;
static CK_RV kbkdf_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot; if (list) list[0] = CKM_SP800_108_COUNTER_KDF; *count = 1; return CKR_OK;
}
static CK_RV kbkdf_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)slot; (void)mechanism; memset(out, 0, sizeof(*out));
    out->ulMinKeySize = FAULT == 6 ? 257 : 256; out->ulMaxKeySize = 256;
    out->flags = FAULT == 1 ? 0 : CKF_DERIVE; return CKR_OK;
}
static CK_RV kbkdf_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s; selected = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        if (attrs[i].type == CKA_ID && attrs[i].ulValueLen == 1) {
            CK_BYTE id = *(CK_BYTE *)attrs[i].pValue;
            if (id == 1) selected = id;
        }
    }
    return CKR_OK;
}
static CK_RV kbkdf_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR handles, CK_ULONG maximum, CK_ULONG_PTR count) {
    (void)s; (void)maximum; *count = selected ? 1 : 0;
    if (selected) handles[0] = selected;
    selected = 0; return CKR_OK;
}
static CK_RV kbkdf_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE handle, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ULONG value = 0, length = sizeof(value);
        switch (attrs[i].type) {
            case CKA_LABEL: attrs[i].ulValueLen = 0; continue;
            case CKA_ID: value = handle; length = 1; break;
            case CKA_CLASS: value = CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: value = FAULT == 7 ? CKK_HKDF : CKK_GENERIC_SECRET; break;
            case CKA_VALUE_LEN: value = FAULT == 8 ? 15 : 32; break;
            case CKA_ALLOWED_MECHANISMS: value = FAULT == 4 ? CKM_HKDF_DERIVE : CKM_SP800_108_COUNTER_KDF; break;
            case CKA_DERIVE: value = FAULT != 3; length = sizeof(CK_BBOOL); break;
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
static CK_RV kbkdf_derive(CK_SESSION_HANDLE s, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE base, CK_ATTRIBUTE_PTR attrs, CK_ULONG count, CK_OBJECT_HANDLE_PTR result) {
    (void)s;
    if (mechanism->mechanism != CKM_SP800_108_COUNTER_KDF || base != 1 || !mechanism->pParameter || mechanism->ulParameterLen != sizeof(CK_SP800_108_KDF_PARAMS)) return CKR_ARGUMENTS_BAD;
    CK_SP800_108_KDF_PARAMS *p = (CK_SP800_108_KDF_PARAMS *)mechanism->pParameter;
    if (p->prfType != CKM_SHA256_HMAC || p->ulAdditionalDerivedKeys != 0 || p->pAdditionalDerivedKeys != NULL || !p->pDataParams) return CKR_MECHANISM_PARAM_INVALID;
    CK_PRF_DATA_PARAM *fields = p->pDataParams;
    if (fields[0].type != CK_SP800_108_ITERATION_VARIABLE || fields[0].ulValueLen != sizeof(CK_SP800_108_COUNTER_FORMAT) || !fields[0].pValue) return CKR_MECHANISM_PARAM_INVALID;
    CK_SP800_108_COUNTER_FORMAT *counter = (CK_SP800_108_COUNTER_FORMAT *)fields[0].pValue;
    if (counter->bLittleEndian != CK_FALSE || counter->ulWidthInBits != 32) return CKR_MECHANISM_PARAM_INVALID;
    CK_ULONG separator;
    if (p->ulNumberOfDataParams == 5) {
        if (fields[1].type != CK_SP800_108_BYTE_ARRAY || fields[1].ulValueLen != 5 || !fields[1].pValue || memcmp(fields[1].pValue, "label", 5)) return CKR_MECHANISM_PARAM_INVALID;
        if (fields[3].type != CK_SP800_108_BYTE_ARRAY || fields[3].ulValueLen != 3 || !fields[3].pValue || memcmp(fields[3].pValue, "ctx", 3)) return CKR_MECHANISM_PARAM_INVALID;
        separator = 2;
    } else if (p->ulNumberOfDataParams == 3) { separator = 1; }
    else { return CKR_MECHANISM_PARAM_INVALID; }
    if (fields[separator].type != CK_SP800_108_BYTE_ARRAY || fields[separator].ulValueLen != 1 || !fields[separator].pValue || *(CK_BYTE *)fields[separator].pValue != 0) return CKR_MECHANISM_PARAM_INVALID;
    CK_PRF_DATA_PARAM *last = &fields[p->ulNumberOfDataParams - 1];
    if (last->type != CK_SP800_108_DKM_LENGTH || last->ulValueLen != sizeof(CK_SP800_108_DKM_LENGTH_FORMAT) || !last->pValue) return CKR_MECHANISM_PARAM_INVALID;
    CK_SP800_108_DKM_LENGTH_FORMAT *length_format = (CK_SP800_108_DKM_LENGTH_FORMAT *)last->pValue;
    if (length_format->dkmLengthMethod != CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS || length_format->bLittleEndian != CK_FALSE || length_format->ulWidthInBits != 32) return CKR_MECHANISM_PARAM_INVALID;
    int sensitive = 0, nonextractable = 0, length = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        if (attrs[i].type == CKA_SENSITIVE) sensitive = *(CK_BBOOL *)attrs[i].pValue;
        if (attrs[i].type == CKA_EXTRACTABLE) nonextractable = !*(CK_BBOOL *)attrs[i].pValue;
        if (attrs[i].type == CKA_VALUE_LEN) length = *(CK_ULONG *)attrs[i].pValue == 32;
    }
    if (!sensitive || !nonextractable || !length) return CKR_TEMPLATE_INCONSISTENT;
    if (FAULT == 5) return CKR_DEVICE_ERROR;
    *result = 3; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetMechanismList = kbkdf_mechanisms;
    functions.C_GetMechanismInfo = kbkdf_info;
    functions.C_FindObjectsInit = kbkdf_find_init;
    functions.C_FindObjects = kbkdf_find;
    functions.C_GetAttributeValue = kbkdf_attributes;
    functions.C_DeriveKey = FAULT == 2 ? NULL : kbkdf_derive;
    *out = &functions; return CKR_OK;
}
