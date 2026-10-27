/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Reuse lifecycle stubs; key attributes and derivation use independent headers. */
#define C_GetFunctionList lifecycle_function_list
#include "cmac.c"
#undef C_GetFunctionList
#define KDF_FAULT (FAULT % 20)
#define FEEDBACK (FAULT >= 20)
#define KDF_MECHANISM (FEEDBACK ? CKM_SP800_108_FEEDBACK_KDF : CKM_SP800_108_COUNTER_KDF)
static CK_OBJECT_HANDLE selected;
static CK_RV kbkdf_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot; if (list) list[0] = KDF_MECHANISM; *count = 1; return CKR_OK;
}
static CK_RV kbkdf_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)slot; (void)mechanism;
    if (KDF_FAULT == 9) return CKR_DEVICE_ERROR;
    memset(out, 0, sizeof(*out));
    out->ulMinKeySize = KDF_FAULT == 6 ? 257 : 256; out->ulMaxKeySize = 256;
    out->flags = KDF_FAULT == 1 ? 0 : CKF_DERIVE; return CKR_OK;
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
            case CKA_KEY_TYPE: value = KDF_FAULT == 7 ? CKK_HKDF : CKK_GENERIC_SECRET; break;
            case CKA_VALUE_LEN: value = KDF_FAULT == 8 ? 15 : 32; break;
            case CKA_ALLOWED_MECHANISMS: value = KDF_FAULT == 4 ? CKM_HKDF_DERIVE : KDF_MECHANISM; break;
            case CKA_DERIVE: value = KDF_FAULT != 3; length = sizeof(CK_BBOOL); break;
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
    if (mechanism->mechanism != KDF_MECHANISM || base != 1 || !mechanism->pParameter) return CKR_ARGUMENTS_BAD;
    CK_PRF_DATA_PARAM *fields;
    CK_ULONG n;
    if (FEEDBACK) {
        if (mechanism->ulParameterLen != sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS)) return CKR_ARGUMENTS_BAD;
        CK_SP800_108_FEEDBACK_KDF_PARAMS *p = mechanism->pParameter;
        if (p->prfType != CKM_SHA256_HMAC || p->ulAdditionalDerivedKeys != 0 || p->pAdditionalDerivedKeys != NULL || !p->pDataParams) return CKR_MECHANISM_PARAM_INVALID;
        if (p->ulIVLen == 0) { if (p->pIV != NULL) return CKR_MECHANISM_PARAM_INVALID; }
        else {
            if (p->ulIVLen != 32 || !p->pIV) return CKR_MECHANISM_PARAM_INVALID;
            for (CK_ULONG i = 0; i < 32; ++i) if (p->pIV[i] != 0xA5) return CKR_MECHANISM_PARAM_INVALID;
        }
        fields = p->pDataParams;
        n = p->ulNumberOfDataParams;
        if (n < 2 || fields[0].type != CK_SP800_108_ITERATION_VARIABLE || fields[0].pValue != NULL || fields[0].ulValueLen != 0) return CKR_MECHANISM_PARAM_INVALID;
        ++fields; --n;
        if (fields[0].type != CK_SP800_108_COUNTER) return CKR_MECHANISM_PARAM_INVALID;
    } else {
        if (mechanism->ulParameterLen != sizeof(CK_SP800_108_KDF_PARAMS)) return CKR_ARGUMENTS_BAD;
        CK_SP800_108_KDF_PARAMS *p = mechanism->pParameter;
        if (p->prfType != CKM_SHA256_HMAC || p->ulAdditionalDerivedKeys != 0 || p->pAdditionalDerivedKeys != NULL || !p->pDataParams) return CKR_MECHANISM_PARAM_INVALID;
        fields = p->pDataParams;
        n = p->ulNumberOfDataParams;
        if (fields[0].type != CK_SP800_108_ITERATION_VARIABLE) return CKR_MECHANISM_PARAM_INVALID;
    }
    if (fields[0].ulValueLen != sizeof(CK_SP800_108_COUNTER_FORMAT) || !fields[0].pValue) return CKR_MECHANISM_PARAM_INVALID;
    CK_SP800_108_COUNTER_FORMAT *counter = fields[0].pValue;
    if (counter->bLittleEndian != CK_FALSE || counter->ulWidthInBits != 32) return CKR_MECHANISM_PARAM_INVALID;
    CK_ULONG separator;
    if (n == 5) {
        if (fields[1].type != CK_SP800_108_BYTE_ARRAY || fields[1].ulValueLen != 5 || !fields[1].pValue || memcmp(fields[1].pValue, "label", 5)) return CKR_MECHANISM_PARAM_INVALID;
        if (fields[3].type != CK_SP800_108_BYTE_ARRAY || fields[3].ulValueLen != 3 || !fields[3].pValue || memcmp(fields[3].pValue, "ctx", 3)) return CKR_MECHANISM_PARAM_INVALID;
        separator = 2;
    } else if (n == 3) { separator = 1; }
    else { return CKR_MECHANISM_PARAM_INVALID; }
    if (fields[separator].type != CK_SP800_108_BYTE_ARRAY || fields[separator].ulValueLen != 1 || !fields[separator].pValue || *(CK_BYTE *)fields[separator].pValue != 0) return CKR_MECHANISM_PARAM_INVALID;
    CK_PRF_DATA_PARAM *last = &fields[n - 1];
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
    if (KDF_FAULT == 5) return CKR_DEVICE_ERROR;
    *result = 3; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetMechanismList = kbkdf_mechanisms;
    functions.C_GetMechanismInfo = kbkdf_info;
    functions.C_FindObjectsInit = kbkdf_find_init;
    functions.C_FindObjects = kbkdf_find;
    functions.C_GetAttributeValue = kbkdf_attributes;
    functions.C_DeriveKey = KDF_FAULT == 2 ? NULL : kbkdf_derive;
    *out = &functions; return CKR_OK;
}
