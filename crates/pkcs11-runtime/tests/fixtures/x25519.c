/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* X25519 descriptors and protected output policy, independent 3.x layouts. */
#ifdef X_KDF_TEST
enum { x_fault = FAULT % 40 };
#else
enum { x_fault = FAULT };
#endif
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
#ifndef X_BITS
#define X_BITS 255
#define X_LENGTH 32
#define X_BASE 9
#define X_PARAMS {6,3,43,101,110}
#define X_OTHER_PARAMS {0x13,10,'c','u','r','v','e','2','5','5','1','9'}
#endif
static CK_OBJECT_HANDLE x_matches[3];
static CK_ULONG x_count, x_cursor;
static CK_OBJECT_CLASS x_class(CK_OBJECT_HANDLE h) { return h == 1 ? CKO_PUBLIC_KEY : h == 2 ? CKO_PRIVATE_KEY : CKO_SECRET_KEY; }
static CK_RV x_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s; x_count = x_cursor = 0;
    for (CK_OBJECT_HANDLE h = 1; h <= (x_fault == 21 ? 3UL : 2UL); ++h) {
        int accept = 1;
        for (CK_ULONG i = 0; i < count; ++i) {
            CK_ATTRIBUTE a = attrs[i];
            if (a.type == CKA_CLASS) accept &= a.ulValueLen == sizeof(CK_OBJECT_CLASS) && *(CK_OBJECT_CLASS *)a.pValue == x_class(h);
            else if (a.type == CKA_ID) accept &= a.ulValueLen == 1 && *(CK_BYTE *)a.pValue == (h == 3 ? 2 : 1);
            else if (a.type == CKA_TOKEN) accept &= a.ulValueLen == 1 && *(CK_BBOOL *)a.pValue == CK_TRUE;
            else accept = 0;
        }
        if (accept) x_matches[x_count++] = h;
    }
    return CKR_OK;
}
static CK_RV x_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR out, CK_ULONG maximum, CK_ULONG_PTR count) {
    (void)s; *count = 0;
    while (x_cursor < x_count && *count < maximum) out[(*count)++] = x_matches[x_cursor++];
    return CKR_OK;
}
static CK_RV x_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        CK_ULONG scalar = 0, length = sizeof(scalar);
        CK_BYTE bytes[64] = {6,3,43,101,110};
        const CK_BYTE params[] = X_PARAMS, other[] = X_OTHER_PARAMS;
        const void *data = &scalar;
        if (x_fault == 17) return CKR_DEVICE_ERROR;
        switch (a->type) {
            case CKA_CLASS: scalar = x_fault == 1 ? CKO_SECRET_KEY : x_class(h); break;
            case CKA_KEY_TYPE: scalar = x_fault == 2 ? CKK_EC_EDWARDS : CKK_EC_MONTGOMERY; break;
            case CKA_LABEL: data = bytes; length = 0; break;
            case CKA_ID: bytes[0] = h == 3 ? 2 : 1; data = bytes; length = 1; break;
            case CKA_EC_PARAMS:
                memcpy(bytes, params, sizeof(params)); data = bytes; length = sizeof(params);
                if (x_fault == 3) { data = other; length = sizeof(other); }
                if (x_fault == 4) bytes[length-1] ^= 1;
                if (x_fault == 5) --length;
                if (x_fault == 15) { a->ulValueLen = 4097; continue; }
                if (x_fault == 16 && a->pValue) { a->ulValueLen += 1; return CKR_OK; }
                break;
            case CKA_EC_POINT:
                memset(bytes, 0, sizeof(bytes)); bytes[0] = X_BASE; data = bytes; length = X_LENGTH;
                if (x_fault == 6) { bytes[0] = 4; bytes[1] = X_LENGTH; bytes[2] = X_BASE; length = X_LENGTH+2; }
                if (x_fault == 7) length = X_LENGTH-1;
                if (x_fault == 8) bytes[0] = 0;
                break;
            case CKA_ALLOWED_MECHANISMS:
                if (x_fault == 26) { a->ulValueLen = CK_UNAVAILABLE_INFORMATION; return CKR_ATTRIBUTE_TYPE_INVALID; }
                scalar = x_fault == 14 ? CKM_ECDSA : CKM_ECDH1_DERIVE; break;
            case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE: case CKA_EXTRACTABLE:
            case CKA_DERIVE: case CKA_ALWAYS_AUTHENTICATE:
                scalar = a->type == CKA_TOKEN || a->type == CKA_PRIVATE || a->type == CKA_SENSITIVE || a->type == CKA_DERIVE;
                if ((x_fault == 9 && a->type == CKA_DERIVE) || (x_fault == 11 && a->type == CKA_SENSITIVE) || (x_fault == 13 && a->type == CKA_PRIVATE)) scalar = 0;
                if ((x_fault == 10 && a->type == CKA_ALWAYS_AUTHENTICATE) || (x_fault == 12 && a->type == CKA_EXTRACTABLE)) scalar = 1;
                bytes[0] = (CK_BBOOL)scalar; data = bytes; length = sizeof(CK_BBOOL); break;
            case CKA_VALUE: return CKR_DEVICE_ERROR;
            default: a->ulValueLen = CK_UNAVAILABLE_INFORMATION; return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        if (a->pValue) {
            if (a->ulValueLen < length) { a->ulValueLen = CK_UNAVAILABLE_INFORMATION; return CKR_BUFFER_TOO_SMALL; }
            memcpy(a->pValue, data, length);
        }
        a->ulValueLen = length;
    }
    return CKR_OK;
}
static CK_RV x_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)s; *count = x_fault == 27 ? 0 : 1; if (list && *count) list[0] = CKM_ECDH1_DERIVE; return CKR_OK;
}
static CK_RV x_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)s;
    if (mechanism != CKM_ECDH1_DERIVE) return CKR_MECHANISM_INVALID;
    memset(out, 0, sizeof(*out));
    out->ulMinKeySize = x_fault == 19 ? X_BITS+1 : X_BITS; out->ulMaxKeySize = X_BITS;
    out->flags = x_fault == 18 ? 0 : CKF_DERIVE; return CKR_OK;
}
static CK_RV x_derive(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE base, CK_ATTRIBUTE_PTR attrs, CK_ULONG count, CK_OBJECT_HANDLE_PTR out) {
    (void)s;
    if (m->mechanism != CKM_ECDH1_DERIVE || !m->pParameter || m->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS) || base != 2) return CKR_MECHANISM_PARAM_INVALID;
    CK_ECDH1_DERIVE_PARAMS *p = m->pParameter;
    CK_BYTE peer[X_LENGTH] = {X_BASE};
    int aes = 0;
    CK_ULONG output_length = X_LENGTH;
#ifdef X_KDF_TEST
    const CK_EC_KDF_TYPE kdfs[] = {CKD_SHA224_KDF, CKD_SHA256_KDF, CKD_SHA384_KDF, CKD_SHA512_KDF,
        CKD_SHA224_KDF_SP800, CKD_SHA256_KDF_SP800, CKD_SHA384_KDF_SP800, CKD_SHA512_KDF_SP800};
    const CK_ULONG lengths[] = {1,64,4096,16,24,32};
    aes = kd_case % 6 >= 3;
    output_length = lengths[kd_case % 6];
    if (p->kdf != kdfs[(kd_case % 48) / 6]) return CKR_MECHANISM_PARAM_INVALID;
    if (kd_case % 6 == 1) { if (p->ulSharedDataLen != 0) return CKR_MECHANISM_PARAM_INVALID; }
    else if (kd_case % 6 == 2) {
        if (p->ulSharedDataLen != 4096 || !p->pSharedData) return CKR_MECHANISM_PARAM_INVALID;
        for (CK_ULONG i = 0; i < 4096; ++i) if (p->pSharedData[i] != 'c') return CKR_MECHANISM_PARAM_INVALID;
    } else if (p->ulSharedDataLen != 8 || !p->pSharedData || memcmp(p->pSharedData,"context\0",8)) return CKR_MECHANISM_PARAM_INVALID;
#else
    if (p->kdf != CKD_NULL || p->ulSharedDataLen != 0 || p->pSharedData != NULL_PTR) return CKR_MECHANISM_PARAM_INVALID;
#endif
    if (p->ulPublicDataLen != sizeof(peer) || !p->pPublicData || memcmp(p->pPublicData, peer, sizeof(peer))) return CKR_MECHANISM_PARAM_INVALID;
    unsigned seen = 0;
    const CK_ATTRIBUTE_TYPE expected[] = {CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN, CKA_TOKEN, CKA_PRIVATE, CKA_SENSITIVE, CKA_DERIVE, CKA_EXTRACTABLE, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_ID, CKA_LABEL};
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE a = attrs[i];
        unsigned index = 0;
        while (index < 16 && expected[index] != a.type) ++index;
        if (index == 16 || (seen & (1U << index))) return CKR_TEMPLATE_INCONSISTENT;
        seen |= 1U << index;
        switch (a.type) {
            case CKA_CLASS: if (a.ulValueLen != sizeof(CK_ULONG) || *(CK_ULONG *)a.pValue != CKO_SECRET_KEY) return CKR_TEMPLATE_INCONSISTENT; break;
            case CKA_KEY_TYPE: if (a.ulValueLen != sizeof(CK_ULONG) || *(CK_ULONG *)a.pValue != (aes ? CKK_AES : CKK_GENERIC_SECRET)) return CKR_TEMPLATE_INCONSISTENT; break;
            case CKA_VALUE_LEN: if (a.ulValueLen != sizeof(CK_ULONG) || *(CK_ULONG *)a.pValue != output_length) return CKR_TEMPLATE_INCONSISTENT; break;
            case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE:
                if (a.ulValueLen != 1 || *(CK_BBOOL *)a.pValue != CK_TRUE) return CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_DERIVE:
                if (a.ulValueLen != 1 || *(CK_BBOOL *)a.pValue != (aes ? CK_FALSE : CK_TRUE)) return CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_ENCRYPT: case CKA_DECRYPT:
                if (a.ulValueLen != 1 || *(CK_BBOOL *)a.pValue != (aes ? CK_TRUE : CK_FALSE)) return CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_EXTRACTABLE: case CKA_SIGN: case CKA_VERIFY: case CKA_WRAP: case CKA_UNWRAP:
                if (a.ulValueLen != 1 || *(CK_BBOOL *)a.pValue != CK_FALSE) return CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_ID: if (a.ulValueLen != 1 || *(CK_BYTE *)a.pValue != 2) return CKR_TEMPLATE_INCONSISTENT; break;
            case CKA_LABEL: if (a.ulValueLen != 6 || memcmp(a.pValue, "shared", 6)) return CKR_TEMPLATE_INCONSISTENT; break;
            default: return CKR_TEMPLATE_INCONSISTENT;
        }
    }
    if (seen != 65535 || count != 16) return CKR_TEMPLATE_INCOMPLETE;
    if (x_fault == 22) return CKR_DEVICE_ERROR;
    *out = 3; return CKR_OK;
}
static CK_RV x_close(CK_SESSION_HANDLE s) { return x_fault == 23 ? CKR_DEVICE_ERROR : close_session(s); }
static CK_RV x_finalize(CK_VOID_PTR p) { return x_fault == 24 ? CKR_DEVICE_ERROR : finalize(p); }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_FindObjectsInit = x_find_init; functions.C_FindObjects = x_find;
    functions.C_GetAttributeValue = x_attributes;
    functions.C_GetMechanismList = x_mechanisms; functions.C_GetMechanismInfo = x_mechanism_info;
    functions.C_DeriveKey = x_fault == 20 ? NULL_PTR : x_derive;
    functions.C_CloseSession = x_close; functions.C_Finalize = x_finalize;
    *out = &functions; return CKR_OK;
}
