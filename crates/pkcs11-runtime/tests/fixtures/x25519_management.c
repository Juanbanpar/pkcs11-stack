/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Exact Montgomery generation/import templates through a legacy function table. */
enum { management_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList

static CK_ULONG duplicates;
static CK_RV management_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s; duplicates = 0;
    if (management_fault == 12) return CKR_DEVICE_ERROR;
    CK_OBJECT_CLASS class = CKO_DATA;
    unsigned seen = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE a = attrs[i];
        if (!a.pValue) return CKR_ARGUMENTS_BAD;
        if (a.type == CKA_CLASS && a.ulValueLen == sizeof(class)) { class = *(CK_OBJECT_CLASS *)a.pValue; seen |= 1; }
        else if (a.type == CKA_TOKEN && a.ulValueLen == 1 && *(CK_BBOOL *)a.pValue == CK_TRUE) seen |= 2;
        else if (a.type == CKA_ID && a.ulValueLen == 1 && *(CK_BYTE *)a.pValue == 2) seen |= 4;
        else return CKR_ARGUMENTS_BAD;
    }
    if (count != 3 || seen != 7) return CKR_ARGUMENTS_BAD;
    duplicates = (management_fault == 9 && class == CKO_PUBLIC_KEY) || (management_fault == 10 && class == CKO_PRIVATE_KEY);
    return CKR_OK;
}
static CK_RV management_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR out, CK_ULONG maximum, CK_ULONG_PTR count) {
    (void)s; *count = duplicates && maximum ? 1 : 0;
    if (*count) out[0] = 1;
    duplicates = 0; return CKR_OK;
}
static CK_RV management_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)s;
    if (management_fault == 15) return CKR_DEVICE_ERROR;
    *count = management_fault == 2 ? 0 : 1;
    if (list && *count) list[0] = CKM_EC_MONTGOMERY_KEY_PAIR_GEN;
    return CKR_OK;
}
static CK_RV management_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    (void)s;
    if (management_fault == 11) return CKR_DEVICE_ERROR;
    if (mechanism != CKM_EC_MONTGOMERY_KEY_PAIR_GEN) return CKR_MECHANISM_INVALID;
    memset(out, 0, sizeof(*out));
    out->flags = management_fault == 3 ? 0 : CKF_GENERATE_KEY_PAIR;
    out->ulMinKeySize = management_fault == 4 ? 256 : 255;
    out->ulMaxKeySize = management_fault == 5 ? 254 : 448;
    return CKR_OK;
}
static int same(CK_ATTRIBUTE a, const void *value, CK_ULONG length) {
    return a.pValue && a.ulValueLen == length && !memcmp(a.pValue, value, length);
}
static CK_RV template_check(CK_ATTRIBUTE_PTR attrs, CK_ULONG count, const CK_ATTRIBUTE_TYPE *types, unsigned total, int private_key) {
    unsigned seen = 0;
    const CK_BYTE oid[] = {6,3,43,101,110}, peer[32] = {9};
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE a = attrs[i]; unsigned index = 0;
        while (index < total && types[index] != a.type) ++index;
        if (index == total || (seen & (1U << index))) return CKR_TEMPLATE_INCONSISTENT;
        seen |= 1U << index;
        CK_ULONG scalar = 0;
        CK_BBOOL boolean = CK_FALSE;
        switch (a.type) {
            case CKA_CLASS: scalar = CKO_PUBLIC_KEY; break;
            case CKA_KEY_TYPE: scalar = CKK_EC_MONTGOMERY; break;
            case CKA_ALLOWED_MECHANISMS: scalar = CKM_ECDH1_DERIVE; break;
            case CKA_EC_PARAMS: if (!same(a, oid, sizeof(oid))) return CKR_TEMPLATE_INCONSISTENT; continue;
            case CKA_EC_POINT: if (!same(a, peer, sizeof(peer))) return CKR_TEMPLATE_INCONSISTENT; continue;
            case CKA_ID: if (!same(a, "\2", 1)) return CKR_TEMPLATE_INCONSISTENT; continue;
            case CKA_LABEL: if (!same(a, "X25519", 6)) return CKR_TEMPLATE_INCONSISTENT; continue;
            case CKA_TOKEN: case CKA_SENSITIVE: boolean = CK_TRUE; break;
            case CKA_PRIVATE: boolean = private_key; break;
            case CKA_DERIVE: boolean = private_key; break;
            case CKA_VERIFY: case CKA_VERIFY_RECOVER: case CKA_ENCRYPT: case CKA_WRAP:
            case CKA_SIGN: case CKA_SIGN_RECOVER: case CKA_DECRYPT: case CKA_UNWRAP:
            case CKA_ALWAYS_AUTHENTICATE: case CKA_EXTRACTABLE: case CKA_TRUSTED: break;
            default: return CKR_TEMPLATE_INCONSISTENT;
        }
        if (a.type == CKA_CLASS || a.type == CKA_KEY_TYPE || a.type == CKA_ALLOWED_MECHANISMS) {
            if (!same(a, &scalar, sizeof(scalar))) return CKR_TEMPLATE_INCONSISTENT;
        } else if (!same(a, &boolean, sizeof(boolean))) return CKR_TEMPLATE_INCONSISTENT;
    }
    return count == total && seen == (1U << total) - 1 ? CKR_OK : CKR_TEMPLATE_INCOMPLETE;
}
static CK_RV management_generate(CK_SESSION_HANDLE s, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR public, CK_ULONG public_count, CK_ATTRIBUTE_PTR private, CK_ULONG private_count, CK_OBJECT_HANDLE_PTR public_out, CK_OBJECT_HANDLE_PTR private_out) {
    (void)s;
    if (mechanism->mechanism != CKM_EC_MONTGOMERY_KEY_PAIR_GEN || mechanism->pParameter || mechanism->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    const CK_ATTRIBUTE_TYPE pub[] = {CKA_TOKEN, CKA_PRIVATE, CKA_ID, CKA_LABEL, CKA_EC_PARAMS, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_ENCRYPT, CKA_WRAP, CKA_DERIVE};
    const CK_ATTRIBUTE_TYPE priv[] = {CKA_SENSITIVE, CKA_TOKEN, CKA_PRIVATE, CKA_ID, CKA_LABEL, CKA_EXTRACTABLE, CKA_DERIVE, CKA_SIGN, CKA_SIGN_RECOVER, CKA_DECRYPT, CKA_UNWRAP, CKA_ALWAYS_AUTHENTICATE, CKA_ALLOWED_MECHANISMS};
    CK_RV rv = template_check(public, public_count, pub, sizeof(pub)/sizeof(pub[0]), 0);
    if (rv != CKR_OK) return rv;
    rv = template_check(private, private_count, priv, sizeof(priv)/sizeof(priv[0]), 1);
    if (rv != CKR_OK) return rv;
    if (management_fault == 6) return CKR_DEVICE_ERROR;
    *public_out = 101; *private_out = 102; return CKR_OK;
}
static CK_RV management_create(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count, CK_OBJECT_HANDLE_PTR out) {
    (void)s;
    const CK_ATTRIBUTE_TYPE types[] = {CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN, CKA_PRIVATE, CKA_ID, CKA_LABEL, CKA_EC_PARAMS, CKA_EC_POINT, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_ENCRYPT, CKA_WRAP, CKA_DERIVE};
    CK_RV rv = template_check(attrs, count, types, sizeof(types)/sizeof(types[0]), 0);
    if (rv != CKR_OK) return rv;
    if (management_fault == 7) return CKR_DEVICE_ERROR;
    *out = 101; return CKR_OK;
}
static CK_RV management_close(CK_SESSION_HANDLE s) { return management_fault == 13 ? CKR_DEVICE_ERROR : close_session(s); }
static CK_RV management_finalize(CK_VOID_PTR p) { return management_fault == 14 ? CKR_DEVICE_ERROR : finalize(p); }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_FindObjectsInit = management_find_init; functions.C_FindObjects = management_find;
    functions.C_GetMechanismList = management_mechanisms; functions.C_GetMechanismInfo = management_mechanism_info;
    functions.C_GenerateKeyPair = management_fault == 1 ? NULL_PTR : management_generate;
    functions.C_CreateObject = management_fault == 8 ? NULL_PTR : management_create;
    functions.C_CloseSession = management_close; functions.C_Finalize = management_finalize;
    *out = &functions; return CKR_OK;
}
