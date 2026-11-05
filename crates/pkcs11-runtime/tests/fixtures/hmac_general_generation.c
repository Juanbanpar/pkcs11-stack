/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#if FAULT >= 10
enum { generation_fault = FAULT - 9 };
#undef FAULT
#define FAULT 0
#else
enum { generation_fault = 0 };
#endif
#define GENERAL_FUNCTION_LIST profile_function_list
#include "hmac_general_profiles.c"

static int generated;
static CK_RV generation_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)slot;
    if (generation_fault == 8) {
        if (list) list[0] = MAC_MECHANISM;
        *count = 1; return CKR_OK;
    }
    if (list) { list[0] = CKM_GENERIC_SECRET_KEY_GEN; list[1] = MAC_MECHANISM; }
    *count = 2; return CKR_OK;
}
static CK_RV generation_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR out) {
    CK_RV rv = mechanism_info(slot, mechanism, out);
    if (mechanism == CKM_GENERIC_SECRET_KEY_GEN) {
        out->ulMinKeySize = 128; out->ulMaxKeySize = 512; out->flags = CKF_GENERATE;
        if (generation_fault == 1) out->ulMinKeySize = out->ulMaxKeySize = 0;
        if (generation_fault == 2) out->ulMaxKeySize = 255;
        if (generation_fault == 3) out->ulMinKeySize = 257;
        if (generation_fault == 4) out->ulMinKeySize = out->ulMaxKeySize = 256;
        if (generation_fault == 5) out->ulMinKeySize = out->ulMaxKeySize = 32;
        if (generation_fault == 6) out->flags = 0;
    }
    return rv;
}
static CK_RV generation_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR h, CK_ULONG n, CK_ULONG_PTR count) {
    if (!generated) { *count = 0; return CKR_OK; }
    return find(s, h, n, count);
}
static CK_RV generate_key(CK_SESSION_HANDLE s, CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs, CK_ULONG count, CK_OBJECT_HANDLE_PTR out) {
    (void)s;
    if (generation_fault != 0 && generation_fault != 4) return CKR_DEVICE_ERROR;
    if (mech->mechanism != CKM_GENERIC_SECRET_KEY_GEN || mech->pParameter || mech->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    unsigned seen = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE a = attrs[i];
        CK_BBOOL expected;
        switch (a.type) {
            case CKA_KEY_TYPE:
                if (a.ulValueLen != sizeof(CK_KEY_TYPE) || *(CK_KEY_TYPE *)a.pValue != CKK_GENERIC_SECRET) return CKR_TEMPLATE_INCONSISTENT;
                seen |= 1; continue;
            case CKA_VALUE_LEN:
                if (a.ulValueLen != sizeof(CK_ULONG) || *(CK_ULONG *)a.pValue != MAC_TAG_LENGTH) return CKR_TEMPLATE_INCONSISTENT;
                seen |= 2; continue;
            case CKA_ALLOWED_MECHANISMS:
                if (a.ulValueLen != sizeof(CK_MECHANISM_TYPE) || *(CK_MECHANISM_TYPE *)a.pValue != MAC_MECHANISM) return CKR_TEMPLATE_INCONSISTENT;
                seen |= 4; continue;
            case CKA_CLASS:
                if (a.ulValueLen != sizeof(CK_OBJECT_CLASS) || *(CK_OBJECT_CLASS *)a.pValue != CKO_SECRET_KEY) return CKR_TEMPLATE_INCONSISTENT;
                seen |= 8; continue;
            case CKA_TOKEN: seen |= 16; expected = CK_TRUE; break;
            case CKA_PRIVATE: seen |= 32; expected = CK_TRUE; break;
            case CKA_SENSITIVE: seen |= 64; expected = CK_TRUE; break;
            case CKA_SIGN: seen |= 128; expected = CK_TRUE; break;
            case CKA_VERIFY: seen |= 256; expected = CK_TRUE; break;
            case CKA_EXTRACTABLE: seen |= 512; expected = CK_FALSE; break;
            case CKA_DERIVE: seen |= 1024; expected = CK_FALSE; break;
            case CKA_ENCRYPT: seen |= 2048; expected = CK_FALSE; break;
            case CKA_DECRYPT: seen |= 4096; expected = CK_FALSE; break;
            case CKA_WRAP: seen |= 8192; expected = CK_FALSE; break;
            case CKA_UNWRAP: seen |= 16384; expected = CK_FALSE; break;
            case CKA_ID: case CKA_LABEL:
                if (a.ulValueLen != 3 || memcmp(a.pValue, "new", 3)) return CKR_TEMPLATE_INCONSISTENT;
                continue;
            default: return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        if (a.ulValueLen != sizeof(CK_BBOOL) || *(CK_BBOOL *)a.pValue != expected) return CKR_TEMPLATE_INCONSISTENT;
    }
    if (seen != 32767) return CKR_TEMPLATE_INCOMPLETE;
    generated = 1; *out = 1; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    profile_function_list(out);
    functions.C_GetMechanismList = generation_mechanisms;
    functions.C_GetMechanismInfo = generation_info;
    functions.C_FindObjects = generation_find;
    functions.C_GenerateKey = generation_fault == 7 ? NULL : generate_key;
    return CKR_OK;
}
