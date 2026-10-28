/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Shared parameter/encoding fixture; defaults use OASIS 2.40 SHA-224.
 * Signature bytes are synthetic, not cryptographic test vectors. */
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
#ifndef SIGN_HASH
#define SIGN_HASH CKM_SHA224
#define SIGN_RSA CKM_SHA224_RSA_PKCS
#define SIGN_PSS CKM_SHA224_RSA_PKCS_PSS
#define SIGN_ECDSA CKM_ECDSA_SHA224
#define SIGN_MGF CKG_MGF1_SHA384
#define SIGN_OID 4
#define SIGN_DIGEST {0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,0x86,0x42,0xa4,0x77,0xbd,0xa2,0x55,0xb3,0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,0xe3,0x6c,0x9d,0xa7}
#endif
static CK_MECHANISM_TYPE selected;
static CK_ULONG signature_length;
static int authenticated;
static CK_RV signature_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR count) {
    (void)s;
    const CK_MECHANISM_TYPE values[] = {CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_ECDSA,
        SIGN_RSA, SIGN_PSS, SIGN_ECDSA};
    if (out) memcpy(out, values, sizeof(values));
    *count = sizeof(values)/sizeof(values[0]); return CKR_OK;
}
static CK_RV signature_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; (void)m; out->ulMinKeySize = 256; out->ulMaxKeySize = 4096;
    out->flags = CKF_SIGN | CKF_VERIFY; return CKR_OK;
}
static CK_RV signature_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        CK_ULONG value = 0, length = sizeof(value);
        CK_BYTE params[] = {6,8,42,134,72,206,61,3,1,7};
        CK_BYTE modulus[256] = {0x80};
        const void *data = &value;
        switch (a->type) {
            case CKA_CLASS: value = (FAULT == 2 || FAULT == 6) ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY; break;
            case CKA_KEY_TYPE: value = FAULT == 3 ? CKK_EC : CKK_RSA; break;
            case CKA_MODULUS: data = modulus; length = sizeof(modulus); break;
            case CKA_MODULUS_BITS: value = 2048; break;
            case CKA_EC_PARAMS: data = params; length = sizeof(params); break;
            case CKA_ALWAYS_AUTHENTICATE: value = CK_TRUE; length = sizeof(CK_BBOOL); break;
            case CKA_SIGN: case CKA_VERIFY: value = FAULT != 4 && FAULT != 6; length = sizeof(CK_BBOOL); break;
            case CKA_ALLOWED_MECHANISMS: a->ulValueLen = 0; continue;
            default: {
                CK_RV rv = attributes(s,h,a,1);
                if (rv != CKR_OK) return rv;
                continue;
            }
        }
        CK_BBOOL flag = (CK_BBOOL)value;
        if (length == sizeof(flag)) data = &flag;
        if (a->pValue) {
            if (a->ulValueLen < length) return CKR_BUFFER_TOO_SMALL;
            memcpy(a->pValue,data,length);
        }
        a->ulValueLen = length;
    }
    return CKR_OK;
}
static CK_RV signature_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h;
    selected = m->mechanism;
    if (FAULT == 5 && (selected == SIGN_RSA || selected == SIGN_PSS || selected == SIGN_ECDSA)) return CKR_DEVICE_ERROR;
    if (selected == CKM_RSA_PKCS_PSS || selected == SIGN_PSS) {
        if (!m->pParameter || m->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)) return CKR_MECHANISM_PARAM_INVALID;
        CK_RSA_PKCS_PSS_PARAMS *p = m->pParameter;
        if (p->hashAlg != SIGN_HASH || p->mgf != SIGN_MGF || p->sLen != 20) return CKR_MECHANISM_PARAM_INVALID;
    } else if (m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    signature_length = (selected == CKM_ECDSA || selected == SIGN_ECDSA) ? 64 : 256;
    active = 1; authenticated = FAULT == 2; return CKR_OK;
}
static CK_RV signature_login(CK_SESSION_HANDLE s, CK_USER_TYPE role, CK_UTF8CHAR_PTR pin, CK_ULONG length) {
    (void)s;
    if (!active || role != CKU_CONTEXT_SPECIFIC) return CKR_ARGUMENTS_BAD;
    if (length != 4 || memcmp(pin,"1234",4)) return CKR_PIN_INCORRECT;
    authenticated = 1; return CKR_OK;
}
static CK_RV signature_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG length, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s;
    const CK_BYTE digest[] = SIGN_DIGEST;
    const CK_BYTE prefix[] = {0x30,0x11+sizeof(digest),0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,SIGN_OID,0x05,0x00,0x04,sizeof(digest)};
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if (selected == CKM_RSA_PKCS) {
        if (length != sizeof(prefix)+sizeof(digest) || memcmp(data,prefix,sizeof(prefix)) || memcmp(data+sizeof(prefix),digest,sizeof(digest))) return CKR_DATA_INVALID;
    } else if (selected == CKM_RSA_PKCS_PSS || selected == CKM_ECDSA) {
        if (length != sizeof(digest) || memcmp(data,digest,length)) return CKR_DATA_INVALID;
    } else if (length != 3 || memcmp(data,"abc",3)) return CKR_DATA_INVALID;
    if (!out) { *written = signature_length; return CKR_OK; }
    if (*written < signature_length) return CKR_BUFFER_TOO_SMALL;
    memset(out,0xab,signature_length); *written = signature_length - (FAULT == 1); active = 0; return CKR_OK;
}
static CK_RV signature_verify(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG length, CK_BYTE_PTR sig, CK_ULONG size) {
    CK_BYTE out[256]; CK_ULONG written = sizeof(out);
    CK_RV rv = signature_sign(s,data,length,out,&written);
    if (rv != CKR_OK) return rv;
    return size == written && !memcmp(sig,out,size) ? CKR_OK : CKR_SIGNATURE_INVALID;
}
#ifndef SIGNATURE_FUNCTION_LIST
#define SIGNATURE_FUNCTION_LIST C_GetFunctionList
#endif
CK_RV SIGNATURE_FUNCTION_LIST(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetMechanismList = signature_mechanisms; functions.C_GetMechanismInfo = signature_info;
    functions.C_GetAttributeValue = signature_attributes; functions.C_Login = signature_login;
    functions.C_SignInit = signature_init; functions.C_Sign = signature_sign;
    functions.C_VerifyInit = signature_init; functions.C_Verify = signature_verify;
    *out = &functions; return CKR_OK;
}
