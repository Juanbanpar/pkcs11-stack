/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Parameter, input and lifecycle fixture. Synthetic signatures, not crypto vectors. */
#define SIGNATURE_FUNCTION_LIST stream_base_function_list
#if SHA3
#include "sha3.c"
#else
#include "sha224.c"
#endif
#ifndef API_MAJOR
#define API_MAJOR 2
#define API_MINOR 40
#endif
static CK_ULONG inits, logins, updates, finals, cancellations, part_length;
static CK_FLAGS direction;
static int finding_public;
static CK_RV stream_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    out->ulDeviceError = (inits << 24) | (logins << 16) | (updates << 8) | (finals << 4) | cancellations;
    return rv;
}
static CK_RV stream_token(CK_SLOT_ID s, CK_TOKEN_INFO_PTR out) {
    CK_RV rv = token(s,out);
    if (AUTH == 2) out->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
    return rv;
}
static CK_RV stream_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; ++i) if (attrs[i].type == CKA_CLASS) {
        finding_public = *(CK_OBJECT_CLASS *)attrs[i].pValue == CKO_PUBLIC_KEY;
    }
    return find_init(s,attrs,count);
}
static CK_RV stream_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        CK_ULONG value = 0, length = sizeof(value);
        CK_BYTE params256[] = {6,8,42,134,72,206,61,3,1,7};
        CK_BYTE params384[] = {6,5,43,129,4,0,34};
        CK_BYTE params521[] = {6,5,43,129,4,0,35};
        CK_BYTE modulus[FAULT == 48 ? 1025 : 256] = {FAULT == 48 ? 1 : 0x80};
        CK_MECHANISM_TYPE allowed[] = {CKM_RSA_PKCS,CKM_RSA_PKCS_PSS,CKM_ECDSA};
        const void *data = &value;
        switch (a->type) {
            case CKA_CLASS: value = finding_public ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY; break;
            case CKA_KEY_TYPE: value = EC_CURVE ? CKK_EC : CKK_RSA; break;
            case CKA_MODULUS: data = modulus; length = sizeof(modulus); break;
            case CKA_EC_PARAMS:
                data = EC_CURVE == 1 ? params256 : EC_CURVE == 2 ? params384 : params521;
                length = EC_CURVE == 1 ? sizeof(params256) : sizeof(params384); break;
            case CKA_ALWAYS_AUTHENTICATE: value = AUTH != 0; length = sizeof(CK_BBOOL); break;
            case CKA_SIGN: value = FAULT != 40; length = sizeof(CK_BBOOL); break;
            case CKA_VERIFY: value = FAULT != 41; length = sizeof(CK_BBOOL); break;
            case CKA_ALLOWED_MECHANISMS:
                if (FAULT != 42) { a->ulValueLen = 0; continue; }
                data = allowed; length = sizeof(allowed); break;
            default: {
                CK_RV rv = signature_attributes(s,h,a,1);
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
static CK_RV stream_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    CK_RV rv = signature_info(s,m,out);
    if (FAULT == 43) out->flags &= ~CKF_SIGN;
    if (FAULT == 44) out->flags &= ~CKF_VERIFY;
    if (FAULT == 48) out->ulMaxKeySize = 16384;
    return rv;
}
static CK_RV stream_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h, CK_FLAGS kind) {
    ++inits; direction = kind; part_length = 0;
    if (FAULT == 20) return CKR_DEVICE_ERROR;
    if (FAULT == 21) return CKR_SIGNATURE_INVALID;
    CK_RV rv = signature_init(s,m,h);
    signature_length = EC_CURVE == 1 ? 64 : EC_CURVE == 2 ? 96 : EC_CURVE == 3 ? 132 : 256;
    authenticated = AUTH == 0 || finding_public;
    return rv;
}
static CK_RV stream_sign_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) { return stream_init(s,m,h,0x800); }
static CK_RV stream_verify_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) { return stream_init(s,m,h,0x2000); }
static CK_RV stream_login(CK_SESSION_HANDLE s, CK_USER_TYPE role, CK_UTF8CHAR_PTR pin, CK_ULONG n) {
    ++logins;
    if (FAULT == 22) return CKR_DEVICE_ERROR;
    if (AUTH == 2 && active && role == CKU_CONTEXT_SPECIFIC && !pin && !n) { authenticated = 1; return CKR_OK; }
    return signature_login(s,role,pin,n);
}
static CK_RV stream_update(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG n) {
    (void)s; ++updates;
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if (selected == CKM_RSA_PKCS || selected == CKM_RSA_PKCS_PSS || selected == CKM_ECDSA) return CKR_MECHANISM_INVALID;
    if (FAULT == 23) return CKR_DEVICE_ERROR;
    if (FAULT == 24) return CKR_SIGNATURE_INVALID;
    if (part_length + n > 3 || memcmp(data,"abc"+part_length,n)) return CKR_DATA_INVALID;
    part_length += n; return CKR_OK;
}
static CK_RV stream_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    ++finals;
    if (!out || *written != signature_length) return CKR_ARGUMENTS_BAD;
    if (FAULT == 25) return CKR_DEVICE_ERROR;
    if (FAULT == 28) { *written += 1; return CKR_BUFFER_TOO_SMALL; }
    CK_RV rv = signature_sign(s,data,n,out,written);
    if (rv == CKR_OK && FAULT == 26) *written -= 1;
    if (rv == CKR_OK && FAULT == 27) *written += 1;
    return rv;
}
static CK_RV stream_sign_final(CK_SESSION_HANDLE s, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    if (part_length != 3 && part_length != 0) return CKR_DATA_LEN_RANGE;
    return stream_sign(s,(CK_BYTE_PTR)"abc",3,out,written);
}
static CK_RV stream_verify(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG n, CK_BYTE_PTR signature, CK_ULONG size) {
    CK_BYTE out[256]; CK_ULONG written = signature_length;
    CK_RV rv = stream_sign(s,data,n,out,&written);
    if (rv != CKR_OK) return rv;
    if (FAULT == 29) return CKR_SIGNATURE_INVALID;
    if (FAULT == 30 || size != signature_length) return CKR_SIGNATURE_LEN_RANGE;
    return !memcmp(signature,out,size) ? CKR_OK : CKR_SIGNATURE_INVALID;
}
static CK_RV stream_verify_final(CK_SESSION_HANDLE s, CK_BYTE_PTR signature, CK_ULONG size) {
    return stream_verify(s,(CK_BYTE_PTR)"abc",3,signature,size);
}
static CK_RV legacy_called(CK_SESSION_HANDLE s) { (void)s; cancellations += 15; return CKR_GENERAL_ERROR; }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
#if API_MAJOR >= 3
static CK_RV stream_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    (void)s; ++cancellations;
    if (FAULT == 39) return CKR_OPERATION_CANCEL_FAILED;
    if (!active || flags != direction) return CKR_ARGUMENTS_BAD;
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
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix);
    *out = &standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    stream_base_function_list(out);
    functions.C_GetSessionInfo = stream_info; functions.C_GetTokenInfo = stream_token;
    functions.C_FindObjectsInit = stream_find_init;
    functions.C_GetAttributeValue = stream_attributes; functions.C_GetMechanismInfo = stream_mechanism_info;
    functions.C_Login = stream_login;
    functions.C_SignInit = FAULT == 37 ? NULL : stream_sign_init;
    functions.C_VerifyInit = FAULT == 38 ? NULL : stream_verify_init;
    functions.C_Sign = FAULT == 35 ? NULL : stream_sign;
    functions.C_Verify = FAULT == 36 ? NULL : stream_verify;
    functions.C_SignUpdate = FAULT == 31 ? NULL : stream_update;
    functions.C_SignFinal = FAULT == 32 ? NULL : stream_sign_final;
    functions.C_VerifyUpdate = FAULT == 33 ? NULL : stream_update;
    functions.C_VerifyFinal = FAULT == 34 ? NULL : stream_verify_final;
    functions.C_CancelFunction = legacy_called; functions.C_GetFunctionStatus = legacy_called;
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions)); current.version.major = 3; current.version.minor = API_MINOR;
    current.C_SessionCancel = stream_cancel;
#endif
    return CKR_OK;
}
