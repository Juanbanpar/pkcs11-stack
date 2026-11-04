/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Official 3.2 parameters on legacy/current tables; signatures are synthetic. */
enum { hash_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
#ifndef STREAM
#define STREAM 0
#endif
#ifndef HASH
#define HASH CKM_SHA512
#define HASH_MECHANISM CKM_HASH_ML_DSA_SHA512
#define HASH_LENGTH 64
#endif
static CK_ULONG inits, completions, logins;
#if STREAM
static CK_ULONG parts, updates, cancellations;
#endif
static int authenticated;
static CK_ULONG signature_size(void) { return PARAMETER == 0 ? 2420 : PARAMETER == 1 ? 3309 : 4627; }
static CK_ULONG public_size(void) { return PARAMETER == 0 ? 1312 : PARAMETER == 1 ? 1952 : 2592; }
static CK_ULONG parameter(void) { return PARAMETER == 0 ? CKP_ML_DSA_44 : PARAMETER == 1 ? CKP_ML_DSA_65 : CKP_ML_DSA_87; }
static CK_MECHANISM_TYPE mechanism(void) { return PREHASH ? CKM_HASH_ML_DSA : HASH_MECHANISM; }
static CK_RV hash_close(CK_SESSION_HANDLE s) {
    CK_RV rv = close_session(s); return hash_fault == 23 ? CKR_DEVICE_ERROR : rv;
}
static CK_RV hash_finalize(CK_VOID_PTR reserved) {
    CK_RV rv = finalize(reserved); return hash_fault == 24 ? CKR_DEVICE_ERROR : rv;
}
static CK_RV hash_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out); out->ulDeviceError = (inits << 16) | (logins << 8) | completions;
#if STREAM
    out->ulDeviceError |= (updates << 24) | (cancellations << 4);
#endif
    return rv;
}
static CK_RV hash_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR n) {
    (void)s; if (out && hash_fault != 26) out[0] = mechanism(); *n = hash_fault == 26 ? 0 : 1; return CKR_OK;
}
static CK_RV hash_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; (void)m; out->ulMinKeySize = public_size() + (hash_fault == 25); out->ulMaxKeySize = public_size();
    out->flags = hash_fault == 1 ? 0 : CKF_SIGN | CKF_VERIFY; return CKR_OK;
}
static CK_RV hash_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i]; CK_ULONG value, length = sizeof(value);
        switch (a->type) {
            case CKA_CLASS: value = (VERIFY != (hash_fault == 4)) ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY; break;
            case CKA_KEY_TYPE: value = CKK_ML_DSA; break;
            case CKA_PARAMETER_SET: value = hash_fault == 5 ? (PARAMETER == 0 ? CKP_ML_DSA_65 : CKP_ML_DSA_44) : parameter(); break;
            case CKA_ALLOWED_MECHANISMS: value = hash_fault == 3 ? CKM_ML_DSA : mechanism(); break;
            case CKA_SIGN: case CKA_VERIFY: value = hash_fault != 2; length = sizeof(CK_BBOOL); break;
            case CKA_ALWAYS_AUTHENTICATE: value = AUTH; length = sizeof(CK_BBOOL); break;
            default: { CK_RV rv = attributes(s,h,a,1); if (rv != CKR_OK) return rv; continue; }
        }
        if (a->pValue) {
            if (a->ulValueLen < length) return CKR_BUFFER_TOO_SMALL;
            if (length == sizeof(CK_BBOOL)) *(CK_BBOOL *)a->pValue = (CK_BBOOL)value;
            else memcpy(a->pValue,&value,length);
        }
        a->ulValueLen = length;
    }
    return CKR_OK;
}
static CK_RV hash_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits;
    if (active) return CKR_OPERATION_ACTIVE;
    if (m->mechanism != mechanism()) return CKR_MECHANISM_INVALID;
    CK_ULONG hedge, length; CK_BYTE_PTR context;
    if (PREHASH) {
        if (!m->pParameter || m->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)) return CKR_MECHANISM_PARAM_INVALID;
        CK_HASH_SIGN_ADDITIONAL_CONTEXT *p = m->pParameter;
        if (p->hash != HASH) return CKR_MECHANISM_PARAM_INVALID;
        hedge = p->hedgeVariant; length = p->ulContextLen; context = p->pContext;
    } else if (HEDGE == 0 && CONTEXT_LENGTH == 0) {
        if (m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
        hedge = 0; length = 0; context = NULL;
    } else {
        if (!m->pParameter || m->ulParameterLen != sizeof(CK_SIGN_ADDITIONAL_CONTEXT)) return CKR_MECHANISM_PARAM_INVALID;
        CK_SIGN_ADDITIONAL_CONTEXT *p = m->pParameter;
        hedge = p->hedgeVariant; length = p->ulContextLen; context = p->pContext;
    }
    if (hedge != HEDGE || length != CONTEXT_LENGTH || (length == 0 ? context != NULL : context == NULL)) return CKR_MECHANISM_PARAM_INVALID;
    for (CK_ULONG i = 0; i < length; ++i) if (context[i] != 0xA5) return CKR_MECHANISM_PARAM_INVALID;
    if (hash_fault == 11) return CKR_DEVICE_ERROR;
    if (hash_fault == 22) return CKR_SIGNATURE_INVALID;
    active = 1; authenticated = !AUTH || VERIFY;
#if STREAM
    parts = 0;
#endif
    return CKR_OK;
}
static CK_RV hash_login(CK_SESSION_HANDLE s, CK_USER_TYPE role, CK_UTF8CHAR_PTR pin, CK_ULONG n) {
    (void)s; ++logins;
    if (!active || role != CKU_CONTEXT_SPECIFIC) return CKR_ARGUMENTS_BAD;
    if (hash_fault == 12) return CKR_DEVICE_ERROR;
    if (n != 4 || memcmp(pin,"1234",4)) return CKR_PIN_INCORRECT;
    authenticated = 1; return CKR_OK;
}
static CK_RV hash_input(CK_BYTE_PTR bytes, CK_ULONG n) {
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if (PREHASH) {
        if (n != HASH_LENGTH) return CKR_DATA_LEN_RANGE;
        for (CK_ULONG i = 0; i < n; ++i) if (bytes[i] != 0xA5) return CKR_DATA_INVALID;
    } else if (n && (n != 3 || memcmp(bytes,"abc",3))) return CKR_DATA_INVALID;
    return CKR_OK;
}
static CK_RV hash_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s; ++completions; CK_RV rv = hash_input(bytes,n); if (rv != CKR_OK) return rv;
    if (!out || *written != signature_size()) return CKR_ARGUMENTS_BAD;
    if (hash_fault == 13) return CKR_DEVICE_ERROR;
    if (hash_fault == 14) { *written = signature_size() + 1; return CKR_BUFFER_TOO_SMALL; }
    if (hash_fault == 17) return CKR_PENDING;
    memset(out,0xAB,signature_size()); active = 0;
    *written = signature_size() - (hash_fault == 15) + (hash_fault == 16); return CKR_OK;
}
static CK_RV hash_verify(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR sig, CK_ULONG length) {
    (void)s; ++completions; CK_RV rv = hash_input(bytes,n); if (rv != CKR_OK) return rv;
    if (hash_fault == 18) return CKR_DEVICE_ERROR;
    if (hash_fault == 21) return CKR_PENDING;
    active = 0;
    if (hash_fault == 19) return CKR_SIGNATURE_INVALID;
    if (hash_fault == 20 || length != signature_size()) return CKR_SIGNATURE_LEN_RANGE;
    for (CK_ULONG i = 0; i < length; ++i) if (sig[i] != 0xAB) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
#if STREAM
static CK_RV hash_update(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n) {
    (void)s; ++updates;
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if (hash_fault == 27) return CKR_DEVICE_ERROR;
    if (hash_fault == 28) return CKR_SIGNATURE_INVALID;
    if (hash_fault == 29) return CKR_PENDING;
    if (hash_fault == 30) return CKR_TOKEN_RESOURCE_EXCEEDED;
    if (hash_fault != 37 && (n > 3-parts || memcmp(bytes,"abc"+parts,n))) return CKR_DATA_INVALID;
    parts += n; return CKR_OK;
}
static CK_RV hash_sign_final(CK_SESSION_HANDLE s, CK_BYTE_PTR out, CK_ULONG_PTR length) {
    if (!updates || (hash_fault != 37 && parts != 0 && parts != 3)) return CKR_ARGUMENTS_BAD;
    return hash_sign(s, NULL, 0, out, length);
}
static CK_RV hash_verify_final(CK_SESSION_HANDLE s, CK_BYTE_PTR sig, CK_ULONG length) {
    if (!updates || (hash_fault != 37 && parts != 0 && parts != 3)) return CKR_ARGUMENTS_BAD;
    return hash_verify(s, NULL, 0, sig, length);
}
#if API_MAJOR >= 3
static CK_RV hash_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    (void)s; ++cancellations;
    if (!active || flags != (VERIFY ? CKF_VERIFY : CKF_SIGN)) return CKR_ARGUMENTS_BAD;
    if (hash_fault == 31) return CKR_OPERATION_CANCEL_FAILED;
    if (hash_fault == 32) return CKR_FUNCTION_NOT_SUPPORTED;
    active = 0; return CKR_OK;
}
#endif
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
#if API_MAJOR >= 3
#if API_MINOR >= 2
static CK_FUNCTION_LIST_3_2 current;
#else
static CK_FUNCTION_LIST_3_0 current;
#endif
static CK_INTERFACE standard = {.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11", .pFunctionList = &current};
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if (!name || strcmp((char *)name,"PKCS 11") || !version || version->major != 3 || version->minor != API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix); *out = &standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_CloseSession = hash_close; functions.C_Finalize = hash_finalize;
    functions.C_GetSessionInfo = hash_info;
    functions.C_GetMechanismList = hash_mechanisms; functions.C_GetMechanismInfo = hash_mechanism_info;
    functions.C_GetAttributeValue = hash_attributes;
    functions.C_SignInit = hash_fault == 7 ? NULL : hash_init;
    functions.C_Sign = hash_fault == 8 ? NULL : hash_sign;
    functions.C_VerifyInit = hash_fault == 9 ? NULL : hash_init;
    functions.C_Verify = hash_fault == 10 ? NULL : hash_verify;
    functions.C_Login = hash_fault == 6 ? NULL : hash_login;
#if STREAM
    functions.C_SignUpdate = hash_fault == 35 ? NULL : hash_update;
    functions.C_SignFinal = hash_fault == 36 ? NULL : hash_sign_final;
    functions.C_VerifyUpdate = hash_fault == 35 ? NULL : hash_update;
    functions.C_VerifyFinal = hash_fault == 36 ? NULL : hash_verify_final;
#else
    /* Generic prehashed HashML-DSA is single-part only. */
    functions.C_SignUpdate = NULL; functions.C_SignFinal = NULL;
    functions.C_VerifyUpdate = NULL; functions.C_VerifyFinal = NULL;
#endif
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions)); current.version.major = 3; current.version.minor = API_MINOR;
#if STREAM
    current.C_SessionCancel = hash_fault == 33 ? NULL : hash_cancel;
#endif
#endif
    *out = &functions; return CKR_OK;
}
