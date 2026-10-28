/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent OASIS 3.2 parameter layout, synthetic signature/state fixture. */
enum { stream_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_ULONG inits, logins, updates, finals, cancellations, parts;
static int authenticated;
static CK_ULONG signature_size(void) { return PARAMETER == 0 ? 2420 : PARAMETER == 1 ? 3309 : 4627; }
static CK_ULONG public_size(void) { return PARAMETER == 0 ? 1312 : PARAMETER == 1 ? 1952 : 2592; }
static CK_ULONG parameter(void) { return PARAMETER == 0 ? CKP_ML_DSA_44 : PARAMETER == 1 ? CKP_ML_DSA_65 : CKP_ML_DSA_87; }
static CK_RV stream_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    out->ulDeviceError = (inits << 24) | (logins << 16) | (updates << 8) | (finals << 4) | cancellations;
    return rv;
}
static CK_RV stream_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR n) {
    (void)s; if (out) out[0] = CKM_ML_DSA; *n = 1; return CKR_OK;
}
static CK_RV stream_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; (void)m; out->ulMinKeySize = public_size() + (stream_fault == 24); out->ulMaxKeySize = public_size();
    out->flags = stream_fault == 1 ? 0 : CKF_SIGN; return CKR_OK;
}
static CK_RV stream_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i]; CK_ULONG value, length = sizeof(value);
        switch (a->type) {
            case CKA_CLASS: value = stream_fault == 4 ? CKO_PUBLIC_KEY : CKO_PRIVATE_KEY; break;
            case CKA_KEY_TYPE: value = CKK_ML_DSA; break;
            case CKA_PARAMETER_SET:
                if (stream_fault == 23) return CKR_ATTRIBUTE_TYPE_INVALID;
                value = stream_fault == 5 ? (PARAMETER == 0 ? CKP_ML_DSA_65 : CKP_ML_DSA_44) : parameter(); break;
            case CKA_ALLOWED_MECHANISMS: value = stream_fault == 3 ? CKM_EDDSA : CKM_ML_DSA; break;
            case CKA_SIGN: value = stream_fault != 2; length = sizeof(CK_BBOOL); break;
            case CKA_ALWAYS_AUTHENTICATE: value = AUTH != 0; length = sizeof(CK_BBOOL); break;
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
static CK_RV stream_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits;
    if (active) return CKR_OPERATION_ACTIVE;
    if (m->mechanism != CKM_ML_DSA) return CKR_MECHANISM_INVALID;
#if HEDGE == 0 && CONTEXT_LENGTH == 0
    if (m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
#else
    if (!m->pParameter || m->ulParameterLen != sizeof(CK_SIGN_ADDITIONAL_CONTEXT)) return CKR_MECHANISM_PARAM_INVALID;
    CK_SIGN_ADDITIONAL_CONTEXT *p = m->pParameter;
    if (p->hedgeVariant != HEDGE || p->ulContextLen != CONTEXT_LENGTH ||
        (CONTEXT_LENGTH == 0 ? p->pContext != NULL : p->pContext == NULL)) return CKR_MECHANISM_PARAM_INVALID;
    for (CK_ULONG i = 0; i < p->ulContextLen; ++i) if (p->pContext[i] != 0xA5) return CKR_MECHANISM_PARAM_INVALID;
#endif
    if (stream_fault == 11) return CKR_DEVICE_ERROR;
    if (stream_fault == 26) return CKR_SIGNATURE_INVALID;
    active = 1; authenticated = AUTH == 0; parts = 0; return CKR_OK;
}
static CK_RV stream_login(CK_SESSION_HANDLE s, CK_USER_TYPE role, CK_UTF8CHAR_PTR pin, CK_ULONG n) {
    (void)s; ++logins;
    if (!active || role != CKU_CONTEXT_SPECIFIC) return CKR_ARGUMENTS_BAD;
    if (stream_fault == 12) return CKR_DEVICE_ERROR;
    if (n != 4 || memcmp(pin,"1234",4)) return CKR_PIN_INCORRECT;
    authenticated = 1; return CKR_OK;
}
static CK_RV stream_update(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n) {
    (void)s; ++updates;
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if (stream_fault == 13) return CKR_DEVICE_ERROR;
    if (stream_fault == 14) return CKR_SIGNATURE_INVALID;
    if (stream_fault == 21) return CKR_PENDING;
    if (stream_fault == 22) return CKR_TOKEN_RESOURCE_EXCEEDED;
    if (n > 3 - parts || memcmp(bytes,"abc"+parts,n)) return CKR_DATA_INVALID;
    parts += n; return CKR_OK;
}
static CK_RV stream_final(CK_SESSION_HANDLE s, CK_BYTE_PTR out, CK_ULONG_PTR n) {
    (void)s; ++finals;
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if (!out || *n != signature_size() || (parts != 0 && parts != 3)) return CKR_ARGUMENTS_BAD;
    if (stream_fault == 15) return CKR_DEVICE_ERROR;
    if (stream_fault == 27) return CKR_PENDING;
    if (stream_fault == 18) { *n = signature_size() + 1; return CKR_BUFFER_TOO_SMALL; }
    memset(out,0xAB,signature_size()); active = 0;
    *n = signature_size() + (stream_fault == 17) - (stream_fault == 16); return CKR_OK;
}
static CK_RV stream_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    CK_RV rv = stream_update(s,bytes,n); return rv == CKR_OK ? stream_final(s,out,written) : rv;
}
static CK_RV legacy_called(CK_SESSION_HANDLE s) { (void)s; cancellations += 15; return CKR_GENERAL_ERROR; }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
#if API_MAJOR >= 3
static CK_RV stream_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    (void)s; ++cancellations;
    if (flags != CKF_SIGN || !active) return CKR_ARGUMENTS_BAD;
    if (stream_fault == 19) return CKR_OPERATION_CANCEL_FAILED;
    if (stream_fault == 25) return CKR_FUNCTION_NOT_SUPPORTED;
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
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix); *out = &standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetSessionInfo = stream_info;
    functions.C_GetMechanismList = stream_mechanisms; functions.C_GetMechanismInfo = stream_mechanism_info;
    functions.C_GetAttributeValue = stream_attributes;
    functions.C_SignInit = stream_fault == 7 ? NULL : stream_init;
    functions.C_SignUpdate = stream_fault == 8 ? NULL : stream_update;
    functions.C_SignFinal = stream_fault == 9 ? NULL : stream_final;
    functions.C_Sign = stream_fault == 10 ? NULL : stream_sign;
    functions.C_Login = stream_fault == 6 ? NULL : stream_login;
    functions.C_VerifyInit = NULL; functions.C_Verify = NULL;
    functions.C_CancelFunction = legacy_called; functions.C_GetFunctionStatus = legacy_called;
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions)); current.version.major = 3; current.version.minor = API_MINOR;
    current.C_SessionCancel = stream_fault == 20 ? NULL : stream_cancel;
#endif
    *out = &functions; return CKR_OK;
}
