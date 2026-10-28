/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent 3.2 signature-first ABI. No legacy verifier may be called. */
enum { verify_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_ULONG inits, updates, finals, cancellations, parts;
static CK_ULONG signature_size(void) { return PARAMETER == 0 ? 2420 : PARAMETER == 1 ? 3309 : 4627; }
static CK_ULONG public_size(void) { return PARAMETER == 0 ? 1312 : PARAMETER == 1 ? 1952 : 2592; }
static CK_ULONG parameter(void) { return PARAMETER == 0 ? CKP_ML_DSA_44 : PARAMETER == 1 ? CKP_ML_DSA_65 : CKP_ML_DSA_87; }
static CK_RV sf_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR n) {
    (void)s; if (out) out[0] = CKM_ML_DSA; *n = 1; return CKR_OK;
}
static CK_ULONG singles;
static int multipart;
static unsigned char saved_signature[4627];
static CK_RV sf_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    out->ulDeviceError = (inits << 24) | (singles << 20) | (updates << 8) | (finals << 4) | cancellations;
    return rv;
}
static CK_RV sf_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; (void)m; out->ulMinKeySize = public_size(); out->ulMaxKeySize = public_size();
    out->flags = verify_fault == 1 ? CKF_SIGN : CKF_VERIFY;
    if (verify_fault == 24) ++out->ulMinKeySize;
    return CKR_OK;
}
static CK_RV sf_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i]; CK_ULONG value, length = sizeof(value);
        switch (a->type) {
            case CKA_KEY_TYPE: value = CKK_ML_DSA; break;
            case CKA_CLASS: value = verify_fault == 4 ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY; break;
            case CKA_VERIFY: value = verify_fault != 2; length = sizeof(CK_BBOOL); break;
            case CKA_SIGN: case CKA_ALWAYS_AUTHENTICATE: return CKR_ATTRIBUTE_TYPE_INVALID;
            case CKA_PARAMETER_SET:
                if (verify_fault == 23) return CKR_ATTRIBUTE_TYPE_INVALID;
                value = verify_fault == 5 ? (PARAMETER == 0 ? CKP_ML_DSA_65 : CKP_ML_DSA_44) : parameter(); break;
            case CKA_ALLOWED_MECHANISMS: value = verify_fault == 3 ? CKM_EDDSA : CKM_ML_DSA; break;
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
static CK_RV sf_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h, CK_BYTE_PTR signature, CK_ULONG n) {
    (void)s; (void)h;
    if (!m) {
        ++cancellations;
        if (h || signature || n || !active) return CKR_ARGUMENTS_BAD;
        if (verify_fault == 19) return CKR_OPERATION_CANCEL_FAILED;
        if (verify_fault == 25) return CKR_FUNCTION_NOT_SUPPORTED;
        active = 0; return CKR_OK;
    }
    ++inits;
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
    active = 1; parts = 0; multipart = 0;
    if (verify_fault == 11) return CKR_DEVICE_ERROR;
    if (verify_fault == 31) return CKR_FUNCTION_NOT_SUPPORTED;
    if (verify_fault == 12) return CKR_SIGNATURE_INVALID;
    if (verify_fault == 29) return CKR_PENDING;
    if (!signature || n != signature_size()) return CKR_SIGNATURE_LEN_RANGE;
    memcpy(saved_signature,signature,n);
    return CKR_OK;
}
static CK_RV sf_update(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n) {
    if (verify_fault == 33) { ++updates; return CKR_FUNCTION_NOT_SUPPORTED; }
    if (verify_fault == 13) { ++updates; return CKR_DEVICE_ERROR; }
    if (verify_fault == 14) { ++updates; return CKR_SIGNATURE_INVALID; }
    if (verify_fault == 21) { ++updates; return CKR_PENDING; }
    if (verify_fault == 22) { ++updates; return CKR_TOKEN_RESOURCE_EXCEEDED; }
    (void)s; ++updates;
    if (!active) return CKR_OPERATION_NOT_INITIALIZED;
    if (n > 3 - parts || memcmp(bytes,"abc"+parts,n)) return CKR_DATA_INVALID;
    multipart = 1; parts += n; return CKR_OK;
}
static CK_RV sf_result(void) {
    active = 0;
    for (CK_ULONG i = 0; i < signature_size(); ++i) if (saved_signature[i] != 0xAB) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
static CK_RV sf_final(CK_SESSION_HANDLE s) {
    (void)s; ++finals;
    if (!active || !multipart || (parts != 0 && parts != 3)) return CKR_OPERATION_NOT_INITIALIZED;
    if (verify_fault == 34) return CKR_FUNCTION_NOT_SUPPORTED;
    if (verify_fault == 15) return CKR_DEVICE_ERROR;
    if (verify_fault == 26) return CKR_PENDING;
    if (verify_fault == 30) return CKR_TOKEN_RESOURCE_EXCEEDED;
    if (verify_fault == 16 || verify_fault == 17) { active = 0; return verify_fault == 16 ? CKR_SIGNATURE_INVALID : CKR_SIGNATURE_LEN_RANGE; }
    return sf_result();
}
static CK_RV sf_single(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n) {
    (void)s; ++singles;
    if (!active || multipart || (n && (n != 3 || memcmp(bytes,"abc",3)))) return CKR_ARGUMENTS_BAD;
    if (verify_fault == 32) return CKR_FUNCTION_NOT_SUPPORTED;
    if (verify_fault == 18) return CKR_DEVICE_ERROR;
    if (verify_fault == 27 || verify_fault == 28) { active = 0; return verify_fault == 27 ? CKR_SIGNATURE_INVALID : CKR_SIGNATURE_LEN_RANGE; }
    return sf_result();
}
static CK_RV legacy_called(CK_SESSION_HANDLE s) { (void)s; cancellations += 15; return CKR_GENERAL_ERROR; }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
#if API_MAJOR >= 3
#if API_MINOR >= 2
static CK_FUNCTION_LIST_3_2 current;
#else
static CK_FUNCTION_LIST_3_0 current;
#endif
static CK_INTERFACE standard = {.pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11", .pFunctionList = &current};
static CK_RV sf_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    (void)flags; return legacy_called(s);
}
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if (!name || strcmp((char *)name,"PKCS 11") || !version || version->major != 3 || version->minor != API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix); *out = &standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    *out = &functions;
    functions.C_GetMechanismList = sf_mechanisms;
    functions.C_VerifyInit = NULL; functions.C_Verify = NULL; functions.C_VerifyUpdate = NULL; functions.C_VerifyFinal = NULL;
    functions.C_CancelFunction = legacy_called; functions.C_GetFunctionStatus = legacy_called;
    functions.C_GetSessionInfo = sf_info;
    functions.C_GetAttributeValue = sf_attributes;
    functions.C_GetMechanismInfo = sf_mechanism_info;
    /* No signing or old verification pointers; verification must be independent. */
    functions.C_SignInit = NULL; functions.C_SignUpdate = NULL; functions.C_SignFinal = NULL; functions.C_Sign = NULL;
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions));
    current.version.major = 3; current.version.minor = API_MINOR;
    current.C_SessionCancel = verify_fault == 20 ? NULL : sf_cancel;
#if API_MINOR >= 2
    current.C_VerifySignatureInit = verify_fault == 6 ? NULL : sf_init;
    current.C_VerifySignature = verify_fault == 7 ? NULL : sf_single;
    current.C_VerifySignatureUpdate = verify_fault == 8 ? NULL : sf_update;
    current.C_VerifySignatureFinal = verify_fault == 9 ? NULL : sf_final;
#endif
#endif
    /* Keep callbacks referenced when testing an older table layout. */
    (void)sf_init; (void)sf_single; (void)sf_update; (void)sf_final;
    return CKR_OK;
}
