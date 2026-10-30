/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent OASIS 3.0 layout checks; signature bytes are synthetic. */
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
#ifndef CURVE448
#define CURVE448 0
#endif
static CK_OBJECT_CLASS selected_class;
static int authenticated;
static CK_RV ed_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR a, CK_ULONG n) {
    selected_class = CKO_PRIVATE_KEY;
    for (CK_ULONG i = 0; i < n; ++i) if (a[i].type == CKA_CLASS) memcpy(&selected_class,a[i].pValue,sizeof(selected_class));
    return find_init(s,a,n);
}
static CK_RV ed_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR n) {
    (void)s; if (out) out[0] = CKM_EDDSA; *n = 1; return CKR_OK;
}
static CK_RV ed_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; (void)m; out->ulMinKeySize = out->ulMaxKeySize = CURVE448 ? 448 : 255;
    if (FAULT == 21) out->ulMinKeySize = out->ulMaxKeySize = CURVE448 ? 449 : 256;
    out->flags = FAULT == 1 ? 0 : CKF_SIGN | CKF_VERIFY; return CKR_OK;
}
static CK_RV ed_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG n) {
    for (CK_ULONG i = 0; i < n; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        CK_ULONG value = 0, length = sizeof(value);
        CK_BBOOL flag;
        CK_BYTE params[] = {6,3,43,101,CURVE448 ? 113 : 112};
        CK_BYTE name25519[] = {0x13,12,'e','d','w','a','r','d','s','2','5','5','1','9'};
        CK_BYTE name448[] = {0x13,10,'e','d','w','a','r','d','s','4','4','8'};
        CK_BYTE point[59] = {4,CURVE448 ? 57 : 32};
        const void *data = &value;
        switch (a->type) {
            case CKA_CLASS: value = selected_class; break;
            case CKA_KEY_TYPE: value = FAULT == 17 ? CKK_EC_MONTGOMERY : CKK_EC_EDWARDS; break;
            case CKA_EC_PARAMS:
                if (FAULT == 15) { a->ulValueLen = 4097; continue; }
                if (FAULT == 11) params[4] = 110;
                data = params; length = sizeof(params);
#ifdef NAMED_SCHEME
                if (FAULT != 20 && FAULT != 11) { data = CURVE448 ? name448 : name25519; length = CURVE448 ? sizeof(name448) : sizeof(name25519); }
#else
                if (FAULT == 20) { data = CURVE448 ? name448 : name25519; length = CURVE448 ? sizeof(name448) : sizeof(name25519); }
#endif
                break;
            case CKA_EC_POINT:
                if (FAULT == 14) point[0] = 3;
                data = point; length = CURVE448 ? 59 : 34;
#ifdef NAMED_SCHEME
                if (FAULT != 14) { data = point+2; length -= 2; }
#endif
                break;
            case CKA_SIGN: value = FAULT != 12; length = sizeof(CK_BBOOL); break;
            case CKA_VERIFY: value = FAULT != 13; length = sizeof(CK_BBOOL); break;
            case CKA_ALWAYS_AUTHENTICATE:
                if (selected_class != CKO_PRIVATE_KEY) return CKR_ATTRIBUTE_TYPE_INVALID;
                value = CK_TRUE; length = sizeof(CK_BBOOL); break;
            case CKA_PRIVATE: value = selected_class == CKO_PRIVATE_KEY; length = sizeof(CK_BBOOL); break;
            case CKA_ALLOWED_MECHANISMS: value = FAULT == 16 ? CKM_ECDSA : CKM_EDDSA; break;
            default: {
                CK_RV rv = attributes(s,h,a,1); if (rv != CKR_OK) return rv; continue;
            }
        }
        flag = (CK_BBOOL)value;
        if (length == sizeof(flag)) data = &flag;
        if (a->pValue) {
            if (a->ulValueLen < length) return CKR_BUFFER_TOO_SMALL;
            memcpy(a->pValue,data,length);
        }
        a->ulValueLen = length;
    }
    return CKR_OK;
}
static CK_RV ed_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h;
    if (FAULT == 3) return CKR_DEVICE_ERROR;
    if (m->mechanism != CKM_EDDSA) return CKR_MECHANISM_INVALID;
#ifdef NAMED_SCHEME
    if (NAMED_SCHEME != 0) {
        if (!m->pParameter || m->ulParameterLen != sizeof(CK_EDDSA_PARAMS)) return CKR_MECHANISM_PARAM_INVALID;
        CK_EDDSA_PARAMS *p = m->pParameter;
        CK_ULONG context_length = FAULT == 24 ? 0 : FAULT == 25 ? 255 : 3;
        if (p->phFlag != (NAMED_SCHEME == 2 || NAMED_SCHEME == 4) || p->ulContextDataLen != context_length) return CKR_MECHANISM_PARAM_INVALID;
        if (!context_length) { if (p->pContextData) return CKR_MECHANISM_PARAM_INVALID; }
        else {
            if (!p->pContextData) return CKR_MECHANISM_PARAM_INVALID;
            for (CK_ULONG i = 0; i < context_length; ++i) if (p->pContextData[i] != 0xA5) return CKR_MECHANISM_PARAM_INVALID;
        }
    } else if (m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
#else
    if (CURVE448 && FAULT == 20) {
        if (!m->pParameter || m->ulParameterLen != sizeof(CK_EDDSA_PARAMS)) return CKR_MECHANISM_PARAM_INVALID;
        CK_EDDSA_PARAMS *p = m->pParameter;
        if (p->phFlag || p->ulContextDataLen || p->pContextData) return CKR_MECHANISM_PARAM_INVALID;
    } else if (m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
#endif
    authenticated = selected_class == CKO_PUBLIC_KEY; active = 1; return CKR_OK;
}
static CK_RV ed_login(CK_SESSION_HANDLE s, CK_USER_TYPE role, CK_UTF8CHAR_PTR pin, CK_ULONG length) {
    (void)s;
    if (!active || role != CKU_CONTEXT_SPECIFIC) return CKR_ARGUMENTS_BAD;
    if (length != 4 || memcmp(pin,"1234",4)) return CKR_PIN_INCORRECT;
    authenticated = 1; return CKR_OK;
}
static CK_RV ed_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR length) {
    (void)s;
    CK_ULONG expected = CURVE448 ? 114 : 64;
    if (!active || !authenticated) return CKR_USER_NOT_LOGGED_IN;
    if ((n != 0 && (n != 3 || memcmp(data,"abc",3))) || !out || *length != expected) return CKR_ARGUMENTS_BAD;
    if (FAULT == 4) return CKR_DEVICE_ERROR;
    if (FAULT == 6) { *length = expected + 1; return CKR_BUFFER_TOO_SMALL; }
    memset(out,0xAB,expected); *length = FAULT == 5 ? expected - 1 : FAULT == 7 ? expected + 1 : expected;
    active = 0; return CKR_OK;
}
static CK_RV ed_verify_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    if (FAULT == 9) return CKR_SIGNATURE_INVALID;
    return ed_init(s,m,h);
}
static CK_RV ed_verify(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG n, CK_BYTE_PTR sig, CK_ULONG length) {
    (void)s; (void)data; (void)n;
    if (!active || !authenticated) return CKR_OPERATION_NOT_INITIALIZED;
    active = 0;
    if (FAULT == 8) return CKR_DEVICE_ERROR;
    if (length != (CURVE448 ? 114 : 64)) return CKR_SIGNATURE_LEN_RANGE;
    for (CK_ULONG i = 0; i < length; ++i) if (sig[i] != 0xAB) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
#ifdef NAMED_SCHEME
static CK_RV ed_close(CK_SESSION_HANDLE h) { return FAULT == 23 ? CKR_DEVICE_ERROR : close_session(h); }
static CK_RV ed_finalize(CK_VOID_PTR p) { return FAULT == 24 ? CKR_DEVICE_ERROR : finalize(p); }
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetMechanismList = ed_mechanisms; functions.C_GetMechanismInfo = ed_info;
    functions.C_FindObjectsInit = ed_find_init; functions.C_GetAttributeValue = ed_attributes;
    functions.C_Login = FAULT == 22 ? NULL : ed_login; functions.C_SignInit = FAULT == 18 ? NULL : ed_init;
    functions.C_Sign = FAULT == 2 ? NULL : ed_sign;
    functions.C_VerifyInit = FAULT == 19 ? NULL : ed_verify_init; functions.C_Verify = FAULT == 10 ? NULL : ed_verify;
#ifdef NAMED_SCHEME
    functions.C_CloseSession = ed_close; functions.C_Finalize = ed_finalize;
#endif
    *out = &functions; return CKR_OK;
}
