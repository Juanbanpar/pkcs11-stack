/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent table/parameter ABI and lifecycle. Cipher bytes are synthetic. */
enum { gcm_fault = FAULT };
#undef FAULT
#define FAULT 0
#define MAC_MECHANISM CKM_AES_GCM
#define MAC_TAG_LENGTH KEY_BYTES
#define MAC_KEY_TYPE CKK_AES
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
#if API_MAJOR >= 3 && API_MINOR >= 2
#define GCM_PENDING CKR_PENDING
#else
/* Pending faults are exercised only with the 3.2 fixture. */
#define GCM_PENDING CKR_GENERAL_ERROR
#endif
static CK_ULONG inits, updates, finals, cancellations, input, emitted;
static CK_FLAGS direction;
static CK_BYTE ciphertext[19];
static CK_RV gcm_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    out->ulDeviceError = (inits << 24) | (updates << 16) | (finals << 8) | cancellations;
    return rv;
}
static CK_RV gcm_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    CK_RV rv = mechanism_info(s,m,out);
    out->flags = (gcm_fault == 3 ? 0 : CKF_ENCRYPT) | (gcm_fault == 4 ? 0 : CKF_DECRYPT);
    out->ulMinKeySize = gcm_fault == 9 ? KEY_BYTES+1 : 16; return rv;
}
static CK_RV gcm_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i=0; i<count; ++i) {
        CK_ATTRIBUTE_PTR a=&attrs[i]; CK_ULONG value, length=sizeof(value);
        switch(a->type) {
            case CKA_CLASS: value=gcm_fault == 5 ? CKO_PUBLIC_KEY : CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: value=gcm_fault == 6 ? CKK_GENERIC_SECRET : CKK_AES; break;
            case CKA_VALUE_LEN: value=gcm_fault == 7 ? 15 : KEY_BYTES; break;
            case CKA_ALLOWED_MECHANISMS: value=gcm_fault == 8 ? CKM_AES_CMAC : CKM_AES_GCM; break;
            case CKA_ENCRYPT: value=gcm_fault != 1; length=sizeof(CK_BBOOL); break;
            case CKA_DECRYPT: value=gcm_fault != 2; length=sizeof(CK_BBOOL); break;
            default: { CK_RV rv=attributes(s,h,a,1); if(rv != CKR_OK) return rv; continue; }
        }
        if(a->pValue) {
            if(a->ulValueLen<length) return CKR_BUFFER_TOO_SMALL;
            if(length==sizeof(CK_BBOOL)) *(CK_BBOOL *)a->pValue=(CK_BBOOL)value;
            else memcpy(a->pValue,&value,length);
        }
        a->ulValueLen=length;
    }
    return CKR_OK;
}
static CK_RV gcm_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits;
    if(active) return CKR_OPERATION_ACTIVE;
    if(!m || m->mechanism != CKM_AES_GCM || m->ulParameterLen != sizeof(CK_GCM_PARAMS) || !m->pParameter) return CKR_MECHANISM_INVALID;
    CK_GCM_PARAMS *p=m->pParameter;
    if(!p->pIv || p->ulIvLen != 12 || p->ulIvBits != 96 || p->ulTagBits != 128 || p->ulAADLen != AAD_LENGTH) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=0; i<12; ++i) if(p->pIv[i]!=0xA5) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=0; i<p->ulAADLen; ++i) if(p->pAAD[i]!=0xA6) return CKR_MECHANISM_PARAM_INVALID;
    if(gcm_fault == 16) return CKR_DEVICE_ERROR;
    if(gcm_fault == 32) return CKR_FUNCTION_NOT_SUPPORTED;
    if(gcm_fault == 25) p->pIv[0]^=1;
    active=1; input=0; emitted=0; return CKR_OK;
}
static CK_RV gcm_encrypt_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) { direction=CKF_ENCRYPT; return gcm_init(s,m,h); }
static CK_RV gcm_decrypt_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) { direction=CKF_DECRYPT; return gcm_init(s,m,h); }
static CK_RV gcm_update(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s; ++updates;
    if(!active || !out) return CKR_ARGUMENTS_BAD; /* NULL would be a forbidden size query. */
    if(gcm_fault == 17 || gcm_fault == 19 || gcm_fault == 26 || gcm_fault == 33 || (gcm_fault == 37 && input)) {
        memset(out,0xCA,*written);
        return (gcm_fault == 17 || gcm_fault == 37) ? CKR_DEVICE_ERROR : gcm_fault == 19 ? CKR_BUFFER_TOO_SMALL : gcm_fault == 26 ? GCM_PENDING : CKR_FUNCTION_NOT_SUPPORTED;
    }
    if(gcm_fault == 18) { ++*written; return CKR_OK; }
    if(direction==CKF_ENCRYPT) {
        if(input+n>3 || memcmp(bytes,"abc"+input,n)) return CKR_DATA_INVALID;
        if(*written<n) return CKR_BUFFER_TOO_SMALL;
        for(CK_ULONG i=0; i<n; ++i) out[i]=bytes[i]^0x80;
        *written=gcm_fault == 30 ? 0 : n;
        emitted+=*written;
    } else {
        if(input+n>19 || *written<input+n-emitted) return CKR_ARGUMENTS_BAD;
        memcpy(ciphertext+input,bytes,n);
        *written=0;
        if(gcm_fault == 38) { *written=n<4?n:4; memset(out,0xCC,*written); }
        if((gcm_fault == 24 || gcm_fault == 36 || gcm_fault == 37) && input+n>16) {
            *written=input+n-16-emitted;
            memcpy(out,"abc"+emitted,*written); emitted+=*written;
        }
    }
    input+=n; return CKR_OK;
}
static CK_RV gcm_final(CK_SESSION_HANDLE s, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s; ++finals;
    if(!active || !out) return CKR_ARGUMENTS_BAD;
    if(gcm_fault == 20 || gcm_fault == 23 || gcm_fault == 27 || gcm_fault == 34 || gcm_fault == 36) {
        memset(out,0xCB,*written);
        return gcm_fault == 20 ? CKR_DEVICE_ERROR : (gcm_fault == 23 || gcm_fault == 36) ? CKR_ENCRYPTED_DATA_INVALID : gcm_fault == 27 ? GCM_PENDING : CKR_FUNCTION_NOT_SUPPORTED;
    }
    if(gcm_fault == 21) { ++*written; return CKR_OK; }
    CK_ULONG expected;
    if(direction==CKF_ENCRYPT) {
        expected=input+16-emitted;
        if(*written != expected) return CKR_ARGUMENTS_BAD;
        for(CK_ULONG i=emitted; i<input; ++i) out[i-emitted]=((CK_BYTE *)"abc")[i]^0x80;
        memset(out+input-emitted,0xEF,16);
    } else {
        if(input!=16 && input!=19) return CKR_ENCRYPTED_DATA_LEN_RANGE;
        expected=input-16;
        for(CK_ULONG i=0; i<expected; ++i) if(ciphertext[i] != (((CK_BYTE *)"abc")[i]^0x80)) return CKR_ENCRYPTED_DATA_INVALID;
        for(CK_ULONG i=expected; i<input; ++i) if(ciphertext[i]!=0xEF) return CKR_ENCRYPTED_DATA_INVALID;
        if(*written<input-emitted) return CKR_ARGUMENTS_BAD;
        expected-=emitted;
        memcpy(out,"abc"+emitted,expected);
    }
    *written=gcm_fault == 22 ? (expected ? expected-1 : 1) : expected;
    active=0; return CKR_OK;
}
static CK_RV gcm_close(CK_SESSION_HANDLE s) {
    CK_RV rv=close_session(s);
    return gcm_fault == 39 ? CKR_DEVICE_ERROR : rv;
}
static CK_RV gcm_finalize(CK_VOID_PTR reserved) {
    CK_RV rv=finalize(reserved);
    return gcm_fault == 40 ? CKR_DEVICE_ERROR : rv;
}
static CK_RV gcm_legacy(CK_SESSION_HANDLE s) { (void)s; cancellations+=255; return CKR_GENERAL_ERROR; }
#if API_MAJOR >= 3
static CK_RV gcm_cancel(CK_SESSION_HANDLE s, CK_FLAGS flags) {
    (void)s; ++cancellations;
    if(!active || flags!=direction) return CKR_ARGUMENTS_BAD;
    if(gcm_fault == 28) return CKR_OPERATION_CANCEL_FAILED;
    if(gcm_fault == 35) return CKR_FUNCTION_NOT_SUPPORTED;
    active=0; return CKR_OK;
}
#if API_MINOR >= 2
static CK_FUNCTION_LIST_3_2 current;
#else
static CK_FUNCTION_LIST_3_0 current;
#endif
static CK_INTERFACE standard={.pInterfaceName=(CK_UTF8CHAR_PTR)"PKCS 11",.pFunctionList=&current};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if(!name || strcmp((char *)name,"PKCS 11") || !version || version->major!=3 || version->minor!=API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix); *out=&standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_CloseSession=gcm_close; functions.C_Finalize=gcm_finalize;
    functions.C_GetSessionInfo=gcm_info; functions.C_GetAttributeValue=gcm_attributes; functions.C_GetMechanismInfo=gcm_mechanism_info;
    functions.C_EncryptInit=gcm_fault == 10 ? NULL : gcm_encrypt_init;
    functions.C_EncryptUpdate=gcm_fault == 11 ? NULL : gcm_update;
    functions.C_EncryptFinal=gcm_fault == 12 ? NULL : gcm_final;
    functions.C_DecryptInit=gcm_fault == 13 ? NULL : gcm_decrypt_init;
    functions.C_DecryptUpdate=gcm_fault == 14 ? NULL : gcm_update;
    functions.C_DecryptFinal=gcm_fault == 15 ? NULL : gcm_final;
    functions.C_Encrypt=NULL; functions.C_Decrypt=NULL;
    functions.C_CancelFunction=gcm_legacy; functions.C_GetFunctionStatus=gcm_legacy;
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions)); current.version.major=3; current.version.minor=API_MINOR;
    current.C_SessionCancel=gcm_fault == 29 ? NULL : gcm_cancel;
#endif
    *out=&functions; return CKR_OK;
}
