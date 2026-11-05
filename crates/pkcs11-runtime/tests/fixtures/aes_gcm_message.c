/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent message parameter ABI, exact bounds and lifecycle; synthetic bytes. */
enum { message_fault = FAULT };
#undef FAULT
#define FAULT 0
#define KEY_BYTES 16
#define AAD_LENGTH 0
#define API_MAJOR CRYPTOKI_VERSION_MAJOR
#define API_MINOR CRYPTOKI_VERSION_MINOR
#define GCM_FUNCTION_LIST stream_function_list
#define C_GetInterface stream_get_interface
#include "aes_gcm_stream.c"
#undef C_GetInterface
static CK_RV message_open(CK_SLOT_ID s, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    inits=updates=finals=0;
    return open_session(s,flags,app,notify,out);
}
static CK_RV message_close(CK_SESSION_HANDLE s) {
    CK_RV rv=close_session(s);
    return message_fault == 29 ? CKR_DEVICE_ERROR : rv;
}
static CK_RV message_finalize(CK_VOID_PTR reserved) {
    CK_RV rv=finalize(reserved);
    return message_fault == 30 ? CKR_DEVICE_ERROR : rv;
}
static CK_RV message_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    CK_RV rv=gcm_mechanism_info(s,m,out);
#if API_MAJOR >= 3
    out->flags=(message_fault == 1 || message_fault == 27 ? 0 : CKF_MESSAGE_ENCRYPT) |
               (message_fault == 2 || message_fault == 27 ? 0 : CKF_MESSAGE_DECRYPT);
#endif
    if(message_fault != 26) out->flags |= CKF_ENCRYPT | CKF_DECRYPT;
    if(message_fault == 19) out->ulMinKeySize=17;
    return rv;
}
static CK_RV message_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    CK_RV rv=gcm_attributes(s,h,attrs,count);
    for(CK_ULONG i=0; i<count; ++i) {
        CK_ATTRIBUTE_PTR a=&attrs[i];
        if(!a->pValue) continue;
        if((message_fault == 20 && a->type == CKA_ENCRYPT) ||
           (message_fault == 21 && a->type == CKA_DECRYPT)) *(CK_BBOOL *)a->pValue=CK_FALSE;
        if(message_fault == 22 && a->type == CKA_ALLOWED_MECHANISMS) *(CK_MECHANISM_TYPE *)a->pValue=CKM_AES_CMAC;
        if(message_fault == 23 && a->type == CKA_CLASS) *(CK_ULONG *)a->pValue=CKO_PUBLIC_KEY;
        if(message_fault == 24 && a->type == CKA_KEY_TYPE) *(CK_ULONG *)a->pValue=CKK_GENERIC_SECRET;
        if(message_fault == 25 && a->type == CKA_VALUE_LEN) *(CK_ULONG *)a->pValue=15;
    }
    return rv;
}
#if API_MAJOR >= 3
static CK_RV message_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; ++inits;
    if(active || h != 1 || !m || m->mechanism != CKM_AES_GCM || m->pParameter || m->ulParameterLen) return CKR_ARGUMENTS_BAD;
    if(message_fault == 9) return CKR_DEVICE_ERROR;
    active=1; return CKR_OK;
}
static CK_RV message_encrypt_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    direction=CKF_ENCRYPT; return message_init(s,m,h);
}
static CK_RV message_decrypt_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    direction=CKF_DECRYPT; return message_init(s,m,h);
}
static CK_RV message_complete(CK_SESSION_HANDLE s, CK_VOID_PTR params, CK_ULONG params_len,
    CK_BYTE_PTR aad, CK_ULONG aad_len, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s; ++updates;
    if(!active || !params || params_len != sizeof(CK_GCM_MESSAGE_PARAMS) || !out || *written != n) return CKR_ARGUMENTS_BAD;
    CK_GCM_MESSAGE_PARAMS *p=params;
    if(!p->pIv || p->ulIvLen != 12 || p->ulIvFixedBits || p->ivGenerator != CKG_NO_GENERATE || !p->pTag || p->ulTagBits != 128) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=1;i<12;++i) if(p->pIv[i] != 0xA5) return CKR_MECHANISM_PARAM_INVALID;
    if(aad_len != 2 || memcmp(aad,"\0\xFF",2)) return CKR_DATA_INVALID;
    if(n != 0 && n != 3) return CKR_DATA_LEN_RANGE;
    if(direction == CKF_ENCRYPT) {
        if(n && memcmp(bytes,"abc",3)) return CKR_DATA_INVALID;
        for(CK_ULONG i=0;i<n;++i) out[i]=bytes[i]^0x80;
        memset(p->pTag,0xEF,16);
    } else {
        for(CK_ULONG i=0;i<n;++i) if(bytes[i] != (((CK_BYTE *)"abc")[i]^0x80)) return CKR_ENCRYPTED_DATA_INVALID;
        for(CK_ULONG i=0;i<16;++i) if(p->pTag[i] != 0xEF) return CKR_ENCRYPTED_DATA_INVALID;
        memcpy(out,"abc",n);
        if(message_fault == 15) p->pTag[0]^=1;
    }
    if(message_fault == 10 || (message_fault == 28 && updates == 2)) return CKR_DEVICE_ERROR;
    if(message_fault == 11) return CKR_BUFFER_TOO_SMALL;
    if(message_fault == 12) ++*written;
    if(message_fault == 13) *written=n ? n-1 : 1;
    if(message_fault == 14) p->pIv[0]^=1;
    if(message_fault == 17) return GCM_PENDING;
    if(message_fault == 18) return CKR_FUNCTION_NOT_SUPPORTED;
    return CKR_OK;
}
static CK_RV message_final(CK_SESSION_HANDLE s) {
    (void)s; ++finals;
    if(!active) return CKR_OPERATION_NOT_INITIALIZED;
    if(message_fault == 16) return CKR_DEVICE_ERROR;
    active=0; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if(!name || strcmp((char *)name,"PKCS 11") || !version || version->major != 3 || version->minor != API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix); *out=&standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    CK_RV rv=stream_function_list(out);
    functions.C_OpenSession=message_open;
    functions.C_CloseSession=message_close;
    functions.C_Finalize=message_finalize;
    functions.C_GetMechanismInfo=message_info;
    functions.C_GetAttributeValue=message_attributes;
    /* Ordinary and multipart pointers do not establish message support. */
    functions.C_EncryptInit=NULL; functions.C_DecryptInit=NULL;
#if API_MAJOR >= 3
    memcpy(&current,&functions,sizeof(functions));
    current.version.major=3; current.version.minor=API_MINOR;
    current.C_MessageEncryptInit=message_fault == 3 ? NULL : message_encrypt_init;
    current.C_EncryptMessage=message_fault == 4 ? NULL : message_complete;
    current.C_MessageEncryptFinal=message_fault == 5 ? NULL : message_final;
    current.C_MessageDecryptInit=message_fault == 6 ? NULL : message_decrypt_init;
    current.C_DecryptMessage=message_fault == 7 ? NULL : message_complete;
    current.C_MessageDecryptFinal=message_fault == 8 ? NULL : message_final;
#endif
    return rv;
}
