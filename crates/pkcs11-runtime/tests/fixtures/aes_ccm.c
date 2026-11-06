/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent CCM ABI, exact output capacity and native failure lifecycle. */
#if FAULT >= 1000
#define API_MAJOR 3
#if FAULT >= 3000
#define API_MINOR 2
#elif FAULT >= 2000
#define API_MINOR 1
#else
#define API_MINOR 0
#endif
#else
#define API_MAJOR 2
#define API_MINOR 40
#endif
enum { ccm_fault=FAULT%100,key_bytes=16+8*((FAULT/100)%10) };
#undef FAULT
#define FAULT 0
#define MAC_MECHANISM CKM_AES_CCM
#define MAC_TAG_LENGTH key_bytes
#define MAC_KEY_TYPE CKK_AES
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_ULONG inits, completions, declared;
static CK_RV ccm_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    out->ulDeviceError = (inits << 16) | completions;
    return rv;
}
static CK_RV ccm_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    if(ccm_fault==12) { *count=0; return CKR_OK; }
    return mechanisms(s,list,count);
}
static CK_RV ccm_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    CK_RV rv = mechanism_info(s,m,out);
    out->flags = (ccm_fault == 3 ? 0 : CKF_ENCRYPT) | (ccm_fault == 4 ? 0 : CKF_DECRYPT);
    out->ulMinKeySize = ccm_fault == 9 ? key_bytes+1 : 16;
    out->ulMaxKeySize = ccm_fault == 15 ? key_bytes-1 : 32; return rv;
}
static CK_RV ccm_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i=0; i<count; ++i) {
        CK_ATTRIBUTE_PTR a=&attrs[i]; CK_ULONG value, length=sizeof(value);
        switch(a->type) {
            case CKA_CLASS: value=ccm_fault == 5 ? CKO_PUBLIC_KEY : CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: value=ccm_fault == 6 ? CKK_GENERIC_SECRET : CKK_AES; break;
            case CKA_VALUE_LEN: value=ccm_fault == 7 ? 15 : key_bytes; break;
            case CKA_ALLOWED_MECHANISMS: value=ccm_fault == 8 ? CKM_AES_CMAC : CKM_AES_CCM; break;
            case CKA_ENCRYPT: value=ccm_fault != 1; length=sizeof(CK_BBOOL); break;
            case CKA_DECRYPT: value=ccm_fault != 2; length=sizeof(CK_BBOOL); break;
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

static CK_RV ccm_open(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    inits=completions=declared=0; return open_session(slot,flags,app,notify,out);
}
static CK_RV ccm_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits; completions=0;
    if(active || !m || m->mechanism!=CKM_AES_CCM || !m->pParameter || m->ulParameterLen!=sizeof(CK_CCM_PARAMS)) return CKR_MECHANISM_PARAM_INVALID;
    CK_CCM_PARAMS *p=m->pParameter;
    if(p->ulNonceLen!=12 || !p->pNonce || p->ulMACLen!=16 || p->ulAADLen!=0 || p->pAAD || (p->ulDataLen!=0 && p->ulDataLen!=3)) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=0;i<12;++i) if(p->pNonce[i]!=0xA5) return CKR_MECHANISM_PARAM_INVALID;
    if(ccm_fault==16) return CKR_DEVICE_ERROR;
    if(ccm_fault==25) p->pNonce[0]^=1;
    declared=p->ulDataLen; active=1; return CKR_OK;
}
static CK_RV complete(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written, int decrypt) {
    (void)s; ++completions;
    if(!active || completions!=1 || !out || n!=declared+(decrypt?16:0) || *written!=declared+(decrypt?0:16)) return CKR_ARGUMENTS_BAD;
    for(CK_ULONG i=0;i<declared;++i) if(bytes[i]!=(decrypt ? (((CK_BYTE *)"abc")[i]^0x80) : ((CK_BYTE *)"abc")[i])) return CKR_DATA_INVALID;
    memset(out,0xCB,*written);
    if(ccm_fault==17) return CKR_DEVICE_ERROR;
    if(ccm_fault==18) return CKR_BUFFER_TOO_SMALL;
    if(ccm_fault==19) return CKR_FUNCTION_NOT_SUPPORTED;
    if(ccm_fault==20) return CKR_ENCRYPTED_DATA_INVALID;
#if API_MAJOR>=3 && API_MINOR>=2
    if(ccm_fault==26) return CKR_PENDING;
#endif
    if(decrypt) {
        for(CK_ULONG i=declared;i<n;++i) if(bytes[i]!=0xEF) return CKR_ENCRYPTED_DATA_INVALID;
        memcpy(out,"abc",declared);
    } else {
        for(CK_ULONG i=0;i<n;++i) out[i]=bytes[i]^0x80;
        memset(out+n,0xEF,16);
    }
    if(ccm_fault==21) ++*written;
    if(ccm_fault==22) *written=(*written ? *written-1 : 1);
    active=0; return CKR_OK;
}
static CK_RV encrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR b, CK_ULONG n, CK_BYTE_PTR o, CK_ULONG_PTR l) { return complete(s,b,n,o,l,0); }
static CK_RV decrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR b, CK_ULONG n, CK_BYTE_PTR o, CK_ULONG_PTR l) { return complete(s,b,n,o,l,1); }
static CK_RV ccm_close(CK_SESSION_HANDLE s) { CK_RV rv=close_session(s);return ccm_fault==27?CKR_DEVICE_ERROR:rv; }
static CK_RV ccm_finalize(CK_VOID_PTR p) { CK_RV rv=finalize(p);return ccm_fault==28?CKR_DEVICE_ERROR:rv; }
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
#if API_MAJOR>=3
#if API_MINOR>=2
static CK_FUNCTION_LIST_3_2 current;
#else
static CK_FUNCTION_LIST_3_0 current;
#endif
static CK_INTERFACE standard={.pInterfaceName=(CK_UTF8CHAR_PTR)"PKCS 11",.pFunctionList=&current};
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR v, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if(!name || strcmp((char *)name,"PKCS 11") || !v || v->major!=3 || v->minor!=API_MINOR || flags) return CKR_FUNCTION_NOT_SUPPORTED;
    CK_FUNCTION_LIST_PTR prefix;C_GetFunctionList(&prefix);*out=&standard;return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_OpenSession=ccm_open; functions.C_CloseSession=ccm_close; functions.C_Finalize=ccm_finalize;
    functions.C_GetSessionInfo=ccm_info; functions.C_GetAttributeValue=ccm_attributes;functions.C_GetMechanismInfo=ccm_mechanism_info; functions.C_GetMechanismList=ccm_mechanisms;
    functions.C_EncryptInit=ccm_fault==10?NULL:ccm_init; functions.C_Encrypt=ccm_fault==11?NULL:encrypt;
    functions.C_DecryptInit=ccm_fault==13?NULL:ccm_init; functions.C_Decrypt=ccm_fault==14?NULL:decrypt;
#if API_MAJOR>=3
    memcpy(&current,&functions,sizeof(functions));current.version.major=3;current.version.minor=API_MINOR;
#endif
    *out=&functions;return CKR_OK;
}
