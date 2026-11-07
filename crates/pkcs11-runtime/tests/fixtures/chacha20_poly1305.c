/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent ChaCha20-Poly1305 ABI, exact output capacity and native failure lifecycle. */
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
enum { cha_fault=FAULT%100,key_bytes=32,generation_fixture=((FAULT/100)%10)!=0 };
#undef FAULT
#define FAULT 0
#define MAC_MECHANISM CKM_CHACHA20_POLY1305
#define MAC_TAG_LENGTH key_bytes
#define MAC_KEY_TYPE CKK_CHACHA20
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_ULONG inits, completions, declared, generations;
static int generated;
static CK_RV cha_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv = session_info(s,out);
    out->ulDeviceError = (generations << 24) | (inits << 16) | completions;
    return rv;
}
static CK_RV cha_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
    (void)s; CK_ULONG n=0;
    if(cha_fault!=12) { if(list) list[n]=CKM_CHACHA20_POLY1305; ++n; }
    if(cha_fault!=35) { if(list) list[n]=CKM_CHACHA20_KEY_GEN; ++n; }
    *count=n; return CKR_OK;
}
static CK_RV cha_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; memset(out,0,sizeof(*out));
    if(m==CKM_CHACHA20_KEY_GEN) {
        out->flags=cha_fault==32?0:CKF_GENERATE;
        out->ulMinKeySize=cha_fault==33?33:32;
        out->ulMaxKeySize=cha_fault==34?31:32;
    } else {
        out->flags=(cha_fault==3?0:CKF_ENCRYPT)|(cha_fault==4?0:CKF_DECRYPT);
        /* Section 6.61 specifies no key-size units for AEAD; do not guess. */
        out->ulMinKeySize=out->ulMaxKeySize=cha_fault==9?256:cha_fault==15?0:32;
    }
    return CKR_OK;
}
static CK_RV cha_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    for (CK_ULONG i=0; i<count; ++i) {
        CK_ATTRIBUTE_PTR a=&attrs[i]; CK_ULONG value, length=sizeof(value);
        switch(a->type) {
            case CKA_CLASS: value=cha_fault == 5 ? CKO_PUBLIC_KEY : CKO_SECRET_KEY; break;
            case CKA_KEY_TYPE: value=cha_fault == 6 ? CKK_GENERIC_SECRET : CKK_CHACHA20; break;
            case CKA_VALUE_LEN: value=cha_fault == 7 ? 31 : key_bytes; break;
            case CKA_ALLOWED_MECHANISMS: value=cha_fault == 8 ? CKM_AES_CMAC : CKM_CHACHA20_POLY1305; break;
            case CKA_ENCRYPT: value=cha_fault != 1; length=sizeof(CK_BBOOL); break;
            case CKA_DECRYPT: value=cha_fault != 2; length=sizeof(CK_BBOOL); break;
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

static CK_RV cha_open(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    inits=completions=declared=generations=0; generated=0; return open_session(slot,flags,app,notify,out);
}
static CK_RV cha_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits; completions=0;
    if(active || !m || m->mechanism!=CKM_CHACHA20_POLY1305 || !m->pParameter || m->ulParameterLen!=sizeof(CK_SALSA20_CHACHA20_POLY1305_PARAMS)) return CKR_MECHANISM_PARAM_INVALID;
    CK_SALSA20_CHACHA20_POLY1305_PARAMS *p=m->pParameter;
    if(p->ulNonceLen!=96 || !p->pNonce || p->ulAADLen!=0 || p->pAAD) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=0;i<12;++i) if(p->pNonce[i]!=0xA5) return CKR_MECHANISM_PARAM_INVALID;
    if(cha_fault==16) return CKR_DEVICE_ERROR;
    if(cha_fault==25) p->pNonce[0]^=1;
    active=1; return CKR_OK;
}
static CK_RV complete(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written, int decrypt) {
    (void)s; ++completions;
    if(decrypt && n<16) return CKR_ARGUMENTS_BAD;
    declared=decrypt?n-16:n;
    if(declared!=0 && declared!=3) return CKR_ARGUMENTS_BAD;
    if(!active || completions!=1 || !out || n!=declared+(decrypt?16:0) || *written!=declared+(decrypt?0:16)) return CKR_ARGUMENTS_BAD;
    for(CK_ULONG i=0;i<declared;++i) if(bytes[i]!=(decrypt ? (((CK_BYTE *)"abc")[i]^0x80) : ((CK_BYTE *)"abc")[i])) return CKR_DATA_INVALID;
    memset(out,0xCB,*written);
    if(cha_fault==17) return CKR_DEVICE_ERROR;
    if(cha_fault==18) return CKR_BUFFER_TOO_SMALL;
    if(cha_fault==19) return CKR_FUNCTION_NOT_SUPPORTED;
    if(cha_fault==20) return CKR_ENCRYPTED_DATA_INVALID;
#if API_MAJOR>=3 && API_MINOR>=2
    if(cha_fault==26) return CKR_PENDING;
#endif
    if(decrypt) {
        for(CK_ULONG i=declared;i<n;++i) if(bytes[i]!=0xEF) return CKR_ENCRYPTED_DATA_INVALID;
        memcpy(out,"abc",declared);
    } else {
        for(CK_ULONG i=0;i<n;++i) out[i]=bytes[i]^0x80;
        memset(out+n,0xEF,16);
    }
    if(cha_fault==21) ++*written;
    if(cha_fault==22) *written=(*written ? *written-1 : 1);
    active=0; return CKR_OK;
}
static CK_RV encrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR b, CK_ULONG n, CK_BYTE_PTR o, CK_ULONG_PTR l) { return complete(s,b,n,o,l,0); }
static CK_RV decrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR b, CK_ULONG n, CK_BYTE_PTR o, CK_ULONG_PTR l) { return complete(s,b,n,o,l,1); }
static CK_RV cha_close(CK_SESSION_HANDLE s) { CK_RV rv=close_session(s);return cha_fault==27?CKR_DEVICE_ERROR:rv; }
static CK_RV cha_finalize(CK_VOID_PTR p) { CK_RV rv=finalize(p);return cha_fault==28?CKR_DEVICE_ERROR:rv; }
static CK_RV cha_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR a, CK_ULONG n) {
    return find_init(s,a,n);
}
static CK_RV cha_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR h, CK_ULONG n, CK_ULONG_PTR count) {
    if(!generation_fixture || generated || cha_fault==30) return find(s,h,n,count);
    (void)s; (void)h; (void)n; *count=0; return CKR_OK;
}
static CK_RV cha_generate(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR a, CK_ULONG n, CK_OBJECT_HANDLE_PTR h) {
    (void)s; ++generations; CK_ULONG required=0;
    if(!m || m->mechanism!=CKM_CHACHA20_KEY_GEN || m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=0;i<n;++i) {
        if(!a[i].pValue) return CKR_TEMPLATE_INCONSISTENT;
        CK_ULONG value=0;
        if(a[i].ulValueLen==sizeof(CK_ULONG)) memcpy(&value,a[i].pValue,sizeof(value));
        switch(a[i].type) {
            case CKA_CLASS: if(value!=CKO_SECRET_KEY) return CKR_TEMPLATE_INCONSISTENT; required|=1;break;
            case CKA_KEY_TYPE: if(value!=CKK_CHACHA20) return CKR_TEMPLATE_INCONSISTENT; required|=2;break;
            case CKA_VALUE_LEN: if(value!=32) return CKR_TEMPLATE_INCONSISTENT;required|=4;break;
            case CKA_ALLOWED_MECHANISMS: if(value!=CKM_CHACHA20_POLY1305 || a[i].ulValueLen!=sizeof(CK_MECHANISM_TYPE)) return CKR_TEMPLATE_INCONSISTENT;required|=8;break;
            case CKA_TOKEN: case CKA_PRIVATE: case CKA_SENSITIVE: case CKA_ENCRYPT: case CKA_DECRYPT:
                if(a[i].ulValueLen!=sizeof(CK_BBOOL) || *(CK_BBOOL *)a[i].pValue!=CK_TRUE) return CKR_TEMPLATE_INCONSISTENT;
                required|=a[i].type==CKA_TOKEN?16:a[i].type==CKA_PRIVATE?32:a[i].type==CKA_SENSITIVE?64:a[i].type==CKA_ENCRYPT?128:256;break;
            case CKA_EXTRACTABLE: case CKA_SIGN: case CKA_VERIFY: case CKA_WRAP: case CKA_UNWRAP: case CKA_DERIVE:
                if(a[i].ulValueLen!=sizeof(CK_BBOOL) || *(CK_BBOOL *)a[i].pValue!=CK_FALSE) return CKR_TEMPLATE_INCONSISTENT;
                required|=a[i].type==CKA_EXTRACTABLE?512:a[i].type==CKA_SIGN?1024:a[i].type==CKA_VERIFY?2048:a[i].type==CKA_WRAP?4096:a[i].type==CKA_UNWRAP?8192:16384;break;
            case CKA_ID: case CKA_LABEL:
                if(a[i].ulValueLen!=5 || memcmp(a[i].pValue,"fresh",5)) return CKR_TEMPLATE_INCONSISTENT;
                required|=a[i].type==CKA_ID?32768:65536;break;
            default:return CKR_TEMPLATE_INCONSISTENT;
        }
    }
    if(required!=131071) return CKR_TEMPLATE_INCOMPLETE;
    if(cha_fault==36) return CKR_DEVICE_ERROR;
    generated=1;*h=1;return CKR_OK;
}
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
    functions.C_OpenSession=cha_open; functions.C_CloseSession=cha_close; functions.C_Finalize=cha_finalize;
    functions.C_GetSessionInfo=cha_info; functions.C_GetAttributeValue=cha_attributes;functions.C_GetMechanismInfo=cha_mechanism_info; functions.C_GetMechanismList=cha_mechanisms;
    functions.C_FindObjectsInit=cha_find_init; functions.C_FindObjects=cha_find;
    functions.C_GenerateKey=cha_fault==31?NULL:cha_generate;
    functions.C_EncryptInit=cha_fault==10?NULL:cha_init; functions.C_Encrypt=cha_fault==11?NULL:encrypt;
    functions.C_DecryptInit=cha_fault==13?NULL:cha_init; functions.C_Decrypt=cha_fault==14?NULL:decrypt;
#if API_MAJOR>=3
    memcpy(&current,&functions,sizeof(functions));current.version.major=3;current.version.minor=API_MINOR;
#endif
    *out=&functions;return CKR_OK;
}
