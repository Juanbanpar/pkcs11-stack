/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Official 3.2 parameter ABI on all four supported table versions; synthetic signatures. */
enum { slh_fault=FAULT%100, generation_fixture=FAULT>=100 };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static const CK_ULONG parameters[]={CKP_SLH_DSA_SHA2_128S,CKP_SLH_DSA_SHA2_128F,CKP_SLH_DSA_SHA2_192S,CKP_SLH_DSA_SHA2_192F,CKP_SLH_DSA_SHA2_256S,CKP_SLH_DSA_SHA2_256F,CKP_SLH_DSA_SHAKE_128S,CKP_SLH_DSA_SHAKE_128F,CKP_SLH_DSA_SHAKE_192S,CKP_SLH_DSA_SHAKE_192F,CKP_SLH_DSA_SHAKE_256S,CKP_SLH_DSA_SHAKE_256F};
static const CK_ULONG signature_sizes[]={7856,17088,16224,35664,29792,49856,7856,17088,16224,35664,29792,49856};
static const CK_ULONG public_sizes[]={32,32,48,48,64,64,32,32,48,48,64,64};
#if HASH_PROFILE
static const CK_MECHANISM_TYPE hash_mechanisms[]={CKM_HASH_SLH_DSA_SHA224,CKM_HASH_SLH_DSA_SHA256,CKM_HASH_SLH_DSA_SHA384,CKM_HASH_SLH_DSA_SHA512,CKM_HASH_SLH_DSA_SHA3_224,CKM_HASH_SLH_DSA_SHA3_256,CKM_HASH_SLH_DSA_SHA3_384,CKM_HASH_SLH_DSA_SHA3_512};
#if PREHASH
static const CK_MECHANISM_TYPE hashes[]={CKM_SHA224,CKM_SHA256,CKM_SHA384,CKM_SHA512,CKM_SHA3_224,CKM_SHA3_256,CKM_SHA3_384,CKM_SHA3_512};
static const CK_ULONG hash_lengths[]={28,32,48,64,28,32,48,64};
#endif
#define SIGN_MECHANISM (PREHASH ? CKM_HASH_SLH_DSA : hash_mechanisms[HASH_INDEX])
#define WRONG_MECHANISM CKM_SLH_DSA
#else
#define SIGN_MECHANISM CKM_SLH_DSA
#define WRONG_MECHANISM CKM_HASH_SLH_DSA
#endif
static CK_ULONG inits,completions,logins,generations;
static CK_OBJECT_CLASS wanted_class;
static int authenticated,generated,found;
static CK_RV slh_open(CK_SLOT_ID s, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    inits=completions=logins=generations=0;
    return open_session(s,flags,app,notify,out);
}
static CK_RV slh_info(CK_SESSION_HANDLE s, CK_SESSION_INFO_PTR out) {
    CK_RV rv=session_info(s,out); out->ulDeviceError=(generations<<24)|(inits<<16)|(logins<<8)|completions; return rv;
}
static CK_RV slh_mechanisms(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR out, CK_ULONG_PTR n) {
    (void)s; *n=slh_fault==1 ? 0 : 2;
    if(out && *n) { out[0]=SIGN_MECHANISM; out[1]=CKM_SLH_DSA_KEY_PAIR_GEN; } return CKR_OK;
}
static CK_RV slh_mechanism_info(CK_SLOT_ID s, CK_MECHANISM_TYPE m, CK_MECHANISM_INFO_PTR out) {
    (void)s; out->ulMinKeySize=public_sizes[PARAMETER]+(slh_fault==3); out->ulMaxKeySize=public_sizes[PARAMETER]-(slh_fault==4);
    out->flags=m==CKM_SLH_DSA_KEY_PAIR_GEN ? (slh_fault==31 ? 0 : CKF_GENERATE_KEY_PAIR) : (slh_fault==2 ? 0 : CKF_SIGN|CKF_VERIFY); return CKR_OK;
}
static CK_RV slh_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR a, CK_ULONG n) {
    (void)s; found=0; wanted_class=CKO_PRIVATE_KEY;
    for(CK_ULONG i=0;i<n;++i) if(a[i].type==CKA_CLASS) memcpy(&wanted_class,a[i].pValue,sizeof(wanted_class));
    return CKR_OK;
}
static CK_RV slh_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR h, CK_ULONG n, CK_ULONG_PTR count) {
    (void)s; (void)n;
    *count=found || (generation_fixture && !generated && slh_fault!=28) ? 0 : 1;
    if(*count) h[0]=wanted_class==CKO_PRIVATE_KEY ? 1 : 2;
    found=1; return CKR_OK;
}
static CK_RV slh_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR a, CK_ULONG n) {
    for(CK_ULONG i=0;i<n;++i) {
        CK_ULONG v=0,len=sizeof(v); CK_BBOOL boolean=0;
        switch(a[i].type) {
            case CKA_CLASS: v=h==1 ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY; break;
            case CKA_KEY_TYPE: v=slh_fault==14 ? CKK_ML_DSA : CKK_SLH_DSA; break;
            case CKA_PARAMETER_SET: v=slh_fault==13 ? ~0UL : parameters[(PARAMETER+(slh_fault==12))%12]; break;
            case CKA_ALLOWED_MECHANISMS: v=slh_fault==11 ? WRONG_MECHANISM : SIGN_MECHANISM; break;
            case CKA_SIGN: v=slh_fault!=9; len=sizeof(CK_BBOOL); break;
            case CKA_VERIFY: v=slh_fault!=10; len=sizeof(CK_BBOOL); break;
            case CKA_ALWAYS_AUTHENTICATE: v=AUTH; len=sizeof(CK_BBOOL); break;
            case CKA_PRIVATE: v=h==1 || slh_fault==35; len=sizeof(CK_BBOOL); break;
            case CKA_VALUE:
                if(h==1) return CKR_ATTRIBUTE_SENSITIVE;
                len=public_sizes[PARAMETER]+(slh_fault==33)-(slh_fault==34);
                if(a[i].pValue) { if(a[i].ulValueLen<len) return CKR_BUFFER_TOO_SMALL; memset(a[i].pValue,0x5A,len); }
                a[i].ulValueLen=len; continue;
            default: { CK_RV rv=attributes(s,h,&a[i],1); if(rv!=CKR_OK) return rv; continue; }
        }
        if(a[i].pValue) {
            if(a[i].ulValueLen<len) return CKR_BUFFER_TOO_SMALL;
            if(len==sizeof(CK_BBOOL)) { boolean=(CK_BBOOL)v; memcpy(a[i].pValue,&boolean,len); }
            else memcpy(a[i].pValue,&v,len);
        }
        a[i].ulValueLen=len;
    }
    return CKR_OK;
}
static CK_RV slh_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    (void)s; (void)h; ++inits;
    if(active || !m || m->mechanism!=SIGN_MECHANISM) return CKR_ARGUMENTS_BAD;
#if HASH_PROFILE && PREHASH
    if(!m->pParameter || m->ulParameterLen!=sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT)) return CKR_MECHANISM_PARAM_INVALID;
    CK_HASH_SIGN_ADDITIONAL_CONTEXT *p=m->pParameter;
    if(p->hash!=hashes[HASH_INDEX] || p->hedgeVariant!=HEDGE || p->ulContextLen!=CONTEXT_LENGTH || (!CONTEXT_LENGTH && p->pContext)) return CKR_MECHANISM_PARAM_INVALID;
    for(CK_ULONG i=0;i<p->ulContextLen;++i) if(p->pContext[i]!=0xA5) return CKR_MECHANISM_PARAM_INVALID;
#else
    if(HEDGE==CKH_HEDGE_PREFERRED && CONTEXT_LENGTH==0) {
        if(m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    } else {
        if(!m->pParameter || m->ulParameterLen!=sizeof(CK_SIGN_ADDITIONAL_CONTEXT)) return CKR_MECHANISM_PARAM_INVALID;
        CK_SIGN_ADDITIONAL_CONTEXT *p=m->pParameter;
        if(p->hedgeVariant!=HEDGE || p->ulContextLen!=CONTEXT_LENGTH || (!CONTEXT_LENGTH && p->pContext)) return CKR_MECHANISM_PARAM_INVALID;
        for(CK_ULONG i=0;i<p->ulContextLen;++i) if(p->pContext[i]!=0xA5) return CKR_MECHANISM_PARAM_INVALID;
    }
#endif
    if(slh_fault==16) return CKR_DEVICE_ERROR;
    active=1; authenticated=!AUTH; return CKR_OK;
}
static CK_RV slh_login(CK_SESSION_HANDLE s, CK_USER_TYPE type, CK_UTF8CHAR_PTR pin, CK_ULONG len) {
    (void)s; ++logins;
    if(!active || type!=CKU_CONTEXT_SPECIFIC || !pin || len!=8 || memcmp(pin,"12345678",8)) return CKR_ARGUMENTS_BAD;
    authenticated=1; return CKR_OK;
}
static int input_valid(CK_BYTE_PTR bytes, CK_ULONG n) {
#if HASH_PROFILE && PREHASH
    if(n!=hash_lengths[HASH_INDEX]) return 0;
    for(CK_ULONG i=0;i<n;++i) if(bytes[i]!=0xC7) return 0;
    return 1;
#else
    return n==0 || (n==3 && !memcmp(bytes,"abc",3));
#endif
}
static CK_RV slh_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s; ++completions;
    if(!active || !authenticated || !out || *written!=signature_sizes[PARAMETER]) return CKR_ARGUMENTS_BAD;
    if(!input_valid(bytes,n)) return CKR_DATA_INVALID;
    if(slh_fault==17) return CKR_DEVICE_ERROR;
    if(slh_fault==18) return CKR_BUFFER_TOO_SMALL;
    if(slh_fault==21) return CKR_PENDING;
    memset(out,0xAB,signature_sizes[PARAMETER]); active=0;
    *written=signature_sizes[PARAMETER]+(slh_fault==19)-(slh_fault==20); return CKR_OK;
}
static CK_RV slh_verify(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR sig, CK_ULONG len) {
    (void)s; ++completions;
    if(!active || !input_valid(bytes,n)) return CKR_ARGUMENTS_BAD;
    if(slh_fault==24) return CKR_DEVICE_ERROR;
    if(slh_fault==25) return CKR_PENDING;
    active=0;
    if(slh_fault==22) return CKR_SIGNATURE_INVALID;
    if(slh_fault==23 || len!=signature_sizes[PARAMETER]) return CKR_SIGNATURE_LEN_RANGE;
    for(CK_ULONG i=0;i<len;++i) if(sig[i]!=0xAB) return CKR_SIGNATURE_INVALID;
    return CKR_OK;
}
static int bool_attribute(CK_ATTRIBUTE_PTR a, CK_ULONG n, CK_ATTRIBUTE_TYPE type, CK_BBOOL value) {
    for(CK_ULONG i=0;i<n;++i) if(a[i].type==type) return a[i].ulValueLen==sizeof(value) && *(CK_BBOOL *)a[i].pValue==value;
    return 0;
}
static CK_RV slh_generate(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR pub, CK_ULONG pn, CK_ATTRIBUTE_PTR priv, CK_ULONG sn, CK_OBJECT_HANDLE_PTR ph, CK_OBJECT_HANDLE_PTR sh) {
    (void)s; ++generations;
    if(!m || m->mechanism!=CKM_SLH_DSA_KEY_PAIR_GEN || m->pParameter || m->ulParameterLen) return CKR_MECHANISM_PARAM_INVALID;
    if(!bool_attribute(pub,pn,CKA_VERIFY,1) || !bool_attribute(pub,pn,CKA_PRIVATE,0) || !bool_attribute(pub,pn,CKA_TOKEN,1) ||
       !bool_attribute(priv,sn,CKA_SIGN,1) || !bool_attribute(priv,sn,CKA_PRIVATE,1) || !bool_attribute(priv,sn,CKA_TOKEN,1) ||
       !bool_attribute(priv,sn,CKA_SENSITIVE,1) || !bool_attribute(priv,sn,CKA_EXTRACTABLE,0)) return CKR_TEMPLATE_INCONSISTENT;
    int parameter=0,allowed=0;
    for(CK_ULONG i=0;i<pn;++i) if(pub[i].type==CKA_PARAMETER_SET && pub[i].ulValueLen==sizeof(CK_ULONG) && *(CK_ULONG *)pub[i].pValue==parameters[PARAMETER]) parameter=1;
    for(CK_ULONG i=0;i<sn;++i) {
        if(priv[i].type==CKA_PARAMETER_SET || priv[i].type==CKA_VALUE || priv[i].type==CKA_SEED) return CKR_TEMPLATE_INCONSISTENT;
        if(priv[i].type==CKA_ALLOWED_MECHANISMS) {
#if HASH_PROFILE
            if(priv[i].ulValueLen==9*sizeof(CK_MECHANISM_TYPE)) {
                CK_MECHANISM_TYPE *m=priv[i].pValue;
                allowed=m[0]==CKM_HASH_SLH_DSA;
                for(CK_ULONG j=0;j<8;++j) if(m[j+1]!=hash_mechanisms[j]) allowed=0;
            }
#else
            if(priv[i].ulValueLen==sizeof(CK_MECHANISM_TYPE) && *(CK_MECHANISM_TYPE *)priv[i].pValue==CKM_SLH_DSA) allowed=1;
#endif
        }
    }
    if(!parameter || !allowed) return CKR_TEMPLATE_INCONSISTENT;
    if(slh_fault==29) return CKR_DEVICE_ERROR;
    generated=1; *ph=2; *sh=1; return CKR_OK;
}
static CK_RV slh_close(CK_SESSION_HANDLE s) { CK_RV rv=close_session(s); return slh_fault==26 ? CKR_DEVICE_ERROR : rv; }
static CK_RV slh_finalize(CK_VOID_PTR p) { CK_RV rv=finalize(p); return slh_fault==27 ? CKR_DEVICE_ERROR : rv; }
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
    CK_FUNCTION_LIST_PTR prefix; C_GetFunctionList(&prefix); *out=&standard; return CKR_OK;
}
#endif
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_OpenSession=slh_open; functions.C_GetSessionInfo=slh_info;
    functions.C_GetMechanismList=slh_mechanisms; functions.C_GetMechanismInfo=slh_mechanism_info;
    functions.C_FindObjectsInit=slh_find_init; functions.C_FindObjects=slh_find; functions.C_GetAttributeValue=slh_attributes;
    functions.C_Login=slh_fault==15 ? NULL : slh_login;
    functions.C_SignInit=slh_fault==5 ? NULL : slh_init; functions.C_Sign=slh_fault==6 ? NULL : slh_sign;
    functions.C_VerifyInit=slh_fault==7 ? NULL : slh_init; functions.C_Verify=slh_fault==8 ? NULL : slh_verify;
    functions.C_GenerateKeyPair=slh_fault==30 ? NULL : slh_generate;
    functions.C_CloseSession=slh_close; functions.C_Finalize=slh_finalize;
#if API_MAJOR>=3
    memcpy(&current,&functions,sizeof(functions)); current.version.major=3; current.version.minor=API_MINOR;
#endif
    *out=&functions; return CKR_OK;
}
