/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Execute the nonce-bit contract on the isolated provider, without persistent keys. */
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(r,n) r n
#define CK_DECLARE_FUNCTION(r,n) r n
#define CK_DECLARE_FUNCTION_POINTER(r,n) r (*n)
#define CK_CALLBACK_FUNCTION(r,n) r (*n)
#define NULL_PTR 0
#include "pkcs11.h"
#define OK(call) do { CK_RV rv=(call); if(rv!=CKR_OK) { fprintf(stderr,"%s: %lx\n",#call,rv);return 1; } } while(0)
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!lib) return 2;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=dlsym(lib,"C_GetFunctionList");CK_FUNCTION_LIST_PTR f;
    if(!get) return 2;
    OK(get(&f));CK_C_INITIALIZE_ARGS init={0};init.flags=CKF_OS_LOCKING_OK;OK(f->C_Initialize(&init));
    CK_SESSION_HANDLE session;OK(f->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&session));
    CK_UTF8CHAR pin[]="12345678";OK(f->C_Login(session,CKU_USER,pin,8));
    CK_OBJECT_CLASS cls=CKO_SECRET_KEY;CK_KEY_TYPE kind=CKK_CHACHA20;CK_BBOOL yes=1,no=0;
    CK_BYTE value[32]={0},nonce[12]={0},tag[16],empty[1];
    CK_ATTRIBUTE attrs[]={{CKA_CLASS,&cls,sizeof(cls)},{CKA_KEY_TYPE,&kind,sizeof(kind)},{CKA_TOKEN,&no,1},{CKA_PRIVATE,&yes,1},{CKA_VALUE,value,32},{CKA_SENSITIVE,&yes,1},{CKA_EXTRACTABLE,&no,1},{CKA_ENCRYPT,&yes,1},{CKA_DECRYPT,&yes,1}};
    CK_OBJECT_HANDLE key;OK(f->C_CreateObject(session,attrs,sizeof(attrs)/sizeof(attrs[0]),&key));
    CK_SALSA20_CHACHA20_POLY1305_PARAMS params={nonce,12,NULL,0};
    CK_MECHANISM mechanism={CKM_CHACHA20_POLY1305,&params,sizeof(params)};
    if(f->C_EncryptInit(session,&mechanism,key)!=CKR_MECHANISM_PARAM_INVALID) return 3;
    if(f->C_DecryptInit(session,&mechanism,key)!=CKR_MECHANISM_PARAM_INVALID) return 3;
    params.ulNonceLen=96;OK(f->C_EncryptInit(session,&mechanism,key));CK_ULONG written=16;
    OK(f->C_Encrypt(session,empty,0,tag,&written));if(written!=16) return 4;
    OK(f->C_DecryptInit(session,&mechanism,key));written=0;
    OK(f->C_Decrypt(session,tag,16,empty,&written));if(written) return 4;
    OK(f->C_DestroyObject(session,key));OK(f->C_CloseSession(session));OK(f->C_Finalize(NULL));dlclose(lib);return 0;
}
