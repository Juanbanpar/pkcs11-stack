/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent EVP verification, including empty messages and binary contexts. */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>
static unsigned char *read_file(const char *path, size_t maximum, size_t *length) {
    FILE *file=fopen(path,"rb");
    if(!file || fseek(file,0,SEEK_END)) exit(2);
    long size=ftell(file);
    if(size<0 || (size_t)size>maximum || fseek(file,0,SEEK_SET)) exit(2);
    unsigned char *bytes=malloc((size_t)size+1);
    if(!bytes || fread(bytes,1,(size_t)size,file)!=(size_t)size || fclose(file)) exit(2);
    *length=(size_t)size; return bytes;
}
int main(int argc, char **argv) {
    if(argc!=5 && argc!=6) return 2;
    size_t der_len,sig_len,msg_len,ctx_len;
    unsigned char *der=read_file(argv[1],256,&der_len);
    unsigned char *sig=read_file(argv[2],49856,&sig_len);
    unsigned char *msg=read_file(argv[3],64*1024*1024,&msg_len);
    unsigned char *ctx=read_file(argv[4],255,&ctx_len);
    const unsigned char *cursor=der;
    EVP_PKEY *key=d2i_PUBKEY(NULL,&cursor,(long)der_len);
    EVP_MD_CTX *md=EVP_MD_CTX_new();
    int encoding=argc==6 ? 0 : 1;
    OSSL_PARAM params[]={OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,&encoding),OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,ctx,ctx_len),OSSL_PARAM_construct_end()};
    if(!key || cursor!=der+der_len || !md || EVP_DigestVerifyInit_ex(md,NULL,NULL,NULL,NULL,key,params)!=1) {
        ERR_print_errors_fp(stderr); return 3;
    }
    int result=EVP_DigestVerify(md,sig,sig_len,msg,msg_len);
    if(result!=1) ERR_print_errors_fp(stderr);
    EVP_MD_CTX_free(md); EVP_PKEY_free(key);
    free(ctx); free(msg); free(sig); free(der);
    return result==1 ? 0 : 1;
}
