/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent EVP adapter using public test keys; emits ciphertext || tag. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
static unsigned char *read_file(const char *path,size_t maximum,int *length) {
    FILE *f=fopen(path,"rb"); if(!f || fseek(f,0,SEEK_END)) exit(2);
    long n=ftell(f);if(n<0 || (size_t)n>maximum || n>INT_MAX || fseek(f,0,SEEK_SET)) exit(2);
    unsigned char *p=malloc((size_t)n+1);if(!p || fread(p,1,(size_t)n,f)!=(size_t)n || fclose(f)) exit(2);
    *length=(int)n;return p;
}
int main(int argc,char **argv) {
    if(argc!=6) return 2;
    unsigned char key[32],nonce[12]; size_t bytes=strlen(argv[1])/2;
    if((bytes!=32) || strlen(argv[2])!=24) return 2;
    for(size_t i=0;i<bytes;++i) { unsigned int b;if(sscanf(argv[1]+2*i,"%2x",&b)!=1)return 2;key[i]=(unsigned char)b; }
    for(size_t i=0;i<12;++i) { unsigned int b;if(sscanf(argv[2]+2*i,"%2x",&b)!=1)return 2;nonce[i]=(unsigned char)b; }
    int an,mn,written,final;
    unsigned char *aad=read_file(argv[3],1048576,&an),*msg=read_file(argv[4],16777216,&mn),*ct=malloc((size_t)mn+16);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();const EVP_CIPHER *cipher=EVP_chacha20_poly1305();
    if(!ctx || !ct || EVP_EncryptInit_ex(ctx,cipher,NULL,NULL,NULL)!=1 || EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_IVLEN,12,NULL)!=1 || EVP_EncryptInit_ex(ctx,NULL,NULL,key,nonce)!=1 || (an && EVP_EncryptUpdate(ctx,NULL,&written,aad,an)!=1) || EVP_EncryptUpdate(ctx,ct,&written,msg,mn)!=1 || written!=mn || EVP_EncryptFinal_ex(ctx,ct+written,&final)!=1 || final || EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,ct+mn)!=1) return 3;
    FILE *f=fopen(argv[5],"wb");if(!f || fwrite(ct,1,(size_t)mn+16,f)!=(size_t)mn+16 || fclose(f)) return 4;
    EVP_CIPHER_CTX_free(ctx);free(aad);free(msg);free(ct);return 0;
}
