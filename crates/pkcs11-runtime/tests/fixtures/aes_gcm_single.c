/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Exact single-part capacity, one completion call, no output-size query. */
enum { single_fault = FAULT };
#undef FAULT
#define FAULT 0
#define KEY_BYTES 16
#define AAD_LENGTH 0
#define API_MAJOR 2
#define API_MINOR 40
#define GCM_FUNCTION_LIST stream_function_list
#include "aes_gcm_stream.c"
#undef GCM_FUNCTION_LIST
static CK_RV single_init(CK_SESSION_HANDLE s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE h) {
    if (single_fault == 1) return CKR_DEVICE_ERROR;
    CK_RV rv = gcm_encrypt_init(s,m,h);
    if (rv == CKR_OK && single_fault == 6) ((CK_GCM_PARAMS *)m->pParameter)->pIv[0] ^= 1;
    return rv;
}
static CK_RV single_encrypt(CK_SESSION_HANDLE s, CK_BYTE_PTR bytes, CK_ULONG n, CK_BYTE_PTR out, CK_ULONG_PTR written) {
    (void)s; ++updates;
    if (!active || updates != 1 || !out || *written != n+16) return CKR_ARGUMENTS_BAD;
    if (n != 0 && (n != 3 || memcmp(bytes,"abc",3))) return CKR_DATA_INVALID;
    if (single_fault == 2 || single_fault == 3) return single_fault == 2 ? CKR_DEVICE_ERROR : CKR_BUFFER_TOO_SMALL;
    for (CK_ULONG i=0;i<n;++i) out[i] = bytes[i]^0x80;
    memset(out+n,0xEF,16);
    if (single_fault == 4) ++*written;
    if (single_fault == 5) --*written;
    active=0; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    CK_RV rv=stream_function_list(out);
    functions.C_EncryptInit=single_fault == 8 ? NULL : single_init;
    functions.C_Encrypt=single_fault == 7 ? NULL : single_encrypt;
    return rv;
}
