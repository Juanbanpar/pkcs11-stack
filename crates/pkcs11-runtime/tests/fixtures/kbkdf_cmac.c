/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Reuse the independently compiled KDF layout, with no standalone MAC API. */
#define KDF_PRF CKM_AES_CMAC
#define KDF_KEY_TYPE CKK_AES
#define KDF_BLOCK_LENGTH 16
#define KDF_FUNCTION_LIST kbkdf_function_list
#include "kbkdf.c"
#undef C_GetFunctionList
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    CK_RV rv = kbkdf_function_list(out);
    functions.C_SignInit = NULL; functions.C_Sign = NULL;
    functions.C_VerifyInit = NULL; functions.C_Verify = NULL;
    return rv;
}
