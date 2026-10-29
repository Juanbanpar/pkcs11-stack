/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Change descriptors without touching any storage through corrupted pointers. */
enum { pointer_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_RV pointer_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        if (a->type != CKA_LABEL) {
            rv = attributes(s, h, a, 1);
            if (rv != CKR_OK) return rv;
            if (a->type == CKA_CLASS && pointer_fault == 0) a->pValue = (CK_VOID_PTR)1;
            if (a->type == CKA_CLASS && pointer_fault == 1) a->type = CKA_KEY_TYPE;
            continue;
        }
        if (a->pValue != NULL_PTR) {
            if (a->ulValueLen < 8) return CKR_BUFFER_TOO_SMALL;
            memcpy(a->pValue, "metadata", 8);
            if (pointer_fault == 2) a->pValue = (CK_VOID_PTR)1;
            if (pointer_fault == 3) a->type = CKA_VALUE;
            if (pointer_fault == 4) { a->pValue = NULL_PTR; a->ulValueLen = 0; continue; }
            if (pointer_fault == 8) {
                a->pValue = (CK_VOID_PTR)1;
                a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
                rv = CKR_ATTRIBUTE_SENSITIVE; continue;
            }
        }
        a->ulValueLen = 8;
        if (pointer_fault == 5 || pointer_fault == 6) {
            a->pValue = (CK_VOID_PTR)1;
            if (pointer_fault == 6) { a->ulValueLen = CK_UNAVAILABLE_INFORMATION; rv = CKR_ATTRIBUTE_SENSITIVE; }
        }
    }
    return rv;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetAttributeValue = pointer_attributes;
    *out = &functions; return CKR_OK;
}
