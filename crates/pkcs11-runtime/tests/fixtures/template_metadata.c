/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Structural reads only: leaf pointers must always remain NULL. */
enum { template_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static unsigned template_calls;
static CK_RV fill_template(CK_ATTRIBUTE_PTR a, unsigned depth) {
    CK_ULONG count = depth == 1 ? (template_fault == 25 ? 128 : 8) : depth == 2 ? 2 : 1;
    CK_ULONG bytes = count * sizeof(CK_ATTRIBUTE);
    if (template_fault == 7 && depth == 1) bytes = 129 * sizeof(CK_ATTRIBUTE);
    if (template_fault == 6 && depth == 1) bytes = 65537;
    if ((template_fault == 5 && depth == 1) || (template_fault == 8 && depth == 2)) ++bytes;
    if (template_fault == 9 && depth == 2) bytes = 128 * sizeof(CK_ATTRIBUTE);
    if (a->pValue == NULL_PTR) { a->ulValueLen = bytes; return CKR_OK; }
    if (a->ulValueLen != bytes) return CKR_ARGUMENTS_BAD;
    a->ulValueLen = bytes;
    CK_ATTRIBUTE_PTR members = a->pValue;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR member = &members[i];
        CK_ATTRIBUTE_TYPE type = CKA_CLASS;
        CK_ULONG length = sizeof(CK_OBJECT_CLASS);
        int nested = 0;
        if (depth == 1 && template_fault != 25) {
            switch (i) {
                case 0: type = CKA_SENSITIVE; length = sizeof(CK_BBOOL); break;
                case 1: type = CKA_VALUE; length = 32; break;
                case 2: type = 0x7fff0001UL; length = ~(CK_ULONG)0 - 1; break;
                case 3: type = ~(CK_ULONG)0; length = 0; break;
                case 4: type = CKA_ALLOWED_MECHANISMS; length = sizeof(CK_MECHANISM_TYPE); break;
                case 5: type = CKA_UNWRAP_TEMPLATE; nested = 1; break;
                case 6: type = CKA_PRIVATE_EXPONENT; length = CK_UNAVAILABLE_INFORMATION; break;
                default: type = CKA_DERIVE_TEMPLATE; length = 0; break;
            }
        } else if (depth == 2 && i == 1) {
            type = CKA_DERIVE_TEMPLATE; nested = 1;
        } else if ((template_fault == 10 && depth < 5) || (template_fault == 26 && depth < 4)) {
            type = CKA_WRAP_TEMPLATE; nested = 1;
        }
        if (template_fault == 24 && depth == 1 && i == 2) type = CKF_ARRAY_ATTRIBUTE | 0x80000001UL;
        if (template_fault == 12 && template_calls >= 3 && depth == 1 && i == 1) ++length;
        if (template_fault == 13 && template_calls >= 3 && depth == 1 && i == 1) type = CKA_LABEL;
        member->type = type;
        if (nested) {
            CK_RV rv = fill_template(member, depth + 1);
            if (rv != CKR_OK) return rv;
            if (template_fault == 21 && template_calls >= 3 && depth == 1) ++member->ulValueLen;
            if (template_fault == 16 && member->pValue != NULL_PTR) member->pValue = (CK_VOID_PTR)1;
        } else {
            if (member->pValue != NULL_PTR) return CKR_DEVICE_ERROR;
            member->ulValueLen = length;
            if (template_fault == 15 && i == 1) member->pValue = (CK_VOID_PTR)1;
        }
    }
    return CKR_OK;
}
static CK_RV template_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    CK_ATTRIBUTE_PTR a = attrs;
    if (a->type != CKA_WRAP_TEMPLATE && a->type != CKA_UNWRAP_TEMPLATE && a->type != CKA_DERIVE_TEMPLATE)
        return attributes(s, h, attrs, count);
    if (count != 1) return CKR_ARGUMENTS_BAD;
    if (++template_calls > 5) return CKR_DEVICE_ERROR;
    if (template_fault >= 2 && template_fault <= 4) {
        a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return template_fault == 2 ? CKR_ATTRIBUTE_SENSITIVE : template_fault == 3 ? CKR_ATTRIBUTE_TYPE_INVALID : CKR_OK;
    }
    if (template_fault == 1) { a->ulValueLen = 0; return CKR_OK; }
    if (template_fault == 17) return CKR_DEVICE_ERROR;
    if (template_fault == 18 || template_fault == 27) {
        a->ulValueLen = CK_UNAVAILABLE_INFORMATION; return CKR_BUFFER_TOO_SMALL;
    }
    if (template_fault == 11 && template_calls > 1) { ++a->ulValueLen; return CKR_OK; }
    if (template_fault == 14) { a->pValue = (CK_VOID_PTR)1; return CKR_OK; }
    if (template_fault == 20) { a->type = CKA_VALUE; return CKR_OK; }
    CK_RV rv = fill_template(a, 1);
    if (template_calls > 1 && (template_fault == 22 || template_fault == 23))
        return template_fault == 22 ? CKR_ATTRIBUTE_SENSITIVE : CKR_ATTRIBUTE_TYPE_INVALID;
    return rv;
}
static CK_RV template_close(CK_SESSION_HANDLE s) {
    return template_fault == 30 ? CKR_DEVICE_ERROR : close_session(s);
}
static CK_RV template_finalize(CK_VOID_PTR reserved) {
    return template_fault == 31 ? CKR_DEVICE_ERROR : finalize(reserved);
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetAttributeValue = template_attributes;
    functions.C_CloseSession = template_close;
    functions.C_Finalize = template_finalize;
    *out = &functions; return CKR_OK;
}
