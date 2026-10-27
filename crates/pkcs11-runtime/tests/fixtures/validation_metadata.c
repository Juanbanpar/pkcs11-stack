/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent 3.2 headers exercise newer metadata through the legacy ABI. */
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static const CK_BYTE vendor_uri[] = "https://vendor.example/validation";
static CK_RV validation_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    CK_RV status = CKR_OK;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR attr = &attrs[i];
        if (attr->type != CKA_VALIDATION_VENDOR_URI) {
            CK_RV rv = attributes(s, h, attr, 1);
            if (rv != CKR_OK) return rv;
            continue;
        }
        if (FAULT == 4) return CKR_DEVICE_ERROR;
        if (FAULT == 2 || FAULT == 3) {
            attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            status = FAULT == 2 ? CKR_ATTRIBUTE_TYPE_INVALID : CKR_ATTRIBUTE_SENSITIVE;
            continue;
        }
        CK_ULONG length = FAULT == 1 ? 0 : sizeof(vendor_uri) - 1;
        if (attr->pValue && attr->ulValueLen < length) {
            attr->ulValueLen = length;
            return CKR_BUFFER_TOO_SMALL;
        }
        if (attr->pValue) memcpy(attr->pValue, vendor_uri, length);
        attr->ulValueLen = length;
    }
    return status;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_GetAttributeValue = validation_attributes;
    *out = &functions;
    return CKR_OK;
}
