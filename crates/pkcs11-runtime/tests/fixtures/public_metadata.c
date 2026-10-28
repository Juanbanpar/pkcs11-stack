/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Optional public metadata through a legacy table, including hostile lengths. */
enum { metadata_fault = FAULT };
#undef FAULT
#define FAULT 0
#define OPAQUE_FUNCTION_LIST opaque_function_list
#include "opaque_metadata.c"
/* Valid SPKI DER with an unknown algorithm OID and opaque public bytes. */
static const CK_BYTE spki[] = {0x30,0x0c,0x30,0x06,0x06,0x04,0x2b,0x06,0x01,0x04,0x03,0x02,0x00,0x01};
static CK_RV public_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    CK_RV status = CKR_OK;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        CK_ULONG scalar = 0x80000001UL, length = sizeof(scalar);
        CK_BYTE bytes[sizeof(CK_ULONG)+1] = {0};
        const CK_BYTE *data = bytes;
        int variable = 0;
        switch (a->type) {
            case CKA_VALUE: return CKR_DEVICE_ERROR;
            case CKA_UNIQUE_ID: data = (const CK_BYTE *)"unique-id"; length = 9; variable = 1; break;
            case CKA_PUBLIC_KEY_INFO: data = spki; length = sizeof(spki); variable = 1; break;
            case CKA_OBJECT_VALIDATION_FLAGS: case CKA_VALIDATION_FLAG: break;
            case CKA_VALIDATION_VERSION: bytes[0] = 3; bytes[1] = 2; length = sizeof(CK_VERSION); break;
            case CKA_VALIDATION_LEVEL: scalar = 3; break;
            case CKA_VALIDATION_COUNTRY: data = (const CK_BYTE *)"US"; length = 2; variable = 1; break;
            case CKA_VALIDATION_MODULE_ID:
            case CKA_VALIDATION_CERTIFICATE_IDENTIFIER: case CKA_VALIDATION_PROFILE:
                data = (const CK_BYTE *)"provider-reported"; length = 17; variable = 1; break;
            case CKA_VALIDATION_CERTIFICATE_URI: case CKA_VALIDATION_VENDOR_URI:
                data = (const CK_BYTE *)"https://validation.invalid/untrusted"; length = 36; variable = 1; break;
            default: {
                CK_RV rv = metadata_attributes(s, h, a, 1);
                if (rv != CKR_OK) status = rv;
                continue;
            }
        }
        if (metadata_fault == 15 && h <= 6) return CKR_DEVICE_ERROR;
        if (metadata_fault >= 2 && metadata_fault <= 4) {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            if (metadata_fault != 4) status = metadata_fault == 2 ? CKR_ATTRIBUTE_SENSITIVE : CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        if (variable && metadata_fault == 1) length = 0;
        if (a->type != CKA_VALIDATION_VERSION && !variable) memcpy(bytes, &scalar, sizeof(scalar));
        if (a->type == CKA_UNIQUE_ID) {
            if (metadata_fault == 12) return CKR_DEVICE_ERROR;
            if (metadata_fault == 5) { a->ulValueLen = 65537; return CKR_OK; }
            if (metadata_fault == 14) {
                if (a->pValue) {
                    if (a->ulValueLen < 65536) return CKR_BUFFER_TOO_SMALL;
                    memset(a->pValue, 'A', 65536);
                }
                a->ulValueLen = 65536; continue;
            }
            if (a->pValue && (metadata_fault == 6 || metadata_fault == 7)) {
                a->ulValueLen += 1;
                return metadata_fault == 6 ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }
        }
        if (a->type == CKA_VALIDATION_VERSION && (metadata_fault == 8 || metadata_fault == 9)) length = metadata_fault == 8 ? 1 : 3;
        if (a->type == CKA_VALIDATION_FLAG && metadata_fault == 10) length -= 1;
        if (a->type == CKA_PUBLIC_KEY_INFO && metadata_fault == 11) { data = (const CK_BYTE *)"invalid"; length = 7; }
        if (a->pValue) {
            if (a->ulValueLen < length) { a->ulValueLen = length; return CKR_BUFFER_TOO_SMALL; }
            memcpy(a->pValue, data, length);
        }
        a->ulValueLen = length;
    }
    return status;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_FindObjectsInit = metadata_find_init;
    functions.C_FindObjects = metadata_find;
    functions.C_GetAttributeValue = public_attributes;
    *out = &functions; return CKR_OK;
}
