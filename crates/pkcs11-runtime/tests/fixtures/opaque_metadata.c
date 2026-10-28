/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Synthetic metadata and rejection fixture, using independent 3.2 headers. */
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_OBJECT_HANDLE matches[8];
static CK_ULONG match_count, cursor;
static CK_ULONG opaque_id(void) {
    return FAULT == 1 ? 0x80000001UL : FAULT == 2 ? ~(CK_ULONG)0 : 0x7FFF0001UL;
}
static CK_OBJECT_CLASS object_class(CK_OBJECT_HANDLE h) {
    switch (h) {
        case 1: return opaque_id();
        case 2: return CKO_PRIVATE_KEY;
        case 3: return CKO_PUBLIC_KEY;
        case 4: return CKO_SECRET_KEY;
        case 5: return CKO_CERTIFICATE;
        case 6: return CKO_DATA;
        case 7: return CKO_VALIDATION;
        default: return CKO_PROFILE;
    }
}
static CK_RV metadata_find_init(CK_SESSION_HANDLE s, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s; cursor = 0; match_count = 0;
    for (CK_OBJECT_HANDLE h = 1; h <= 8; ++h) {
        int accept = 1;
        for (CK_ULONG i = 0; i < count; ++i) {
            CK_ATTRIBUTE a = attrs[i];
            if (a.type == CKA_CLASS) accept &= a.ulValueLen == sizeof(CK_OBJECT_CLASS) && *(CK_OBJECT_CLASS *)a.pValue == object_class(h);
            else if (a.type == CKA_ID) accept &= a.ulValueLen == 1 && *(CK_BYTE *)a.pValue == h;
            else if (a.type == CKA_LABEL) {
                CK_BYTE label[] = "opaque-0"; label[7] = '0' + (CK_BYTE)h;
                accept &= a.ulValueLen == sizeof(label)-1 && !memcmp(a.pValue, label, sizeof(label)-1);
            }
            else if (a.type == CKA_TOKEN) accept &= a.ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL *)a.pValue == CK_TRUE;
            else accept = 0;
        }
        if (accept) matches[match_count++] = h;
    }
    return CKR_OK;
}
static CK_RV metadata_find(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE_PTR out, CK_ULONG maximum, CK_ULONG_PTR count) {
    (void)s; *count = 0;
    while (cursor < match_count && *count < maximum) out[(*count)++] = matches[cursor++];
    return CKR_OK;
}
static CK_RV metadata_attributes(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_PTR attrs, CK_ULONG count) {
    (void)s;
    if (h < 1 || h > 8) return CKR_OBJECT_HANDLE_INVALID;
    CK_RV status = CKR_OK;
    const CK_ATTRIBUTE_TYPE scalar_types[] = { CKA_CLASS, CKA_KEY_TYPE, CKA_CERTIFICATE_TYPE, CKA_PROFILE_ID, CKA_VALIDATION_TYPE, CKA_VALIDATION_AUTHORITY_TYPE };
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_ATTRIBUTE_PTR a = &attrs[i];
        CK_ULONG value = 0, length = sizeof(value);
        CK_BYTE bytes[sizeof(CK_ULONG)+1] = {0};
        CK_BYTE label[] = "opaque-0"; label[7] = '0' + (CK_BYTE)h;
        const CK_BYTE *data = bytes;
        int scalar = 1, boolean = 0;
        switch (a->type) {
            case CKA_CLASS: value = object_class(h); break;
            case CKA_KEY_TYPE: if (h < 2 || h > 4) goto unavailable; value = opaque_id(); break;
            case CKA_CERTIFICATE_TYPE: if (h != 5) goto unavailable; value = opaque_id(); break;
            case CKA_PROFILE_ID: if (h != 8) goto unavailable; value = opaque_id(); break;
            case CKA_VALIDATION_TYPE: case CKA_VALIDATION_AUTHORITY_TYPE:
                if (h != 7) goto unavailable;
                value = opaque_id(); break;
            case CKA_LABEL: data = label; length = sizeof(label)-1; scalar = 0; break;
            case CKA_ID: bytes[0] = (CK_BYTE)h; length = 1; scalar = 0; break;
            case CKA_TOKEN: case CKA_MODIFIABLE: case CKA_COPYABLE: case CKA_DESTROYABLE:
            case CKA_SIGN: case CKA_VERIFY: case CKA_ENCRYPT: case CKA_DECRYPT:
            case CKA_DERIVE: case CKA_WRAP: case CKA_UNWRAP: case CKA_SENSITIVE:
                value = 1; boolean = 1; break;
            case CKA_PRIVATE: case CKA_EXTRACTABLE: case CKA_ALWAYS_AUTHENTICATE:
            case CKA_TRUSTED: case CKA_WRAP_WITH_TRUSTED: boolean = 1; break;
            case CKA_VALUE_LEN: value = 32; break;
            case CKA_VALUE:
                /* Explicit public certificate/data export stays available. Other
                 * reads would cross the application's key-material boundary. */
                if (h != 5 && h != 6) return CKR_DEVICE_ERROR;
                data = (const CK_BYTE *)(h == 5 ? "opaque-certificate" : "public-data");
                length = (CK_ULONG)strlen((const char *)data); scalar = 0; break;
            default: goto unavailable;
        }
        if (FAULT == 15 && a->type == CKA_CLASS) return CKR_DEVICE_ERROR;
        if (boolean) {
            CK_BBOOL flag = value ? CK_TRUE : CK_FALSE;
            length = sizeof(flag); memcpy(bytes, &flag, length);
        } else if (scalar) {
            memcpy(bytes, &value, sizeof(value));
            if (FAULT >= 3 && FAULT <= 14 && a->type == scalar_types[(FAULT - 3) % 6]) {
                length = FAULT < 9 ? sizeof(value)-1 : sizeof(value)+1;
            }
        }
        if (a->pValue && a->ulValueLen < length) {
            a->ulValueLen = length;
            status = CKR_BUFFER_TOO_SMALL; continue;
        }
        if (a->pValue) memcpy(a->pValue, data, length);
        a->ulValueLen = length; continue;
    unavailable:
        a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        if (status == CKR_OK) status = CKR_ATTRIBUTE_TYPE_INVALID;
    }
    return status;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    functions.C_FindObjectsInit = metadata_find_init;
    functions.C_FindObjects = metadata_find;
    functions.C_GetAttributeValue = metadata_attributes;
    *out = &functions; return CKR_OK;
}
