/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Independent 3.2 ABI and same-session last-operation semantics. */
enum { validation_fault = FAULT };
#undef FAULT
#define FAULT 0
#define C_GetFunctionList base_function_list
#include "cmac.c"
#undef C_GetFunctionList
static CK_FLAGS last_flags[16];
static CK_SESSION_HANDLE next_session;
static CK_RV validation_open(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR out) {
    CK_RV rv = open_session(slot, flags, app, notify, out);
    if (rv != CKR_OK) return rv;
    if (next_session >= 15) return CKR_SESSION_COUNT;
    *out = ++next_session; last_flags[*out] = 0; return CKR_OK;
}
static CK_RV validation_sign(CK_SESSION_HANDLE s, CK_BYTE_PTR data, CK_ULONG length, CK_BYTE_PTR out, CK_ULONG_PTR size) {
    CK_RV rv = sign(s, data, length, out, size);
    if (rv == CKR_OK) last_flags[s] = validation_fault == 5 ? ~(CK_FLAGS)0 : 0x80000001UL;
    return rv;
}
static CK_RV validation_flags(CK_SESSION_HANDLE s, CK_SESSION_VALIDATION_FLAGS_TYPE type, CK_FLAGS_PTR out) {
    if (s < 1 || s > next_session || type != CKS_LAST_VALIDATION_OK || !out) return CKR_ARGUMENTS_BAD;
    if (validation_fault == 2) return CKR_FUNCTION_NOT_SUPPORTED;
    if (validation_fault == 3) return CKR_DEVICE_ERROR;
    if (validation_fault == 7) return CKR_GENERAL_ERROR;
    *out = validation_fault == 4 ? 0 : last_flags[s];
    return CKR_OK;
}
static CK_FUNCTION_LIST_3_2 current = {
    .version = {3,2}, .C_Initialize = initialize, .C_Finalize = finalize,
    .C_GetInfo = info, .C_GetSlotList = slots, .C_GetSlotInfo = slot_info, .C_GetTokenInfo = token,
    .C_GetMechanismList = mechanisms, .C_GetMechanismInfo = mechanism_info,
    .C_OpenSession = validation_open, .C_CloseSession = close_session, .C_GetSessionInfo = session_info,
    .C_FindObjectsInit = find_init, .C_FindObjects = find, .C_FindObjectsFinal = find_final,
    .C_GetAttributeValue = attributes, .C_SignInit = sign_init, .C_Sign = validation_sign,
    .C_GetSessionValidationFlags = validation_flags,
};
static CK_FUNCTION_LIST_3_0 older = {
    .version = {3,0}, .C_Initialize = initialize, .C_Finalize = finalize,
    .C_GetInfo = info, .C_GetSlotList = slots, .C_GetSlotInfo = slot_info, .C_GetTokenInfo = token,
    .C_GetMechanismList = mechanisms, .C_GetMechanismInfo = mechanism_info,
    .C_OpenSession = validation_open, .C_CloseSession = close_session, .C_GetSessionInfo = session_info,
    .C_FindObjectsInit = find_init, .C_FindObjects = find, .C_FindObjectsFinal = find_final,
    .C_GetAttributeValue = attributes, .C_SignInit = sign_init, .C_Sign = validation_sign,
};
static CK_INTERFACE current_interface = {
    .pInterfaceName = (CK_UTF8CHAR_PTR)"PKCS 11", .pFunctionList = &current,
};
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if (validation_fault == 6) return CKR_FUNCTION_NOT_SUPPORTED;
    if (validation_fault == 8 || validation_fault == 9) {
        CK_BYTE minor = validation_fault == 8 ? 0 : 1;
        if (!version || version->major != 3 || version->minor != minor) return CKR_FUNCTION_NOT_SUPPORTED;
        older.version.minor = minor; current_interface.pFunctionList = &older;
        *out = &current_interface; return CKR_OK;
    }
    if (!name || !version || flags || strcmp((char *)name, "PKCS 11") || version->major != 3 || version->minor != 2) return CKR_FUNCTION_NOT_SUPPORTED;
    if (validation_fault == 1) current.C_GetSessionValidationFlags = NULL;
    *out = &current_interface; return CKR_OK;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    *out = &functions; return CKR_OK;
}
