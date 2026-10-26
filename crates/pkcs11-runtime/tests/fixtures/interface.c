/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Compile against each version's unmodified OASIS headers. */
#include <stddef.h>
#include <string.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"
#ifndef FAULT
#define FAULT 0
#endif

static int initialized;
static CK_RV initialize(CK_VOID_PTR args) {
    CK_C_INITIALIZE_ARGS_PTR init = args;
    if (initialized) return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    if (!init || init->flags != CKF_OS_LOCKING_OK) return CKR_CANT_LOCK;
    initialized = 1;
    return CKR_OK;
}
static CK_RV finalize(CK_VOID_PTR reserved) {
    if (reserved) return CKR_ARGUMENTS_BAD;
    if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    initialized = 0;
    return CKR_OK;
}
static CK_RV info(CK_INFO_PTR out) {
    if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    memset(out, 0, sizeof(*out));
    memset(out->manufacturerID, ' ', sizeof(out->manufacturerID));
    memcpy(out->manufacturerID, "fixture", 7);
    memset(out->libraryDescription, ' ', sizeof(out->libraryDescription));
    memcpy(out->libraryDescription, "interface fixture", 17);
    out->cryptokiVersion.major = API_MAJOR;
    out->cryptokiVersion.minor = API_MINOR;
    return CKR_OK;
}
static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR list, CK_ULONG_PTR count) {
    (void)present;
    (void)list;
    if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    *count = 0;
    return CKR_OK;
}
#ifndef INTERFACE_ONLY
static CK_FUNCTION_LIST legacy = {
    .version = {FAULT == 17 ? 3 : 2, FAULT == 17 ? 2 : FAULT == 8 ? 20 : 40},
    .C_Initialize = FAULT == 15 ? NULL : initialize,
    .C_Finalize = FAULT == 9 ? NULL : finalize,
    .C_GetInfo = FAULT == 14 ? NULL : info,
    .C_GetSlotList = slots,
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    *out = FAULT == 7 ? NULL : &legacy;
    return CKR_OK;
}
#endif

#if API_MAJOR == 3
#if API_MINOR == 2
#define TABLE CK_FUNCTION_LIST_3_2
#else
#define TABLE CK_FUNCTION_LIST_3_0
#endif
static CK_RV cancel(CK_SESSION_HANDLE session, CK_FLAGS flags) {
    (void)session;
    (void)flags;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
#if API_MINOR == 2
static CK_RV encapsulate(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE public_key, CK_ATTRIBUTE_PTR attributes,
                        CK_ULONG count, CK_BYTE_PTR ciphertext, CK_ULONG_PTR length,
                        CK_OBJECT_HANDLE_PTR key) {
    (void)session; (void)mechanism; (void)public_key; (void)attributes;
    (void)count; (void)ciphertext; (void)length; (void)key;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
#if FAULT == 16
static CK_FUNCTION_LIST_3_0 older[2] = {
    {.version = {3, 0}, .C_Initialize = initialize, .C_Finalize = finalize,
     .C_GetInfo = info, .C_GetSlotList = slots, .C_SessionCancel = cancel},
    {.version = {3, 1}, .C_Initialize = initialize, .C_Finalize = finalize,
     .C_GetInfo = info, .C_GetSlotList = slots, .C_SessionCancel = cancel},
};
#endif
#endif
static TABLE current = {
    .version = {FAULT == 3 ? 4 : API_MAJOR, API_MINOR},
    .C_Initialize = FAULT == 15 ? NULL : initialize,
    .C_Finalize = FAULT == 9 ? NULL : finalize,
    .C_GetInfo = FAULT == 14 ? NULL : info,
    .C_GetSlotList = slots,
    .C_SessionCancel = cancel,
#if API_MINOR == 2
    .C_EncapsulateKey = encapsulate,
#endif
};
static CK_INTERFACE interface = {
    .pInterfaceName = (CK_UTF8CHAR_PTR)(FAULT == 4 ? "vendor" : "PKCS 11"),
    .pFunctionList = &current,
    .flags = CKF_INTERFACE_FORK_SAFE,
};
CK_RV C_GetInterface(CK_UTF8CHAR_PTR name, CK_VERSION_PTR version,
                     CK_INTERFACE_PTR_PTR out, CK_FLAGS flags) {
    if (FAULT == 5) return CKR_GENERAL_ERROR;
    if (FAULT == 6) return CKR_HOST_MEMORY;
    if (FAULT == 10) return CKR_FUNCTION_FAILED;
    if (FAULT == 11) return CKR_FUNCTION_NOT_SUPPORTED;
    /* A default query is deliberately unusable: callers must request a version. */
    if (!name || !version || flags || strcmp((char *)name, "PKCS 11") ||
        version->major != API_MAJOR)
        return CKR_FUNCTION_FAILED;
#if API_MINOR == 2 && FAULT == 16
    if (version->minor < 2) {
        interface.pFunctionList = &older[version->minor];
        *out = &interface;
        return CKR_OK;
    }
#endif
    if (version->minor != API_MINOR) return CKR_FUNCTION_FAILED;
    interface.pFunctionList = &current;
    if (FAULT == 2) interface.pFunctionList = NULL;
    if (FAULT == 13) interface.pInterfaceName = NULL;
    *out = FAULT == 1 ? NULL : &interface;
    return CKR_OK;
}
#endif
