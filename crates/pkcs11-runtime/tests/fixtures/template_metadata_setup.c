/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Provision a disposable SoftHSM key using independent native template layout. */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define NULL_PTR 0
#include "pkcs11.h"
#define CHECK(call) do { CK_RV rv = (call); if (rv != CKR_OK) { fprintf(stderr, #call ": 0x%lx\n", rv); return 1; } } while (0)
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (module == NULL) return 1;
    CK_C_GetFunctionList get_functions = (CK_C_GetFunctionList)dlsym(module, "C_GetFunctionList");
    if (get_functions == NULL) return 1;
    CK_FUNCTION_LIST_PTR f;
    CHECK(get_functions(&f));
    CHECK(f->C_Initialize(NULL_PTR));
    CK_SLOT_ID slots[64]; CK_ULONG count = 64;
    CHECK(f->C_GetSlotList(CK_TRUE, slots, &count));
    CK_SLOT_ID selected = 0; int found = 0;
    for (CK_ULONG i = 0; i < count; ++i) {
        CK_TOKEN_INFO info;
        CHECK(f->C_GetTokenInfo(slots[i], &info));
        if (memcmp(info.label, "client-test                     ", 32) == 0) { selected = slots[i]; found = 1; break; }
    }
    if (!found) return 1;
    CK_SESSION_HANDLE session;
    CHECK(f->C_OpenSession(selected, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session));
    CK_UTF8CHAR pin[] = "12345678";
    CHECK(f->C_Login(session, CKU_USER, pin, sizeof(pin)-1));
    CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY; CK_KEY_TYPE type = CKK_AES;
    CK_BYTE key[16] = {0}, id[] = {0xd8, 0x54, 0x4d};
    CK_UTF8CHAR label[] = "template-metadata-fixture";
    CK_ATTRIBUTE constraints[] = {
        {CKA_SENSITIVE, &yes, sizeof(yes)},
        {CKA_EXTRACTABLE, &no, sizeof(no)},
    };
    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &class, sizeof(class)}, {CKA_KEY_TYPE, &type, sizeof(type)},
        {CKA_TOKEN, &yes, sizeof(yes)}, {CKA_PRIVATE, &yes, sizeof(yes)},
        {CKA_SENSITIVE, &yes, sizeof(yes)}, {CKA_EXTRACTABLE, &no, sizeof(no)},
        {CKA_WRAP, &yes, sizeof(yes)}, {CKA_UNWRAP, &yes, sizeof(yes)},
        {CKA_VALUE, key, sizeof(key)}, {CKA_ID, id, sizeof(id)},
        {CKA_LABEL, label, sizeof(label)-1},
        {CKA_WRAP_TEMPLATE, constraints, sizeof(constraints)},
        {CKA_UNWRAP_TEMPLATE, NULL_PTR, 0},
    };
    CK_OBJECT_HANDLE object;
    CHECK(f->C_CreateObject(session, attrs, sizeof(attrs)/sizeof(attrs[0]), &object));
    CHECK(f->C_CloseSession(session));
    CHECK(f->C_Finalize(NULL_PTR));
    return dlclose(module) == 0 ? 0 : 1;
}
