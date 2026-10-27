/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#define MAC_MECHANISM CKM_SHA384_HMAC
#define MAC_KEY_TYPE CKK_SHA384_HMAC
#define MAC_TAG_LENGTH 48
#include "cmac.c"
