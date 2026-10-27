/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#define MAC_MECHANISM CKM_SHA384_HMAC_GENERAL
#define MAC_KEY_TYPE CKK_SHA384_HMAC
#define MAC_TAG_LENGTH 48
#define MAC_MIN_TAG_LENGTH 24
#include "cmac_general.c"
