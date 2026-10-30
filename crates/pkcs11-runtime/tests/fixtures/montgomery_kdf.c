/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Four exact key profiles, eight KDFs, six protected outputs. */
enum { kd_case = FAULT / 40 };
#define X_KDF_TEST 1
#if FAULT / 40 / 48 == 0
#define X_BITS 255
#define X_LENGTH 32
#define X_BASE 9
#define X_PARAMS {6,3,43,101,110}
#define X_OTHER_PARAMS {0x13,10,'c','u','r','v','e','2','5','5','1','9'}
#elif FAULT / 40 / 48 == 1
#define X_BITS 448
#define X_LENGTH 56
#define X_BASE 5
#define X_PARAMS {6,3,43,101,111}
#define X_OTHER_PARAMS {0x13,8,'c','u','r','v','e','4','4','8'}
#elif FAULT / 40 / 48 == 2
#define X_BITS 255
#define X_LENGTH 32
#define X_BASE 9
#define X_PARAMS {0x13,10,'c','u','r','v','e','2','5','5','1','9'}
#define X_OTHER_PARAMS {6,3,43,101,110}
#else
#define X_BITS 448
#define X_LENGTH 56
#define X_BASE 5
#define X_PARAMS {0x13,8,'c','u','r','v','e','4','4','8'}
#define X_OTHER_PARAMS {6,3,43,101,111}
#endif
#include "x25519.c"
