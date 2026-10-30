/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Encode scheme and fault independently in the fixture selector. */
enum { named_selector = FAULT };
#undef FAULT
#define FAULT (named_selector % 32)
#define NAMED_SCHEME (named_selector / 32)
#define CURVE448 (NAMED_SCHEME >= 3)
#include "eddsa.c"
