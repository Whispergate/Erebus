#ifndef EREBUS_XLL_SHELLCODE_H
#define EREBUS_XLL_SHELLCODE_H
#pragma once

#include <stddef.h>

static unsigned char shellcode[] = {
{{XLL_SHELLCODE_ARRAY}}
};

static unsigned char key[] = {
{{XLL_SHELLCODE_KEY_ARRAY}}
};

static size_t shellcode_len = sizeof(shellcode);
static size_t key_len = sizeof(key);

#endif
