#ifndef EREBUS_GUARDRAIL_HPP
#define EREBUS_GUARDRAIL_HPP
#pragma once

#include <windows.h>

// Define a custom ErebusGuardrail() to gate execution. Return TRUE to allow.
static BOOL ErebusGuardrail(void) {
    return TRUE;
}

#endif
