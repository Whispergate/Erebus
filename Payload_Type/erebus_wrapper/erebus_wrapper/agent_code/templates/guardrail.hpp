#ifndef EREBUS_GUARDRAIL_HPP
#define EREBUS_GUARDRAIL_HPP
#pragma once

{% if guardrail_includes %}
{{ guardrail_includes }}
{% endif %}
#include <windows.h>

{% if guardrail_code %}
{{ guardrail_code }}
{% else %}
static BOOL ErebusGuardrail(void) {
    return TRUE;
}
{% endif %}

#endif
