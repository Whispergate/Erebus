#ifndef EREBUS_GUARDRAIL_HPP
#define EREBUS_GUARDRAIL_HPP
#pragma once

{% if guardrail_includes %}
{{ guardrail_includes }}
{% endif %}
#include <windows.h>

{% if use_builtin_guardrails %}
#include "../include/guardrails/guardrails.hpp"

static BOOL ErebusGuardrail(void) {
    erebus::guardrails::GuardrailConfig config = erebus::guardrails::GetDefaultConfig();
    
    {% if check_debugger %}
    config.check_debugger_present = true;
    {% endif %}
    {% if check_remote_debugger %}
    config.check_remote_debugger = true;
    {% endif %}
    {% if check_debugger_processes %}
    config.check_debugger_processes = true;
    {% endif %}
    {% if check_hardware_breakpoints %}
    config.check_hardware_breakpoints = true;
    {% endif %}
    {% if check_timing %}
    config.check_timing_checks = true;
    {% endif %}
    
    {% if allowed_hostnames %}
    static const char* allowed_hosts[] = {
        {% for host in allowed_hostnames %}
        "{{ host }}",
        {% endfor %}
    };
    config.allowed_hostnames = allowed_hosts;
    config.hostname_count_allowed = sizeof(allowed_hosts) / sizeof(allowed_hosts[0]);
    {% endif %}
    
    {% if blocked_hostnames %}
    static const char* blocked_hosts[] = {
        {% for host in blocked_hostnames %}
        "{{ host }}",
        {% endfor %}
    };
    config.blocked_hostnames = blocked_hosts;
    config.hostname_count_blocked = sizeof(blocked_hosts) / sizeof(blocked_hosts[0]);
    {% endif %}
    
    {% if blocked_usernames %}
    static const char* blocked_users[] = {
        {% for user in blocked_usernames %}
        "{{ user }}",
        {% endfor %}
    };
    config.blocked_usernames = blocked_users;
    config.username_count_blocked = sizeof(blocked_users) / sizeof(blocked_users[0]);
    {% endif %}
    
    {% if allowed_ips %}
    static const char* allowed_ip_ranges[] = {
        {% for ip in allowed_ips %}
        "{{ ip }}",
        {% endfor %}
    };
    config.allowed_ips = allowed_ip_ranges;
    config.ip_count_allowed = sizeof(allowed_ip_ranges) / sizeof(allowed_ip_ranges[0]);
    {% endif %}
    
    {% if blocked_ips %}
    static const char* blocked_ip_ranges[] = {
        {% for ip in blocked_ips %}
        "{{ ip }}",
        {% endfor %}
    };
    config.blocked_ips = blocked_ip_ranges;
    config.ip_count_blocked = sizeof(blocked_ip_ranges) / sizeof(blocked_ip_ranges[0]);
    {% endif %}
    
    {% if allowed_domains %}
    static const char* allowed_domain_list[] = {
        {% for domain in allowed_domains %}
        "{{ domain }}",
        {% endfor %}
    };
    config.allowed_domains = allowed_domain_list;
    config.domain_count_allowed = sizeof(allowed_domain_list) / sizeof(allowed_domain_list[0]);
    {% endif %}
    
    erebus::guardrails::CheckResult result = erebus::guardrails::RunGuardrails(config);
    return result.passed ? TRUE : FALSE;
}
{% elif guardrail_code %}
{{ guardrail_code }}
{% else %}
static BOOL ErebusGuardrail(void) {
    return TRUE;
}
{% endif %}

#endif

