# sysmon-eid1-detection-engineering

Detection engineering with Sysmon EID 1 in Splunk, including process baselining, LOLBin detections, and alert tuning.



\# Sysmon EID 1 Detection Engineering — Splunk



\## Overview

This repository documents a focused detection engineering experiment using \*\*Sysmon Event ID 1 (Process Creation)\*\* ingested into \*\*Splunk\*\*.  

The goal was to establish trusted endpoint telemetry, build a process creation baseline, and engineer low-noise detections for common Windows LOLBins.



This experiment emphasizes \*\*judgment, false-positive reduction, and alert operationalization\*\*, rather than quantity of detections.



---



\## Environment

\- Windows 10 Endpoint

\- Sysmon (Operational channel)

\- Splunk Enterprise

\- Splunk Universal Forwarder



Logs were ingested into Splunk and validated for consistency before detection development.



---



\## Telemetry Validation

\- Confirmed reliable ingestion of Sysmon Operational logs

\- Identified inconsistent default field extraction

\- Implemented \*\*search-time XML parsing\*\* using `rex` against raw event data

\- Extracted key fields:

&nbsp; - Image

&nbsp; - CommandLine

&nbsp; - ParentImage

&nbsp; - User

&nbsp; - ProcessId / ParentProcessId



This approach mirrors real-world scenarios where source parsing is imperfect.



---



\## Baseline Analysis

\- Built a noise-suppressed investigator view for process creation

\- Excluded Splunk Universal Forwarder binaries to reduce agent noise

\- Established a normal process execution baseline for the host



---



\## Detections Implemented



\### 1. Suspicious `rundll32.exe` Execution

\- Focus: LOLBin abuse via signed binary proxy execution

\- Technique: MITRE ATT\&CK T1218.011

\- Logic:

&nbsp; - Detect `rundll32.exe` process creation events

&nbsp; - Analyze full command-line context

&nbsp; - Suppress known-good Windows AppX ShellRefresh behavior

\- Outcome:

&nbsp; - Reduced false positives

&nbsp; - Operationalized as a scheduled Splunk alert

&nbsp; - Assigned \*\*Low severity\*\* due to benign-but-suspicious nature without corroboration



---



\### 2. Abnormal `dllhost.exe` Parent Process

\- Focus: COM surrogate abuse detection

\- Logic:

&nbsp; - Detect `dllhost.exe` executions

&nbsp; - Alert when spawned by unexpected parent processes

\- Outcome:

&nbsp; - Quiet baseline (0 results)

&nbsp; - Implemented as a guardrail detection

&nbsp; - Assigned \*\*Low severity\*\*



---



\## Alerting Strategy

\- Alerts are scheduled (not real-time)

\- Trigger on any result (`> 0`)

\- Throttled to reduce noise

\- Severity intentionally scoped based on signal strength and context



This reflects SOC best practices for early-stage behavioral detections.



---



\## Key Takeaways

\- Reliable detections often require \*\*search-time parsing\*\*, not perfect sourcetypes

\- LOLBins require \*\*contextual analysis\*\*, not binary name matching

\- Low-severity alerts can still provide high investigative value

\- Detection engineering is iterative and judgment-driven



---



\## Scope \& Next Steps

This experiment focused exclusively on \*\*Sysmon EID 1 process creation visibility\*\*.



Future experiments (out of scope for this repo):

\- Windows Security log authentication abuse

\- Network correlation (Sysmon EID 3)

\- Honeypot-based telemetry



---



\## Author

Detection engineering lab developed as part of a Blue Team Home Lab project.



