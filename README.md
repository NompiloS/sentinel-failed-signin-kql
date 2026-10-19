# Microsoft Sentinel: Repeated Failed Sign-in Detection

## Project Overview

This project demonstrates how Microsoft Sentinel, Azure Log Analytics, and Kusto Query Language (KQL) can be used to identify repeated failed sign-in attempts and support security operations centre (SOC) investigations.

The goal is to identify user accounts experiencing multiple authentication failures from the same source IP address and provide relevant information for further investigation.

## Tools and Technologies

- Microsoft Sentinel
- Microsoft Entra ID sign-in logs
- Azure Log Analytics
- Kusto Query Language (KQL)
- GitHub

## Detection Query

The following query searches the previous 24 hours of Microsoft Entra ID sign-in logs for five or more
failed sign-in attempts associated with the same user account and source IP address.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where isnotempty(tostring(ResultType))
| where tostring(ResultType) != "0"
| where isnotempty(UserPrincipalName)
| where isnotempty(IPAddress)
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    FailureReasons = make_set(ResultType, 10),
    FailureDescriptions = make_set(ResultDescription, 5),
    Applications = make_set(AppDisplayName, 5),
    Locations = make_set(Location, 5)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| project
    UserPrincipalName,
    IPAddress,
    FailedAttempts,
    FirstAttempt,
    LastAttempt,
    FailureReasons,
    FailureDescriptions,
    Applications,
    Locations
| sort by FailedAttempts desc
```

## Detection Logic

| Setting | Description |
|---|---|
| Data source | `SigninLogs` |
| Lookback period | Previous 24 hours |
| Failure condition | Result type is not `0` |
| Threshold | Five or more failed sign-ins |
| Grouping | User principal name and source IP address |
| Output | Failure count, timestamps, failure details, applications, and locations |

The query excludes successful sign-ins and groups the remaining events by user and source IP address. It returns only groups that meet the five-failure threshold.

**Important:** This query aggregates failures across the entire 24-hour lookback period. It does not require the failures to occur within a one-hour window. Authentication failures should also be reviewed to distinguish suspicious activity from legitimate causes, such as incorrect passwords or expired credentials.

## Investigation Workflow

When the query identifies a matching user/IP pair, a SOC analyst can:

1. Review the affected account and source IP address.
2. Examine the timestamps and frequency of authentication failures.
3. Investigate the failure codes and descriptions to understand why authentication failed.
4. Check for successful sign-ins before and after the failed attempts.
5. Review the applications and locations associated with the activity.
6. Correlate the findings with other security alerts and available identity logs.
7. Document the evidence, assess the risk, and escalate suspected account compromise according to incident response procedures.

## Testing and Validation

The query was tested against the available Microsoft Sentinel lab environment.

### Initial Test Results

| Metric | Result |
|---|---:|
| Total sign-ins | 4 |
| Failed sign-ins | 0 |
| Successful sign-ins | 4 |
| Detection results | No matching events |

The initial test returned four successful sign-ins and no failed sign-ins in the previous 24 hours. Therefore, the detection query had no qualifying events to return.

**Validation status:** The basic query syntax has executed successfully, but the detection logic still requires testing against authorised data containing failed sign-in events. The threshold and output should be verified before this query is used operationally.

## Limitations

- The `SigninLogs` table must contain relevant authentication events for the query's lookback period.
- The query depends on the availability and completeness of sign-in log data.
- Five failed attempts is an illustrative threshold and may require tuning to suit the environment.
- Events are grouped by user and source IP address. Attempts distributed across multiple IP addresses are evaluated separately.
- The query aggregates failures over 24 hours and does not implement a rolling one-hour detection window.
- A failed sign-in does not automatically indicate a brute-force attack or compromised account.
- The query is a hunting example, not a validated production detection or deployed Sentinel analytics rule.

## Skills Demonstrated

- KQL query development
- Microsoft Sentinel and Log Analytics
- Authentication log analysis
- Failed sign-in investigation
- Security alert triage
- Threat hunting fundamentals
- Evidence documentation and incident escalation

## References

- [Microsoft Learn: SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft Learn: Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/kusto/query/)
- [Microsoft Learn: Detect threats with analytics rules in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)

## Project Status

**Status:** Learning lab / demonstration.

The query has executed against the available lab data, but detection validation remains outstanding. Further testing with authorised data containing failed sign-in events is required.

All examples published in this repository should use sanitised or fictional data. Do not publish real user credentials, email addresses, tenant identifiers, access tokens, or sensitive sign-in records.
