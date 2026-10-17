// Microsoft Sentinel: Repeated failed sign-in detection
//A Microsoft Sentinel KQL hunting query that identifies repeated failed sign-ins by user and source IP within hourly windows, providing authentication failure details and investigation context to support SOC triage and threat hunting.
let lookback = 24h;
let threshold = 5;
let timeWindow = 1h;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != "0"
| where isnotempty(UserPrincipalName) and isnotempty(IPAddress)
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    FailureReasons = make_set(ResultType, 10),
    FailureDescriptions = make_set(ResultDescription, 5),
    Applications = make_set(AppDisplayName, 5),
    Locations = make_set(Location, 5)
    by UserPrincipalName, IPAddress,
       TimeWindow = bin(TimeGenerated, timeWindow)
| where FailedAttempts >= threshold
| extend DurationMinutes =
    datetime_diff('minute', LastAttempt, FirstAttempt)
| project TimeWindow, UserPrincipalName, IPAddress,
    FailedAttempts, FirstAttempt, LastAttempt,
    DurationMinutes, FailureReasons, FailureDescriptions,
    Applications, Locations
| sort by FailedAttempts desc
