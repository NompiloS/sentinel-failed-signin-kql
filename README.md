# sentinel-failed-signin-kql
// Repeated failed sign-ins per user and IP
let lookback = 24h;
let threshold = 5;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != "0"
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    FailureReasons = make_set(ResultType, 10),
    Applications = make_set(AppDisplayName, 5),
    Locations = make_set(Location, 5)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= threshold
| extend DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| sort by FailedAttempts desc
