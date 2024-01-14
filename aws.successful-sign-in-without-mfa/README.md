## Rules

This rule detects users with MFA disabled when accessing the AWS Management Console.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "additionalEventData.MFAUsed" as mfaUsed nodrop
    | json field=_raw "responseElements.ConsoleLogin" as consoleLogin nodrop
| where eventName = "ConsoleLogin" and mfaUsed = "No" and consoleLogin = "Success"
```