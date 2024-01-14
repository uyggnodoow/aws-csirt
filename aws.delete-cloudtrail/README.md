## Rules

This rule detects Amazon CloudTrail (Trail) deletion.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DeleteTrail"
```