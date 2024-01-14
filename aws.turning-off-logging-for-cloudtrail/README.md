## Rules

This rule detects that logging stops on Amazon CloudTrail.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "StopLogging"
```