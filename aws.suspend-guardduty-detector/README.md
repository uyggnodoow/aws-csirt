## Rules

This rule detects the Amazon GuardDuty being stopped.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.enable" as enable nodrop
| where isNull(errorCode) and eventName = "UpdateDetector"
| where enable = "false"
```