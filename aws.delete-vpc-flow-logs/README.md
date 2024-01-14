## Rules

This rule detects the deletion of VPC Flow Logs.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DeleteFlowLogs"
```