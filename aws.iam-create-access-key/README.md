## Rules

This rule detects access key generation in the AWS IAM.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "CreateAccessKey"
```