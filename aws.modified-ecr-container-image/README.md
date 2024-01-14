## Rules

This rule detects container images being updated in the Amazon ECR.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "PutImage"
```