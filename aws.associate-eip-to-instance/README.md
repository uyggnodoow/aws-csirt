## Rules

This rule detects EIP that associate to an instance.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "AssociateAddress"
```