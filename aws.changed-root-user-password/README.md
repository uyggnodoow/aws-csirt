## Rules

This rule detects password changes for the Root user.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "userIdentity.type" as type nodrop
| where eventName = "ChangePassword" and type = "Root"
```