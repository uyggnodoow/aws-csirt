## Rules

This rule detects logins for the Root user.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "userIdentity.type" as type nodrop
| where eventName = "ConsoleLogin" and type = "Root"
```