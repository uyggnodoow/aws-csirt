## Rules

This rule detects the disabling of Public Access Block when creating a DB instance.

```text
_sourceCategory=aws/cloudtrail
   | json field=_raw "responseElements.publiclyAccessible" as publiclyAccessible nodrop
| where isNull(errorCode) and eventName = "CreateDBInstance"
| where publiclyAccessible = "true"
```