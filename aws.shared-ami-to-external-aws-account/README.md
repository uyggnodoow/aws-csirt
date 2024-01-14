## Rules

This rule detects AMI images being shared to external accounts.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.launchPermission.add.items[*]" as items nodrop
| where isNull(errorCode) and eventName = "ModifyImageAttribute"
| where !isNull(items)
```