## Rules

This rule detects Amazon EBS snapshots being shared to external accounts.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.createVolumePermission.add.items[*]" as items nodrop
| where isNull(errorCode) and eventName = "ModifySnapshotAttribute"
| where !isNull(items)
```