## Rules

This rule detects database snapshots being shared to external accounts on the Amazon RDS.

```text
_sourceCategory=aws/cloudtrail
   | json field=_raw "responseElements.dBClusterSnapshotAttributes[0].attributeValues[0]" as attributeValues nodrop
| where isNull(errorCode) and eventName = "ModifyDBClusterSnapshotAttribute"
| where !isNull(attributeValues)
```