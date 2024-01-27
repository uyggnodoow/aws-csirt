## Rules

This rule detects changes to the database master user password for the Amazon RDS.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "responseElements.pendingModifiedValues.masterUserPassword" as masterUserPassword nodrop
| where isNull(errorCode) and eventName = "ModifyDBCluster"
| where !isNull(masterUserPassword)
```