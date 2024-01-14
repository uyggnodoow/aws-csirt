## Rules

This rule detects the deactivation of the Amazon GuardDuty.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DeleteDetector"
```

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.autoEnableOrganizationMembers" as autoEnableOrganizationMembers nodrop
| where isNull(errorCode) and eventName = "UpdateOrganizationConfiguration"
| where autoEnableOrganizationMembers = "NONE" 
```

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "StopMonitoringMembers"
```