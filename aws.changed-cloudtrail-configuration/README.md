## Rules

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "PutInsightSelectors"
```

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "responseElements.eventSelectors[0].dataResources[*]" as dataResources nodrop
| where isNull(errorCode) and eventName = "PutEventSelectors"
| where isNull(dataResources)
```

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "responseElements.eventSelectors[0].includeManagementEvents" as includeManagementEvents nodrop
| where isNull(errorCode) and eventName = "PutEventSelectors"
| where includeManagementEvents = "false"
```