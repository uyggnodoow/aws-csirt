## Rules

This rule detects when the log retention policy being updated is lower than the log retention policy defined by your organization.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.LifecycleConfiguration.Rule.Expiration.Days" as expiration nodrop
| where isNull(errorCode) and eventName = "PutBucketLifecycle" 
| where expiration < 730
```