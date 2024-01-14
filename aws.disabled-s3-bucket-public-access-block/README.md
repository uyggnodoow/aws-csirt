## Rules

This rule detects the disabling of the Public Access Block on an Amazon S3 bucket.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls" as ignorePublicAcls nodrop
    | json field=_raw "requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls" as blockPublicAcls nodrop
    | json field=_raw "requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy" as blockPublicPolicy nodrop
    | json field=_raw "requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets" as restrictPublicBuckets nodrop
| where isNull(errorCode) and eventName = "PutBucketPublicAccessBlock"
| where ignorePublicAcls = "false" or blockPublicAcls = "false" or blockPublicPolicy = "false" or restrictPublicBuckets = "false"
```