## Rules

This rule detects the creation of an Amazon EKS cluster endpoint with public access enabled.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.resourcesVpcConfig.endpointPublicAccess" as endpointPublicAccess
| where isNull(errorCode) and eventSource = "eks.amazonaws.com" and eventName = "CreateCluster"
| where endpointPublicAccess = "true"
```