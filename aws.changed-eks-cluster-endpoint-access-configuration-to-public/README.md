## Rules

This rule detects updating the configuration for an Amazon EKS cluster endpoint to make it publicly accessible.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "requestParameters.resourcesVpcConfig.endpointPublicAccess" as endpointPublicAccess
| where isNull(errorCode) and eventSource = "eks.amazonaws.com" and eventName = "UpdateClusterConfig" 
| where endpointPublicAccess = "true"
```