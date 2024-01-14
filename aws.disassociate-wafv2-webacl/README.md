## Rules

This rule detects the disassociation of WebACLs with AWS resources.

ex. Application LoadBalancer, Amazon API Gateway, Amazon Cognito user pool, etc. 

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DisassociateWebACL"
```