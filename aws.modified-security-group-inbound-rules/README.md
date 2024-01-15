## Rules

This rule detects the creation or change of inbound rules for sensitive ports in the security group.

```text
_sourceCategory=aws/cloudtrail
   | json field=_raw "responseElements.securityGroupRuleSet.items[*].toPort" as port nodrop
| where isNull(errorCode) and eventName = "AuthorizeSecurityGroupIngress"
| where port contains "22" or port contains "389" or port contains "3389"
```

```text
_sourceCategory=aws/cloudtrail
   | json field=_raw "requestParameters.ModifySecurityGroupRulesRequest.SecurityGroupRule.SecurityGroupRule.ToPort" as port nodrop
| where isNull(errorCode) and eventName = "ModifySecurityGroupRules"
| where port contains "22" or port contains "389" or port contains "3389"
```