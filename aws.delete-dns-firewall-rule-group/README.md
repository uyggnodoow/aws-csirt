## Rules

This rule detects the deletion of a DNS Firewall Rule Group.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DeleteFirewallRuleGroup"
```