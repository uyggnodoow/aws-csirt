# Rules

This rule detects the disassociation of Firewall Rule Group with Amazon VPC.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DisassociateFirewallRuleGroup"
```