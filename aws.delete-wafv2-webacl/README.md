## Rules

This rule detects AWS WAFv2 WebACL deletion.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "DeleteWebACL"
```