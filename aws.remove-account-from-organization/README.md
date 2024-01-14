## Rules

This rule detects AWS accounts leaving an Organization.

```text
_sourceCategory=aws/cloudtrail
| where isNull(errorCode) and eventName = "RemoveAccountFromOrganization"
```