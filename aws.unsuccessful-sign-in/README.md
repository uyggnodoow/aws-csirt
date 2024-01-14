## Rules

This rule detects failed attempts to log in to the AWS Management Console.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "responseElements.ConsoleLogin" as consoleLogin nodrop
| where eventName = "ConsoleLogin" and consoleLogin = "Failure"
```