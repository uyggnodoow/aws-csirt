## Rules

This rule detects suspicious IPs that use access keys to request operations.

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "userIdentity.accessKeyId" as accessKeyId nodrop
    | lookup country_code from geo://location on ip=sourceIPAddress
| where accessKeyId contains "AKIA"
| where !(sourceIPAddress contains ".amazonaws.com") and country_code != "KR"
```

```text
_sourceCategory=aws/cloudtrail
    | json field=_raw "userIdentity.accessKeyId" as accessKeyId nodrop
| where accessKeyId contains "AKIA"
| where sourceIPAddress not in ("OFFICE_IP_A", "OFFICE_IP_B", "VPN_IP_A", "VPN_IP_B", "NAT_IP_A", "NAT_IP_B")
```