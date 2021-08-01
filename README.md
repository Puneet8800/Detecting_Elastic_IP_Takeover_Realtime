# Detecting_Elastic_IP_Takeover_Realtime

# Purpose

The purpose of this automation is to detect misconfigured Elastic IP Realtime which are vulnerable to takeover and sends an alert on Slack. For more information refer to this link: https://puneetkmr187.hashnode.dev/detecting-vulnerable-elastic-ips-realtime

# Deployment Options

* AWS Lambda

# Prerequisites

* IAM role with a permission of route53("ListHostedZones", "ListResourceRecordSets", "ListDomains", "describe_addresses").

# Configuration Steps

* Configure IAM role with permission mention above in prerequisites.
* Create a Cloudwatch rule and paste the json of cloudwatch_events.json in that rule
* Trigger lambda via cloudwatch rule.
* In slack_alert() please put the incoming webhook url of slack channel.
