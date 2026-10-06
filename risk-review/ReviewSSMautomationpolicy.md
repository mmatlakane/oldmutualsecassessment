# Annexure A Review: SSM Automation IAM Policy
### Use Case Assessment

The architecture shows:

- Azure DevOps Pipeline
- EKS Fargate Agent Pod using IRSA
- Cross-account role assumption
- SSM Automation execution across multiple AWS accounts
- Deployment of applications and commands through SSM

This is a valid enterprise automation pattern and avoids permanent SSH/RDP access to servers.

## Finding A1: Overly Broad S3 Object Access

**Current Permission:**
```
{
    "Action": [
    "s3:GetObject",
    "s3:PutObject"
    ],
    "Resource": "arn:aws:s3:::*/*"
}
```
**Risk:**
This permission allows access to objects in every bucket in the account and potentially any bucket to which access is granted.
Potential impacts:
- Sensitive data exposure
- Modification of application artifacts
- Deployment package tampering
- Supply chain attack vector

#### Risk Level
- Medium to High

#### Impact
- High

#### Recommendation
- Restrict to deployment buckets only.

Example:
```
"Resource": [
    "arn:aws:s3:::automated-deployment-dev/*",
    "arn:aws:s3:::automated-deployment-prod/*",
    "arn:aws:s3::: automated-deployment*"
]
```

## Finding A2: Unrestricted AWS RunShellScript Permission
Current Permission:
```
{
    "Sid": "SSMSendCmdDocs",
    "Effect": "Allow",
    "Action": "ssm:SendCommand",
    "Resource": [
    "arn:aws:ssm:eu-west-1::document/AWS-RunShellScript",
    "arn:aws:ssm:eu-west-1::document/AWS-RunPowerShellScript",
    "arn:aws:ssm:eu-west-1:222222222222:document/Automated-Deployment-Dev",
    "arn:aws:ssm:eu-west-1:839864138277:document/customer-*"
    ]   
}
```
### Risk
These AWS managed documents allow execution of arbitrary operating system commands.

A compromised Azure DevOps pipeline could:

- Download malware
- Install backdoors
- Disable monitoring agents
- Modify application configurations
- Exfiltrate secrets

The current tag restrictions only control target instances, not command content.

#### Risk Level
- Medium

#### Impact
- Critical

#### Recommendation

Use only approved custom SSM documents:
```
Automated-Deployment-Dev
customer-*
```

Remove:
```
AWS-RunShellScript
AWS-RunPowerShellScript
```
Where possible.
Implement document approval workflows.

## Finding A3.1: EC2 CreateTags Permission

Current Permission:
```
{
    "Sid": "EC2ControlledActions",
    "Effect": "Allow",
    "Action": [
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:RebootInstances",
    "ec2:CreateTags"
    ],
    "Resource": "arn:aws:ec2:eu-west-1:22222222222:instance/*"
}
```
### Risk

A user can modify metadata used by automation controls.

Examples:

- Add AutomationAllowed=true
- Spoof application tags
- Circumvent deployment controls

#### Risk Level

- Medium

#### Impact

- Medium

### Recommendation

Restrict tag creation to:
```
Condition:
{
  "ForAllValues:StringEquals":
  {
      "aws:TagKeys":[
          "DeploymentVersion"
      ]
  }
}
```
Or remove if not required.

## Finding A3.2: Start, Stop and Reboot Across All Instances

Current Permission:
```
arn:aws:ec2:eu-west-1:22222222222:instance/*
```
### Risk

Can affect production workloads unintentionally.

Potential impact:

- Service outages
- Business disruption
- Failed deployments
#### Recommendation

Restrict by tag:
```
Environment=Dev
Application=Automated-Deployment-Dev
```
#### Risk Level
- Low

## Finding A4: Cross-Account SSM Document Usage

Current Permission:
```
arn:aws:ssm:eu-west-1:839864138277:document/customer-*
```
### Risk

Trusting a wildcard document pattern in another account introduces supply chain risk.

If document ownership is compromised:

- Malicious commands may execute across accounts.
#### Recommendation

Use explicit document names and version pinning.

Example:
```
customer-deploy-v1
customer-deploy-v2
```
Avoid:
```
customer-*
```
#### Risk Level

- Low

## Finding A5: Missing CloudTrail Monitoring Requirement
### Risk

The policy grants the ability to execute operationally significant actions but does not mandate monitoring.

#### Recommendation

Implement:

- CloudTrail
- CloudTrail Lake queries
- EventBridge monitoring
- GuardDuty
- Security Hub alerts

Monitor:

- Plain Text
- StartInstances
- StopInstances
- RebootInstances
- SendCommand
- AssumeRole
#### Risk Level

- Low

