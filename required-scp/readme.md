# AWS Organizations SCP – Restrict AWS Usage to eu-west-1

### Overview

This Service Control Policy (SCP) restricts AWS service usage to the **eu-west-1 (Ireland)** region.

The policy is implemented using an explicit **Deny** statement that blocks requests made to AWS services outside the approved region.

AWS Organizations SCPs do not grant permissions. Instead, they define the maximum available permissions for accounts and Organizational Units (OUs) within an AWS Organization.

This SCP provides a preventative control that supports:

- Data residency requirements
- Regulatory compliance
- Consistent operational governance
- Reduction of accidental deployments
- Improved security monitoring coverage
- Simplified operational support

# SCP Policy Objective

Allow AWS resources to be provisioned and managed only within:

```text
eu-west-1
```

Deny resource creation and management in regions such as:

```text
us-east-1
us-west-2
eu-central-1
ap-southeast-1
ap-southeast-2
etc
```

### SCP Design Approach

The SCP uses an explicit deny model:

```json
{
  "Effect": "Deny"
}
```

This approach ensures that even highly privileged IAM administrators cannot bypass the regional restriction.

The policy evaluates the AWS global condition key:

```json
aws:RequestedRegion
```

If the requested region is not:

```text
eu-west-1
```

the request is denied.


## Excluded Global Services

Certain AWS services are global and do not operate within a specific region.

These services are excluded from the SCP restriction:

- IAM
- AWS Organizations
- Route53
- CloudFront
- AWS Support
- AWS Health Dashboard
- AWS Billing
- AWS Budgets
- AWS Cost Explorer
- AWS Artifact
- AWS Trusted Advisor
- AWS STS

Without these exclusions, core identity, billing and management functionality may be impacted.


## Security Benefits

### Data Residency

Ensures that data and resources remain within the approved AWS region.

### Compliance

Supports compliance requirements related to:

- GDPR
- Data sovereignty
- Internal governance policies

### Reduced Attack Surface

Prevents deployment of resources into unmanaged regions where:

- Security controls may not exist
- Monitoring may not be configured
- Security teams may have reduced visibility

### Operational Consistency

Ensures that:

- Logs
- Monitoring
- Backups
- Security tooling

remain concentrated within the approved region.

## Deployment Procedure

### Deploy via AWS Console, in the Management Account
>  WARNING  
>
> Attaching an SCP at the Organizational Root affects all member accounts and OUs immediately. It is recommended to test the SCP in a non-production OU before attaching it to the Root to avoid unintended operational impact.

## SCP Evaluation Logic: How SCPs Are Evaluated

AWS evaluates permissions using multiple policy types.

For a request to succeed:

- The SCP must allow the action.
- IAM policies must allow the action.
- Resource policies must allow the action (where applicable).

An explicit Deny in any SCP overrides all Allow permissions.

***Example:***

User has:
```
IAM Policy:
- ec2:RunInstances = Allow
```
SCP:
- Deny all actions outside eu-west-1

Result:
```
Launching an EC2 instance in us-east-1 = Denied

The SCP takes precedence over the IAM policy.
```
## SCP Policy Deployment/Implementation
1. Sign in to the **AWS Management Console**.
2. Open AWS Organizations.
3. Navigate to:
   - Policies
   - Service Control Policies
4. Select **Create Policy**.
5. Paste the contents of `scp-eu-west-1.json`.
6. Save the policy.
7. Attach the policy to:
   - **Organizational Root:** 
    - - Only apply the SCP to the **Organizational Root** when you want it to apply to all OUs and member accounts underneath that root. 
    - - Essentially, If you attach the SCP to the Organizational Root, the SCP is inherited by all OUs and member accounts underneath that root. You don't need to attach the same SCP individually to every OU and account.
   - **Organizational Unit (OU)**
   - - If you attach it to an OU
   
   ```
   Example: 
    Root
    │
    ├── Production OU -- SCP attached here
    │   ├── Account A ← inherits SCP
    │   ├── Account B ← inherits SCP
    │   └── Database OU
    │       └── Account C ← inherits SCP
    │
    └── Development OU
        └── Account D ← NOT affected
   ``` 
   - **Individual AWS Accounts**
   - - Attach directly to single account.

In essence, attach the policy depending on organizational requirements.


## Deploy via Terraform

Example:

```hcl
resource "aws_organizations_policy" "eu_west_1_only" {
  name        = "restrict-eu-west-1"
  description = "Restrict AWS resource usage to eu-west-1"
  type        = "SERVICE_CONTROL_POLICY"

  content = file("${path.module}/scp-eu-west-1.json")
}

resource "aws_organizations_policy_attachment" "target_ou" {
  policy_id = aws_organizations_policy.eu_west_1_only.id
  target_id = "ou-xxxxxxxx"
}
```
## Limitations

This SCP does not:

- Delete existing resources.
- Move resources into eu-west-1.
- Grant permissions.
- Override service-linked roles.
- Protect standalone AWS accounts that are not part of AWS Organizations.

The SCP only acts as a preventative guardrail for accounts governed by AWS Organizations.

## Testing Procedure

Before production deployment:

### Test Case 1

Attempt to launch an EC2 instance in:

```text
eu-west-1
```

Expected Result:

```text
Success
```

---

### Test Case 2

Attempt to launch an EC2 instance in:

```text
us-east-1
```

Expected Result:

```text
Access Denied
```

---

### Test Case 3

Attempt to create an RDS instance in:

```text
eu-central-1
```

Expected Result:

```text
Access Denied
```

---

### Test Case 4

Verify that users can still:

- Assume IAM roles
- Access AWS Organizations
- Use IAM Identity Center
- Access Route53
- Access CloudFront
- View Billing Information

Expected Result:

```text
Success
```

## Risks and Considerations

### STS Operations

The policy excludes AWS STS because it is commonly required for:

- IAM Identity Center
- SAML Federation
- Azure Entra ID Federation
- Cross-account role assumption
- CI/CD pipelines

If regional STS endpoints are mandated, additional controls should be implemented outside this SCP.

### Multi-Region Services

Services that rely on multi-region architecture may require separate design considerations, including:

- Disaster Recovery
- Global CloudFront distribution
- Route53 DNS management

### Existing Resources

The SCP does not remove or modify existing resources deployed in non-approved regions.

Organizations should conduct an audit before deployment to identify:

- Existing resources
- Replication services
- Backup destinations
- Disaster recovery architectures


## Rollout Recommendation

A phased deployment approach is recommended:

1. Deploy to a non-production OU.
2. Validate application deployments.
3. Validate CI/CD pipelines.
4. Validate IAM Identity Center federation.
5. Validate monitoring and logging integrations.
6. Deploy to production OUs after successful testing.


## Approval Recommendation

**Approved with Controlled Rollout**

This SCP provides an effective preventative guardrail that enforces regional governance and reduces compliance, security and operational risks associated with resource deployment outside the approved AWS region.