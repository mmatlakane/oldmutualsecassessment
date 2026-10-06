# Annexure C & D – Risk Review: AWS RDS IAM Roles and Federated Database Access

## Overview

The proposed solution introduces federated access to Amazon RDS databases using:

```text
SailPoint
   ↓
Microsoft Entra ID
   ↓
AWS IAM Identity Center
   ↓
IAM Permission Sets
   ↓
RDS IAM Authentication
   ↓
Database Roles (ReadOnly / CRUD / Admin)
```

## Intended Use Case

Provide user-specific database access aligned to least-privilege principles:

| Role | Intended Database Permissions |
|--------|--------|
| ReadOnly | SELECT only |
| CRUD | SELECT, INSERT, UPDATE, DELETE |
| Admin | Full DDL and DML permissions |

This approach eliminates shared database accounts and enables centralized identity lifecycle management through SailPoint and Entra ID.

# Architecture Security Assessment

## Positive Security Attributes

The proposed design demonstrates several strong security practices:

- Federated authentication via Entra ID
- Centralized provisioning through SailPoint
- Elimination of shared database credentials
- AWS IAM Identity Center integration
- IAM database authentication support
- Role-based access model
- Improved auditability and traceability
- Reduced password management overhead


# Finding R1: Administrative Role Has Excessive AWS Permissions

## Current Configuration

```json
"Action": [
  "rds:*"
]
```

### Risk

The permission allows unrestricted adminis*rative control across all RDS reso*rces within the AWS account.

Capabilities include:

- Create databases
- Delete databases
- Modify database configurations
- Disable backups
- Modify parameter groups
- Restore snapshots
- Delete snapshots
- Modify security configurations

A compromised administrative account could result in:

- Data loss
- Service outages
- Unauthorized configuration changes
- Compliance violations

#### Impact

- High

#### Risk Level

- Medium

#### Recommendation
*Replace the wildcard permission wi*h only those actions required for administration.

Example:

```json
  "rds:Describe*",
  "rds:ModifyD*Instance",
  "rds:CreateDBSnapshot*,
  "rds:RestoreDBInstanceFromDBSnapshot",
  "rds:ModifyDBParameterGroup"
]
```

Implement separation between operational administration and database administration where possible.

#### Risk level

- Medium


# Finding R2: CRUD Role Does Not Match Business Requirement

#### Current Configuration

```json
{
 "Effect": "Allow",
  "Action": [
   "rds:*"
  ],
  "Resource": "*"

```

### Risk

The documented requirement states:

```text
CRUD Role
- SELECT
- INSERT
- UPDATE
- DELETE
```

However, the assigned AWS permissions allow:

- Database creation
- Database deletion
- Snapshot management
- Backup manipulation
- Configuration changes
- Security group modifications

The granted permissions significantly exceed the stated requirement.

#### Impact

- High

#### Risk Level

- High

#### Recommendation

The CRUD role should only be able to authenticate and connect to the database.

Example:

```json
{
  "Effect": "Allow",
  "Action": "rds-db:connect",
  "Resource": [
    "arn:aws:rds-db:eu-west-1:ACCOUNT_ID:dbuser:db-*/crud_user"
  ]
}
```

CRUD permissions should be enforced within the database engine using native database roles.

#### Risk Level
- Low


## Finding R3: Database Role Separation Not Enforced by IAM

### Risk

The architecture assumes three levels of database access:

```text
ReadOnly
CRUD
Admin
```

However, AWS IAM permissions alone do not enforce SQL-level permissions.

IAM only controls:

- Authentication
- Authorization to connect

Actual permissions such as:

- SELECT
- INSERT
- UPDATE
- DELETE
- CREATE
- ALTER
- DROP

must be enforced inside the database.

Without proper database role configuration:

- ReadOnly users