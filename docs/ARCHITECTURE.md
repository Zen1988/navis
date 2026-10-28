# Architecture

Version: 1.0

Status: Draft

---

# Overview

Navis is a vendor-neutral Connectivity Intelligence Engine.

The platform is designed to answer:

```text
Can Source A communicate with Destination B on Service C?
```

and determine:

```text
What path will traffic take?
What policy allows the traffic?
What policy blocks the traffic?
What change is required?
```

Navis is not a configuration management platform.

Navis is not a monitoring system.

Navis is an analytical engine focused on connectivity reasoning.

---

# High-Level Architecture

```text
                          +------------------+
                          | External Clients |
                          +------------------+
                                     |
                                     |
                                     v

                          +------------------+
                          |    Navis API     |
                          +------------------+
                                     |
                                     |
                +--------------------+--------------------+
                |                                         |
                v                                         v

      +------------------+                 +------------------+
      | Analysis Service |                 | Inventory Service|
      +------------------+                 +------------------+
                |                                         |
                +--------------------+--------------------+
                                     |
                                     v

                      +-----------------------------+
                      | PostgreSQL Cluster          |
                      | CloudNativePG              |
                      |                            |
                      | JSONB Storage              |
                      | Relational Storage         |
                      | Apache AGE Graph Layer     |
                      +-----------------------------+

                                     ^
                                     |
                                     |

                        +-------------------------+
                        | Collection Platforms    |
                        +-------------------------+

                                     ^
                                     |
                                     |

                 Ansible / AWX / AAP / Custom Collectors

                                     ^
                                     |
                                     |

      NSX-T | Cisco ACI | Palo Alto | FortiGate | Cloud | Kubernetes
```

---

# Architectural Principles

## Single Source Of Truth

PostgreSQL is the authoritative datastore.

All important business data must exist inside PostgreSQL.

Examples:

```text
Assets
Policies
Contracts
Interfaces
Zones
Routes
NAT
Services
Analysis Results
```

No critical information should exist only in graph structures.

---

## Graph Is Derived

Relationships are generated from authoritative configuration.

Graph data must be rebuildable.

Loss of graph data should never result in loss of business data.

Recovery process:

```text
PostgreSQL
  ↓
Graph Builder
  ↓
Apache AGE
```

---

## API First

Every capability must be accessible through APIs.

Examples:

```text
Connectivity Analysis
Asset Lookup
Policy Lookup
Impact Analysis
Recommendation Generation
```

Graphical interfaces are consumers of APIs.

---

## External Collection

Navis does not collect infrastructure data directly.

Collection is performed by:

```text
Ansible
AWX
Red Hat AAP
Custom Automation Systems
```

Navis consumes normalized inventory and configuration data.

---

## External Credential Ownership

Navis never stores:

```text
Passwords
SSH Keys
Privileged Accounts
API Tokens
```

Credential ownership remains external:

```text
CyberArk
Vault
Key Vault
Secrets Manager
```

---

# Core Services

---

# Inventory Service

Purpose:

```text
Receive infrastructure data
Store authoritative records
Maintain inventory
```

Responsibilities:

```text
Asset Registration
Config Ingestion
Version Tracking
Inventory Search
Metadata Maintenance
```

Inputs:

```text
NSX Configurations
ACI Configurations
Firewall Policies
Routes
Asset Inventory
```

Outputs:

```text
Normalized Data
Inventory Views
Graph Builder Inputs
```

---

# Analysis Service

Purpose:

```text
Evaluate connectivity
```

Responsibilities:

```text
Path Analysis
Policy Evaluation
Route Analysis
NAT Evaluation
Recommendation Generation
```

Inputs:

```text
Source
Destination
Protocol
Port
```

Outputs:

```text
Allowed
Blocked
Unknown
Missing Policy
Recommendation
```

---

# Graph Builder

Purpose:

```text
Construct connectivity relationships
```

Responsibilities:

```text
Topology Creation
Policy Relationships
Dependency Relationships
Graph Synchronization
```

Inputs:

```text
Normalized Inventory
Normalized Policies
Routes
Topology Data
```

Outputs:

```text
Apache AGE Graph Structures
```

---

# Recommendation Engine

Purpose:

```text
Explain required changes
```

Responsibilities:

```text
Missing Policy Identification
Blocking Point Identification
Suggested Remediation
```

Example:

```text
Platform:
Palo Alto

Policy:
APP → DB TCP/1433

Status:
Missing

Recommendation:
Create Allow Policy
```

---

# PostgreSQL Architecture

---

# Database Platform

```text
PostgreSQL
```

Running on:

```text
CloudNativePG
```

Deployment Goals:

```text
High Availability
Automatic Failover
Backups
Point-In-Time Recovery
Kubernetes Native Operations
```

---

# Data Storage Strategy

PostgreSQL serves three roles:

```text
System of Record
Document Store
Graph Platform
```

---

# Relational Storage

Used for:

```text
Assets
Devices
Services
Policies
Analysis Requests
Analysis Results
```

---

# JSONB Storage

Used for:

```text
NSX Policies
ACI Contracts
Firewall Configurations
Routing Information
NAT Definitions
Vendor Metadata
```

Example:

```json
{
  "platform": "nsx",
  "object_type": "security_policy",
  "payload": {}
}
```

Benefits:

```text
Vendor Independence
Schema Flexibility
Historic Replay
Version Preservation
```

---

# Apache AGE

Purpose:

```text
Graph Traversal
Connectivity Analysis
Path Discovery
Impact Analysis
```

Apache AGE runs inside PostgreSQL.

No external graph database is required.

Benefits:

```text
Single Database Platform
Single Backup Model
Single Recovery Model
Single HA Architecture
```

---

# Connectivity Model

Navis analyzes connectivity using a unified model.

All vendors are mapped into:

```text
Source
Destination
Service
Action
Enforcement Point
```

This abstraction allows policy analysis across different technologies.

---

# Asset Model

Represents:

```text
VMs
Servers
Containers
Endpoints
Load Balancers
VIPs
```

Example:

```text
APP01
DB01
WEB01
```

---

# Endpoint Group Model

Represents:

```text
NSX Groups
ACI EPGs
Address Groups
Security Groups
```

Unified Type:

```text
EndpointGroup
```

---

# Service Model

Represents:

```text
Protocol
Port
Application Service
```

Examples:

```text
TCP/80
TCP/443
TCP/1433
UDP/53
```

---

# Policy Model

Represents:

```text
Source
Destination
Service
Action
```

Examples:

```text
NSX Rule
Firewall Policy
Contract
Security Group Rule
```

---

# Enforcement Point Model

Represents systems capable of making permit or deny decisions.

Examples:

```text
NSX DFW
Palo Alto
FortiGate
ACI Contract Engine
AWS Security Groups
```

---

# Data Lifecycle

---

## Stage 1

Collection

```text
Infrastructure
 ↓
Collector
```

Examples:

```text
Ansible
AWX
```

---

## Stage 2

Ingestion

```text
Collector
 ↓
Navis API
```

---

## Stage 3

Persistence

```text
Navis API
 ↓
PostgreSQL
```

Stored as:

```text
Raw Configuration
Inventory
Metadata
```

---

## Stage 4

Normalization

```text
Raw Configuration
 ↓
Normalized Models
```

Examples:

```text
Policy
Zone
Endpoint Group
Service
Route
Asset
```

---

## Stage 5

Graph Construction

```text
Normalized Models
 ↓
Apache AGE
```

Relationships are generated.

---

## Stage 6

Analysis

```text
Request
 ↓
Analysis Engine
 ↓
Result
```

---

# Analysis Pipeline

Given:

```text
10.10.1.10
 →
10.20.1.20
TCP/443
```

Pipeline:

```text
Source Resolution
 ↓
Destination Resolution
 ↓
Asset Correlation
 ↓
Route Evaluation
 ↓
NAT Evaluation
 ↓
NSX Evaluation
 ↓
ACI Evaluation
 ↓
Firewall Evaluation
 ↓
Policy Correlation
 ↓
Path Construction
 ↓
Recommendation
```

Output:

```text
Allowed
Blocked
Missing Policy
Unknown
```

---

# Supported Platforms

## Initial Scope

```text
VMware NSX-T
Cisco ACI
Palo Alto Networks
Fortinet FortiGate
```

---

## Future Scope

```text
AWS Security Groups
Azure NSG
GCP Firewall Rules
Check Point
Cisco Secure Firewall
Kubernetes Network Policies
Service Mesh Policies
```

---

# Deployment Model

---

# Kubernetes

Navis is intended for Kubernetes.

Recommended deployment:

```text
Kubernetes
+
CloudNativePG
+
FastAPI
```

---

# Stateless Services

The following services should remain stateless:

```text
API
Analysis Workers
Recommendation Engine
Graph Builder
```

State belongs in PostgreSQL.

---

# Scalability Strategy

Scale horizontally:

```text
API Replicas
Worker Replicas
Ingestion Replicas
```

Database scaling is provided by:

```text
CloudNativePG
```

---

# Future Architecture Themes

Future development should focus on:

```text
Policy Intelligence
Impact Analysis
Change Simulation
Connectivity Assurance
```

Future development should avoid:

```text
Configuration Deployment
Secrets Management
PAM
RBAC Platforms
Monitoring
```

These concerns belong to dedicated systems.

---

# Architecture Motto

```text
PostgreSQL Stores Truth.

Apache AGE Explains Relationships.

Navis Understands Connectivity.
```
