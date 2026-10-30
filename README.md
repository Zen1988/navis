<p align="center">
  <img src="docs/logo/navis-banner.svg" width="900">
</p>

<p align="center">
  <strong>Understand Every Path.</strong>
</p>

<p align="center">
  Vendor-Neutral Connectivity Intelligence Engine
</p>
> Understand Every Path.

Navis is a vendor-neutral connectivity intelligence engine designed to analyze, explain, and reason about connectivity across modern enterprise infrastructure.

For the current development status, known gaps and next steps, see [Project status](docs/STATUS.md). The project remains a prototype and the vision below is not a claim that all capabilities are complete.

For integrations from other projects, see the [API integration guide](docs/INTEGRATION_API.md), [OpenAPI snapshot](docs/api/openapi.json) and [validated request examples](docs/api/examples/).

Navis answers a simple question:

```text
Can Source A communicate with Destination B on Service C?
```

and if not:

```text
What is blocking it?
Where is it blocked?
What change is required?
```

---

# Vision

Modern enterprise connectivity spans multiple enforcement domains:

```text
VMware NSX Distributed Firewall
Cisco ACI Contracts
Palo Alto Policies
FortiGate Policies
AWS Security Groups
Azure NSGs
Kubernetes Network Policies
Traditional Routing
Network Address Translation
```

Understanding connectivity requires correlating these controls into a unified model.

Navis provides a policy-centric analysis engine capable of reasoning across heterogeneous infrastructure.

---

# Core Philosophy

Navis is an analysis platform.

Navis is not a management platform.

The primary objective is:

```text
Explain connectivity.
```

Not:

```text
Configure connectivity.
```

---

# Design Goals

## Connectivity Analysis

Input:

```json
{
  "src_ip": "10.10.1.10",
  "dst_ip": "10.20.1.20",
  "protocol": "tcp",
  "port": 443
}
```

Output:

```json
{
  "status": "blocked",
  "path": [
    "NSX",
    "ACI",
    "PA-DC-01"
  ],
  "blocking_point": "PA-DC-01",
  "recommendation": {
    "type": "firewall_policy",
    "source_zone": "APP",
    "destination_zone": "DMZ",
    "service": "tcp/443"
  }
}
```

---

## Vendor Neutrality

Navis normalizes vendor-specific constructs into a common model.

Examples:

| Platform | Native Object |
|----------|--------------|
| Palo Alto | Security Policy |
| FortiGate | Firewall Policy |
| NSX | DFW Rule |
| ACI | Contract |
| AWS | Security Group |
| Azure | NSG |

Unified Representation:

```text
Source
Destination
Service
Action
Enforcement Point
```

---

## API First

Navis is designed as a backend service.

External systems may include:

```text
CyberArk
ServiceNow
Internal Portals
Developer Platforms
Automation Systems
```

Navis exposes analysis services through APIs.

---

# Architecture

```text
                     +-----------------+
                     |   Navis API     |
                     +-----------------+
                               |
                               v

                     +-----------------+
                     | Analysis Engine |
                     +-----------------+
                               |
                               v

      +--------------------------------------------+
      |            PostgreSQL Cluster              |
      |                                            |
      |  CloudNativePG                             |
      |                                            |
      |  Relational Storage                        |
      |  JSONB Storage                             |
      |  Apache AGE Graph Layer                    |
      +--------------------------------------------+

                               ^
                               |
                               |

                     +-----------------+
                     | Ansible / AWX   |
                     +-----------------+

                               ^
                               |
      ---------------------------------------------------

      NSX     APIC     Firewalls     Cloud Platforms
```

---

# Database Strategy

## PostgreSQL as System of Record

PostgreSQL is the authoritative datastore.

All collected data is persisted in PostgreSQL.

Examples:

```text
Assets
Policies
Contracts
Security Groups
Zones
Interfaces
Routes
NAT Rules
Analysis Results
```

---

## JSONB for Configuration Storage

Vendor-native configurations are stored without schema loss.

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
Flexible
Versionable
Auditable
Vendor Agnostic
```

---

## Apache AGE

Apache AGE provides graph capabilities directly within PostgreSQL.

Benefits:

```text
Single Database Platform
Single Backup Strategy
Single HA Architecture
Single Operational Model
```

Graph relationships are maintained inside PostgreSQL.

Examples:

```text
APP01
  ↓
NSX Group
  ↓
DFW Policy
  ↓
Firewall Zone
  ↓
Destination
```

---

## Why Not Neo4j

Navis is primarily a policy intelligence platform.

The authoritative data is configuration.

Graph relationships are derived from configuration.

Using PostgreSQL plus Apache AGE provides:

```text
Lower Operational Complexity
Native Kubernetes Integration
Simplified Disaster Recovery
Unified Data Platform
```

without requiring a separate graph database.

---

# Security Model

## No Direct Device Access

Navis does not log into devices directly.

Collection is delegated to external automation platforms.

Recommended:

```text
Ansible
AWX
Red Hat AAP
```

Collected information is pushed into Navis.

---

## No Credential Storage

Navis should never store:

```text
Administrator Passwords
Firewall Credentials
SSH Keys
API Secrets
Privileged Credentials
```

Credential ownership remains external.

Examples:

```text
CyberArk
HashiCorp Vault
Azure Key Vault
AWS Secrets Manager
Ansible Credential Stores
```

---

# Core Components

## Inventory Service

Responsible for:

```text
Asset Inventory
Configuration Ingestion
Raw Data Storage
```

---

## Policy Normalizer

Responsible for:

```text
NSX Normalization
ACI Normalization
Firewall Normalization
Cloud Policy Normalization
```

---

## Graph Builder

Responsible for:

```text
Relationship Construction
Policy Correlation
Topology Correlation
Graph Population
```

---

## Analysis Engine

Responsible for:

```text
Connectivity Analysis
Path Evaluation
Policy Evaluation
NAT Evaluation
Recommendation Generation
```

---

# Analysis Workflow

Given:

```text
Source IP
Destination IP
Protocol
Port
```

Navis performs:

```text
Resolve Source Asset
 ↓
Resolve Destination Asset
 ↓
Determine Connectivity Path
 ↓
Evaluate Routing
 ↓
Evaluate NAT
 ↓
Evaluate NSX Policies
 ↓
Evaluate ACI Contracts
 ↓
Evaluate Firewall Policies
 ↓
Determine Blocking Point
 ↓
Generate Recommendation
```

---

# Example Analysis

Input:

```text
APP01
 →
DB01
TCP/1433
```

Output:

```text
Path

NSX Distributed Firewall
 ↓
ACI Contract
 ↓
PA-DC-01

Results

NSX
 ✓ ALLOW

ACI
 ✓ ALLOW

PA-DC-01
 ✗ NO MATCHING POLICY

Recommendation

Platform:
Palo Alto

Source Zone:
APP

Destination Zone:
DB

Service:
TCP/1433
```

---

# Kubernetes Deployment

## Platform

```text
Kubernetes
```

## Database

```text
CloudNativePG
```

## PostgreSQL

Always deploy the latest supported PostgreSQL version.

Security updates and minor upgrades should be applied regularly.

## Apache AGE

Deploy the latest Apache AGE version compatible with the selected PostgreSQL release.

Custom PostgreSQL container images may be used to package Apache AGE alongside PostgreSQL.

---

# Roadmap

## Phase 1

```text
Project Foundation
Inventory APIs
JSONB Storage
Asset Management
```

## Phase 2

```text
Apache AGE Integration
Topology Modeling
Route Analysis
```

## Phase 3

```text
Firewall Analysis
Zone Resolution
NAT Analysis
```

## Phase 4

```text
VMware NSX Support
Cisco ACI Support
Unified Policy Model
```

## Phase 5

```text
Policy Recommendation Engine
Impact Analysis
What-If Simulation
```

---

# Long-Term Objective

Build a vendor-neutral connectivity intelligence engine capable of answering:

```text
Can application A communicate with application B?
```

and:

```text
If not,

What is blocking it?

Where is it blocked?

What change is required?
```

without requiring direct administrative access to the underlying infrastructure.

---

# Technology Stack

```text
Language
--------
Python

API
---
FastAPI

Database
--------
PostgreSQL

Graph
-----
Apache AGE

PostgreSQL Operator
-------------------
CloudNativePG

Collection
----------
Ansible
AWX

Runtime
-------
Kubernetes
```

---

# Project Status

```text
🚧 Design Phase
```

Navis is currently focused on defining the foundational architecture, data model, and policy analysis framework.

---

# Name

**Navis**

*Latin: ship, navigation, voyage.*

Because every packet has a path.
