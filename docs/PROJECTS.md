# Navis Project Charter

Version: 1.0

Status: Active

---

# Mission

Navis exists to understand connectivity.

Modern infrastructure contains multiple independent policy domains that influence communication between systems. Determining whether connectivity is possible is no longer a matter of checking a single firewall.

Navis provides a vendor-neutral analytical engine that explains how traffic traverses infrastructure and identifies the controls that govern communication.

Navis answers:

```text
Can Source A communicate with Destination B on Service C?
```

If communication is not possible, Navis answers:

```text
What is blocking it?
Where is it blocked?
What change is required?
```

---

# Product Vision

Enterprise connectivity is increasingly controlled by multiple independent systems:

```text
Routing
NAT
VMware NSX
Cisco ACI
Palo Alto
FortiGate
Cloud Security Groups
Kubernetes Network Policies
```

These systems are often managed by different teams, have different data models, and expose different APIs.

Navis unifies these domains into a single analytical model.

The long-term vision is:

```text
Understand Every Path.
```

---

# Product Identity

Navis is:

```text
Connectivity Intelligence Engine
```

Navis is:

- Analytical
- Vendor-neutral
- Infrastructure-aware
- API-first
- Kubernetes-native

Navis is not:

- A monitoring platform
- A configuration management system
- A firewall manager
- A PAM solution
- A credential vault
- A ticketing system
- A CMDB replacement

---

# Core Questions

All functionality should help answer one or more of the following questions:

```text
Can source reach destination?

What path will traffic follow?

Which enforcement points are evaluated?

Which policy allows the traffic?

Which policy blocks the traffic?

Which object is involved?

Which change is required?

What systems are affected by a proposed change?
```

If a feature does not help answer these questions, it should be reconsidered.

---

# Design Principles

## Principle 1 - Connectivity First

Connectivity is the product.

Infrastructure devices exist only to support connectivity analysis.

Navis should reason about:

```text
Sources
Destinations
Services
Policies
Relationships
Paths
```

instead of:

```text
Specific vendors
Specific appliances
Specific technologies
```

---

## Principle 2 - Policy Is More Valuable Than Topology

Topology describes where traffic can go.

Policy determines whether traffic is allowed.

When both are available:

```text
Policy always takes precedence.
```

Examples:

```text
NSX DFW Rules
Firewall Policies
ACI Contracts
Security Groups
NAT Rules
```

must be treated as first-class citizens.

---

## Principle 3 - Vendor Neutrality

Every vendor has unique terminology.

Examples:

```text
NSX Group
ACI EPG
Address Group
Security Group
Object Group
```

Navis should provide common abstractions.

The engine must analyze:

```text
Connectivity
```

not vendors.

---

## Principle 4 - API First

Every capability must be exposed through APIs.

User interfaces are consumers.

Portals are consumers.

Automation platforms are consumers.

The analysis engine must never depend on a specific UI implementation.

---

## Principle 5 - Kubernetes Native

Navis is designed for Kubernetes deployment.

Requirements:

```text
Containerized
Stateless Services
Horizontal Scalability
Declarative Deployment
Operator-Friendly
```

All services should assume Kubernetes execution.

---

## Principle 6 - Open Source Friendly

Navis should remain accessible to:

```text
Engineers
Community Contributors
Home Labs
Small Teams
Enterprises
```

Avoid unnecessary commercial dependencies.

Avoid enterprise-only architectural requirements.

---

# Architectural Principles

---

## PostgreSQL Is The System Of Record

PostgreSQL is the authoritative datastore.

All valuable data must exist in PostgreSQL.

Examples:

```text
Assets
Policies
Contracts
Interfaces
Zones
Routes
NAT Rules
Services
Analysis Results
Inventory
```

If PostgreSQL is unavailable:

```text
Navis has lost its source of truth.
```

---

## Graph Is Derived Data

Graph data is generated from authoritative data.

Graph data may be rebuilt at any time.

Graph data must never be the sole location of critical information.

Example:

```text
PostgreSQL
    ↓
Graph Builder
    ↓
Apache AGE
```

If graph data is lost:

```text
Rebuild graph.
```

Do not restore business logic from graph structures.

---

## Configuration Is More Important Than Relationships

Configuration drives analysis.

Relationships support analysis.

Configuration examples:

```text
Firewall Rules
NSX Rules
Contracts
Security Groups
Route Tables
```

Relationship examples:

```text
Asset → Group
Group → Policy
Policy → Zone
Zone → Destination
```

Configuration must be preserved.

Relationships may be regenerated.

---

# Technology Direction

## Primary Database

```text
PostgreSQL
```

Responsibilities:

```text
Inventory
Asset Data
Configuration Data
Analysis Results
Metadata
Normalization
```

---

## JSONB

Vendor-native configurations are stored using JSONB.

Examples:

```json
{
  "platform": "nsx",
  "object_type": "security_policy",
  "payload": {}
}
```

Do not discard vendor-specific attributes.

Preserve original data whenever practical.

Benefits:

```text
Replay
Audit
Debugging
Future Features
Vendor Upgrades
```

---

## Graph Layer

```text
Apache AGE
```

Apache AGE runs inside PostgreSQL.

Responsibilities:

```text
Connectivity Graph
Topology Graph
Policy Relationship Graph
Impact Analysis
Path Traversal
```

Graph data is a derived analytical layer.

---

## Kubernetes Platform

Preferred deployment:

```text
CloudNativePG
```

Database requirements:

```text
High Availability
Failover
Replication
Backup
Recovery
```

Navis services should assume:

```text
CloudNativePG
+
Latest Supported PostgreSQL
+
Latest Compatible Apache AGE
```

---

# Data Lifecycle

## Layer 1 - Raw Configuration

Purpose:

```text
Store collected vendor-native data.
```

Examples:

```text
NSX Policies
ACI Contracts
Firewall Policies
Route Tables
Interface Definitions
```

Format:

```text
JSONB
```

Characteristics:

```text
Immutable
Versionable
Recoverable
Auditable
```

---

## Layer 2 - Normalized Objects

Purpose:

```text
Create vendor-independent models.
```

Examples:

```text
Policy
Endpoint Group
Service
Zone
Route
NAT
```

Characteristics:

```text
Vendor-Neutral
Query-Friendly
Stable
```

---

## Layer 3 - Connectivity Graph

Purpose:

```text
Relationship Analysis
Path Discovery
Impact Analysis
Traversal
```

Examples:

```text
Asset
 ↓
Group
 ↓
Policy
 ↓
Zone
 ↓
Destination
```

Characteristics:

```text
Generated
Rebuildable
Non-Authoritative
```

---

# Collection Philosophy

Navis does not collect device data directly.

Collection belongs elsewhere.

Approved collection platforms:

```text
Ansible
AWX
Red Hat AAP
Custom Collectors
```

Collection workflow:

```text
Infrastructure
    ↓
Collectors
    ↓
Navis API
    ↓
PostgreSQL
```

Navis consumes data.

Navis does not own collection.

---

# Credential Philosophy

Navis must never store:

```text
Administrator Passwords
SSH Keys
Privileged Credentials
API Tokens
Secrets
```

Credential ownership belongs to:

```text
CyberArk
Vault
Key Vault
Secrets Manager
Automation Platforms
```

Navis is an analytical engine.

Navis is not a privileged access platform.

---

# Supported Domains

## Current Scope

```text
Routing
NAT
Firewall Policies
VMware NSX
Cisco ACI
```

---

## Future Scope

```text
AWS Security Groups
Azure NSG
GCP Firewall Rules
Kubernetes Network Policies
Service Mesh Policies
```

---

# Unified Connectivity Model

Every platform should eventually map to:

```text
Source
Destination
Service
Action
Enforcement Point
```

The engine should not care whether the policy originates from:

```text
NSX
ACI
Firewall
Cloud
Kubernetes
```

It should evaluate:

```text
Allow
Deny
Missing
Unknown
```

consistently.

---

# Analysis Workflow

Given:

```text
Source
Destination
Protocol
Port
```

The engine performs:

```text
1. Asset Resolution

2. Endpoint Resolution

3. Route Resolution

4. NAT Resolution

5. Policy Resolution

6. Enforcement Evaluation

7. Path Construction

8. Recommendation Generation
```

Result:

```text
Allowed
Blocked
Missing Policy
Unknown
```

---

# Recommendation Philosophy

Recommendations must be:

```text
Actionable
Deterministic
Explainable
```

Bad:

```text
Traffic appears blocked.
```

Good:

```text
FW-DC-01

APP Zone
 →
DB Zone

Missing TCP/1433 Allow Policy
```

The recommendation should identify:

```text
Platform
Object
Policy Type
Required Change
```

whenever possible.

---

# Development Philosophy

---

## Simplicity Over Cleverness

Prefer:

```text
Simple
Readable
Boring
Maintainable
```

over:

```text
Complex
Abstract
Over-Engineered
```

---

## PostgreSQL First

Before introducing a new datastore ask:

```text
Can PostgreSQL solve this?
```

If yes:

```text
Use PostgreSQL.
```

---

## Build For Understanding

Always optimize for:

```text
Explainability
```

over:

```text
Technical sophistication
```

A slower answer that is explainable is preferable to a faster answer that cannot be understood.

---

## Preserve Data

When in doubt:

```text
Store more information.
```

Storage is cheaper than re-discovery.

---

# Non Goals

Navis will not become:

```text
Firewall Manager
Configuration Tool
Monitoring Platform
CMDB
Ticketing System
PAM Solution
Credential Vault
Network Controller
```

These concerns belong to other systems.

Navis remains focused on:

```text
Connectivity Intelligence.
```

---

# Decision Framework

Before implementing a feature, ask:

```text
Does this improve Navis' ability to explain connectivity?
```

If:

```text
Yes
```

continue.

If:

```text
No
```

do not build it.

---

# Navis Motto

```text
Understand Every Path.
```

---

# Application-Centered Connectivity

An application may define static membership of devices and hosts and the flows it requires. Navis derives the network dependencies for those flows from routing, topology, NAT, and policy evidence. The resulting application view shows the relevant paths and controls, including shared infrastructure, and explains why each is involved. Membership alone does not specify required flows; missing flow definitions make dependency analysis incomplete.

Navis can identify rules that permit a particular flow locally while another control or missing route prevents end-to-end connectivity. Findings must identify the native device and rule, the analyzed scope, evidence, and limitations. A finding about one flow does not prove an entire rule is unused or safe to remove. Usage claims require suitable usage evidence; Navis recommends changes and does not apply them.

# Collection and API Access

External collectors acquire infrastructure data and push it to Navis. Product adapters interpret submitted data; they do not access devices or manage device credentials. A CMDB or other external inventory may provide identity mappings.

Application identity and credential management remain external. Navis may validate externally issued credentials and enforce API scopes and data boundaries. This refines the earlier authentication and authorization non-goal: Navis does not build an identity or credential management platform, but protects its APIs.
