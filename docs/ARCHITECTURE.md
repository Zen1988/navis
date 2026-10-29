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

---

# Connectivity Data and Analysis Design

The following is a conceptual design for implementation, not a completed schema.
See [PostgreSQL schema design](SCHEMA.md) for proposed tables, relationships, and constraints.

## Identity and snapshots

Each device has a stable Navis UUID. Source-system identifiers map to that UUID with provenance and validity; CMDB, collector, or explicitly supplied mappings can provide the association. IP addresses, device type, and display names can help identify candidates but are not sufficient to merge devices automatically. Ambiguous imports remain unresolved for reconciliation.

A device can have many addresses on physical interfaces, VLAN interfaces, loopbacks, or management interfaces. Interface addresses and routing contexts are distinct records; overlapping IP addresses can exist in different contexts. A device snapshot records collection and ingestion times, platform and firmware version, and completeness by data type. Normalized records reference their snapshot, and raw vendor payloads are preserved in JSONB. Record the adapter version used to interpret a payload.

An analysis records the precise snapshots used across devices and reports missing, incomplete, or stale evidence. This allows results to be understood and reproduced even when collection times differ.

## Routes and topology

Route records include a destination prefix, routing context, route type, protocol, preference and metric when supplied. Related next-hop records support multiple next hops and outgoing interfaces. Preserve whether the collected data represents candidate routes, selected routing entries, or installed forwarding entries; do not treat a persisted selection flag as a permanent decision.

For a destination and routing context, the engine finds containing prefixes and applies longest-prefix matching, then uses available platform-specific selection and eligibility evidence. It handles recursive next hops, alternatives, discard routes and loops. A more specific route does not automatically fall back to a broader one when a next hop fails. BGP instances, peers, AS paths, filters, import/export policy and redistribution are optional evidence for explaining route exchange and selection.

Neighbor and MAC forwarding entries help resolve next-hop IPs, interfaces and Layer 2 attachment. MAC entries alone do not establish a direct link. Imported neighbor and topology evidence, and manually declared links where discovery is unavailable, contribute relationships to the graph. Store manual links in PostgreSQL with endpoints, context and provenance; preserve conflicts and uncertainty rather than silently overwriting evidence.

## NAT and policy

NAT rules are ordered and preserve match conditions, processing context, translation action, and native references. Support source and destination translation, combined translation, dynamic pools and port translation, and explicit no-NAT rules where the platform supports them. The engine carries packet addresses and ports through transformations. Adapters preserve platform-specific routing, NAT and policy processing order and identify which original or translated fields each stage evaluates.

Adapters convert native policy constructs into a shared model while retaining their evaluation semantics and native object references. Policy rule sets capture scope, ordering, direction and a default action of allow, deny or unknown. Apply the default only when the relevant rule set and its behavior are known; incomplete evidence produces an unknown result. Rules retain native device rule IDs, selectors, action, service, schedule or validity, and applicable interfaces and security zones. Address objects represent effective hosts, prefixes, ranges, groups and exclusions separately from interface subnet configuration.

Organizational network zones and device-specific security zones are separate concepts. Security zones are scoped to the relevant enforcement point and context, and their membership and mapping are interpreted by the adapter. Zone names are not globally unique. VRFs represent routing contexts; a policy permitting traffic between contexts does not by itself establish a route between them.

## Graph and application views

Apache AGE holds a derived global graph of topology and routing relationships, with links to source records and snapshots. Graph traversal discovers candidate paths; the analysis engine evaluates destination prefixes, routing contexts, NAT and enforcement at each step. Graph data is rebuildable from PostgreSQL and does not serve as the sole source of critical information.

The initial builder and its current limitations are described in [Graph builder](GRAPH.md).

Application membership and required flows are stored in PostgreSQL. An application view combines explicitly selected members with dynamically derived paths and controls for those flows. Alternative paths and shared dependencies remain visible when supported by evidence. Without defined flows, dependency analysis is incomplete.

## Results and recommendations

API results identify the analyzed flow and snapshots, path steps, route decisions, packet transformations, policy evaluations, evidence, and any uncertainty. Recommendations identify the enforcement device, native policy context, source and destination, zones, service, action, applicable interfaces, validity and rule placement when known. An unspecified validity period must not imply a permanent rule.

Policy-effectiveness findings identify the native rule ID and device, analyzed flow, evidence, coverage and limitations. A rule that permits one flow locally may still be ineffective end to end, but that alone does not establish that the entire rule is unused or safe to delete. Duplicate, shadowed or expired-rule findings require sufficient platform-specific evidence; usage claims require usage data. Navis provides findings for external review and does not deploy changes.

## Adapter integrity and ingestion

An approved artifact registry records adapter product, version, executable digest and approval status. The runtime verifies trusted adapter bytes before execution and rejects unknown, revoked or mismatched artifacts, recording the failure. Approvals and expected hashes come from a trusted administrative release process, never from the submitted payload. See [PostgreSQL schema design](SCHEMA.md) for the proposed records and execution boundary.

Authenticated transport, application identity, authorization and payload validation protect ingestion independently. A hash mismatch indicates an integrity failure; it cannot by itself establish the cause or authenticate a collector. External collectors retain responsibility for their own executables and device access.

For production deployments, a trusted ingress such as Apache HTTP Server can enforce client-certificate authentication with mTLS in addition to Navis application authentication and scope checks. Direct access to the API must be restricted; forwarded certificate identities must be injected only by the trusted ingress after stripping caller-supplied identity headers. Certificate identity must be mapped to an authorized consumer. The detailed trust boundary and current implementation status are in [API design](API.md).
