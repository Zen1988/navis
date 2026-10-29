# CONTRIBUTING.md

# Contributing to Navis

Thank you for contributing to Navis.

Navis is a Connectivity Intelligence Engine focused on understanding and explaining connectivity across modern enterprise infrastructure.

This document is primarily written for:

- Human contributors
- AI coding assistants
- Autonomous development agents
- Future maintainers

Before writing code, read:

```text
README.md
docs/PROJECTS.md
docs/ARCHITECTURE.md
```

The project philosophy is defined in those documents.

For collector and adapter work, follow the responsibility boundary in `docs/ARCHITECTURE.md`: collectors retrieve native evidence, product adapters normalize vendor semantics, and the analysis engine evaluates common models. Do not move vendor interpretation into the playbook or ask users to hand-map policies as a substitute for implementing the adapter. Keep incomplete or ambiguous evidence explicit and do not claim a mapping is complete without validating it.

---

# Mission Reminder

Navis exists to answer:

```text
Can Source A communicate with Destination B on Service C?
```

and:

```text
What is blocking it?
Where is it blocked?
What change is required?
```

Every contribution should improve Navis' ability to answer these questions.

---

# Rule Zero

Before implementing any feature, ask:

```text
Does this improve Navis' ability to explain connectivity?
```

If:

```text
YES
```

continue.

If:

```text
NO
```

reconsider the change.

---

# Guidance For AI Agents

This section is critical.

Most software projects fail because AI assistants optimize for technical elegance instead of product intent.

Navis prioritizes:

```text
Correctness
Explainability
Simplicity
Maintainability
```

over:

```text
Architectural novelty
Fancy frameworks
Premature optimization
```

---

# AI Design Principles

## Principle 1

Understand the domain before writing code.

Navis is:

```text
Policy Intelligence
```

Navis is not:

```text
Monitoring
Configuration Management
Network Management
PAM
CMDB
```

Do not introduce functionality from unrelated domains.

---

## Principle 2

Preserve vendor neutrality.

Never hardcode business logic around a single vendor.

Bad:

```python
if palo_alto:
```

Preferred:

```python
enforcement_point.type
```

The engine should reason about:

```text
Policy
Zone
Endpoint Group
Path
Service
```

not vendor implementations.

---

## Principle 3

Prefer abstractions over vendors.

Examples:

Instead of:

```text
NSX Group
```

prefer:

```text
EndpointGroup
```

Instead of:

```text
Palo Alto Rule
```

prefer:

```text
Policy
```

Vendor-specific fields may exist, but the analysis engine should operate on normalized models whenever practical.

---

## Principle 4

Store first, optimize later.

If information may be useful for:

```text
Audit
Debugging
Analysis
Future Features
```

store it.

Navis prefers preserving information over discarding it.

---

## Principle 5

Graph data is derived.

Graph data must be rebuildable from PostgreSQL.

Never create a feature that stores critical information exclusively inside graph structures.

Authoritative data must remain in PostgreSQL.

---

# Technical Principles

---

## PostgreSQL First

Before adding:

```text
Database
Cache
Message Bus
Queue
Search Engine
Graph Engine
```

ask:

```text
Can PostgreSQL solve this?
```

If yes:

```text
Use PostgreSQL.
```

Additional infrastructure must be justified.

---

## JSONB First

Vendor-native payloads belong in JSONB.

Example:

```json
{
  "platform": "nsx",
  "payload": {}
}
```

Do not attempt full normalization prematurely.

---

## Structured Normalization

Normalize only what is needed.

Examples:

```text
Asset
Policy
Service
Zone
Route
NAT
Endpoint Group
```

Avoid creating large numbers of tables for vendor-specific constructs.

---

## API First

Every capability should eventually be accessible through APIs.

Avoid implementing functionality that only works through:

```text
CLI
UI
Internal Code Paths
```

---

## Kubernetes Native

Assume:

```text
Kubernetes
CloudNativePG
Containerized Services
```

Avoid assumptions about:

```text
Bare Metal
Single Node Deployments
Manual Operations
```

---

# Non Goals

Contributors must not introduce functionality related to:

```text
Tenant Management
Authentication
Authorization
Workflow Approval
Secrets Management
PAM
Credential Vaulting
Direct Device Administration
```

These responsibilities belong to external systems.

Examples:

```text
CyberArk
Vault
Entra ID
ServiceNow
AWX
```

---

# Collection Philosophy

Navis does not collect infrastructure data directly.

Collection belongs to:

```text
Ansible
AWX
Automation Platforms
```

Navis consumes data.

Navis analyzes data.

Navis does not own collection.

---

# Credential Policy

Contributors must never implement:

```text
Password Storage
SSH Key Storage
Privileged API Tokens
Secrets Databases
```

Navis must remain credential-independent.

---

# Data Model Guidelines

When introducing new models:

Ask:

```text
Is this authoritative data?
```

If yes:

```text
Store in PostgreSQL.
```

Then ask:

```text
Is this a relationship?
```

If yes:

```text
Represent it in the graph layer.
```

Examples:

### Authoritative

```text
Firewall Policy
NSX Rule
ACI Contract
Asset Inventory
```

### Derived

```text
Reachability Graph
Policy Relationship Graph
Connectivity Path
```

---

# Analysis Engine Guidelines

The analysis engine should remain deterministic.

The same input should produce the same output when using the same dataset.

Analysis should be:

```text
Repeatable
Traceable
Explainable
```

Avoid heuristic-heavy implementations unless clearly documented.

---

# Recommendation Engine Rules

Recommendations must contain:

```text
Where
What
Why
```

Bad:

```text
Traffic blocked.
```

Good:

```text
Platform:
Palo Alto

Policy:
Missing APP -> DB TCP/1433

Reason:
No matching allow rule was found.
```

---

# Code Style

---

## Readability First

Prefer:

```python
if policy_matches:
    return ALLOW
```

over:

```python
return True if x and y and z else False
```

if readability suffers.

---

## Explicit Over Implicit

Prefer:

```python
resolve_route()
evaluate_nat()
evaluate_policy()
```

instead of deeply nested logic.

---

## Small Components

Prefer:

```text
Single Responsibility
```

Components should have one clear purpose.

Examples:

```text
Inventory Service
Graph Builder
Analysis Engine
Recommendation Engine
```

---

# Pull Request Guidelines

Every pull request should explain:

```text
What problem is being solved?

Why is it needed?

How does it improve connectivity analysis?

How was it tested?
```

---

# Documentation Requirements

New features should include:

```text
Purpose
Architecture
Data Flow
Examples
```

If a feature cannot be explained simply, reconsider the design.

---

# Architecture Decision Records

Major decisions should be documented.

Examples:

```text
New Databases
New Frameworks
New Storage Models
New Platform Integrations
```

Use:

```text
/docs/ADR
```

Format:

```text
Context
Decision
Alternatives
Consequences
```

---

# Things AI Agents Must Avoid

Do not introduce:

```text
Microservices without justification
Additional databases by default
Complex event systems prematurely
Vendor-specific business logic
Custom authentication systems
Custom RBAC systems
Custom secrets management systems
```

Navis favors simplicity.

---

# Success Criteria

A change is successful when Navis becomes better at answering:

```text
Can source communicate with destination?

Why?

Through what path?

Through which policies?

What is required to enable connectivity?
```

If a contribution improves those answers, it is likely a good contribution.

---

# Final Principle

```text
Understand Every Path.
```

Every contribution should bring Navis closer to that objective.
