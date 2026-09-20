# Phase 24: role-aware console

## Delivered

- Server-issued access-context endpoint at `GET /api/v1/access/context`.
- Console navigation tailored to the authenticated role: viewer, auditor, analyst, incident commander, OT engineer, organization administrator, or platform administrator.
- API authorization remains the sole enforcement point; hiding a console link never grants or removes access.

## Boundary

The browser consumes only a server-issued role and permission summary. It contains no secrets and makes no authorization decision for the API.
