# Phase 29 — Threat knowledge graph

The threat graph renders only durable evidence already stored in Cascadia:

- security event to asset edges, from an event's `assetExternalIds`;
- anomaly finding to source event edges;
- incident to evidence edges when the evidence was manually linked; and
- threat indicators as separate source-intelligence nodes until evidence links them to an incident.

It deliberately does not infer relationships, geographical position, impact, or compromise from an indicator alone.
