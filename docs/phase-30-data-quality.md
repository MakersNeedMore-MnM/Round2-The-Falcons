# Phase 30 — Data quality and connector freshness

`GET /api/v1/data-quality` reports the freshness of configured integrations using only stored signed-delivery evidence. A source is **current** when Cascadia recorded a delivery in the last 24 hours; it is **stale** after that window, and **no data** when no delivery has been stored.

This is an evidence-quality view, not a vendor availability probe and not a claim that all upstream data was complete.
