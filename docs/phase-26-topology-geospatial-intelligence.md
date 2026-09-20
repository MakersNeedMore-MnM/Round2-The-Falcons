# Phase 26: topology and geospatial intelligence

## Delivered

- Operational map at `/app/topology`.
- Dependency lines between assets with user-provided valid latitude and longitude metadata.
- Location evidence table and explicit unmapped-asset behavior.
- Optional site name and coordinate inputs when creating a new asset from the Launchpad.

## Boundary

The map never geocodes, estimates, or fabricates an asset location. It renders only coordinates explicitly stored in asset metadata.
