# Gap Analysis and Fix Blueprint (Generic)

Checklist (for each route→sink path)
- URL decoding: performed and safe against double‑encoding?
- Segment validation: each segment checked (no '.'/'..'/control chars/'/')?
- Canonicalization: realpath of the candidate path under allowed base?
- Base prefix enforcement: canonical(candidate) startswith canonical(base)?
- Sink gating: FS calls occur only after all controls?

Fix shape (apply BEFORE sink)
1) Decode to a stable form (reject nested encoding or iterate to stability with a cap)
2) Split and validate segments (safe character policy)
3) Compose absolute path under base; realpath it
4) Enforce prefix containment
5) On failure, return 404/403; do not call sink

