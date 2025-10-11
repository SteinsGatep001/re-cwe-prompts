# Gap Analysis and Fix Blueprint (Generic)

Objective: Determine whether a route→sink path is vulnerable to CWE-22 and describe a fix blueprint that can be applied in the handler layer.

Checklist (for each route→sink path)
- Is URL decoding performed? Is decoding order safe (defeats double-encoding)?
- Are path segments validated individually? (reject '.', '..', control chars, embedded '/')
- Is canonicalization performed (realpath) on the candidate path?
- Is there a base-directory prefix containment check post-canonicalization?
- Are FS calls gated on all of the above? (no early calls)

If any answer is "no":
- Insert a guard sequence BEFORE FS calls:
  1) Decode to stable form (reject nested encoding or iterate to stability with a cap)
  2) Split and validate each segment (safe character policy; no '.'/'..')
  3) Compose absolute path under the intended base; realpath it
  4) Enforce canonical prefix containment (canonical(candidate).startswith(canonical(base)))
  5) On failure, send 404/403; do not proceed to FS sink

Documentation
- Use `set_comment` on handler and path utility functions to record the required preconditions and why they matter (link to CWE-22).

