# Generate a Generic Traversal Report (Static + Dynamic)

Sections
1) Summary — CWE type and impact
2) Environment — target, tools (IDA/Ghidra), probe scripts
3) Dynamic evidence — per‑payload status/previews, sensitive disclosure if any
4) Static analysis — role‑based call graph (2–3 hops), controls present/absent and order
5) Root cause — missing/incorrect control chain
6) Fix guidance — decode→validate segments→canonicalize→prefix‑check→FS
7) Verification checklist — static re‑inspection + dynamic re‑probe

Assembly steps
- Use decompiler + call graph to document roles and control placement
- Keep names role‑oriented; avoid tool‑ or symbol‑specific labels in the final report

