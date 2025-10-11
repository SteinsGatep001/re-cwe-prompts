# Naming and Comments Template

Purpose
- Keep role-driven names and succinct comments that accelerate team comprehension.

Conventions
- Function rename: `<role>__<short_purpose>` e.g., `handler__download`, `sanitize__canonicalize_path`.
- Variable rename: `req_path`, `canon_path`, `base_dir`.
- Comment: `role:<role>; controls:<decode,validate,canon,prefix>; notes:<key observation>`.

IDA MCP
- Use `set_comment` at function entry and at critical guards/sinks.
- Keep names short and role-first.

Ghidra
- Plate Comments at function heads; rename symbols with role-first scheme.

Do
- Prefer roles over guessed library names.
- Note ordering of guards explicitly.

Don’t
- Don’t rename aggressively if confidence is low — use comments first.

