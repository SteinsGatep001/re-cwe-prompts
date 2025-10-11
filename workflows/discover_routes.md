# Discover Request Routes (Generic)

See also: `tool-notes/IDA_MCP.md` for IDA MCP command cheatsheet.

Goal: Locate HTTP route dispatchers and candidate static handlers without relying on exact symbol names.

Steps (IDA MCP / Ghidra)
0) Seed from captures (primary)
   - From `targets-local/<TARGET_KEY>/captures/`, extract request lines and dedupe paths into `routes[]` in target.json.
   - Save top‑N request lines to `targets-local/<TARGET_KEY>/evidence/top_request_lines.txt`.
1) Enumerate HTTP‑related strings
   - Search for: `HTTP/1`, `Content-Type`, `Location:`, common extensions (`.html`, `.css`, images)
2) Xref to candidate dispatchers
   - Jump to refs and decompile; look for branching on path tokens and many callees
3) Identify path extraction points
   - Find reads of request path buffers and string ops: URL decode, strchr/split, memmove/join
4) Mark candidate static handlers
   - Handlers that build filesystem paths from request path + base directory and then invoke file existence/open routines are traversal candidates
