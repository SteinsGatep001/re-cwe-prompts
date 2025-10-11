# Discover Request Routes (Generic)

Goal: Locate HTTP route dispatchers and candidate static handlers without relying on exact symbol names.

Steps (IDA MCP / Ghidra)
1) Enumerate HTTP‑related strings
   - Search for: `HTTP/1`, `Content-Type`, `Location:`, common extensions (`.html`, `.css`, images)
2) Xref to candidate dispatchers
   - Jump to refs and decompile; look for branching on path tokens and many callees
3) Identify path extraction points
   - Find reads of request path buffers and string ops: URL decode, strchr/split, memmove/join
4) Mark candidate static handlers
   - Handlers that build filesystem paths from request path + base directory and then invoke file existence/open routines are traversal candidates

