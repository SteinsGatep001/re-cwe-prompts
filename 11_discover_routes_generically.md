# Discover Request Routes (Generic, No Specific Names)

Goal: Locate HTTP route dispatchers and candidate static content handlers without relying on exact symbol names.

Steps (ida-pro-mcp)
1) Enumerate HTTP-related strings
   - Use: `list_strings_filter(filter="HTTP/1")`, `list_strings_filter(filter="Content-Type")`, `list_strings_filter(filter="Location:")`
   - For UI/static buckets, also try broader content strings: `list_strings_filter(filter=".html")`, `list_strings_filter(filter="text/html")`

2) Xref hunt to candidate dispatchers
   - For each interesting string address, run: `get_xrefs_to(<addr>)`
   - Decompile those functions: `decompile_function(<func_addr>)`
   - Look for large branching over path tokens (strcmp/equals-fold), and many callees — a sign of router/dispatcher.

3) Identify path extraction points
   - In decompiled code, locate reads of request path buffers and string operations: URL decode, strchr for '/', memcpy/memmove, path joins.
   - Tag these functions via `set_comment` (describe role generically: "route dispatcher", "static handler", "path utility").

4) Mark candidate static handlers
   - Handlers that build filesystem paths from request path + base directory and then invoke file existence/open routines are traversal candidates.

