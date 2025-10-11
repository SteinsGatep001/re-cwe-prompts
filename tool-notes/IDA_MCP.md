# IDA MCP Notes (Command Cheatsheet)

Connection
- `check_connection`

Discovery
- `list_strings_filter {count, filter, offset}`
- `get_xrefs_to {address}`

Decompile/Graph
- `decompile_function {address}`
- `get_callees {function_address}`
- `get_callers {function_address}`

Annotate
- `rename_function {function_address, new_name}`
- `set_comment {address, comment}`

Types/Vars (as needed)
- `set_function_prototype {function_address, prototype}`
- `set_local_variable_type {function_address, variable_name, new_type}`

Tips
- Move from strings → xrefs → functions → callees; tag by role.
- Keep renames role-based (see `roles/README.md`).

