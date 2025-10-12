# Ghidra MCP Tool Categories

**Total Tools:** 57 MCP Tools
**Status:** Production Ready (100% success rate)
**Version:** Based on Ghidra MCP v1.2.0

---

## 📋 Overview

This document catalogs all 57 Ghidra MCP tools, organized into 7 functional categories. Each tool is documented with parameters, return values, and practical examples.

---

## 🔧 Category 1: Core System Tools (6 tools)

Essential tools for connection, metadata, and basic operations.

### 1.1 Connection & Status

#### `check_connection`
**Purpose:** Verify Ghidra MCP plugin connectivity
**Parameters:** None
**Returns:** Connection status message
**Usage:**
```python
status = check_connection()
# Returns: {"status": "connected", "version": "1.2.0"}
```

#### `get_metadata`
**Purpose:** Get current program metadata
**Parameters:** None
**Returns:** Program information (name, architecture, base address, entry points)
**Usage:**
```python
metadata = get_metadata()
# Returns: {
#   "program_name": "snmpd",
#   "architecture": "MIPS:BE:32:default",
#   "base_address": "0x00400000",
#   "entry_points": ["0x00401000"]
# }
```

#### `get_entry_points`
**Purpose:** List all program entry points
**Parameters:** None
**Returns:** List of entry point addresses and names
**Usage:**
```python
entries = get_entry_points()
# Returns: [{"address": "0x401000", "name": "_start"}]
```

### 1.2 Current Location

#### `get_current_address`
**Purpose:** Get cursor address in Ghidra GUI
**Parameters:** None
**Returns:** Hex address string
**Usage:**
```python
addr = get_current_address()
# Returns: "0x00401234"
```

#### `get_current_function`
**Purpose:** Get function at cursor location
**Parameters:** None
**Returns:** Function information at current address
**Usage:**
```python
func = get_current_function()
# Returns: {"name": "main", "address": "0x401000", "size": 256}
```

### 1.3 Utilities

#### `convert_number`
**Purpose:** Convert numbers between formats (hex/dec/bin)
**Parameters:**
- `text` (str): Number to convert (e.g., "0x1234" or "4660")
- `size` (int): Size in bytes (1, 2, 4, or 8)
**Returns:** Multiple representations
**Usage:**
```python
result = convert_number("0x1234", size=4)
# Returns: {
#   "hex": "0x1234",
#   "decimal": 4660,
#   "binary": "0001001000110100",
#   "signed": 4660,
#   "unsigned": 4660
# }
```

---

## 🔍 Category 2: Function Analysis Tools (19 tools)

Comprehensive function discovery, analysis, and modification capabilities.

### 2.1 Function Discovery

#### `list_functions`
**Purpose:** List all functions with pagination
**Parameters:**
- `offset` (int): Starting position (default: 0)
- `limit` (int): Max results (default: 100)
**Returns:** List of functions with metadata
**Usage:**
```python
funcs = list_functions(offset=0, limit=100)
# Returns: [
#   {"name": "main", "address": "0x401000", "size": 256},
#   {"name": "FUN_00401100", "address": "0x401100", "size": 128}
# ]
```

#### `search_functions_by_name`
**Purpose:** Search functions by name pattern
**Parameters:**
- `query` (str): Search pattern (e.g., "handler", "snmp")
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** Matching functions
**Usage:**
```python
handlers = search_functions_by_name(query="handler", limit=50)
# Returns: [
#   {"name": "snmp_handler", "address": "0x402000"},
#   {"name": "http_handler", "address": "0x403000"}
# ]
```

#### `get_function_by_address`
**Purpose:** Get function at specific address
**Parameters:**
- `address` (str): Hex address (e.g., "0x401000")
**Returns:** Function information
**Usage:**
```python
func = get_function_by_address("0x401000")
# Returns: {"name": "main", "address": "0x401000", "size": 256}
```

### 2.2 Function Code Analysis

#### `decompile_function`
**Purpose:** Decompile function to C pseudocode
**Parameters:**
- `name` (str): Function name (e.g., "main")
**Returns:** Decompiled C code
**Usage:**
```python
code = decompile_function("main")
# Returns: """
# int main(int argc, char** argv) {
#   ...
# }
# """
```

#### `disassemble_function`
**Purpose:** Get assembly code listing
**Parameters:**
- `address` (str): Function address
**Returns:** Assembly instructions with addresses
**Usage:**
```python
asm = disassemble_function("0x401000")
# Returns: [
#   {"address": "0x401000", "instruction": "addiu $sp,$sp,-0x20"},
#   {"address": "0x401004", "instruction": "sw $ra,0x1c($sp)"}
# ]
```

#### `get_function_labels`
**Purpose:** Get all labels within a function
**Parameters:**
- `name` (str): Function name
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 20)
**Returns:** List of labels
**Usage:**
```python
labels = get_function_labels("main", limit=20)
# Returns: [
#   {"address": "0x401020", "name": "loop_start"},
#   {"address": "0x401040", "name": "error_exit"}
# ]
```

#### `get_function_jump_target_addresses`
**Purpose:** Get all jump target addresses in function
**Parameters:**
- `name` (str): Function name
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of jump targets
**Usage:**
```python
jumps = get_function_jump_target_addresses("dispatcher", limit=50)
# Returns: ["0x401100", "0x401200", "0x401300"]
```

### 2.3 Function Relationships

#### `get_function_xrefs`
**Purpose:** Get all cross-references TO a function
**Parameters:**
- `name` (str): Function name
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of references
**Usage:**
```python
xrefs = get_function_xrefs("snmp_handler", limit=50)
# Returns: [
#   {"from_address": "0x403000", "type": "CALL"},
#   {"from_address": "0x404000", "type": "CALL"}
# ]
```

#### `get_function_callees`
**Purpose:** Get functions CALLED BY this function
**Parameters:**
- `name` (str): Function name
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of called functions
**Usage:**
```python
callees = get_function_callees("main", limit=50)
# Returns: [
#   {"name": "init_config", "address": "0x402000"},
#   {"name": "start_server", "address": "0x403000"}
# ]
```

#### `get_function_callers`
**Purpose:** Get functions that CALL this function
**Parameters:**
- `name` (str): Function name
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of caller functions
**Usage:**
```python
callers = get_function_callers("validate_path", limit=50)
# Returns: [
#   {"name": "handle_get_request", "address": "0x404000"},
#   {"name": "handle_post_request", "address": "0x405000"}
# ]
```

#### `get_function_call_graph`
**Purpose:** Get localized call graph for a function
**Parameters:**
- `name` (str): Function name
- `depth` (int): Max depth to traverse (default: 2)
- `direction` (str): "callers", "callees", or "both" (default: "both")
**Returns:** List of call relationships
**Usage:**
```python
graph = get_function_call_graph("dispatcher", depth=3, direction="callees")
# Returns: [
#   "dispatcher -> handler_get",
#   "dispatcher -> handler_post",
#   "handler_get -> validate_path",
#   "handler_get -> open_file"
# ]
```

#### `get_full_call_graph`
**Purpose:** Get complete program call graph
**Parameters:**
- `format` (str): "edges", "adjacency", "dot", or "mermaid" (default: "edges")
- `limit` (int): Max edges (default: 1000)
**Returns:** Call graph in specified format
**Usage:**
```python
graph = get_full_call_graph(format="mermaid", limit=500)
# Returns: Mermaid diagram syntax for visualization
```

### 2.4 Function Modification

#### `rename_function`
**Purpose:** Rename function by current name
**Parameters:**
- `old_name` (str): Current function name
- `new_name` (str): New function name
**Returns:** Success/failure message
**Usage:**
```python
rename_function("FUN_00401000", "snmp_request_handler")
# Returns: {"status": "success", "renamed": "FUN_00401000 -> snmp_request_handler"}
```

#### `rename_function_by_address`
**Purpose:** Rename function by address
**Parameters:**
- `function_address` (str): Function address
- `new_name` (str): New function name
**Returns:** Success/failure message
**Usage:**
```python
rename_function_by_address("0x401000", "main_entry")
```

#### `set_function_prototype`
**Purpose:** Set function signature/prototype
**Parameters:**
- `function_address` (str): Function address
- `prototype` (str): Function signature (e.g., "int main(int argc, char** argv)")
- `calling_convention` (str): Optional (e.g., "__cdecl", "__stdcall")
**Returns:** Success/failure message
**Usage:**
```python
set_function_prototype(
    "0x401000",
    "int snmp_handler(snmp_request* req, snmp_response* resp)"
)
```

#### `rename_variable`
**Purpose:** Rename local variable within function
**Parameters:**
- `function_name` (str): Function containing the variable
- `old_name` (str): Current variable name (e.g., "iVar1")
- `new_name` (str): New variable name
**Returns:** Success/failure message
**Usage:**
```python
rename_variable("main", "iVar1", "status_code")
rename_variable("main", "pcVar2", "buffer_ptr")
```

#### `set_local_variable_type`
**Purpose:** Set type of local variable
**Parameters:**
- `function_address` (str): Function address
- `variable_name` (str): Variable name
- `new_type` (str): New type (e.g., "int", "char*", "size_t")
**Returns:** Success/failure message
**Usage:**
```python
set_local_variable_type("0x401000", "buffer", "char[256]")
set_local_variable_type("0x401000", "fd", "int")
```

---

## 🗂️ Category 3: Data Structure Tools (16 tools)

Tools for discovering, creating, and managing data types and structures.

### 3.1 Program Structure

#### `list_classes`
**Purpose:** List namespace/class names (C++ binaries)
**Parameters:**
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of classes/namespaces
**Usage:**
```python
classes = list_classes(limit=50)
# Returns: ["std::string", "HttpServer::Connection"]
```

#### `list_segments`
**Purpose:** List memory segments
**Parameters:**
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** Memory segment information
**Usage:**
```python
segments = list_segments()
# Returns: [
#   {"name": ".text", "start": "0x400000", "end": "0x410000", "perms": "r-x"},
#   {"name": ".data", "start": "0x420000", "end": "0x421000", "perms": "rw-"}
# ]
```

#### `list_namespaces`
**Purpose:** List non-global namespaces
**Parameters:**
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of namespaces
**Usage:**
```python
namespaces = list_namespaces(limit=50)
```

### 3.2 Data Types - Basic

#### `list_data_types`
**Purpose:** List available data types
**Parameters:**
- `category` (str): Optional filter ("struct", "enum", "pointer", etc.)
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of data types
**Usage:**
```python
structs = list_data_types(category="struct", limit=50)
# Returns: [
#   {"name": "sockaddr", "category": "struct", "size": 16},
#   {"name": "in_addr", "category": "struct", "size": 4}
# ]
```

#### `create_struct`
**Purpose:** Create new structure definition
**Parameters:**
- `name` (str): Structure name
- `fields` (list): Field definitions [{"name": str, "type": str, "offset": int (optional)}]
**Returns:** Success/failure message
**Usage:**
```python
fields = [
    {"name": "version", "type": "int"},
    {"name": "community", "type": "char[32]"},
    {"name": "pdu_type", "type": "byte"},
    {"name": "data_ptr", "type": "void*"}
]
create_struct("snmp_packet", fields)
```

#### `create_enum`
**Purpose:** Create new enumeration
**Parameters:**
- `name` (str): Enum name
- `values` (dict): Name-value pairs (e.g., {"IDLE": 0, "RUNNING": 1})
- `size` (int): Size in bytes (1, 2, 4, or 8, default: 4)
**Returns:** Success/failure message
**Usage:**
```python
values = {
    "SNMP_GET": 0,
    "SNMP_GETNEXT": 1,
    "SNMP_SET": 3,
    "SNMP_TRAP": 4
}
create_enum("snmp_pdu_type", values, size=1)
```

#### `apply_data_type`
**Purpose:** Apply data type at memory address
**Parameters:**
- `address` (str): Target address
- `type_name` (str): Data type name to apply
- `clear_existing` (bool): Clear existing data (default: True)
**Returns:** Success/failure message
**Usage:**
```python
apply_data_type("0x420000", "snmp_packet", clear_existing=True)
```

### 3.3 Data Types - Advanced

#### `mcp_ghidra_analyze_data_types`
**Purpose:** Analyze data types at address with depth
**Parameters:**
- `address` (str): Target address
- `depth` (int): Analysis depth for following pointers (default: 1)
**Returns:** Detailed type analysis
**Usage:**
```python
analysis = mcp_ghidra_analyze_data_types("0x420000", depth=2)
```

#### `mcp_ghidra_create_union`
**Purpose:** Create union type
**Parameters:**
- `name` (str): Union name
- `fields` (list): Field definitions
**Returns:** Success/failure message
**Usage:**
```python
fields = [
    {"name": "as_int", "type": "int"},
    {"name": "as_float", "type": "float"},
    {"name": "as_bytes", "type": "char[4]"}
]
mcp_ghidra_create_union("value_union", fields)
```

#### `mcp_ghidra_get_type_size`
**Purpose:** Get type size and alignment
**Parameters:**
- `type_name` (str): Data type name
**Returns:** Size and alignment information
**Usage:**
```python
info = mcp_ghidra_get_type_size("snmp_packet")
# Returns: {"size": 276, "alignment": 4}
```

#### `mcp_ghidra_get_struct_layout`
**Purpose:** Get detailed structure layout with field offsets
**Parameters:**
- `struct_name` (str): Structure name
**Returns:** Detailed layout information
**Usage:**
```python
layout = mcp_ghidra_get_struct_layout("snmp_packet")
# Returns: [
#   {"name": "version", "offset": 0, "size": 4, "type": "int"},
#   {"name": "community", "offset": 4, "size": 32, "type": "char[32]"},
#   ...
# ]
```

#### `mcp_ghidra_search_data_types`
**Purpose:** Search data types by name pattern
**Parameters:**
- `pattern` (str): Search pattern
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** Matching data types
**Usage:**
```python
types = mcp_ghidra_search_data_types("request", limit=20)
```

#### `mcp_ghidra_auto_create_struct`
**Purpose:** Automatically create structure by analyzing memory
**Parameters:**
- `address` (str): Target address
- `size` (int): Size in bytes (0 for automatic)
- `name` (str): Structure name
**Returns:** Success/failure message
**Usage:**
```python
mcp_ghidra_auto_create_struct("0x421000", size=128, name="auto_discovered_struct")
```

#### `mcp_ghidra_get_enum_values`
**Purpose:** Get all values in an enumeration
**Parameters:**
- `enum_name` (str): Enumeration name
**Returns:** List of enum values
**Usage:**
```python
values = mcp_ghidra_get_enum_values("snmp_pdu_type")
# Returns: [
#   {"name": "SNMP_GET", "value": 0},
#   {"name": "SNMP_GETNEXT", "value": 1}
# ]
```

#### `mcp_ghidra_create_typedef`
**Purpose:** Create type alias/typedef
**Parameters:**
- `name` (str): Typedef name
- `base_type` (str): Base type to alias
**Returns:** Success/failure message
**Usage:**
```python
mcp_ghidra_create_typedef("RequestHandler", "int (*)(snmp_request*)")
```

#### `mcp_ghidra_clone_data_type`
**Purpose:** Clone existing data type with new name
**Parameters:**
- `source_type` (str): Source type name
- `new_name` (str): New type name
**Returns:** Success/failure message
**Usage:**
```python
mcp_ghidra_clone_data_type("snmp_packet", "snmpv3_packet")
```

#### `mcp_ghidra_validate_data_type`
**Purpose:** Validate if type can be applied at address
**Parameters:**
- `address` (str): Target address
- `type_name` (str): Data type to validate
**Returns:** Validation results
**Usage:**
```python
result = mcp_ghidra_validate_data_type("0x422000", "snmp_packet")
# Returns: {"valid": True, "alignment_ok": True, "size_available": True}
```

#### `mcp_ghidra_export_data_types`
**Purpose:** Export data types to C header or JSON
**Parameters:**
- `format` (str): "c", "json", or "summary" (default: "c")
- `category` (str): Optional category filter
**Returns:** Exported type definitions
**Usage:**
```python
header = mcp_ghidra_export_data_types(format="c", category="struct")
# Returns: C header file content
```

---

## 📊 Category 4: Data Analysis Tools (5 tools)

Tools for analyzing data items, strings, and cross-references.

### 4.1 Data Items & Strings

#### `list_data_items`
**Purpose:** List defined data labels
**Parameters:**
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of data items
**Usage:**
```python
data = list_data_items(limit=50)
# Returns: [
#   {"address": "0x420000", "name": "server_config", "type": "config_t"},
#   {"address": "0x421000", "name": "DAT_00421000", "type": "undefined4"}
# ]
```

#### `list_strings`
**Purpose:** List all strings with optional filter
**Parameters:**
- `filter` (str): Optional filter pattern
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 2000)
**Returns:** List of strings
**Usage:**
```python
# Find all strings
all_strings = list_strings(limit=1000)

# Find HTTP routes
routes = list_strings(filter="/api/", limit=200)

# Find SNMP-related strings
snmp = list_strings(filter="community", limit=50)
```

#### `rename_data`
**Purpose:** Rename data label at address
**Parameters:**
- `address` (str): Data address
- `new_name` (str): New label name
**Returns:** Success/failure message
**Usage:**
```python
rename_data("0x420000", "snmp_community_string")
```

### 4.2 Cross-References

#### `get_xrefs_to`
**Purpose:** Get all references TO an address
**Parameters:**
- `address` (str): Target address
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of references
**Usage:**
```python
xrefs = get_xrefs_to("0x420000", limit=50)
# Returns: [
#   {"from_address": "0x401000", "type": "READ", "function": "main"},
#   {"from_address": "0x402000", "type": "WRITE", "function": "init_config"}
# ]
```

#### `get_xrefs_from`
**Purpose:** Get all references FROM an address
**Parameters:**
- `address` (str): Source address
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of references
**Usage:**
```python
xrefs = get_xrefs_from("0x401000", limit=50)
# Returns: [
#   {"to_address": "0x420000", "type": "READ"},
#   {"to_address": "0x430000", "type": "CALL"}
# ]
```

---

## 🏷️ Category 5: Symbol Management Tools (7 tools)

Tools for managing labels, globals, imports, and exports.

### 5.1 Labels

#### `create_label`
**Purpose:** Create new label at address
**Parameters:**
- `address` (str): Target address
- `name` (str): Label name
**Returns:** Success/failure message
**Usage:**
```python
create_label("0x423000", "crypto_key_buffer")
```

#### `rename_label`
**Purpose:** Rename existing label
**Parameters:**
- `address` (str): Label address
- `old_name` (str): Current label name
- `new_name` (str): New label name
**Returns:** Success/failure message
**Usage:**
```python
rename_label("0x423000", "DAT_00423000", "jwt_secret")
```

### 5.2 Global Variables

#### `list_globals`
**Purpose:** List global variables
**Parameters:**
- `filter` (str): Optional filter pattern
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of global variables
**Usage:**
```python
# All globals
all_globals = list_globals(limit=100)

# Filtered search
configs = list_globals(filter="config", limit=50)
```

#### `rename_global_variable`
**Purpose:** Rename global variable
**Parameters:**
- `old_name` (str): Current name
- `new_name` (str): New name
**Returns:** Success/failure message
**Usage:**
```python
rename_global_variable("DAT_00424000", "server_port")
```

### 5.3 Import/Export Analysis

#### `list_imports`
**Purpose:** List imported symbols
**Parameters:**
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of imported symbols
**Usage:**
```python
imports = list_imports(limit=100)
# Returns: [
#   {"name": "malloc", "library": "libc.so.6", "address": "0x400500"},
#   {"name": "strcpy", "library": "libc.so.6", "address": "0x400510"}
# ]
```

#### `list_exports`
**Purpose:** List exported symbols
**Parameters:**
- `offset` (int): Pagination offset
- `limit` (int): Max results (default: 100)
**Returns:** List of exported symbols
**Usage:**
```python
exports = list_exports(limit=100)
# Returns: [
#   {"name": "snmp_init", "address": "0x401000"},
#   {"name": "snmp_process_request", "address": "0x402000"}
# ]
```

---

## 💬 Category 6: Documentation Tools (2 tools)

Tools for adding comments and annotations.

#### `set_decompiler_comment`
**Purpose:** Add comment in decompiled view
**Parameters:**
- `address` (str): Address to comment
- `comment` (str): Comment text (supports // C-style comments)
**Returns:** Success/failure message
**Usage:**
```python
set_decompiler_comment(
    "0x401234",
    "// SECURITY: CVE-2025-20362 Path traversal vulnerability\n"
    "// Risk: Missing path validation before file open\n"
    "// Fix: Add canonicalize_path() + prefix check"
)
```

#### `set_disassembly_comment`
**Purpose:** Add comment in assembly view
**Parameters:**
- `address` (str): Address to comment
- `comment` (str): Comment text (supports ; assembly-style comments)
**Returns:** Success/failure message
**Usage:**
```python
set_disassembly_comment(
    "0x401234",
    "; Missing bounds check - buffer overflow risk"
)
```

---

## 🚀 Category 7: Advanced Features (2 tools)

Already covered in Function Analysis (call graph tools).

---

## 💡 Quick Reference: Common Tasks

### Task 1: Find All Handlers
```python
# Search by name
handlers = search_functions_by_name("handler", limit=100)

# Or by string references
routes = list_strings(filter="/api/", limit=100)
for route in routes:
    xrefs = get_xrefs_to(route['address'])
    # Analyze each xref
```

### Task 2: Analyze Function
```python
# Get code
code = decompile_function("snmp_handler")

# Get relationships
callees = get_function_callees("snmp_handler")
callers = get_function_callers("snmp_handler")

# Build call graph
graph = get_function_call_graph("snmp_handler", depth=3, direction="both")
```

### Task 3: Rename Systematically
```python
# Rename function
rename_function_by_address("0x401000", "snmp_request_dispatcher")

# Set function signature
set_function_prototype("0x401000", "int snmp_request_dispatcher(snmp_pdu* pdu)")

# Rename variables
rename_variable("snmp_request_dispatcher", "iVar1", "pdu_type")
rename_variable("snmp_request_dispatcher", "pcVar2", "community_str")
```

### Task 4: Document Vulnerability
```python
# Add security comment
set_decompiler_comment(
    "0x402345",
    "// VULNERABILITY: Buffer overflow in strcpy\n"
    "// CWE-120: Buffer Copy without Checking Size of Input\n"
    "// Fix: Replace with strncpy or strlcpy"
)

# Rename function to mark it
rename_function_by_address("0x402300", "VULN_unsafe_string_copy")
```

---

**Last Updated:** 2025-10-12
**Status:** Complete (57/57 tools documented)
**Version:** Based on Ghidra MCP v1.2.0
