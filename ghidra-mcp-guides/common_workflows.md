# Ghidra MCP Common Workflows

**Purpose:** Standard analysis workflows using Ghidra MCP tools for systematic reverse engineering.

---

## 📋 Overview

This document provides proven workflows for common reverse engineering tasks. Each workflow is tool-agnostic (not protocol-specific) and can be applied across different analysis scenarios.

### Workflow Categories
1. [Basic Discovery Workflows](#basic-discovery-workflows) - Find entry points, strings, functions
2. [Code Analysis Workflows](#code-analysis-workflows) - Analyze function behavior and relationships
3. [Data Flow Workflows](#data-flow-workflows) - Trace data from source to sink
4. [Code Enhancement Workflows](#code-enhancement-workflows) - Rename and document systematically
5. [Vulnerability Analysis Workflows](#vulnerability-analysis-workflows) - Find and document security issues

---

## 🔍 Basic Discovery Workflows

### Workflow 1: String Search → Xref → Decompile

**Purpose:** Find functions that reference specific strings (routes, commands, error messages)

**Steps:**
```python
# Step 1: Search for strings
target_strings = list_strings(filter="<search_pattern>", limit=100)

# Step 2: For each string, find cross-references
for string_item in target_strings:
    print(f"\n=== String: '{string_item['value']}' at {string_item['address']} ===")
    xrefs = get_xrefs_to(string_item['address'], limit=50)

    # Step 3: For each xref, get the containing function
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        if func:
            print(f"  Referenced in: {func['name']} at {func['address']}")

            # Step 4: Decompile to understand context
            code = decompile_function(func['name'])
            # Analyze code to understand how string is used
```

**Use Cases:**
- Find HTTP route handlers: `filter="/api/"`
- Find command parsers: `filter="command"`
- Find SNMP handlers: `filter="community"`
- Find file operations: `filter=".log"` or `filter=".conf"`

**Example Output:**
```
=== String: '/api/upload' at 0x420000 ===
  Referenced in: handle_post_request at 0x401000
  Referenced in: route_dispatcher at 0x402000

=== String: '/api/download' at 0x420010 ===
  Referenced in: handle_get_request at 0x403000
  Referenced in: route_dispatcher at 0x402000
```

---

### Workflow 2: Import Analysis → Trace Callers

**Purpose:** Find all functions that use specific library functions (crypto, file I/O, network)

**Steps:**
```python
# Step 1: List all imports
imports = list_imports(limit=200)

# Step 2: Filter for specific categories
target_imports = [imp for imp in imports if any(
    keyword in imp['name'].lower()
    for keyword in ['crypt', 'aes', 'rsa', 'sha', 'md5', 'fopen', 'system', 'exec']
)]

# Step 3: For each import, find callers
for imp in target_imports:
    print(f"\n=== Import: {imp['name']} from {imp.get('library', 'unknown')} ===")
    xrefs = get_xrefs_to(imp['address'], limit=100)

    # Step 4: Trace back to higher-level functions
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        if func:
            print(f"  Called by: {func['name']}")

            # Step 5: Get callers of this function (trace up)
            callers = get_function_callers(func['name'], limit=20)
            for caller in callers:
                print(f"    <- {caller['name']}")
```

**Use Cases:**
- Audit crypto usage: `['aes', 'rsa', 'sha', 'md5', 'crypt']`
- Find file operations: `['fopen', 'open', 'read', 'write', 'unlink']`
- Find command execution: `['system', 'exec', 'popen', 'fork']`
- Find network operations: `['socket', 'bind', 'connect', 'send', 'recv']`

---

### Workflow 3: Entry Point → Call Graph Exploration

**Purpose:** Map the program's control flow from entry points

**Steps:**
```python
# Step 1: Get all entry points
entry_points = get_entry_points()

# Step 2: For each entry point, build call graph
for entry in entry_points:
    print(f"\n=== Entry Point: {entry['name']} at {entry['address']} ===")

    # Step 3: Get function at entry point
    func = get_function_by_address(entry['address'])

    # Step 4: Build localized call graph
    call_graph = get_function_call_graph(
        func['name'],
        depth=3,  # 3 levels deep
        direction="callees"  # Show what this calls
    )

    print("Call relationships:")
    for edge in call_graph:
        print(f"  {edge}")

    # Step 5: Identify key functions (those called often)
    # Count occurrences of each callee
    callee_counts = {}
    for edge in call_graph:
        parts = edge.split(" -> ")
        if len(parts) == 2:
            callee = parts[1].strip()
            callee_counts[callee] = callee_counts.get(callee, 0) + 1

    # Step 6: Highlight central functions
    print("\nFrequently called functions:")
    sorted_callees = sorted(callee_counts.items(), key=lambda x: x[1], reverse=True)
    for callee, count in sorted_callees[:10]:
        print(f"  {callee}: called {count} times")
```

**Use Cases:**
- Understand program initialization
- Find main dispatch loops
- Identify central utility functions
- Map attack surface from entry points

---

## 🔬 Code Analysis Workflows

### Workflow 4: Function Classification by Behavior

**Purpose:** Automatically classify functions by their role (dispatcher, handler, sanitizer, sink, utility)

**Steps:**
```python
def classify_function(func_name):
    """Classify function based on code analysis."""
    code = decompile_function(func_name)
    callees = get_function_callees(func_name, limit=50)
    callers = get_function_callers(func_name, limit=50)

    # Dispatcher: string comparison + switch/if-else branching
    if any(keyword in code for keyword in ['strcmp', 'strncmp', 'strcasecmp']):
        if any(keyword in code for keyword in ['switch', 'if', 'else if']):
            if len(callees) > 5:  # Calls many functions
                return "dispatcher"

    # Handler: processes input, calls validators and sinks
    validator_callees = [c for c in callees if any(
        kw in c['name'].lower() for kw in ['validate', 'check', 'sanitize', 'verify']
    )]
    sink_callees = [c for c in callees if any(
        kw in c['name'].lower() for kw in ['fopen', 'system', 'exec', 'send', 'write']
    )]
    if validator_callees or sink_callees:
        return "handler"

    # Sanitizer: validation logic
    if any(keyword in code.lower() for keyword in [
        'validate', 'check', 'sanitize', 'verify', 'isalnum', 'isdigit', 'strlen'
    ]):
        return "sanitizer"

    # Sink: file/network/exec operations
    if any(keyword in code for keyword in [
        'fopen', 'open', 'system', 'exec', 'popen', 'sendto', 'write', 'unlink'
    ]):
        return "sink"

    # Utility: everything else
    return "utility"

# Apply to all functions
functions = list_functions(limit=1000)
for func in functions:
    role = classify_function(func['name'])
    print(f"{func['name']:40s} -> {role}")

    # Rename with role prefix (optional)
    if not func['name'].startswith(role):
        new_name = f"{role}_{func['name']}"
        rename_function(func['name'], new_name)
```

**Classifications:**
- **Dispatcher:** Routes requests to handlers (string comparison + branching)
- **Handler:** Processes requests (calls validators + sinks)
- **Sanitizer:** Validates/normalizes input
- **Sink:** Performs I/O operations (file/network/exec)
- **Utility:** Helper functions

---

### Workflow 5: Trace Dispatcher → Handler → Sink

**Purpose:** Trace data flow from entry point through handlers to dangerous sinks

**Steps:**
```python
# Step 1: Find dispatcher functions
dispatchers = [f for f in list_functions(limit=1000)
               if 'dispatch' in f['name'].lower() or 'route' in f['name'].lower()]

# Step 2: For each dispatcher, trace to handlers
for dispatcher in dispatchers:
    print(f"\n=== Dispatcher: {dispatcher['name']} ===")

    # Get handlers (functions called by dispatcher)
    handlers = get_function_callees(dispatcher['name'], limit=100)

    # Step 3: For each handler, trace to utilities
    for handler in handlers:
        print(f"\n  Handler: {handler['name']}")

        # Get utilities called by handler
        utilities = get_function_callees(handler['name'], limit=50)

        # Step 4: For each utility, check for sinks
        for util in utilities:
            code = decompile_function(util['name'])

            # Check for dangerous operations
            dangerous_ops = []
            if 'fopen' in code or 'open' in code:
                dangerous_ops.append('file_open')
            if 'system' in code or 'exec' in code:
                dangerous_ops.append('command_exec')
            if 'strcpy' in code or 'sprintf' in code:
                dangerous_ops.append('unsafe_string')
            if 'sendto' in code or 'write' in code:
                dangerous_ops.append('network_write')

            if dangerous_ops:
                print(f"    Utility: {util['name']} -> SINKS: {dangerous_ops}")

                # Step 5: Trace to actual sinks
                sinks = get_function_callees(util['name'], limit=20)
                for sink in sinks:
                    sink_code = decompile_function(sink['name'])
                    if any(op in sink_code for op in ['fopen', 'system', 'exec']):
                        print(f"      Sink: {sink['name']}")
                        print(f"        Path: {dispatcher['name']} -> {handler['name']} -> {util['name']} -> {sink['name']}")
```

**Use Cases:**
- Find paths from user input to file operations (path traversal)
- Find paths from user input to command execution (command injection)
- Find paths from network input to memory operations (buffer overflow)

---

### Workflow 6: Protocol Handler Registration Analysis

**Purpose:** Find how protocol handlers are registered (table-driven or runtime)

**Steps:**
```python
# Pattern 1: Table-Driven Registration
# Look for structure arrays with function pointers

# Step 1: Search for handler-related strings
handler_strings = list_strings(filter="handler", limit=100)

# Step 2: Find data structures
data_items = list_data_items(limit=500)

# Step 3: Look for arrays of structures
structs = list_data_types(category="struct", limit=100)
handler_tables = []

for struct in structs:
    # Check if struct has function pointer field
    layout = mcp_ghidra_get_struct_layout(struct['name'])
    has_func_ptr = any('*' in field.get('type', '') for field in layout)

    if has_func_ptr:
        print(f"Potential handler table struct: {struct['name']}")
        handler_tables.append(struct)

        # Step 4: Find arrays of this struct
        for data in data_items:
            if struct['name'] in data.get('type', ''):
                print(f"  Handler table instance: {data['name']} at {data['address']}")

                # Step 5: Get xrefs to see where it's used
                xrefs = get_xrefs_to(data['address'], limit=20)
                for xref in xrefs:
                    func = get_function_by_address(xref['from_address'])
                    if func:
                        print(f"    Used in: {func['name']}")

# Pattern 2: Runtime Registration
# Look for registration functions

# Step 6: Search for "register" functions
register_funcs = search_functions_by_name("register", limit=50)

for func in register_funcs:
    print(f"\n=== Registration function: {func['name']} ===")

    # Decompile to see how handlers are registered
    code = decompile_function(func['name'])

    # Look for function pointer assignments
    # This is pattern-based - adjust for your binary

    # Step 7: Find who calls the registration function
    callers = get_function_callers(func['name'], limit=20)
    print("Called by:")
    for caller in callers:
        print(f"  {caller['name']}")
```

**Use Cases:**
- Understand SNMP OID → handler mappings
- Find HTTP route → handler registrations
- Map command name → function pointer tables

---

## 🔄 Data Flow Workflows

### Workflow 7: Source → Sanitizer → Sink Analysis

**Purpose:** Check if data flows through proper sanitization before reaching sinks

**Steps:**
```python
def analyze_data_flow(source_func, sink_func):
    """
    Trace data flow from source to sink, checking for sanitization.

    Args:
        source_func: Function name that receives external input
        sink_func: Function name that performs dangerous operation
    """
    print(f"\n=== Data Flow: {source_func} -> ... -> {sink_func} ===")

    # Step 1: Get all paths from source to sink (BFS/DFS approach)
    # This is simplified - real implementation needs graph traversal

    # Build call graph from source
    source_callees = get_function_callees(source_func, limit=100)

    # Check if sink is directly called
    direct_sink = any(c['name'] == sink_func for c in source_callees)
    if direct_sink:
        print(f"  WARNING: Direct call from {source_func} to {sink_func}")
        print(f"  No sanitization detected!")
        return {"sanitized": False, "path": [source_func, sink_func]}

    # Step 2: For each intermediate function, check if it's a sanitizer
    paths = []
    for callee in source_callees:
        # Check if this is a sanitizer
        code = decompile_function(callee['name'])
        is_sanitizer = any(keyword in code.lower() for keyword in [
            'validate', 'check', 'sanitize', 'verify', 'isalnum', 'strlen'
        ])

        # Check if this calls the sink
        callee_callees = get_function_callees(callee['name'], limit=50)
        calls_sink = any(c['name'] == sink_func for c in callee_callees)

        if calls_sink:
            path = [source_func, callee['name'], sink_func]
            paths.append({
                "path": path,
                "sanitized": is_sanitizer,
                "sanitizer": callee['name'] if is_sanitizer else None
            })

    # Step 3: Report findings
    for path_info in paths:
        path_str = " -> ".join(path_info['path'])
        if path_info['sanitized']:
            print(f"  ✓ SAFE: {path_str}")
            print(f"    Sanitizer: {path_info['sanitizer']}")
        else:
            print(f"  ✗ UNSAFE: {path_str}")
            print(f"    Missing sanitization!")

    return paths

# Example usage
# Find all network input functions
recv_funcs = search_functions_by_name("recv", limit=20)

# Find all file operation sinks
file_ops = ["fopen", "open", "unlink", "rename"]
for recv_func in recv_funcs:
    for file_op in file_ops:
        sinks = search_functions_by_name(file_op, limit=10)
        for sink in sinks:
            analyze_data_flow(recv_func['name'], sink['name'])
```

**Output Example:**
```
=== Data Flow: handle_network_request -> ... -> fopen ===
  ✗ UNSAFE: handle_network_request -> parse_filename -> fopen
    Missing sanitization!

  ✓ SAFE: handle_network_request -> validate_path -> safe_fopen
    Sanitizer: validate_path
```

---

### Workflow 8: Taint Analysis (Manual)

**Purpose:** Manually trace how user-controlled data propagates through the program

**Steps:**
```python
# Step 1: Identify taint sources (user input functions)
taint_sources = [
    "recv", "recvfrom", "read", "fgets", "scanf",
    "getenv", "argv", "getopt"
]

# Step 2: Identify taint sinks (dangerous operations)
taint_sinks = {
    "file": ["fopen", "open", "unlink", "rename", "chmod"],
    "exec": ["system", "exec", "popen", "fork"],
    "memory": ["strcpy", "sprintf", "memcpy", "strcat"],
    "network": ["sendto", "write", "send"]
}

# Step 3: For each source, trace to sinks
for source_name in taint_sources:
    sources = search_functions_by_name(source_name, limit=10)

    for source in sources:
        print(f"\n=== Taint Source: {source['name']} ===")

        # Get callers (who receives this data)
        callers = get_function_callers(source['name'], limit=50)

        for caller in callers:
            print(f"\n  Data received by: {caller['name']}")

            # Decompile to see how data is used
            code = decompile_function(caller['name'])

            # Check for direct use in sinks
            for sink_category, sink_funcs in taint_sinks.items():
                for sink_func in sink_funcs:
                    if sink_func in code:
                        print(f"    ⚠ Potential {sink_category} vulnerability: uses {sink_func}")

                        # Check for sanitization before sink
                        if any(san in code.lower() for san in ['validate', 'check', 'sanitize']):
                            print(f"      ✓ Sanitization detected")
                        else:
                            print(f"      ✗ NO sanitization detected!")

                            # Add security comment
                            set_decompiler_comment(
                                caller['address'],
                                f"// SECURITY: Tainted data from {source['name']} used in {sink_func}\n"
                                f"// Risk: CWE-{get_cwe_for_sink(sink_category)}\n"
                                f"// Fix: Add validation before {sink_func}"
                            )
```

---

## 🎨 Code Enhancement Workflows

### Workflow 9: Systematic Function Renaming

**Purpose:** Rename functions systematically based on role and purpose

**Steps:**
```python
# Step 1: Classify all functions (use Workflow 4)
functions = list_functions(limit=1000)
classifications = {}

for func in functions:
    role = classify_function(func['name'])  # From Workflow 4
    classifications[func['name']] = role

# Step 2: For each role, apply naming convention
for func_name, role in classifications.items():
    # Skip if already has role prefix
    if func_name.startswith(f"{role}_"):
        continue

    # Get function details
    func = get_function_by_address(
        search_functions_by_name(func_name, limit=1)[0]['address']
    )

    # Determine purpose from code analysis
    code = decompile_function(func_name)

    # Extract purpose keywords
    purpose = extract_purpose(code)  # Custom function

    # Build new name with role prefix
    if func_name.startswith("FUN_"):
        # Keep address suffix
        addr_suffix = func_name.split("_", 1)[1]
        new_name = f"{role}_FUN_{addr_suffix}_{purpose}"
    else:
        new_name = f"{role}_{func_name}_{purpose}"

    # Rename
    print(f"Renaming: {func_name} -> {new_name}")
    rename_function(func_name, new_name)

# Step 3: Set function prototypes
for func_name in [name for name in classifications.keys()]:
    # Infer function signature from decompilation
    code = decompile_function(func_name)
    signature = infer_signature(code)  # Custom function

    set_function_prototype(
        func['address'],
        signature
    )
```

**Naming Convention:**
```
<role>_<original_or_FUN_addr>_<purpose>

Examples:
- dispatcher_FUN_00401000_route_matcher
- handler_process_snmp_request
- sanitizer_validate_path
- sink_FUN_00403000_file_writer
- utility_string_helper
```

---

### Workflow 10: Variable Renaming for Readability

**Purpose:** Rename variables systematically to improve code readability

**Steps:**
```python
def rename_variables_in_function(func_name):
    """Systematically rename variables in a function."""

    # Step 1: Decompile to see variable usage
    code = decompile_function(func_name)

    # Step 2: Parse variable names and usage patterns
    # This is pattern-based - adjust for your decompiler output

    import re

    # Find variable declarations and usage
    # Pattern: type varName; or type varName = ...;
    var_pattern = r'(\w+\*?)\s+(\w+)\s*[;=]'
    variables = re.findall(var_pattern, code)

    # Step 3: For each variable, determine better name
    for var_type, var_name in variables:
        # Skip if already well-named
        if not any(var_name.startswith(prefix) for prefix in ['iVar', 'pcVar', 'uVar', 'local_']):
            continue

        # Analyze usage context
        # Look for patterns like:
        # - fopen(..., var) -> file_fd, file_handle
        # - strlen(var) -> str_len, buffer_size
        # - strcpy(..., var) -> src_buffer, dest_buffer

        new_name = None

        # File descriptors
        if 'fd' in code or 'fopen' in code or 'open(' in code:
            if var_type in ['int', 'FILE*']:
                new_name = 'file_fd' if var_type == 'int' else 'file_ptr'

        # Strings/buffers
        elif 'char*' in var_type or 'char[' in var_type:
            if 'strlen' in code:
                new_name = 'str_len' if var_type == 'int' else 'buffer'
            elif 'strcpy' in code or 'sprintf' in code:
                new_name = 'dest_buffer' if 'dest' in code else 'src_buffer'
            else:
                new_name = 'str_ptr'

        # Sizes/lengths
        elif var_type in ['int', 'size_t', 'uint32_t'] and ('len' in code or 'size' in code):
            new_name = 'buffer_size'

        # Pointers
        elif '*' in var_type:
            base_type = var_type.replace('*', '').strip()
            new_name = f'{base_type}_ptr'

        # Rename if we found a better name
        if new_name and new_name != var_name:
            print(f"  {func_name}: {var_name} -> {new_name}")
            rename_variable(func_name, var_name, new_name)

# Apply to all functions
functions = list_functions(limit=1000)
for func in functions:
    print(f"\nRenaming variables in: {func['name']}")
    rename_variables_in_function(func['name'])
```

**Variable Naming Convention:**
```
<purpose>_<type_suffix>

Type suffixes:
- _ptr: pointers
- _fd: file descriptors
- _size, _len: sizes and lengths
- _buffer: buffers
- _str: strings
- _array: arrays
- _idx: indices
- _count: counters
- _flag: boolean flags

Examples:
- file_fd (int file descriptor)
- path_buffer (char[] buffer)
- request_ptr (request_t* pointer)
- buffer_size (size_t size)
- loop_idx (int index)
```

---

### Workflow 11: Comprehensive Code Documentation

**Purpose:** Add detailed comments to document analysis findings

**Steps:**
```python
def document_function(func_name):
    """Add comprehensive documentation to a function."""

    # Get function details
    func = search_functions_by_name(func_name, limit=1)[0]
    code = decompile_function(func_name)
    callees = get_function_callees(func_name, limit=50)
    callers = get_function_callers(func_name, limit=50)

    # Step 1: Add function header comment
    header_comment = f"""// FUNCTION: {func_name}
// Address: {func['address']}
// Role: {classify_function(func_name)}
// Callers: {len(callers)} function(s)
// Callees: {len(callees)} function(s)
//
// Purpose: [Analyze code to determine purpose]
//
// Parameters:
//   [Extract from decompilation]
//
// Returns:
//   [Extract from decompilation]
//
// Security Notes:
//   [Add if relevant]
"""

    set_decompiler_comment(func['address'], header_comment)

    # Step 2: Document key operations within function
    # This requires parsing decompiled code to find key operations

    # Example: Document dangerous operations
    dangerous_ops = []
    if 'fopen' in code:
        dangerous_ops.append('file_open')
    if 'strcpy' in code or 'sprintf' in code:
        dangerous_ops.append('unsafe_string_copy')
    if 'system' in code or 'exec' in code:
        dangerous_ops.append('command_execution')

    if dangerous_ops:
        security_comment = f"""// SECURITY WARNING:
// This function performs dangerous operations: {', '.join(dangerous_ops)}
// Ensure proper input validation before calling this function
"""
        # Add comment at function entry
        set_decompiler_comment(func['address'], security_comment)

    # Step 3: Document call relationships
    if len(callers) > 0:
        callers_comment = f"// Called by: {', '.join([c['name'] for c in callers[:5]])}"
        if len(callers) > 5:
            callers_comment += f" (and {len(callers) - 5} more)"
        set_decompiler_comment(func['address'], callers_comment)

    if len(callees) > 0:
        callees_comment = f"// Calls: {', '.join([c['name'] for c in callees[:5]])}"
        if len(callees) > 5:
            callees_comment += f" (and {len(callees) - 5} more)"
        set_decompiler_comment(func['address'], callees_comment)
```

---

## 🛡️ Vulnerability Analysis Workflows

### Workflow 12: Path Traversal Detection

**Purpose:** Find potential path traversal vulnerabilities

**Steps:**
```python
# Step 1: Find file operation sinks
file_ops = ["fopen", "open", "unlink", "rename", "chmod"]
file_sinks = []

for op in file_ops:
    sinks = search_functions_by_name(op, limit=20)
    file_sinks.extend(sinks)

# Step 2: For each sink, trace back to user input
for sink in file_sinks:
    print(f"\n=== Analyzing: {sink['name']} ===")

    # Get callers
    callers = get_function_callers(sink['name'], limit=50)

    for caller in callers:
        code = decompile_function(caller['name'])

        # Check for path construction
        has_path_construction = any(op in code for op in [
            'strcat', 'sprintf', 'snprintf', '+'
        ])

        if has_path_construction:
            print(f"  Caller: {caller['name']} - constructs path")

            # Check for path validation
            has_validation = any(check in code.lower() for check in [
                'realpath', 'canonicalize', 'validate_path',
                'check_prefix', 'startswith', 'strncmp'
            ])

            if not has_validation:
                print(f"    ⚠ VULNERABILITY: Missing path validation!")

                # Document the vulnerability
                set_decompiler_comment(
                    caller['address'],
                    """// VULNERABILITY: CWE-22 Path Traversal
// Risk: User-controlled path passed to file operation without validation
// Attack: Could use "../" to access files outside intended directory
//
// Fix Required:
// 1. Canonicalize path (realpath, GetFullPathName)
// 2. Validate path starts with allowed prefix
// 3. Check for ".." sequences after canonicalization
//
// Example Fix:
//   char* canonical = realpath(user_path, NULL);
//   if (!canonical || strncmp(canonical, BASE_DIR, strlen(BASE_DIR)) != 0) {
//       return ERROR;
//   }
"""
                )

                # Rename function to mark vulnerability
                rename_function_by_address(
                    caller['address'],
                    f"VULN_path_traversal_{caller['name']}"
                )
```

---

### Workflow 13: Command Injection Detection

**Purpose:** Find potential command injection vulnerabilities

**Steps:**
```python
# Step 1: Find command execution sinks
cmd_ops = ["system", "exec", "execl", "execlp", "execv", "execvp", "popen"]
cmd_sinks = []

for op in cmd_ops:
    sinks = search_functions_by_name(op, limit=20)
    cmd_sinks.extend(sinks)

# Step 2: For each sink, analyze command construction
for sink in cmd_sinks:
    print(f"\n=== Analyzing: {sink['name']} ===")

    callers = get_function_callers(sink['name'], limit=50)

    for caller in callers:
        code = decompile_function(caller['name'])

        # Check for string concatenation/formatting
        has_cmd_construction = any(op in code for op in [
            'strcat', 'sprintf', 'snprintf', 'strdup', '+'
        ])

        if has_cmd_construction:
            print(f"  Caller: {caller['name']} - constructs command")

            # Check for shell metacharacter sanitization
            has_sanitization = any(check in code.lower() for check in [
                'quote', 'escape', 'sanitize', 'validate',
                'isalnum', 'whitelist'
            ])

            if not has_sanitization:
                print(f"    ⚠ VULNERABILITY: Missing command sanitization!")

                # Document the vulnerability
                set_decompiler_comment(
                    caller['address'],
                    """// VULNERABILITY: CWE-78 Command Injection
// Risk: User-controlled data in system() without sanitization
// Attack: Could inject shell metacharacters (; | & ` $ ( ) etc.)
//
// Fix Required:
// 1. Use execv() instead of system() (no shell interpretation)
// 2. If must use system(), sanitize all special characters
// 3. Whitelist allowed characters (alphanumeric + specific safe chars)
//
// Example Fix:
//   // Instead of: system(sprintf("process %s", user_input))
//   char* args[] = {"/bin/process", user_input, NULL};
//   execv("/bin/process", args);
"""
                )

                rename_function_by_address(
                    caller['address'],
                    f"VULN_command_injection_{caller['name']}"
                )
```

---

### Workflow 14: Buffer Overflow Detection

**Purpose:** Find potential buffer overflow vulnerabilities

**Steps:**
```python
# Step 1: Find unsafe string operations
unsafe_ops = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
unsafe_funcs = []

for op in unsafe_ops:
    funcs = search_functions_by_name(op, limit=50)
    unsafe_funcs.extend([(op, f) for f in funcs])

# Step 2: Analyze each usage
for op_name, func in unsafe_funcs:
    print(f"\n=== Unsafe operation: {op_name} in {func['name']} ===")

    callers = get_function_callers(func['name'], limit=50)

    for caller in callers:
        code = decompile_function(caller['name'])

        # Check for bounds checking before unsafe operation
        has_bounds_check = any(check in code.lower() for check in [
            'strlen', 'sizeof', 'strnlen', 'if', 'while', 'for'
        ])

        # Check if safe alternative is used
        uses_safe_alternative = any(safe in code for safe in [
            'strncpy', 'strlcpy', 'snprintf', 'strncat', 'strlcat', 'fgets'
        ])

        if not has_bounds_check and not uses_safe_alternative:
            print(f"  ⚠ VULNERABILITY in {caller['name']}: Unsafe {op_name} without bounds check!")

            # Document the vulnerability
            set_decompiler_comment(
                caller['address'],
                f"""// VULNERABILITY: CWE-120 Buffer Overflow
// Risk: {op_name}() without bounds checking
// Attack: Could overflow destination buffer with long input
//
// Fix Required:
// Replace {op_name}() with safe alternative:
//   strcpy  -> strncpy/strlcpy
//   strcat  -> strncat/strlcat
//   sprintf -> snprintf
//   gets    -> fgets
//   scanf   -> fgets + sscanf with length limit
//
// Always check: strlen(src) + 1 <= sizeof(dest)
"""
            )

            rename_function_by_address(
                caller['address'],
                f"VULN_buffer_overflow_{caller['name']}"
            )
```

---

## 💡 Tips for Effective Workflow Use

### 1. Combine Workflows
Most real analysis requires combining multiple workflows:
```
Workflow 1 (String Search) → Workflow 5 (Trace to Sink) → Workflow 12 (Path Traversal Check)
```

### 2. Iterate and Refine
- First pass: Broad discovery (Workflows 1-3)
- Second pass: Deep analysis (Workflows 4-8)
- Third pass: Enhancement (Workflows 9-11)
- Final pass: Vulnerability documentation (Workflows 12-14)

### 3. Save Your Progress
Document your findings as you go:
```python
# After each major discovery, add comments
set_decompiler_comment(address, "// ANALYSIS: [your findings]")

# Track progress in external notes
with open("analysis_log.md", "a") as f:
    f.write(f"## {func_name}\n")
    f.write(f"- Role: {role}\n")
    f.write(f"- Findings: [summary]\n\n")
```

### 4. Use Pagination Wisely
```python
# Bad: Load everything at once
all_funcs = list_functions(limit=10000)  # May timeout or OOM

# Good: Process in batches
offset = 0
batch_size = 100
while True:
    batch = list_functions(offset=offset, limit=batch_size)
    if not batch:
        break
    # Process batch
    offset += batch_size
```

---

**Last Updated:** 2025-10-12
**Status:** Complete (14 workflows documented)
**Version:** 1.0
