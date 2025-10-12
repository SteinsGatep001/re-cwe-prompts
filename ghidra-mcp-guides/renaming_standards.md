# Ghidra MCP Renaming Standards

**Purpose:** Systematic naming conventions for functions, variables, and symbols to improve code readability.

---

## 📋 Overview

Consistent naming conventions are critical for effective reverse engineering. This document provides standards for renaming functions, variables, labels, and data items discovered during analysis.

### Key Principles

1. **Preserve Context:** Keep original function addresses when renaming (e.g., `FUN_00401000` → `handler_FUN_00401000_process_request`)
2. **Role-Based Prefixes:** Use role prefixes to indicate function purpose
3. **Descriptive Names:** Names should reveal intent, not implementation details
4. **Consistency:** Follow the same patterns across the entire codebase
5. **Reversibility:** Maintain enough information to trace back to original names

---

## 🎯 Function Naming Standards

### Standard Format

```
<role>_<original_or_base>_<purpose>

Components:
- role: Function classification (dispatcher, handler, sanitizer, sink, utility)
- original_or_base: Original function name or FUN_<address> if unnamed
- purpose: What the function does (optional, but recommended)
```

### Role Prefixes

| Role | Prefix | Description | Examples |
|------|--------|-------------|----------|
| **Dispatcher** | `dispatcher_` | Routes requests to handlers; string comparison + branching | `dispatcher_FUN_00401000_route_matcher` |
| **Handler** | `handler_` | Processes requests; calls validators and sinks | `handler_process_snmp_request` |
| **Sanitizer** | `sanitizer_` | Validates/normalizes input | `sanitizer_validate_path` |
| **Sink** | `sink_` | Performs I/O (file/network/exec) | `sink_FUN_00403000_file_writer` |
| **Utility** | `util_` | Helper/support functions | `util_string_trim` |
| **Vulnerability** | `VULN_` | **Special:** Functions with identified vulnerabilities | `VULN_path_traversal_open_file` |

### Role Classification Guide

#### Dispatcher
**Characteristics:**
- String comparison operations (`strcmp`, `strncmp`, `strcasecmp`)
- Branching logic (`switch`, `if-else` chains)
- Calls multiple handler functions (>5)
- Often has "route", "dispatch", "parse" in original name

**Examples:**
```python
# Original: FUN_00401000
# Decompiled: switch(method_type) { case GET: handle_get(); case POST: handle_post(); }
# Renamed: dispatcher_FUN_00401000_http_method_router

# Original: route_handler
# Renamed: dispatcher_route_handler_api_endpoints
```

#### Handler
**Characteristics:**
- Processes specific request types
- Calls sanitizers/validators
- Calls sinks (file, network, exec)
- Often has "handle", "process", "execute" in original name

**Examples:**
```python
# Original: FUN_00402000
# Decompiled: validates path, then opens file
# Renamed: handler_FUN_00402000_file_download

# Original: process_snmp_get
# Renamed: handler_process_snmp_get_request
```

#### Sanitizer
**Characteristics:**
- Validation logic (`strlen`, `isalnum`, `isdigit`)
- Checking operations (`check`, `validate`, `verify`)
- Normalizing operations (`trim`, `canonicalize`, `escape`)
- Returns boolean or normalized value

**Examples:**
```python
# Original: FUN_00403000
# Decompiled: checks path doesn't contain ".."
# Renamed: sanitizer_FUN_00403000_check_path_traversal

# Original: validate_input
# Renamed: sanitizer_validate_input_alphanumeric
```

#### Sink
**Characteristics:**
- File operations (`fopen`, `open`, `write`, `unlink`)
- Network operations (`sendto`, `send`, `connect`)
- Command execution (`system`, `exec`, `popen`)
- Dangerous string operations (`strcpy`, `sprintf`)

**Examples:**
```python
# Original: FUN_00404000
# Decompiled: calls fopen() with user-provided path
# Renamed: sink_FUN_00404000_file_open

# Original: write_log
# Renamed: sink_write_log_to_file
```

#### Utility
**Characteristics:**
- Helper functions (string manipulation, math, formatting)
- No direct user input or dangerous operations
- Called by multiple other functions
- Pure functions (no side effects)

**Examples:**
```python
# Original: FUN_00405000
# Decompiled: trims whitespace from string
# Renamed: util_FUN_00405000_string_trim

# Original: calculate_checksum
# Renamed: util_calculate_checksum_crc32
```

#### Vulnerability (Special)
**Use:** Mark functions with identified security vulnerabilities

**Format:** `VULN_<cwe_type>_<original_name>`

**Examples:**
```python
# Path traversal vulnerability
VULN_path_traversal_open_file

# Command injection vulnerability
VULN_command_injection_process_cmd

# Buffer overflow vulnerability
VULN_buffer_overflow_strcpy_wrapper
```

---

### Preserving Original Names

**When original name is meaningful:**
```python
# Original: process_snmp_request
# Add role prefix
# Renamed: handler_process_snmp_request
```

**When original name is auto-generated (FUN_):**
```python
# Original: FUN_00401000
# Keep address in name for traceability
# Renamed: handler_FUN_00401000_process_request
```

**Why preserve addresses:**
- Easy to map back to disassembly
- Multiple functions may have similar purposes
- Address provides unique identifier

---

### Protocol-Specific Naming

**Include protocol name when relevant:**
```python
# SNMP functions
handler_snmp_get_request
handler_snmp_set_request
sanitizer_snmp_validate_community

# HTTP functions
handler_http_get
handler_http_post
dispatcher_http_route_matcher

# SSH functions
handler_ssh_auth
handler_ssh_channel_request
```

---

## 📦 Variable Naming Standards

### Standard Format

```
<purpose>_<type_suffix>

Components:
- purpose: What the variable represents
- type_suffix: Type indicator (ptr, fd, size, len, buffer, etc.)
```

### Type Suffixes

| Suffix | Type | Examples |
|--------|------|----------|
| `_ptr` | Pointers | `request_ptr`, `buffer_ptr`, `node_ptr` |
| `_fd` | File descriptors (int) | `file_fd`, `socket_fd`, `pipe_fd` |
| `_handle` | File handles (FILE*) | `file_handle`, `log_handle` |
| `_size` | Sizes (size_t, int) | `buffer_size`, `file_size`, `total_size` |
| `_len` | Lengths (size_t, int) | `str_len`, `path_len`, `data_len` |
| `_buffer` | Buffers (char[], uint8_t[]) | `input_buffer`, `temp_buffer`, `output_buffer` |
| `_str` | String pointers (char*) | `path_str`, `command_str`, `error_str` |
| `_array` | Arrays | `handlers_array`, `routes_array` |
| `_idx` | Indices (int) | `loop_idx`, `array_idx`, `current_idx` |
| `_count` | Counters (int) | `error_count`, `retry_count`, `total_count` |
| `_flag` | Booleans/flags (int, bool) | `error_flag`, `found_flag`, `valid_flag` |
| `_offset` | Offsets (int, size_t) | `buffer_offset`, `file_offset` |
| `_addr` | Addresses (void*, uintptr_t) | `base_addr`, `target_addr` |

### Common Variable Patterns

#### Auto-Generated Variable Names (Ghidra)

**Ghidra patterns to replace:**
- `iVar1`, `iVar2`, ... → Descriptive names with `_count`, `_idx`, or `_fd`
- `pcVar1`, `pcVar2`, ... → Descriptive names with `_str` or `_ptr`
- `uVar1`, `uVar2`, ... → Descriptive names with `_size` or `_len`
- `local_XX` → Descriptive names based on usage

**Examples:**
```c
// Before (Ghidra auto-generated)
int iVar1;
char *pcVar2;
uint uVar3;
char local_100[256];

// After (descriptive)
int file_fd;
char *path_str;
uint buffer_size;
char input_buffer[256];
```

#### File Operations
```c
int file_fd;              // File descriptor from open()
FILE *file_handle;        // File pointer from fopen()
char path_buffer[256];    // Path string buffer
char *filename_str;       // Filename string pointer
size_t file_size;         // File size
off_t file_offset;        // File offset for seek
```

#### Network Operations
```c
int socket_fd;            // Socket descriptor
struct sockaddr_in server_addr;   // Server address
char recv_buffer[1024];   // Receive buffer
size_t recv_len;          // Received data length
char *hostname_str;       // Hostname string
uint16_t port_num;        // Port number
```

#### String Operations
```c
char *src_str;            // Source string
char *dest_str;           // Destination string
size_t str_len;           // String length
char temp_buffer[512];    // Temporary buffer
char *token_str;          // Token from strtok
```

#### Loop Variables
```c
int loop_idx;             // Loop index
int array_idx;            // Array index
size_t current_idx;       // Current position index
int retry_count;          // Retry counter
```

#### Pointers and Structures
```c
request_t *request_ptr;         // Request structure pointer
response_t *response_ptr;       // Response structure pointer
config_t *config_ptr;           // Configuration pointer
node_t *current_node_ptr;       // Linked list node pointer
```

---

## 🏷️ Label and Data Naming Standards

### Labels

**Format:** `<purpose>_<type>`

**Examples:**
```
error_handler           // Error handling code block
success_exit           // Successful exit point
loop_start             // Start of loop
loop_end               // End of loop
validation_failed      // Validation failure path
```

### Global Data

**Format:** `<scope>_<purpose>_<type>`

**Examples:**
```
global_server_config     // Global server configuration
static_error_messages    // Static error message array
const_crypto_key         // Constant cryptographic key
global_handler_table     // Global handler function pointer table
```

### String Constants

**Format:** `str_<purpose>`

**Examples:**
```
str_api_route_upload      // "/api/upload"
str_error_invalid_path    // "Error: Invalid path"
str_community_public      // "public" (SNMP community)
str_default_filename      // "default.conf"
```

---

## 🔄 Renaming Workflow

### Step-by-Step Process

```python
# 1. Analyze function
func_name = "FUN_00401000"
code = decompile_function(func_name)
callees = get_function_callees(func_name)
callers = get_function_callers(func_name)

# 2. Classify role
role = classify_function(func_name)  # Returns: dispatcher/handler/sanitizer/sink/utility

# 3. Determine purpose (analyze code)
if "strcmp" in code and "/api/" in code:
    purpose = "route_matcher"
elif "validate" in code:
    purpose = "validate_input"
elif "fopen" in code:
    purpose = "file_open"
else:
    purpose = "generic"

# 4. Build new name
if func_name.startswith("FUN_"):
    addr = func_name.split("_", 1)[1]
    new_name = f"{role}_FUN_{addr}_{purpose}"
else:
    new_name = f"{role}_{func_name}_{purpose}"

# 5. Rename function
rename_function(func_name, new_name)

# 6. Set function prototype
signature = infer_signature(code)  # Analyze decompiled code
set_function_prototype(func_addr, signature)

# 7. Rename variables within function
for var in get_variables_in_function(new_name):
    if var.startswith("iVar") or var.startswith("pcVar"):
        new_var_name = determine_variable_purpose(var, code)
        rename_variable(new_name, var, new_var_name)
```

---

## ✅ Renaming Checklist

### Function Renaming
- [ ] Function classified by role (dispatcher/handler/sanitizer/sink/utility)
- [ ] Role prefix added
- [ ] Purpose clearly described in name
- [ ] Original name or address preserved
- [ ] Protocol name included (if relevant)
- [ ] Function prototype set
- [ ] Vulnerability marked (if applicable)

### Variable Renaming
- [ ] Auto-generated names (iVar, pcVar, uVar, local_XX) replaced
- [ ] Type suffix added (_ptr, _fd, _size, etc.)
- [ ] Purpose clearly described
- [ ] Consistent with similar variables in other functions
- [ ] All usages still compile/make sense

### Label Renaming
- [ ] Labels describe code block purpose
- [ ] Consistent naming across similar labels
- [ ] Easy to understand in disassembly view

### Data Renaming
- [ ] Global scope indicated
- [ ] Type included (config, table, array, etc.)
- [ ] Purpose clear from name

---

## ⚠️ Common Pitfalls

### DON'T

❌ **Don't lose original address:**
```python
# Bad: FUN_00401000 → handler_process_request
# Good: FUN_00401000 → handler_FUN_00401000_process_request
```

❌ **Don't use implementation details:**
```python
# Bad: handler_uses_strcmp_and_switch
# Good: handler_route_matcher
```

❌ **Don't make names too long:**
```python
# Bad: handler_FUN_00401000_process_incoming_http_get_request_with_validation
# Good: handler_FUN_00401000_http_get_processor
```

❌ **Don't rename without understanding:**
```python
# Bad: Renaming based on one keyword
# Good: Analyze complete function logic before renaming
```

### DO

✅ **Do preserve traceability:**
```python
# Keep address or original meaningful name
handler_FUN_00401000_process_request
sanitizer_validate_input_enhanced
```

✅ **Do use consistent patterns:**
```python
# All handlers start with handler_
# All sanitizers start with sanitizer_
# All variables of same type use same suffix
```

✅ **Do document your renaming:**
```python
# Add comment explaining renaming rationale
set_decompiler_comment(addr,
    "// RENAMED: FUN_00401000 -> handler_FUN_00401000_process_request\n"
    "// Reason: Routes incoming requests based on method type")
```

✅ **Do rename incrementally:**
```python
# Phase 1: Classify and add role prefixes
# Phase 2: Add purpose descriptions
# Phase 3: Refine based on deeper analysis
```

---

## 📊 Before/After Examples

### Example 1: SNMP Handler Function

**Before:**
```c
undefined4 FUN_00401234(undefined4 param_1, undefined4 param_2) {
    int iVar1;
    char *pcVar2;
    char local_100[256];

    pcVar2 = (char *)param_1;
    iVar1 = strcmp(pcVar2, "public");
    if (iVar1 == 0) {
        strcpy(local_100, (char *)param_2);
        // ... more code
    }
    return 0;
}
```

**After:**
```c
int handler_FUN_00401234_snmp_process_get(
    snmp_request *request_ptr,
    snmp_response *response_ptr
) {
    int auth_result;
    char *community_str;
    char oid_buffer[256];

    community_str = request_ptr->community;
    auth_result = strcmp(community_str, "public");
    if (auth_result == 0) {
        strcpy(oid_buffer, request_ptr->oid);
        // ... more code
    }
    return 0;
}
```

### Example 2: Path Validation Function

**Before:**
```c
int FUN_00402468(char *param_1) {
    int iVar1;
    char *pcVar2;

    pcVar2 = strstr(param_1, "..");
    if (pcVar2 != (char *)0x0) {
        iVar1 = -1;
    } else {
        iVar1 = 0;
    }
    return iVar1;
}
```

**After:**
```c
int sanitizer_FUN_00402468_check_path_traversal(char *path_str) {
    int validation_result;
    char *traversal_ptr;

    traversal_ptr = strstr(path_str, "..");
    if (traversal_ptr != NULL) {
        validation_result = -1;  // Path traversal detected
    } else {
        validation_result = 0;   // Path is safe
    }
    return validation_result;
}
```

---

## 🔗 Integration with Workflows

Renaming should be integrated into your analysis workflow:

1. **Discovery Phase:** Use original names, add notes
2. **Classification Phase:** Add role prefixes
3. **Deep Analysis Phase:** Add purpose descriptions
4. **Enhancement Phase:** Rename variables and add types
5. **Documentation Phase:** Add comments explaining renames

Reference: See `common_workflows.md` → Workflow 9 (Systematic Function Renaming) and Workflow 10 (Variable Renaming)

---

**Last Updated:** 2025-10-12
**Status:** Complete
**Version:** 1.0
