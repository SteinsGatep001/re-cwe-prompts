# GhidraSage Deep Analysis - Master Prompt

**Version:** 1.0
**Date:** 2025-10-12
**Purpose:** Complete orchestration prompt for AI Agent to perform deep SNMP vulnerability analysis in Ghidra GUI mode

---

## 🎯 Your Mission

You are a **professional reverse engineer and security researcher** tasked with performing a comprehensive analysis of an SNMP vulnerability using GhidraSage in **GUI mode**.

Your goal is to:
1. Find all SNMP request processing entry points
2. Map handler registration mechanisms
3. Trace data flow from entry to dangerous sinks
4. Identify vulnerabilities (buffer overflow, path traversal, command injection, etc.)
5. Systematically rename functions and variables for clarity
6. Add detailed security annotations
7. Generate comprehensive analysis reports

---

## 📋 Prerequisites Check

Before starting, verify:

- [ ] **Ghidra GUI is running** with the target binary loaded
- [ ] **MCP connection active** at `http://127.0.0.1:8765/mcp`
- [ ] **Case directory exists:** `.work/cases/<vendor>/<case>/`
- [ ] **You have read:**
  - This master prompt (you are here)
  - `protocol-analysis/SNMP/analysis_checklist.md` (your step-by-step guide)
  - `prompts/re-cwe-prompts/INDEX.md` (for document navigation)

**Verify MCP connection now:**
```python
check_connection()
metadata = get_metadata()
print(f"✓ Analyzing: {metadata['program_name']}")
```

---

## 🗺️ Complete 5-Phase Workflow

### Overview
```
Phase 1: Context Preparation     (15 min)
    ↓
Phase 2: Entry Point Discovery   (30 min)
    ↓
Phase 3: Deep Analysis           (2-3 hours)
    ↓
Phase 4: Code Enhancement        (1 hour)
    ↓
Phase 5: Report Generation       (30 min)
```

**Total Time:** 4-5 hours for complete analysis

---

## 📚 Phase 1: Context Preparation (15 min)

### 1.1 Understand the Target

**Read case context:**
```bash
# Case information
.work/cases/<vendor>/<case>/context/case_context.json

# Previous stage outputs
.work/cases/<vendor>/<case>/summaries/stage_a_summary.json  # CVE info
.work/cases/<vendor>/<case>/summaries/stage_c_summary.json  # Fingerprints
```

**Gather binary information:**
```python
# Get program metadata
metadata = get_metadata()
print(f"Program: {metadata['program_name']}")
print(f"Architecture: {metadata['architecture']}")
print(f"Base Address: {metadata['base_address']}")

# Get entry points
entry_points = get_entry_points()
print(f"Entry points: {entry_points}")

# Get memory layout
segments = list_segments(limit=100)
for seg in segments:
    print(f"  {seg['name']}: {seg['start']} - {seg['end']}")

# Get imports (focus on libc, network, file operations)
imports = list_imports(limit=200)
network_imports = [imp for imp in imports if any(k in imp['name'].lower()
                   for k in ['recv', 'send', 'socket', 'accept'])]
file_imports = [imp for imp in imports if any(k in imp['name'].lower()
                for k in ['fopen', 'open', 'read', 'write'])]
print(f"Network imports: {len(network_imports)}")
print(f"File imports: {len(file_imports)}")
```

### 1.2 Collect SNMP Artifacts

**Reference:** `protocol-analysis/SNMP/protocol_overview.md` for SNMP basics

**Search for SNMP-related strings:**
```python
# SNMP protocol strings
snmp_strings = list_strings(filter="snmp", limit=100)
print(f"Found {len(snmp_strings)} SNMP-related strings")

# Community strings (authentication)
community_strings = list_strings(filter="community", limit=50)
print(f"Found {len(community_strings)} community string references")

# OID-related strings
oid_strings = list_strings(filter="oid", limit=50)
print(f"Found {len(oid_strings)} OID-related strings")

# MIB-related strings
mib_strings = list_strings(filter="mib", limit=50)
print(f"Found {len(mib_strings)} MIB-related strings")

# PDU type strings
pdu_strings = []
for pdu_type in ["GET", "SET", "TRAP", "GETNEXT"]:
    pdu_strings += list_strings(filter=pdu_type, limit=20)
print(f"Found {len(pdu_strings)} PDU type strings")
```

**Save findings to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/phase1_context.md
```

---

## 🔍 Phase 2: Entry Point Discovery (30 min)

### 2.1 Find SNMP Entry Functions

**Reference:** `protocol-analysis/SNMP/handler_patterns.md`

**Strategy 1: String-based discovery (most reliable)**
```python
# Find functions that reference "community" string
community_functions = []
for string_item in community_strings:
    xrefs = get_xrefs_to(string_item['address'], limit=50)
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        if func and func not in community_functions:
            community_functions.append(func)
            print(f"SNMP function candidate: {func['name']} at {func['address']}")

# Rename candidates for tracking
for i, func in enumerate(community_functions):
    rename_function_by_address(
        func['address'],
        f"snmp_candidate_{i}_{func['name']}"
    )
```

**Strategy 2: Function name search**
```python
# Search for SNMP-related function names
snmp_funcs = search_functions_by_name("snmp", limit=100)
recv_funcs = search_functions_by_name("recv", limit=20)
process_funcs = search_functions_by_name("process", limit=100)

print(f"Found {len(snmp_funcs)} snmp functions")
print(f"Found {len(recv_funcs)} recv functions")
print(f"Found {len(process_funcs)} process functions")
```

### 2.2 Identify PDU Dispatcher

**Look for PDU type constants (0xA0-0xA6):**
```python
# Analyze community string validators to find dispatcher
for func in community_functions:
    code = decompile_function(func['name'])

    # Check for PDU type constants
    has_pdu_types = any(const in code.lower() for const in
                        ['0xa0', '0xa1', '0xa2', '0xa3', '0xa4', '0xa5'])

    # Check for switch/branching
    has_dispatch_logic = 'switch' in code or code.count('if') > 5

    if has_pdu_types and has_dispatch_logic:
        print(f"✓ PDU DISPATCHER FOUND: {func['name']}")
        rename_function_by_address(func['address'], f"dispatcher_snmp_pdu_router")

        # Get all handlers (functions called by dispatcher)
        handlers = get_function_callees(func['name'], limit=100)
        print(f"  Found {len(handlers)} potential handlers")
        break
```

### 2.3 Build Initial Call Graph

```python
# Build call graph from entry point
dispatcher = "dispatcher_snmp_pdu_router"  # Adjust based on your finding
call_graph = get_function_call_graph(dispatcher, depth=4, direction="callees")

print("SNMP Request Flow:")
for edge in call_graph:
    print(f"  {edge}")

# Save call graph
with open(".work/cases/<vendor>/<case>/analysis/stage_d/evidence/call_graphs/entry_to_handlers.txt", "w") as f:
    for edge in call_graph:
        f.write(edge + "\n")
```

**Save findings to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/entrypoints.md
```

---

## 🔬 Phase 3: Deep Analysis (2-3 hours)

### 3.1 Map Handler Registration (30 min)

**Reference:** `protocol-analysis/SNMP/handler_patterns.md`

**Analyze handler registration mechanism:**
```python
# Check Pattern 1: Static handler table
data_items = list_data_items(limit=500)
handler_tables = [data for data in data_items
                  if 'handler' in data.get('name', '').lower()]

for table in handler_tables:
    print(f"Potential handler table: {table['name']} at {table['address']}")

    # Check who uses this table
    xrefs = get_xrefs_to(table['address'], limit=20)
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        if func:
            print(f"  Used by: {func['name']}")

# Check Pattern 2: Runtime registration
register_funcs = search_functions_by_name("register", limit=50)
for func in register_funcs:
    code = decompile_function(func['name'])
    if 'snmp' in code.lower() or 'handler' in code.lower():
        print(f"Registration function: {func['name']}")
        callers = get_function_callers(func['name'], limit=20)
        for caller in callers:
            print(f"  Registered by: {caller['name']}")
```

**Document handler mappings:**
```markdown
# Handler Registration Analysis

## Mechanism: [Table-driven / Runtime registration]

## Handler Mappings:
- PDU Type 0xA0 (GET) → handler_snmp_get_request
- PDU Type 0xA1 (GETNEXT) → handler_snmp_getnext_request
- PDU Type 0xA3 (SET) → handler_snmp_set_request
- PDU Type 0xA4 (TRAP) → handler_snmp_trap

## Registration Code Location: [Address]
```

**Save to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/handlers.md
```

### 3.2 Analyze Each Handler (45 min)

**Reference:**
- `ghidra-mcp-guides/common_workflows.md` → Workflow 5 (Trace to Sink)
- `protocol-analysis/SNMP/vulnerability_patterns.md`

**For GET handler:**
```python
get_handler = "handler_snmp_get_request"  # Adjust based on your finding

# Decompile
code = decompile_function(get_handler)
print(f"=== {get_handler} ===")
print(code)

# Analyze callees
callees = get_function_callees(get_handler, limit=50)
print(f"\nCallees ({len(callees)}):")
for callee in callees:
    print(f"  - {callee['name']}")

    # Classify
    callee_code = decompile_function(callee['name'])
    if any(k in callee_code.lower() for k in ['validate', 'check', 'verify']):
        role = "sanitizer"
    elif any(k in callee_code for k in ['fopen', 'open', 'system', 'exec']):
        role = "sink"
    else:
        role = "utility"

    # Rename with role
    rename_function_by_address(callee['address'], f"{role}_{callee['name']}")
```

**For SET handler (HIGH PRIORITY - most dangerous):**
```python
set_handler = "handler_snmp_set_request"  # Adjust

code = decompile_function(set_handler)
print(f"=== {set_handler} (DANGEROUS!) ===")

# Check for dangerous operations
dangerous_ops = []
if 'system' in code or 'popen' in code or 'exec' in code:
    dangerous_ops.append('command_execution')
if 'fopen' in code or 'open' in code:
    dangerous_ops.append('file_access')
if 'strcpy' in code or 'sprintf' in code:
    dangerous_ops.append('buffer_overflow_risk')

if dangerous_ops:
    print(f"⚠ DANGEROUS OPERATIONS: {dangerous_ops}")

    # Mark as vulnerable
    set_comment(
        set_handler_address,
        f"// ⚠ SECURITY: SET handler performs: {', '.join(dangerous_ops)}\n"
        "// Requires careful analysis for vulnerabilities"
    )
```

### 3.3 Vulnerability Identification (45 min)

**Reference:** `protocol-analysis/SNMP/vulnerability_patterns.md`

**Check each vulnerability pattern:**

**1. Buffer Overflow (CWE-120)**
```python
# Find strcpy/sprintf usage in SNMP handlers
for handler in all_handlers:
    code = decompile_function(handler['name'])

    if 'strcpy' in code or 'sprintf' in code:
        # Check for bounds checking
        if 'strlen' not in code and 'sizeof' not in code:
            print(f"⚠ CWE-120: Buffer overflow risk in {handler['name']}")
            print(f"  Location: {handler['address']}")

            # Add vulnerability comment
            set_decompiler_comment(
                handler['address'],
                """// ============================================================================
// VULNERABILITY: CWE-120 Buffer Copy Without Checking Size
// ============================================================================
//
// RISK: strcpy/sprintf used without bounds check
// ATTACK: Send oversized community/OID string → buffer overflow
//
// FIX REQUIRED:
// 1. Replace strcpy with strncpy
// 2. Add length validation before copy
// 3. Ensure null termination
//
// EXPLOITABILITY: High (remote code execution possible)
// ============================================================================
"""
            )

            # Rename to mark vulnerability
            rename_function_by_address(
                handler['address'],
                f"VULN_buffer_overflow_{handler['name']}"
            )
```

**2. Path Traversal (CWE-22)**
```python
# Find file operations in MIB/OID handlers
for handler in all_handlers:
    code = decompile_function(handler['name'])

    if ('fopen' in code or 'open' in code) and 'mib' in code.lower():
        # Check for path validation
        if 'realpath' not in code.lower() and 'canonicalize' not in code.lower():
            print(f"⚠ CWE-22: Path traversal risk in {handler['name']}")

            set_decompiler_comment(
                handler['address'],
                """// ============================================================================
// VULNERABILITY: CWE-22 Path Traversal
// ============================================================================
//
// RISK: OID mapped to file path without validation
// ATTACK: Send OID="../../../../etc/passwd" → read arbitrary files
//
// FIX REQUIRED:
// 1. Canonicalize path with realpath()
// 2. Validate path starts with /var/lib/snmp/mibs/
// 3. Reject paths containing ".."
//
// CVE: CVE-2025-20362 (if applicable)
// ============================================================================
"""
            )

            rename_function_by_address(
                handler['address'],
                f"VULN_path_traversal_{handler['name']}"
            )
```

**3. Command Injection (CWE-78)**
```python
# Check SET handlers for command execution
for handler in set_handlers:
    code = decompile_function(handler['name'])

    if 'system' in code or 'popen' in code:
        # Check for input sanitization
        if not any(k in code.lower() for k in ['sanitize', 'validate', 'escape']):
            print(f"⚠ CWE-78: Command injection risk in {handler['name']}")

            set_decompiler_comment(
                handler['address'],
                """// ============================================================================
// VULNERABILITY: CWE-78 Command Injection
// ============================================================================
//
// RISK: User-controlled value passed to system() without sanitization
// ATTACK: Send SET with value="; malicious_cmd" → arbitrary command execution
//
// FIX REQUIRED:
// 1. Use execv() instead of system() (no shell)
// 2. If must use system(), sanitize all special chars
// 3. Whitelist allowed characters
//
// EXPLOITABILITY: Critical (remote code execution)
// ============================================================================
"""
            )

            rename_function_by_address(
                handler['address'],
                f"VULN_command_injection_{handler['name']}"
            )
```

**4. Integer Overflow (CWE-190)**
```python
# Check BER/length parsing
parse_funcs = search_functions_by_name("parse", limit=50)
for func in parse_funcs:
    code = decompile_function(func['name'])

    if 'length' in code.lower() and 'malloc' in code:
        if 'MAX' not in code:
            print(f"⚠ CWE-190: Integer overflow risk in {func['name']}")
```

**Save all vulnerabilities to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/risk_functions.md
```

### 3.4 Data Flow Analysis (30 min)

**Reference:** `ghidra-mcp-guides/common_workflows.md` → Workflow 7

**Trace from entry to each vulnerability:**
```python
# For each vulnerability, trace back to entry point
vuln_func = "VULN_buffer_overflow_handle_get"

# Get callers chain
callers_l1 = get_function_callers(vuln_func, limit=20)
print(f"Vulnerability: {vuln_func}")
print("Call chain:")

for caller1 in callers_l1:
    print(f"  ← {caller1['name']}")

    callers_l2 = get_function_callers(caller1['name'], limit=20)
    for caller2 in callers_l2:
        print(f"    ← {caller2['name']}")

        # Check if this reaches entry point
        if 'recv' in caller2['name'].lower() or 'process' in caller2['name'].lower():
            print(f"      ✓ Reaches entry point!")
```

**Document attack path:**
```markdown
# Attack Path: Buffer Overflow in GET Handler

Entry: snmp_recv() [0x00401000]
  ↓
Parse: parse_snmp_packet() [0x00402000]
  ↓
Auth: validate_community() [0x00403000]
  ↓
Dispatch: dispatcher_snmp_pdu_router() [0x00404000]
  ↓
Handler: handler_snmp_get_request() [0x00405000]
  ↓
VULNERABLE: strcpy(oid_buffer, request->oid) [0x00405234]
  - No bounds check
  - oid_buffer is 256 bytes
  - request->oid can be 512+ bytes from network
```

**Save to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/data_flow.md
```

---

## 🎨 Phase 4: Code Enhancement (1 hour)

### 4.1 Systematic Function Renaming (30 min)

**Reference:** `ghidra-mcp-guides/renaming_standards.md`

**Rename all functions with role prefixes:**
```python
# Get all functions
all_functions = list_functions(limit=1000)

# Classify and rename
for func in all_functions:
    # Skip if already renamed
    if any(func['name'].startswith(prefix) for prefix in
           ['dispatcher_', 'handler_', 'sanitizer_', 'sink_', 'util_', 'VULN_']):
        continue

    # Classify
    code = decompile_function(func['name'])

    # Determine role
    if 'switch' in code and any(c in code.lower() for c in ['0xa0', '0xa1', '0xa3']):
        role = "dispatcher"
    elif any(k in code for k in ['strcpy', 'sprintf', 'fopen', 'system']):
        role = "sink"
    elif any(k in code.lower() for k in ['validate', 'check', 'sanitize']):
        role = "sanitizer"
    elif 'snmp' in func['name'].lower() or 'handler' in func['name'].lower():
        role = "handler"
    else:
        role = "util"

    # Build new name
    if func['name'].startswith('FUN_'):
        addr = func['name'].split('_', 1)[1]
        new_name = f"{role}_FUN_{addr}"
    else:
        new_name = f"{role}_{func['name']}"

    # Rename
    print(f"Renaming: {func['name']} → {new_name}")
    rename_function(func['name'], new_name)
```

**Set function prototypes:**
```python
# For key functions, infer and set prototypes
key_functions = [
    ("dispatcher_snmp_pdu_router", "int snmp_pdu_router(snmp_packet* pkt)"),
    ("handler_snmp_get_request", "int handle_get(snmp_request* req, snmp_response* resp)"),
    ("sanitizer_validate_community", "int validate_community(char* community_str)"),
]

for func_name, prototype in key_functions:
    funcs = search_functions_by_name(func_name, limit=1)
    if funcs:
        set_function_prototype(funcs[0]['address'], prototype)
        print(f"✓ Set prototype for {func_name}")
```

### 4.2 Variable Renaming (15 min)

**Reference:** `ghidra-mcp-guides/renaming_standards.md` § Variables

**Rename variables in key functions:**
```python
key_handlers = [
    "handler_snmp_get_request",
    "handler_snmp_set_request",
    "dispatcher_snmp_pdu_router"
]

for handler in key_handlers:
    code = decompile_function(handler)

    # Common patterns to rename
    renames = [
        ("iVar1", "pdu_type"),
        ("iVar2", "status_code"),
        ("pcVar1", "community_str"),
        ("pcVar2", "oid_str"),
        ("pcVar3", "value_str"),
        ("uVar1", "buffer_size"),
        ("uVar2", "string_len"),
        ("local_100", "oid_buffer"),
        ("local_200", "value_buffer"),
    ]

    for old_name, new_name in renames:
        if old_name in code:
            try:
                rename_variable(handler, old_name, new_name)
                print(f"  {handler}: {old_name} → {new_name}")
            except:
                pass  # Variable might not exist or already renamed
```

### 4.3 Add Comprehensive Comments (15 min)

**Reference:** `ghidra-mcp-guides/annotation_guidelines.md`

**Add function headers to all handlers:**
```python
handlers = [
    "dispatcher_snmp_pdu_router",
    "handler_snmp_get_request",
    "handler_snmp_set_request",
    "sanitizer_validate_community",
]

for handler in handlers:
    func = search_functions_by_name(handler, limit=1)[0]
    callees = get_function_callees(handler, limit=50)
    callers = get_function_callers(handler, limit=50)

    header = f"""// ============================================================================
// FUNCTION: {handler}
// Address: {func['address']}
// Role: {handler.split('_')[0]}
// ============================================================================
//
// PURPOSE:
//   [Analyze code and describe purpose]
//
// PARAMETERS:
//   [Extract from decompilation]
//
// RETURNS:
//   [Extract from decompilation]
//
// CALLERS: ({len(callers)} functions)
//   {', '.join([c['name'] for c in callers[:5]])}
//
// CALLEES: ({len(callees)} functions)
//   {', '.join([c['name'] for c in callees[:5]])}
//
// ANALYSIS DATE: 2025-10-12
// ============================================================================
"""

    set_decompiler_comment(func['address'], header)
    print(f"✓ Added header comment to {handler}")
```

---

## 📊 Phase 5: Report Generation (30 min)

### 5.1 Generate Analysis Reports

**Create comprehensive analysis report:**

```markdown
# SNMP Vulnerability Analysis - Full Report

## Executive Summary
[2-3 paragraphs summarizing findings]

## Target Information
- **Binary:** [name]
- **Architecture:** [arch]
- **Version:** [if known]
- **CVE:** [if applicable]

## Entry Points Discovered
1. snmp_recv() at 0x00401000
2. process_snmp_packet() at 0x00402000

## Handler Mappings
- GET (0xA0) → handler_snmp_get_request
- SET (0xA3) → handler_snmp_set_request
- TRAP (0xA4) → handler_snmp_trap

## Vulnerabilities Identified

### 1. CWE-120: Buffer Overflow in GET Handler
- **Location:** handler_snmp_get_request + 0x234
- **Severity:** High (CVSS 8.1)
- **Description:** [details]
- **Attack Scenario:** [steps]
- **Fix:** [code patch]

### 2. CWE-22: Path Traversal in MIB Access
- **Location:** sink_mib_file_open + 0x100
- **Severity:** High (CVSS 7.5)
- **Description:** [details]
- **Attack Scenario:** [steps]
- **Fix:** [code patch]

## Data Flow Analysis
[Include call graphs and data flow diagrams]

## Code Enhancements
- Functions renamed: 127
- Variables renamed: 243
- Comments added: 89
- Structures defined: 5

## Recommendations
1. [Immediate fix 1]
2. [Immediate fix 2]
3. [Long-term improvement]
```

**Save to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md
```

### 5.2 Generate Vulnerability Details Report

```markdown
# Vulnerability Details

## CWE-120: Buffer Overflow in SNMP GET Handler

### Location
- **Function:** handler_snmp_get_request
- **Address:** 0x00405234
- **File:** snmpd (if source available)
- **Line:** N/A (binary analysis)

### Vulnerable Code
\`\`\`c
// Decompiled pseudo-C
int handler_snmp_get_request(snmp_request *request, snmp_response *response) {
    char oid_buffer[256];  // Fixed-size buffer

    // VULNERABLE: No bounds check!
    strcpy(oid_buffer, request->oid);  // request->oid from network, can be 512+ bytes

    // ... rest of handler ...
}
\`\`\`

### Attack Scenario
1. Attacker sends SNMP GET request with 300-byte OID string
2. strcpy() copies entire string to 256-byte buffer
3. Stack overflow overwrites return address
4. Control flow hijacked to attacker's shellcode

### Proof of Concept
\`\`\`python
import socket

# Craft oversized OID (300 bytes)
malicious_oid = "1." + "9" * 300

# Build SNMP packet
packet = build_snmp_get(community="public", oid=malicious_oid)

# Send to target
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, (target_ip, 161))
\`\`\`

### Exploitability Assessment
- **Difficulty:** Medium (requires ROP or NX bypass)
- **Prerequisites:** Network access to SNMP port (UDP 161)
- **Impact:** Remote Code Execution (RCE)
- **CVSS v3.1:** 8.1 (High)
  - Attack Vector: Network (AV:N)
  - Attack Complexity: Low (AC:L)
  - Privileges Required: None (PR:N)
  - User Interaction: None (UI:N)
  - Scope: Unchanged (S:U)
  - Confidentiality: High (C:H)
  - Integrity: High (I:H)
  - Availability: High (A:H)

### Fix Recommendation
\`\`\`c
// SAFE CODE
int handler_snmp_get_request_FIXED(snmp_request *request, snmp_response *response) {
    char oid_buffer[256];

    // FIX 1: Validate length before copy
    size_t oid_len = strlen(request->oid);
    if (oid_len >= sizeof(oid_buffer)) {
        log_error("OID too long: %zu bytes", oid_len);
        return ERROR_OID_TOO_LONG;
    }

    // FIX 2: Use safe string function
    strncpy(oid_buffer, request->oid, sizeof(oid_buffer) - 1);
    oid_buffer[sizeof(oid_buffer) - 1] = '\0';  // Ensure null termination

    // ... rest of handler ...
}
\`\`\`

### References
- CWE-120: https://cwe.mitre.org/data/definitions/120.html
- CVE-2025-20362 (if applicable)
```

**Save to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md
```

### 5.3 Generate Fix Recommendations

```markdown
# Fix Recommendations

## Immediate Actions (Critical - Deploy ASAP)

### 1. Patch Buffer Overflow in GET Handler
**Priority:** Critical
**Effort:** Low (2 hours)

**Files to Modify:**
- snmpd.c (or equivalent)
- Function: handle_get_request()

**Code Patch:**
\`\`\`diff
- strcpy(oid_buffer, request->oid);
+ if (strlen(request->oid) >= sizeof(oid_buffer)) {
+     return ERROR_OID_TOO_LONG;
+ }
+ strncpy(oid_buffer, request->oid, sizeof(oid_buffer) - 1);
+ oid_buffer[sizeof(oid_buffer) - 1] = '\0';
\`\`\`

**Testing:**
- Unit test with 100, 256, 300, 512 byte OIDs
- Verify rejection of oversized OIDs
- Verify normal operation with valid OIDs

### 2. Add Path Validation in MIB Access
**Priority:** High
**Effort:** Medium (4 hours)

**Code Patch:**
\`\`\`c
// Before opening MIB file
char canonical[PATH_MAX];
char *resolved = realpath(mib_path, canonical);

if (!resolved) {
    log_error("Invalid MIB path: %s", mib_path);
    return ERROR_INVALID_PATH;
}

if (strncmp(canonical, MIB_BASE_DIR, strlen(MIB_BASE_DIR)) != 0) {
    log_error("MIB path outside base directory: %s", canonical);
    return ERROR_ACCESS_DENIED;
}

// Now safe to open
FILE *mib_file = fopen(canonical, "r");
\`\`\`

## Short-Term Actions (1-2 weeks)

### 3. Replace all strcpy/sprintf with safe alternatives
**Priority:** High
**Effort:** High (1-2 days)

**Global Search & Replace:**
- strcpy → strncpy (with size validation)
- strcat → strncat (with size validation)
- sprintf → snprintf (always)
- gets → fgets (always)

### 4. Add comprehensive input validation
**Priority:** High
**Effort:** Medium (1 day)

**Validation Functions to Add:**
- validate_community_string(char *community)
- validate_oid_format(char *oid)
- validate_pdu_length(uint32_t length)
- validate_value_type(uint8_t type)

## Long-Term Actions (1-2 months)

### 5. Migrate to SNMPv3 with encryption
**Priority:** Medium
**Effort:** Very High (2-3 weeks)

**Benefits:**
- Strong authentication (HMAC-SHA)
- Encryption (AES)
- No plain-text community strings

### 6. Implement fuzzing test suite
**Priority:** Medium
**Effort:** High (1 week)

**Coverage:**
- AFL/LibFuzzer for packet parsing
- 10,000+ test cases
- CI/CD integration

### 7. Code review and security audit
**Priority:** Medium
**Effort:** High (1 week)

**Scope:**
- Manual code review of all handlers
- Static analysis (Coverity, SonarQube)
- Dynamic analysis (Valgrind, ASan)
```

**Save to:**
```
.work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md
```

### 5.4 Update Stage Summary

**Create Stage D summary JSON:**
```json
{
  "stage": "stage_d",
  "version": "2.8.0",
  "date": "2025-10-12",
  "status": "completed",
  "analysis_mode": "gui",
  "entry_points": [
    {"name": "snmp_recv", "address": "0x00401000"},
    {"name": "process_snmp_packet", "address": "0x00402000"}
  ],
  "handlers_mapped": 4,
  "vulnerabilities_found": 3,
  "functions_renamed": 127,
  "variables_renamed": 243,
  "comments_added": 89,
  "reports_generated": [
    "FULL_ANALYSIS_REPORT.md",
    "VULNERABILITY_DETAILS.md",
    "FIX_RECOMMENDATIONS.md"
  ],
  "evidence": {
    "call_graphs": ["entry_to_handlers.txt", "full_call_graph.mmd"],
    "decompiled_code": ["handler_get.c", "handler_set.c"],
    "screenshots": ["vuln_buffer_overflow.png", "vuln_path_traversal.png"]
  }
}
```

**Save to:**
```
.work/cases/<vendor>/<case>/summaries/stage_d_summary.json
```

---

## ✅ Quality Assurance Checklist

Before completing, verify:

### Completeness
- [ ] All SNMP entry points identified and documented
- [ ] All handler functions (GET, SET, GETNEXT, TRAP) analyzed
- [ ] Complete call graph from entry to all sinks
- [ ] All vulnerabilities documented with CWE numbers
- [ ] All high-risk functions renamed and commented

### Accuracy
- [ ] Function classifications correct (dispatcher/handler/sanitizer/sink)
- [ ] Vulnerability assessments validated with code review
- [ ] Attack scenarios technically feasible
- [ ] Fix recommendations tested (if possible)
- [ ] No false positives in vulnerability list

### Documentation
- [ ] Function header comments on all key handlers
- [ ] Security annotations at all vulnerability locations
- [ ] Complex logic explained with inline comments
- [ ] All reports saved in correct locations (`.work/cases/`)
- [ ] Evidence chain complete (code + screenshots + call graphs)

### Reproducibility
- [ ] Another analyst can follow your analysis
- [ ] All MCP tool commands documented
- [ ] All assumptions explicitly stated
- [ ] All findings traceable to evidence

### Reports
- [ ] FULL_ANALYSIS_REPORT.md complete (20-30 pages)
- [ ] VULNERABILITY_DETAILS.md with PoC code
- [ ] FIX_RECOMMENDATIONS.md with patches
- [ ] stage_d_summary.json with metrics
- [ ] Evidence files (graphs, code, screenshots) saved

---

## 📚 Reference Documents

You should have quick access to these documents during analysis:

### Phase-Specific Guides
- **Phase 1:** `ghidra-mcp-guides/tool_categories.md` (tools reference)
- **Phase 2:** `protocol-analysis/SNMP/handler_patterns.md` (find handlers)
- **Phase 3:** `protocol-analysis/SNMP/vulnerability_patterns.md` (find vulns)
- **Phase 4:** `ghidra-mcp-guides/renaming_standards.md` (naming conventions)
- **Phase 4:** `ghidra-mcp-guides/annotation_guidelines.md` (comment standards)
- **Phase 5:** `master-prompts/quality_checklist.md` (QA checklist)

### Universal Guides
- **Tool Reference:** `ghidra-mcp-guides/tool_categories.md` (57 tools)
- **Workflows:** `ghidra-mcp-guides/common_workflows.md` (14 workflows)
- **SNMP Protocol:** `protocol-analysis/SNMP/protocol_overview.md` (protocol basics)

### Navigation
- **Document Index:** `prompts/re-cwe-prompts/INDEX.md` (find any document)
- **Step-by-Step:** `protocol-analysis/SNMP/analysis_checklist.md` (detailed steps)

---

## 💡 Tips for Success

### Efficient Workflow
1. **Follow the phases in order** - Don't skip ahead
2. **Document as you go** - Don't wait until the end
3. **Save frequently** - Write findings to files after each phase
4. **Use the checklist** - `protocol-analysis/SNMP/analysis_checklist.md`

### Tool Usage
1. **Paginate large results** - Use `limit=100` for list operations
2. **Cache frequently accessed data** - Store function lists, call graphs
3. **Use specific lookups** - `get_function_by_address()` is faster than searching
4. **Build call graphs early** - They help understand the big picture

### Analysis Quality
1. **Verify findings** - Don't assume, check the decompiled code
2. **Think like an attacker** - How would you exploit this?
3. **Consider edge cases** - What if OID is empty? 10MB? Unicode?
4. **Test your theories** - If claiming buffer overflow, calculate the overflow

### Common Pitfalls
1. ❌ **Skipping context preparation** - Always read case files first
2. ❌ **Renaming before understanding** - Analyze first, rename later
3. ❌ **Over-commenting** - Focus on security-critical areas
4. ❌ **Missing evidence** - Save call graphs, screenshots, code samples
5. ❌ **Incomplete reports** - Use the templates provided

---

## 🚨 When to Ask for Help

If you encounter:
- **MCP connection issues** - Check `docs/stage_d/guides/GUI_HEADLESS_MODE_SWITCHING_GUIDE.md`
- **Can't find entry points** - Review `protocol-analysis/SNMP/handler_patterns.md`
- **Unsure about vulnerability** - Check `protocol-analysis/SNMP/vulnerability_patterns.md`
- **Tool not working** - Verify tool name in `ghidra-mcp-guides/tool_categories.md`
- **Report format unclear** - See examples in `.work/cases/` from previous analyses

---

## 🎯 Success Criteria

You will have successfully completed this mission when:

1. ✅ **All entry points found** - You can trace from network input to handlers
2. ✅ **All handlers mapped** - You know what each PDU type does
3. ✅ **Vulnerabilities identified** - At least 1 security issue found and documented
4. ✅ **Code enhanced** - 50+ functions renamed, 100+ variables renamed, key functions commented
5. ✅ **Reports generated** - 3 comprehensive markdown reports in `.work/cases/`
6. ✅ **Evidence collected** - Call graphs, decompiled code, screenshots saved
7. ✅ **Quality verified** - All checklist items completed

**Expected Output:**
- Analysis time: 4-5 hours
- Functions analyzed: 100-200
- Functions renamed: 50-150
- Variables renamed: 100-300
- Vulnerabilities found: 1-5
- Reports generated: 3 (Full Analysis, Vulnerability Details, Fix Recommendations)
- Evidence files: 5-10 (graphs, code, screenshots)

---

## 🎓 Learning Outcomes

After completing this analysis, you will have:

1. **Mastered SNMP analysis** - Understand SNMP protocol internals
2. **Applied systematic RE workflow** - 5-phase methodology
3. **Used 57 Ghidra MCP tools** - Practical experience with complete toolset
4. **Identified real vulnerabilities** - Security analysis skills
5. **Generated professional reports** - Documentation skills
6. **Enhanced code quality** - Systematic renaming and commenting

---

**Mission Start Time:** _______________
**Expected Completion:** _______________ (4-5 hours later)
**Status:** Ready to begin

**Good luck, Agent! 🎯**

---

**Document Version:** 1.0
**Created:** 2025-10-12
**Last Updated:** 2025-10-12
**Author:** GhidraSage Team
**Status:** Ready for Production Use
