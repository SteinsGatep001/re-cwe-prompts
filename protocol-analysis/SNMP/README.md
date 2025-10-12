# SNMP Protocol Analysis Templates

**Purpose:** Protocol-specific analysis guidance for SNMP (Simple Network Management Protocol) vulnerability research.

---

## 📚 Template Overview

This directory contains SNMP-specific analysis templates for identifying vulnerabilities in SNMP implementations.

### Files in This Directory

| File | Purpose | Use Case |
|------|---------|----------|
| [protocol_overview.md](protocol_overview.md) | SNMP protocol structure, PDU types, encoding | Understanding SNMP basics |
| [handler_patterns.md](handler_patterns.md) | Common handler registration mechanisms | Finding entry points |
| [vulnerability_patterns.md](vulnerability_patterns.md) | Known SNMP vulnerability patterns | Identifying security issues |
| [analysis_checklist.md](analysis_checklist.md) | Step-by-step analysis checklist | Systematic analysis workflow |

---

## 🎯 Quick Start for SNMP Analysis

### 1. Understand the Protocol
Start with: [protocol_overview.md](protocol_overview.md)
- Learn SNMP PDU types (GET, SET, TRAP, etc.)
- Understand BER/DER encoding
- Review authentication mechanisms (community strings, SNMPv3)

### 2. Find Entry Points
Reference: [handler_patterns.md](handler_patterns.md)
- Locate SNMP request processing functions
- Find handler registration tables
- Map PDU type → handler function mappings

### 3. Identify Vulnerabilities
Reference: [vulnerability_patterns.md](vulnerability_patterns.md)
- Check for common SNMP vulnerabilities
- Trace user-controlled data to sinks
- Validate sanitization mechanisms

### 4. Systematic Analysis
Follow: [analysis_checklist.md](analysis_checklist.md)
- Step-by-step workflow
- Quality checkpoints
- Documentation standards

---

## 🔗 Integration with Universal Guides

These SNMP-specific templates should be used **in combination with** the universal Ghidra MCP guides:

```
Universal Guides (ghidra-mcp-guides/)
    +
SNMP Protocol Analysis (this directory)
    =
Complete SNMP Vulnerability Analysis
```

**Example Workflow:**
1. Use `ghidra-mcp-guides/tool_categories.md` to understand available MCP tools
2. Use `ghidra-mcp-guides/common_workflows.md` → Workflow 1 (String Search) to find SNMP-related strings
3. Use `protocol-analysis/SNMP/handler_patterns.md` to identify SNMP handler patterns
4. Use `ghidra-mcp-guides/common_workflows.md` → Workflow 5 (Trace to Sink) to trace data flow
5. Use `protocol-analysis/SNMP/vulnerability_patterns.md` to check for known SNMP vulnerabilities
6. Use `ghidra-mcp-guides/renaming_standards.md` to rename functions systematically
7. Use `ghidra-mcp-guides/annotation_guidelines.md` to document findings

---

## 🧪 SNMP-Specific MCP Tool Usage

### Finding SNMP Entry Points

```python
# Step 1: Search for SNMP-related strings
snmp_strings = list_strings(filter="snmp", limit=100)
community_strings = list_strings(filter="community", limit=50)
oid_strings = list_strings(filter="oid", limit=50)

# Step 2: Find references to these strings
for string_item in community_strings:
    xrefs = get_xrefs_to(string_item['address'])
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        print(f"SNMP function candidate: {func['name']}")
```

### Analyzing SNMP Handler Tables

```python
# Search for handler registration patterns
handler_funcs = search_functions_by_name("handler", limit=100)
register_funcs = search_functions_by_name("register", limit=50)

# Look for function pointer arrays
data_items = list_data_items(limit=500)
for data in data_items:
    if 'handler' in data.get('name', '').lower():
        print(f"Potential handler table: {data['name']} at {data['address']}")
```

### Tracing SNMP Request Processing

```python
# Find SNMP receive functions
recv_funcs = search_functions_by_name("snmp_recv", limit=20)
process_funcs = search_functions_by_name("process_pdu", limit=20)

# Build call graph from entry point
for func in recv_funcs:
    call_graph = get_function_call_graph(func['name'], depth=4, direction="callees")
    # Analyze call graph to find handlers
```

---

## 📖 SNMP CVE Examples

### Common SNMP Vulnerabilities

1. **CVE-2025-20362 (Cisco)** - Path traversal in SNMP OID handling
   - Pattern: Missing path validation in MIB file access
   - Template: See `vulnerability_patterns.md` → Path Traversal

2. **CVE-2020-15862 (Net-SNMP)** - Integer overflow in packet parsing
   - Pattern: Unchecked length field in BER decoding
   - Template: See `vulnerability_patterns.md` → Integer Overflow

3. **CVE-2019-13500 (PHP-SNMP)** - Command injection via SNMP options
   - Pattern: Unsanitized SNMP options passed to shell
   - Template: See `vulnerability_patterns.md` → Command Injection

4. **CVE-2018-18065 (Net-SNMP)** - Buffer overflow in community string
   - Pattern: strcpy without bounds check on community string
   - Template: See `vulnerability_patterns.md` → Buffer Overflow

---

## 🎓 Learning Resources

### SNMP Protocol References
- **RFC 1157:** SNMPv1 Protocol Specification
- **RFC 3416:** SNMPv2c Protocol Operations
- **RFC 3417:** SNMPv2c Transport Mappings
- **RFC 3418:** SNMPv2c MIB for SNMP
- **RFC 3411-3418:** SNMPv3 Framework

### SNMP Security References
- **OWASP:** SNMP Security Cheat Sheet
- **NIST SP 800-88:** Guidelines for SNMP Security
- **CWE-15:** External Control of System or Configuration Setting
- **CWE-287:** Improper Authentication (SNMP community strings)

---

## ⚙️ SNMP Implementation Variants

Different SNMP implementations have different patterns:

### Net-SNMP (Most Common)
- Handler registration: `netsnmp_register_handler()`
- MIB parsing: `parse_mib()`, `read_mib()`
- OID handling: `snmp_oid_compare()`, `netsnmp_oid_equals()`

### Cisco IOS SNMP
- Handler tables: Static arrays of `{OID, handler_func}` structs
- Community string validation: Custom implementation
- MIB access: Often file-based with path construction

### Embedded SNMP (Custom)
- Minimal implementations
- Often lack proper validation
- Simple switch/case on PDU type

---

## 🚨 Security Research Notes

### High-Risk Areas in SNMP

1. **Community String Handling**
   - Often fixed-size buffers
   - strcpy/sprintf without bounds checks
   - Focus: Buffer overflow vulnerabilities

2. **OID Processing**
   - Path traversal if OIDs map to file paths
   - Integer overflow in OID parsing
   - Focus: Input validation issues

3. **BER/DER Decoding**
   - Complex parsing logic
   - Length fields controlled by attacker
   - Focus: Integer overflow, buffer overflow

4. **MIB File Access**
   - File path construction from OIDs
   - Missing canonicalization
   - Focus: Path traversal vulnerabilities

5. **SET Request Handling**
   - Writes to configuration
   - May invoke system commands
   - Focus: Command injection, privilege escalation

---

## 🔍 SNMP-Specific Search Keywords

When searching for SNMP code, use these keywords:

**Protocol Terms:**
- snmp, snmpd, snmp_agent
- community, community_string
- oid, object_identifier
- pdu, packet_data_unit
- mib, management_information_base
- trap, inform, notification

**PDU Types:**
- get, getnext, getbulk
- set, set_request
- response, reply
- trap, snmpv2_trap

**Operations:**
- parse, decode, encode
- process, handle, dispatch
- validate, check, verify
- register, bind, map

**Data Structures:**
- snmp_request, snmp_pdu
- snmp_session, snmp_context
- variable_binding, varbind
- oid_tree, mib_tree

---

## 📊 Analysis Workflow Summary

```
1. Protocol Understanding (protocol_overview.md)
   ↓
2. Entry Point Discovery (handler_patterns.md + Ghidra MCP)
   ↓
3. Handler Mapping (handler_patterns.md)
   ↓
4. Data Flow Tracing (common_workflows.md)
   ↓
5. Vulnerability Identification (vulnerability_patterns.md)
   ↓
6. Code Enhancement (renaming_standards.md + annotation_guidelines.md)
   ↓
7. Documentation (analysis_checklist.md)
```

---

**Created:** 2025-10-12
**Purpose:** SNMP-specific analysis guidance for GhidraSage workflows
**Audience:** Security researchers analyzing SNMP vulnerabilities
**Status:** Complete (4 template files)
