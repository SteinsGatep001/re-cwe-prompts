# GhidraSage Deep Analysis - Quick Start Guide

**For AI Agents performing SNMP vulnerability analysis in Ghidra GUI mode**

---

## 🚀 30-Second Start

### What You Are
Professional reverse engineer / security researcher tasked with deep SNMP vulnerability analysis.

### What You Need
1. Read: `prompts/re-cwe-prompts/INDEX.md` (navigation hub)
2. Read: `prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md` (your workflow)
3. Load documents **on-demand** using INDEX as reference

### What You Do
Follow 5-phase workflow:
- Phase 1: Context Prep (15 min)
- Phase 2: Entry Discovery (30 min)
- Phase 3: Deep Analysis (2-3 hrs)
- Phase 4: Code Enhancement (1 hr)
- Phase 5: Report Generation (30 min)

**Total Time:** 4-5 hours

---

## 📖 Essential Documents (Load These First)

### 🔴 Critical Priority

1. **INDEX.md** - Navigation hub
   - Path: `prompts/re-cwe-prompts/INDEX.md`
   - Purpose: Find any document quickly
   - Use: Reference throughout workflow

2. **Master Prompt** - Your workflow guide
   - Path: `prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md`
   - Purpose: Complete 5-phase orchestration
   - Use: Follow step-by-step instructions

3. **Analysis Checklist** - Concrete action items
   - Path: `prompts/re-cwe-prompts/protocol-analysis/SNMP/analysis_checklist.md`
   - Purpose: Step-by-step checklist for each phase
   - Use: Track your progress

### 🟡 High Priority (Load When Needed)

4. **Tool Categories** - MCP tool reference (57 tools)
   - Path: `prompts/re-cwe-prompts/ghidra-mcp-guides/tool_categories.md`
   - When: Phase 1 (tool lookups)

5. **Handler Patterns** - Find SNMP handlers
   - Path: `prompts/re-cwe-prompts/protocol-analysis/SNMP/handler_patterns.md`
   - When: Phase 2 (entry point discovery)

6. **Vulnerability Patterns** - Detect vulnerabilities
   - Path: `prompts/re-cwe-prompts/protocol-analysis/SNMP/vulnerability_patterns.md`
   - When: Phase 3 (vulnerability identification)

7. **Renaming Standards** - Function/variable naming
   - Path: `prompts/re-cwe-prompts/ghidra-mcp-guides/renaming_standards.md`
   - When: Phase 4 (code enhancement)

8. **Annotation Guidelines** - Comment formatting
   - Path: `prompts/re-cwe-prompts/ghidra-mcp-guides/annotation_guidelines.md`
   - When: Phase 4 (adding comments)

---

## 🔧 Prerequisites Verification

### Before Starting

```python
# 1. Verify MCP connection
check_connection()

# 2. Get program metadata
metadata = get_metadata()
print(f"✓ Analyzing: {metadata['program_name']}")
print(f"✓ Architecture: {metadata['architecture']}")
print(f"✓ Base: {metadata['base_address']}")

# 3. Check case context exists
import os
case_path = ".work/cases/<vendor>/<case>/"
assert os.path.exists(case_path + "context/case_context.json")
print(f"✓ Case context loaded")
```

**If all checks pass:** Proceed to Phase 1

**If checks fail:**
- MCP connection issues: Check Ghidra GUI is running
- Missing case context: Run earlier stages (A→C) first

---

## 📋 5-Phase Workflow Summary

### Phase 1: Context Preparation (15 min)

**Goals:**
- Understand target binary
- Collect SNMP artifacts (strings, imports)
- Review case context

**Key Tools:**
```python
get_metadata()                              # Binary info
get_entry_points()                          # Entry addresses
list_segments(limit=100)                    # Memory layout
list_imports(limit=200)                     # Imported functions
list_strings(filter="snmp", limit=100)      # SNMP strings
```

**Output:** `.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/phase1_context.md`

---

### Phase 2: Entry Point Discovery (30 min)

**Goals:**
- Find SNMP packet entry functions
- Identify PDU type dispatcher
- Build initial call graph

**Key Tools:**
```python
search_functions_by_name("snmp", limit=100)     # SNMP functions
get_xrefs_to(string_address, limit=50)          # Cross-references
decompile_function(func_name)                   # Decompiled code
get_function_callees(func_name, limit=50)       # Called functions
get_function_call_graph(func, depth=4)          # Call graph
```

**Key Pattern:**
```python
# Find dispatcher: function with PDU type constants (0xA0-0xA6)
if any(const in code.lower() for const in ['0xa0', '0xa1', '0xa3']):
    print(f"✓ PDU DISPATCHER FOUND: {func['name']}")
```

**Output:** `.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/entrypoints.md`

---

### Phase 3: Deep Analysis (2-3 hours)

**Goals:**
- Map handler registration mechanism
- Analyze each handler (GET, SET, TRAP)
- Identify vulnerabilities (CWE-120, CWE-22, CWE-78, CWE-190)
- Trace data flow from entry to sinks

**Key Vulnerabilities to Check:**
```python
# CWE-120: Buffer Overflow
if 'strcpy' in code or 'sprintf' in code:
    if 'strlen' not in code:
        print("⚠ CWE-120: Buffer overflow risk")

# CWE-22: Path Traversal
if 'fopen' in code or 'open' in code:
    if 'realpath' not in code.lower():
        print("⚠ CWE-22: Path traversal risk")

# CWE-78: Command Injection
if 'system' in code or 'popen' in code:
    print("⚠ CWE-78: Command injection risk")
```

**Outputs:**
- `.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/handlers.md`
- `.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/risk_functions.md`
- `.work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/data_flow.md`

---

### Phase 4: Code Enhancement (1 hour)

**Goals:**
- Rename functions with role prefixes (50-150 functions)
- Rename variables (100-300 variables)
- Add comprehensive comments (security annotations)

**Naming Convention:**
```python
# Function naming: <role>_<original>_<purpose>
dispatcher_snmp_pdu_router
handler_snmp_get_request
sanitizer_validate_community
sink_file_open
VULN_buffer_overflow_strcpy

# Variable naming: <purpose>_<type_suffix>
pdu_type              # int
community_str         # char*
oid_buffer           # char[]
request_size         # size_t
file_fd              # int
```

**Security Annotation Template:**
```c
// ============================================================================
// VULNERABILITY: CWE-120 Buffer Copy Without Checking Size
// ============================================================================
//
// RISK: strcpy used without bounds check
// ATTACK: Send oversized OID → buffer overflow → RCE
//
// FIX REQUIRED:
// 1. Replace strcpy with strncpy
// 2. Add length validation
// 3. Ensure null termination
//
// EXPLOITABILITY: High (remote code execution possible)
// ============================================================================
```

**Outputs:** Enhanced code in Ghidra GUI

---

### Phase 5: Report Generation (30 min)

**Goals:**
- Generate comprehensive analysis reports
- Document all vulnerabilities with PoC
- Create fix recommendations
- Save evidence (call graphs, code, screenshots)

**Required Reports:**

1. **Full Analysis Report** (20-30 pages)
   - Executive summary
   - Entry points discovered
   - Handler mappings
   - Vulnerabilities found
   - Call graphs
   - Data flow diagrams

2. **Vulnerability Details Report**
   - Each vulnerability with CWE number
   - Attack scenarios
   - Proof-of-concept code
   - Exploitability assessment
   - CVSS scoring

3. **Fix Recommendations Report**
   - Code patches
   - Configuration changes
   - Security best practices
   - Testing procedures

**Outputs:**
- `.work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`
- `.work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`
- `.work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`
- `.work/cases/<vendor>/<case>/summaries/stage_d_summary.json`

---

## ✅ Success Criteria

### You Have Succeeded When:

**Analysis Completeness:**
- ✅ All SNMP entry points identified
- ✅ All handlers mapped (GET, SET, GETNEXT, TRAP)
- ✅ Complete call graph from entry to sinks
- ✅ ≥1 vulnerability identified and documented

**Code Enhancement:**
- ✅ ≥50 functions renamed with role prefixes
- ✅ ≥100 variables renamed with descriptive names
- ✅ Key functions have header comments
- ✅ All vulnerabilities have security annotations

**Reports Generated:**
- ✅ Full Analysis Report (20-30 pages)
- ✅ Vulnerability Details with PoC
- ✅ Fix Recommendations with patches
- ✅ Stage D summary JSON

**Quality Standards:**
- ✅ All findings traceable to evidence
- ✅ Another analyst can reproduce your analysis
- ✅ No false positives in vulnerability list
- ✅ Fix recommendations are technically sound

---

## 🚨 Common Pitfalls

### ❌ DON'T:
- Load all 74 documents at once (token waste)
- Skip phases (breaks the workflow)
- Rename before understanding (causes confusion)
- Over-comment trivial code (focus on security-critical areas)
- Miss evidence collection (screenshots, call graphs)

### ✅ DO:
- Use INDEX.md for navigation
- Load documents on-demand
- Follow phases in sequence
- Verify findings with decompiled code
- Document all assumptions
- Save evidence as you go
- Complete quality checklist

---

## 📞 When You Need Help

| Question | Document |
|----------|----------|
| How to use a specific MCP tool? | `ghidra-mcp-guides/tool_categories.md` |
| How to find SNMP handlers? | `protocol-analysis/SNMP/handler_patterns.md` |
| What are common SNMP vulns? | `protocol-analysis/SNMP/vulnerability_patterns.md` |
| How to rename systematically? | `ghidra-mcp-guides/renaming_standards.md` |
| How to format comments? | `ghidra-mcp-guides/annotation_guidelines.md` |
| What workflows are available? | `ghidra-mcp-guides/common_workflows.md` |
| Where to find any document? | `INDEX.md` (navigation hub) |

---

## 🎯 Quick Commands Cheat Sheet

### Context & Discovery
```python
# Get binary info
metadata = get_metadata()

# Find SNMP strings
snmp_strings = list_strings(filter="snmp", limit=100)

# Find functions
funcs = search_functions_by_name("snmp", limit=100)

# Get cross-references
xrefs = get_xrefs_to(address, limit=50)
```

### Analysis
```python
# Decompile function
code = decompile_function(func_name)

# Get function by address
func = get_function_by_address(address)

# Get callees (functions called by this function)
callees = get_function_callees(func_name, limit=50)

# Get callers (functions that call this function)
callers = get_function_callers(func_name, limit=50)

# Build call graph
graph = get_function_call_graph(func_name, depth=4, direction="callees")
```

### Enhancement
```python
# Rename function
rename_function_by_address(address, new_name)

# Rename variable
rename_variable(func_name, old_var_name, new_var_name)

# Add comment to decompiled code
set_decompiler_comment(address, comment_text)

# Add comment to disassembly
set_disassembly_comment(address, comment_text)
```

---

## 🏁 Start Now

**Step 1:** Read this quick start guide (✅ You're here)

**Step 2:** Verify prerequisites:
```python
check_connection()
metadata = get_metadata()
```

**Step 3:** Load critical documents:
- INDEX.md
- master-prompts/ghidrasage_deep_analysis.md
- protocol-analysis/SNMP/analysis_checklist.md

**Step 4:** Begin Phase 1 (Context Preparation)

**Step 5:** Follow the master prompt, one phase at a time

---

## 📊 Expected Timeline

| Phase | Time | Cumulative |
|-------|------|------------|
| Phase 1: Context Preparation | 15 min | 0:15 |
| Phase 2: Entry Point Discovery | 30 min | 0:45 |
| Phase 3: Deep Analysis | 2-3 hours | 3:45 |
| Phase 4: Code Enhancement | 1 hour | 4:45 |
| Phase 5: Report Generation | 30 min | 5:15 |

**Total:** 4-5 hours for complete analysis

---

**Good luck, Agent! 🎯**

**Remember:**
- Follow the workflow systematically
- Use INDEX.md for navigation
- Load documents on-demand
- Verify all findings
- Complete quality checklist
- Save evidence continuously

---

**Document Version:** 1.0
**Created:** 2025-10-12
**Status:** Ready for Use
**Next:** Begin Phase 1 of your analysis
