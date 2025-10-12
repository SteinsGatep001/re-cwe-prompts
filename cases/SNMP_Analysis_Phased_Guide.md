# SNMP Vulnerability Analysis - Phased Guide for AI Agents

**Purpose**: Systematic 5-phase workflow to guide AI agents through deep SNMP vulnerability analysis in embedded firmware using Ghidra/IDA with MCP integration.

**Target Scenario**: Network device firmware with SNMP daemon/agent implementation
**Estimated Time**: 5-6 hours total
**Tool Requirements**: Ghidra GUI + GhidraSage MCP, or IDA Pro + IDA MCP

---

## 📖 Overview

This guide provides **sequential, copy-paste prompts** for each analysis phase. Each prompt is self-contained and references relevant documentation from the `re-cwe-prompts` repository.

**Important**:
- Send prompts **one phase at a time**
- Wait for agent confirmation before proceeding to next phase
- Agent will explicitly state "ready for Phase N" when complete
- Do not send all phases at once - this will overwhelm the agent

---

## 🚀 Phase 0: Initialization & Connection Verification

**Estimated Time**: 2-5 minutes
**Objective**: Verify MCP connection and load program metadata

### Prompt to Send

```
You are a professional reverse engineer and security researcher.

Your task: Complete SNMP vulnerability deep analysis in Ghidra/IDA GUI using MCP tools.

First, read the workflow overview:
prompts/re-cwe-prompts/START_HERE.md

Then execute these verification steps:

1. Verify MCP connection:
   check_connection()

2. Get program metadata:
   metadata = get_metadata()
   print(f"Program: {metadata['program_name']}")
   print(f"Architecture: {metadata['architecture']}")

If connection succeeds, tell me you are ready for Phase 1.
If it fails, report the specific error message.
```

**Expected Output**: Agent executes verification commands and reports readiness or errors.

---

## 📝 Phase 1: Context Gathering

**Estimated Time**: 15-20 minutes
**Objective**: Collect SNMP-related strings, imports, and memory layout

**Wait for Phase 0 completion, then send:**

```
Begin Phase 1: Context Gathering

Reference documentation:
- prompts/re-cwe-prompts/protocol-analysis/SNMP/analysis_checklist.md
  (Focus on "Phase 1: Context Preparation" section)

Task Checklist:

1. Collect SNMP-related strings:
   - snmp_strings = list_strings(filter="snmp", limit=100)
   - community_strings = list_strings(filter="community", limit=50)
   - oid_strings = list_strings(filter="oid", limit=50)
   - mib_strings = list_strings(filter="mib", limit=50)

2. Collect imports (focus on network and file operations):
   - imports = list_imports(limit=200)
   - Filter for: recv, send, socket, fopen, open, read, write functions

3. Get memory layout:
   - segments = list_segments(limit=100)

4. Summarize findings:
   - Report how many SNMP-related strings found
   - List 5-10 most relevant import functions
   - Create notes documenting initial findings

When complete, report:
- Number of SNMP-related strings found
- Top 5 most relevant import functions
- Confirm readiness for Phase 2
```

**Expected Output**: Agent executes commands, reports statistics, and confirms readiness for Phase 2.

---

## 🔍 Phase 2: Entry Point Discovery

**Estimated Time**: 30-45 minutes
**Objective**: Locate SNMP packet handling entry points and PDU dispatcher functions

**Wait for Phase 1 completion, then send:**

```
Begin Phase 2: Entry Point Discovery

Reference documentation:
- prompts/re-cwe-prompts/protocol-analysis/SNMP/handler_patterns.md
  (Focus on first 3 patterns and "Step 1-2")

Goal: Find SNMP packet processing entry points and PDU dispatcher logic

Tasks:

1. Find functions referencing "community" strings:
   - For each community_string:
     - Get cross-references: get_xrefs_to(string['address'])
     - Identify referencing functions
     - Decompile these functions

2. Identify PDU dispatcher:
   - Search decompiled code for PDU type constants (0xA0, 0xA1, 0xA3, 0xA4)
   - Look for switch statements or function pointer tables
   - Locate branching logic handling different PDU types

3. Map handler functions:
   - Use get_function_callees() to find all functions called by dispatcher
   - Identify which function handles GET (0xA0)
   - Identify which function handles SET (0xA3)
   - Identify which function handles TRAP (0xA4)

4. Build initial call graph:
   - call_graph = get_function_call_graph(dispatcher_name, depth=3)

When complete, report:
- SNMP entry function name and address
- PDU dispatcher name and address
- GET/SET/TRAP handler names and addresses
- Brief call graph description

Confirm readiness for Phase 3
```

**Expected Output**: Agent locates entry points, dispatcher, and main handlers with addresses.

---

## 🔬 Phase 3: Deep Vulnerability Analysis

**Estimated Time**: 2-3 hours
**Objective**: Identify security vulnerabilities using pattern-based detection

**This is the most critical phase. Wait for Phase 2 completion, then send:**

```
Begin Phase 3: Deep Vulnerability Analysis

This is the most important phase - you must find security vulnerabilities.

Reference documentation:
- prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md
  (Jump to "Phase 3: Deep Analysis" section)
- prompts/re-cwe-prompts/protocol-analysis/SNMP/vulnerability_patterns.md
  (Review 5 common vulnerability patterns)

Task Breakdown:

### 3.1 Analyze Handler Registration Mechanism (30 min)
- Determine if using static table, switch dispatch, or runtime registration
- Document PDU type → handler function mapping

### 3.2 Analyze GET Handler (30 min)
- Decompile GET handler function
- Trace data flow: community → OID → response building
- Check input validation and boundary checks
- Identify called functions (sanitizer/utility/sink)

### 3.3 Analyze SET Handler (45 min) ⚠️ HIGH PRIORITY
- Decompile SET handler function
- Check authorization verification (requires "private" community?)
- Verify OID and value validation
- **Focus on dangerous operations:**
  - Any system()/popen() calls? → CWE-78 command injection
  - Any fopen() with OID-constructed path? → CWE-22 path traversal
  - Any strcpy()/sprintf() without length checks? → CWE-120 buffer overflow

### 3.4 Vulnerability Detection (45 min)
For each handler function, check these patterns:

**CWE-120: Buffer Overflow**
if ('strcpy' in code or 'sprintf' in code) and ('strlen' not in code):
    → Flag as vulnerability

**CWE-22: Path Traversal**
if ('fopen' in code or 'open' in code) and ('realpath' not in code):
    → Flag as vulnerability

**CWE-78: Command Injection**
if ('system' in code or 'popen' in code):
    → Flag as vulnerability

**CWE-190: Integer Overflow**
if ('malloc' in code and 'length' in code) and ('MAX' not in code):
    → Flag as vulnerability

### 3.5 Data Flow Analysis (30 min)
- For each vulnerability, trace complete call chain from entry to vuln point
- Use get_function_callers() to backtrack callers
- Document attack paths

When complete, report:
- Number of vulnerabilities found
- Each vulnerability's type (CWE-XXX)
- Vulnerability location (function name + address)
- Severity (High/Medium/Low)
- Call chain from entry to vulnerability

Confirm readiness for Phase 4
```

**Expected Output**: Agent analyzes each handler, identifies vulnerabilities, and reports complete call chains.

---

## 🎨 Phase 4: Code Optimization & Annotation

**Estimated Time**: 1 hour
**Objective**: Systematically rename functions/variables and add security annotations

**Wait for Phase 3 completion, then send:**

```
Begin Phase 4: Code Optimization & Annotation

Goal: Systematically rename functions and variables, add security comments.

Reference documentation:
- prompts/re-cwe-prompts/ghidra-mcp-guides/renaming_standards.md
- prompts/re-cwe-prompts/ghidra-mcp-guides/annotation_guidelines.md

### 4.1 Rename Key Functions (30 min)

Use role-based prefixes:

**Dispatcher:**
rename_function_by_address(dispatcher_addr, "dispatcher_snmp_pdu_router")

**Handlers:**
rename_function_by_address(get_handler_addr, "handler_snmp_get_request")
rename_function_by_address(set_handler_addr, "handler_snmp_set_request")
rename_function_by_address(trap_handler_addr, "handler_snmp_trap")

**Validators:**
rename_function_by_address(validate_addr, "sanitizer_validate_community")
rename_function_by_address(validate_oid_addr, "sanitizer_validate_oid")

**Dangerous Functions (sinks):**
rename_function_by_address(file_open_addr, "sink_mib_file_open")
rename_function_by_address(exec_addr, "sink_execute_command")

**Vulnerable Functions:**
rename_function_by_address(vuln_addr, "VULN_buffer_overflow_strcpy")
rename_function_by_address(vuln2_addr, "VULN_path_traversal_fopen")

Target: Rename at least 50 critical functions

### 4.2 Rename Variables (15 min)

In critical functions, rename:
- iVar1 → pdu_type
- pcVar1 → community_str
- pcVar2 → oid_str
- pcVar3 → value_str
- local_100 → oid_buffer
- local_200 → value_buffer

Target: Rename at least 100 variables

### 4.3 Add Security Annotations (15 min)

Add detailed security comments for each vulnerability:

set_decompiler_comment(vuln_addr, """
// ============================================================================
// VULNERABILITY: CWE-120 Buffer Overflow
// ============================================================================
//
// Risk: strcpy() used without length check
//
// Attack Scenario:
//   1. Attacker sends oversized OID string (300+ bytes)
//   2. strcpy copies entire string to 256-byte stack buffer
//   3. Stack overflow overwrites return address
//   4. Control flow hijacked, executes attacker shellcode
//
// Fix Recommendations:
//   1. Validate OID length before copying
//   2. Replace strcpy with strncpy
//   3. Ensure buffer null termination
//
// Exploit Difficulty: Medium (requires ROP or NX bypass)
// Impact: Remote Code Execution (RCE)
// CVSS v3.1: 8.1 (High)
// ============================================================================
""")

When complete, report:
- Number of functions renamed
- Number of variables renamed
- Number of vulnerabilities annotated

Confirm readiness for Phase 5
```

**Expected Output**: Agent systematically renames functions/variables and adds detailed security annotations.

---

## 📊 Phase 5: Report Generation

**Estimated Time**: 30-45 minutes
**Objective**: Generate 3 comprehensive analysis reports

**Final phase. Wait for Phase 4 completion, then send:**

```
Begin Phase 5: Report Generation

Goal: Generate 3 complete analysis reports

Reference report templates:
- prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md
  (See "Phase 5: Report Generation" section)

### 5.1 Generate Full Analysis Report

Create file: `.work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`

Include these sections:
1. Executive Summary (2-3 paragraphs)
2. Target Information (binary, architecture, CVE)
3. Discovered Entry Points
4. Handler Function Mapping (PDU → function)
5. Discovered Vulnerabilities (one subsection per vuln)
6. Data Flow Analysis (call graphs)
7. Code Enhancement Summary (rename statistics)
8. Recommended Mitigations

### 5.2 Generate Vulnerability Details Report

Create file: `.work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`

For each vulnerability, include:
- Vulnerability location (function name + address + code line)
- Affected code (decompiled pseudo-C code)
- Attack scenario (step-by-step)
- PoC code (proof of concept)
- Exploit difficulty assessment
- CVSS v3.1 score (with calculation breakdown)
- References (CWE links, CVE links)

### 5.3 Generate Fix Recommendations Report

Create file: `.work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`

Organize into three tiers:

**Immediate Fixes (Critical):**
- Specific code patches for each vulnerability
- Files and functions to modify
- Testing methodology

**Short-term Improvements (1-2 weeks):**
- Global unsafe function replacement (strcpy→strncpy)
- Comprehensive input validation
- Authentication mechanism hardening

**Long-term Hardening (1-2 months):**
- Migrate to SNMPv3
- Implement fuzz testing
- Code audit and static analysis

### 5.4 Save Evidence Files

- Export call graph: get_full_call_graph(format="mermaid")
- Save to: `.work/cases/<vendor>/<case>/analysis/stage_d/evidence/call_graphs/`
- Screenshot critical functions
- Save decompiled code

### 5.5 Update Stage D Summary

Create file: `.work/cases/<vendor>/<case>/summaries/stage_d_summary.json`

Format:
{
  "stage": "stage_d",
  "status": "completed",
  "analysis_mode": "gui",
  "entry_points": [...],
  "handlers_mapped": 4,
  "vulnerabilities_found": 3,
  "functions_renamed": 127,
  "variables_renamed": 243,
  "reports_generated": ["FULL_ANALYSIS_REPORT.md", ...]
}

When complete, report:
- Paths to 3 report files
- Page count or word count for each report
- Number of evidence files
- Contents of stage_d_summary.json
```

**Expected Output**: Agent generates 3 detailed analysis reports and stage_d_summary.json.

---

## ✅ Final Quality Assurance

**After all phases complete, send this prompt for agent self-check:**

```
Perform final quality assurance check.

Reference documentation:
- prompts/re-cwe-prompts/protocol-analysis/SNMP/analysis_checklist.md
  (See "Quality Assurance Checklist" section)

Check these items:

### Completeness:
- [ ] All SNMP entry points identified and documented
- [ ] All handlers (GET, SET, GETNEXT, TRAP) analyzed
- [ ] Complete call graph from entry to all sinks built
- [ ] All vulnerabilities have CWE numbers
- [ ] All high-risk functions renamed and annotated

### Accuracy:
- [ ] Function classification correct (dispatcher/handler/sanitizer/sink)
- [ ] Vulnerability assessments verified through code review
- [ ] Attack scenarios technically feasible
- [ ] Fix recommendations tested (where possible)
- [ ] No false positives in vulnerability list

### Documentation:
- [ ] All critical handler functions have header comments
- [ ] All vulnerability locations have security annotations
- [ ] Complex logic has inline comments
- [ ] All reports saved in correct location (.work/cases/)
- [ ] Evidence chain complete (code + screenshots + call graphs)

### Reproducibility:
- [ ] Another analyst can follow your analysis
- [ ] All MCP tool commands documented
- [ ] All assumptions explicitly stated
- [ ] All findings traceable to evidence

If all checks pass, report:
"✅ Quality check complete, analysis ready for submission"

If checks fail, state which items failed and why.
```

---

## 📈 Timeline Summary

| Phase | Time | Cumulative |
|-------|------|------------|
| Phase 0: Initialization | 2-5 min | 0:05 |
| Phase 1: Context Gathering | 15-20 min | 0:25 |
| Phase 2: Entry Point Discovery | 30-45 min | 1:10 |
| Phase 3: Deep Analysis | 2-3 hours | 4:10 |
| Phase 4: Code Optimization | 1 hour | 5:10 |
| Phase 5: Report Generation | 30-45 min | 5:55 |

**Total**: Approximately 5-6 hours for complete analysis

---

## 💡 Usage Tips

### 1. Sequential Execution
Do not skip phases or send all prompts at once.

### 2. Wait for Completion
Each phase ends with agent explicitly stating "ready for Phase N".

### 3. Intervene When Needed
If agent gets stuck or goes off-track:
- Remind it to return to current phase task checklist
- Provide additional reference documentation
- Break down tasks into smaller sub-tasks

### 4. Save Intermediate Results
Encourage agent to save notes and findings at each phase completion.

### 5. Flexible Adjustment
If a phase takes too long, split into smaller sub-tasks.

---

## 🎯 Success Criteria

Upon completing all phases, you should have:

**Deliverables:**
- 3 detailed analysis reports (30-50 pages total)
- stage_d_summary.json
- Call graph files
- Screenshots and decompiled code

**Ghidra/IDA Project State:**
- 50-150 functions renamed
- 100-300 variables renamed
- All vulnerabilities have detailed security annotations
- All critical functions have documentation headers

**Analysis Quality:**
- At least 1 real vulnerability found
- Each vulnerability has complete call chain
- Fix recommendations specific and actionable
- All findings backed by code evidence

---

## 🔗 Related Documentation

- `../protocol-analysis/SNMP/` - SNMP-specific analysis patterns
- `../ghidra-mcp-guides/` - Ghidra MCP best practices
- `../workflows/` - Modular workflow components
- `../cwes/` - CWE vulnerability patterns
- `../master-prompts/` - Deep analysis templates

---

**Document Version**: 1.1
**Created**: 2025-10-12
**Purpose**: Guide users in systematically directing AI agents through complex SNMP vulnerability analysis
**Status**: Production-ready
**Original**: Adapted from `PHASED_PROMPTS_FOR_USER.md`
