# SNMP Analysis Checklist

**Purpose:** Step-by-step checklist for systematic SNMP vulnerability analysis.

---

## 📋 Pre-Analysis Setup

- [ ] **Load binary in Ghidra GUI mode**
  ```bash
  ./ghidrasage-gui work/cases/<vendor>/<case_slug>
  ```

- [ ] **Verify MCP connection**
  ```python
  check_connection()
  metadata = get_metadata()
  print(f"Analyzing: {metadata['program_name']}")
  ```

- [ ] **Review case context**
  - Read: `work/cases/<vendor>/<case>/context/case_context.json`
  - Read: `work/cases/<vendor>/<case>/summaries/stage_a_summary.json`
  - Read: `work/cases/<vendor>/<case>/summaries/stage_c_summary.json`

- [ ] **Read CVE details** (if applicable)
  - CVE ID, CVSS score, affected versions
  - Proof-of-concept (PoC) if available

---

## Phase 1: Context Preparation (15 min)

### 1.1 Understand Target
- [ ] Binary architecture: `get_metadata()`
- [ ] Entry points: `get_entry_points()`
- [ ] Memory layout: `list_segments()`
- [ ] Imported functions: `list_imports(limit=200)`
- [ ] Exported functions: `list_exports(limit=100)`

### 1.2 Collect SNMP Artifacts
- [ ] SNMP strings: `list_strings(filter="snmp", limit=100)`
- [ ] Community strings: `list_strings(filter="community", limit=50)`
- [ ] OID strings: `list_strings(filter="oid", limit=50)`
- [ ] MIB strings: `list_strings(filter="mib", limit=50)`
- [ ] PDU type strings: `list_strings(filter="GET", limit=20)`

---

## Phase 2: Entry Point Discovery (30 min)

### 2.1 Find SNMP Entry Functions
- [ ] Search for SNMP functions: `search_functions_by_name("snmp", limit=100)`
- [ ] Search for receive functions: `search_functions_by_name("recv", limit=20)`
- [ ] Search for process functions: `search_functions_by_name("process", limit=100)`

### 2.2 Identify Request Handler
- [ ] Find function that parses SNMP packets
- [ ] Locate community string validation
- [ ] Find PDU type dispatcher (switch or table)
- [ ] Map PDU types to handler functions

### 2.3 Build Initial Call Graph
- [ ] From entry point: `get_function_call_graph(entry_func, depth=3, direction="callees")`
- [ ] Visualize request flow: Dispatcher → Handlers → Sinks
- [ ] Document in: `work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/entrypoints.md`

---

## Phase 3: Deep Analysis (2-3 hours)

### 3.1 Analyze Handler Registration (30 min)

Reference: `handler_patterns.md`

- [ ] **If table-driven:**
  - Find handler table structure
  - Map PDU type → handler function
  - Check for NULL entries or bounds

- [ ] **If switch-based:**
  - Find dispatcher function
  - Extract case statements
  - Map PDU values → handler functions

- [ ] **If runtime registration:**
  - Find registration function
  - Trace initialization code
  - Map all register calls

- [ ] **Document findings:**
  - File: `work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/handlers.md`
  - Include: Handler table structure, PDU→function mappings, call graph

### 3.2 Trace GET Handler (30 min)

- [ ] Decompile GET handler: `decompile_function(handler_name)`
- [ ] Trace data flow:
  - Input: community string, OID
  - Processing: validation, MIB lookup
  - Output: response construction
- [ ] Identify sanitizers and sinks
- [ ] Check for vulnerabilities (see Phase 3.5)

### 3.3 Trace SET Handler (45 min) **HIGH PRIORITY**

- [ ] Decompile SET handler
- [ ] Trace data flow:
  - Input: community string, OID, value
  - Processing: validation, authorization
  - Sink: file write, config update, command exec
- [ ] **Security focus:** SET is most dangerous
- [ ] Check authorization: Is "private" required?
- [ ] Check sanitization: Are oid/value validated?
- [ ] Check sinks: Any system()/fopen() calls?

### 3.4 Trace Other Handlers (30 min)

- [ ] GETNEXT handler
- [ ] TRAP handler
- [ ] GETBULK handler (v2c/v3)
- [ ] INFORM handler (v2c/v3)

### 3.5 Vulnerability Identification (45 min)

Reference: `vulnerability_patterns.md`

For each handler, check:

**Buffer Overflow (CWE-120)**
- [ ] Community string handling (strcpy/sprintf)
- [ ] OID string handling
- [ ] Value string handling (SET requests)
- [ ] BER decoding buffers

**Path Traversal (CWE-22)**
- [ ] MIB file access
- [ ] OID → file path mapping
- [ ] Missing realpath()/canonicalization
- [ ] Missing prefix validation

**Integer Overflow (CWE-190)**
- [ ] BER length field parsing
- [ ] OID component parsing
- [ ] Array index calculations
- [ ] malloc() size calculations

**Command Injection (CWE-78)**
- [ ] system()/popen() with user data
- [ ] SET handler execution paths
- [ ] Configuration update mechanisms

**Authentication Bypass (CWE-287)**
- [ ] Community string validation logic
- [ ] "public" vs "private" enforcement
- [ ] SET request authorization

### 3.6 Data Flow Analysis (30 min)

- [ ] Trace from entry to each vulnerability
- [ ] Build attack chain: Input → Processing → Sink
- [ ] Identify missing sanitizers
- [ ] Document in: `work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/data_flow.md`

---

## Phase 4: Code Enhancement (1 hour)

Reference: `renaming_standards.md` + `annotation_guidelines.md`

### 4.1 Rename Functions (30 min)

- [ ] Classify functions by role (dispatcher/handler/sanitizer/sink/utility)
- [ ] Rename with role prefixes:
  - `dispatcher_snmp_pdu_router`
  - `handler_snmp_get_request`
  - `sanitizer_validate_community`
  - `sink_mib_file_access`
- [ ] Preserve FUN_ addresses: `handler_FUN_00401234_snmp_get`
- [ ] Set function prototypes where possible

### 4.2 Rename Variables (15 min)

- [ ] Replace auto-generated names (iVar1, pcVar2, uVar3)
- [ ] Use type suffixes (_ptr, _fd, _size, _len, _buffer)
- [ ] Examples:
  - `iVar1` → `pdu_type`
  - `pcVar2` → `community_str`
  - `local_100` → `oid_buffer`

### 4.3 Add Comments (15 min)

- [ ] Function headers (purpose, parameters, returns)
- [ ] Security annotations at vulnerabilities
- [ ] Inline comments for complex logic
- [ ] Data structure documentation

**Example vulnerability comment:**
```c
// ============================================================================
// VULNERABILITY: CWE-22 Path Traversal
// ============================================================================
//
// RISK: User-controlled OID mapped to file path without validation
// ATTACK: Send OID="../../../../etc/passwd" to read arbitrary files
//
// FIX REQUIRED:
// 1. Canonicalize path with realpath()
// 2. Validate path starts with /var/lib/snmp/mibs/
// 3. Reject paths containing ".."
//
// CVE: CVE-2025-20362
// ============================================================================
```

---

## Phase 5: Report Generation (30 min)

### 5.1 Generate Analysis Reports

- [ ] **Full Analysis Report:** `work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`
  - Executive summary
  - Entry points discovered
  - Handler mappings
  - Data flow diagrams
  - Vulnerabilities found
  - Call graphs

- [ ] **Vulnerability Details:** `work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`
  - Each vulnerability with CWE
  - Attack scenarios
  - Proof-of-concept code
  - Exploitability assessment

- [ ] **Fix Recommendations:** `work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`
  - Code patches
  - Configuration changes
  - Security best practices

### 5.2 Save Evidence

- [ ] Export call graphs: `get_full_call_graph(format="mermaid")`
- [ ] Save decompiled code of key functions
- [ ] Screenshot vulnerable code in Ghidra
- [ ] Save to: `work/cases/<vendor>/<case>/analysis/stage_d/evidence/`

### 5.3 Update Stage Summary

- [ ] Create: `work/cases/<vendor>/<case>/summaries/stage_d_summary.json`
- [ ] Include:
  - Entry points found
  - Handlers mapped
  - Vulnerabilities identified
  - Functions renamed (count)
  - Analysis completion status

---

## Quality Assurance Checklist

### Completeness
- [ ] All SNMP entry points identified
- [ ] All handlers (GET, SET, GETNEXT, TRAP) analyzed
- [ ] Complete call graph from entry to sinks
- [ ] All vulnerabilities documented with CWE
- [ ] All high-risk functions renamed and commented

### Accuracy
- [ ] Function classifications correct (dispatcher/handler/sink)
- [ ] Vulnerability assessments validated
- [ ] Attack scenarios tested (if possible)
- [ ] Fix recommendations technically sound

### Documentation
- [ ] Function header comments on all handlers
- [ ] Security annotations at all vulnerabilities
- [ ] Complex logic explained with inline comments
- [ ] Reports saved in correct locations
- [ ] Evidence chain complete (code + screenshots + graphs)

### Reproducibility
- [ ] Another analyst can follow your analysis
- [ ] All tool commands documented
- [ ] All assumptions documented
- [ ] All findings traceable to evidence

---

## Time Estimates

| Phase | Time | Priority |
|-------|------|----------|
| Phase 1: Context Preparation | 15 min | Required |
| Phase 2: Entry Point Discovery | 30 min | Required |
| Phase 3: Deep Analysis | 2-3 hours | Required |
| Phase 4: Code Enhancement | 1 hour | Recommended |
| Phase 5: Report Generation | 30 min | Required |
| **Total** | **4-5 hours** | - |

---

## Next Steps After Completion

1. **Review with Team:** Present findings to security team
2. **PoC Development:** Create proof-of-concept exploits (Stage E)
3. **Vendor Notification:** Coordinate disclosure if new CVE
4. **Documentation:** Update project documentation
5. **Knowledge Base:** Add findings to vulnerability database

---

**Created:** 2025-10-12
**Status:** Ready for use
**Version:** 1.0
