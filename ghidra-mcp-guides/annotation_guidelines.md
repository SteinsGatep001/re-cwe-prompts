# Ghidra MCP Annotation Guidelines

**Purpose:** Standards for adding comments and documentation to reverse-engineered code.

---

## 📋 Overview

Good annotations transform incomprehensible decompiled code into readable, maintainable documentation. This guide provides standards for commenting functions, security issues, and complex logic.

### Annotation Goals

1. **Explain Intent:** What the code is trying to achieve, not just what it does
2. **Document Security:** Highlight vulnerabilities, risks, and mitigations
3. **Aid Analysis:** Help future analysts understand your findings
4. **Maintain Context:** Preserve analysis history and decisions
5. **Enable Collaboration:** Make your work understandable to others

---

## 💬 Comment Types

### 1. Function Header Comments

**Location:** At function entry point
**Tool:** `set_decompiler_comment()`
**Purpose:** Provide function overview

**Template:**
```c
// ============================================================================
// FUNCTION: <function_name>
// Address: <hex_address>
// Role: <dispatcher|handler|sanitizer|sink|utility>
// ============================================================================
//
// PURPOSE:
//   <Brief description of what this function does>
//
// PARAMETERS:
//   param1 (type): <description>
//   param2 (type): <description>
//
// RETURNS:
//   <return_type>: <description of return value>
//   - Success: <what indicates success>
//   - Failure: <what indicates failure>
//
// CALLERS:
//   - <function1>: <why it calls this>
//   - <function2>: <why it calls this>
//   (Total: <N> callers)
//
// CALLEES:
//   - <function1>: <what it does>
//   - <function2>: <what it does>
//   (Total: <N> callees)
//
// SECURITY NOTES:
//   <Any security-relevant information>
//
// ANALYSIS DATE: <YYYY-MM-DD>
// ANALYST: <Your name or identifier>
// ============================================================================
```

**Example:**
```c
// ============================================================================
// FUNCTION: handler_FUN_00401234_snmp_process_get
// Address: 0x00401234
// Role: handler
// ============================================================================
//
// PURPOSE:
//   Processes SNMP GET requests after authentication. Extracts OID from
//   request, looks up value in MIB table, and constructs response.
//
// PARAMETERS:
//   request_ptr (snmp_request*): Pointer to incoming SNMP request structure
//   response_ptr (snmp_response*): Pointer to response structure to populate
//
// RETURNS:
//   int: Status code
//   - 0: Success, response populated
//   - -1: Invalid OID
//   - -2: Access denied
//
// CALLERS:
//   - dispatcher_FUN_00401000_snmp_pdu_router: Routes GET requests here
//   (Total: 1 caller)
//
// CALLEES:
//   - sanitizer_FUN_00402000_validate_oid: Validates OID format
//   - sink_FUN_00403000_mib_lookup: Looks up OID in MIB table
//   - util_FUN_00404000_build_response: Constructs response PDU
//   (Total: 3 callees)
//
// SECURITY NOTES:
//   - OID validation performed before MIB lookup
//   - No bounds checking on OID string before strcpy (potential overflow)
//   - Community string already verified by caller
//
// ANALYSIS DATE: 2025-10-12
// ANALYST: Claude (GhidraSage Analysis)
// ============================================================================
```

---

### 2. Security Annotations

**Location:** At vulnerability sites
**Tool:** `set_decompiler_comment()` + function renaming
**Purpose:** Document security issues

**Template:**
```c
// ============================================================================
// VULNERABILITY: CWE-<number> <vulnerability_type>
// ============================================================================
//
// RISK:
//   <Description of the security risk>
//
// ATTACK SCENARIO:
//   1. <Step 1 of attack>
//   2. <Step 2 of attack>
//   3. <Result/impact>
//
// AFFECTED CODE:
//   Line/Address: <specific location>
//   Operation: <vulnerable operation>
//
// ROOT CAUSE:
//   <Why the vulnerability exists>
//
// EXPLOITABILITY:
//   Difficulty: <Low|Medium|High>
//   Prerequisites: <What attacker needs>
//   Impact: <Confidentiality|Integrity|Availability>
//
// MITIGATION:
//   Required fixes:
//   1. <Fix 1>
//   2. <Fix 2>
//   3. <Fix 3>
//
//   Example fix:
//   <Code snippet showing proper implementation>
//
// CVE: <CVE-YYYY-NNNNN> (if applicable)
// CVSS: <score> (if applicable)
//
// ANALYSIS DATE: <YYYY-MM-DD>
// ============================================================================
```

**Example - Path Traversal:**
```c
// ============================================================================
// VULNERABILITY: CWE-22 Path Traversal
// ============================================================================
//
// RISK:
//   User-controlled file path passed to fopen() without canonicalization
//   or prefix validation. Attacker can read arbitrary files on the system.
//
// ATTACK SCENARIO:
//   1. Attacker sends request with path: "../../../../etc/passwd"
//   2. Function constructs path: BASE_DIR + user_path
//   3. fopen() opens /etc/passwd instead of intended file
//   4. Contents returned to attacker
//
// AFFECTED CODE:
//   Line/Address: 0x00401250
//   Operation: fopen(user_path, "r")
//
// ROOT CAUSE:
//   Missing path canonicalization and base directory validation.
//   Function assumes user_path is relative but doesn't enforce it.
//
// EXPLOITABILITY:
//   Difficulty: Low (trivial to exploit)
//   Prerequisites: None (any user can exploit)
//   Impact: Confidentiality (read any file)
//
// MITIGATION:
//   Required fixes:
//   1. Canonicalize path using realpath() or GetFullPathName()
//   2. Validate canonicalized path starts with BASE_DIR
//   3. Reject paths containing ".." even after canonicalization
//
//   Example fix:
//   char* canonical = realpath(user_path, NULL);
//   if (!canonical) return ERROR_INVALID_PATH;
//   if (strncmp(canonical, BASE_DIR, strlen(BASE_DIR)) != 0) {
//       free(canonical);
//       return ERROR_ACCESS_DENIED;
//   }
//   file_fd = fopen(canonical, "r");
//   free(canonical);
//
// CVE: CVE-2025-20362
// CVSS: 7.5 (High)
//
// ANALYSIS DATE: 2025-10-12
// ============================================================================
```

**Example - Buffer Overflow:**
```c
// ============================================================================
// VULNERABILITY: CWE-120 Buffer Copy Without Checking Size
// ============================================================================
//
// RISK:
//   strcpy() used without bounds checking. Source string length controlled
//   by attacker. Destination buffer is 256 bytes on stack.
//
// ATTACK SCENARIO:
//   1. Attacker sends request with 300-byte community string
//   2. strcpy() copies entire string to 256-byte buffer
//   3. Stack overflow overwrites return address
//   4. Control flow hijacked to attacker's code
//
// AFFECTED CODE:
//   Line/Address: 0x00401280
//   Operation: strcpy(oid_buffer, request_ptr->oid)
//
// ROOT CAUSE:
//   No validation of source string length before copy.
//   Assumption that OID strings are always < 256 bytes.
//
// EXPLOITABILITY:
//   Difficulty: Medium (requires ROP gadgets or executable stack)
//   Prerequisites: Network access to SNMP port
//   Impact: Integrity + Availability (code execution or crash)
//
// MITIGATION:
//   Required fixes:
//   1. Replace strcpy with strncpy or strlcpy
//   2. Add length check before copy
//   3. Null-terminate destination buffer explicitly
//
//   Example fix:
//   size_t oid_len = strlen(request_ptr->oid);
//   if (oid_len >= sizeof(oid_buffer)) {
//       return ERROR_OID_TOO_LONG;
//   }
//   strncpy(oid_buffer, request_ptr->oid, sizeof(oid_buffer) - 1);
//   oid_buffer[sizeof(oid_buffer) - 1] = '\0';
//
// CVE: (Not yet assigned)
// CVSS: 8.1 (High)
//
// ANALYSIS DATE: 2025-10-12
// ============================================================================
```

---

### 3. Inline Code Comments

**Location:** Next to specific operations
**Tool:** `set_decompiler_comment()` at specific address
**Purpose:** Explain complex or non-obvious logic

**Guidelines:**
- Explain **why**, not **what**
- Document assumptions
- Highlight edge cases
- Note deviations from standards

**Examples:**

```c
// Check if community string matches "public"
// NOTE: Case-sensitive comparison - "Public" will fail
auth_result = strcmp(community_str, "public");

// Allocate response buffer
// ASSUMPTION: Response never exceeds 1024 bytes (not validated!)
response_buffer = malloc(1024);

// Skip over type byte to get to length field
// PROTOCOL: SNMP BER encoding - type(1) + length(N) + value
data_ptr = pdu_buffer + 1;

// WORKAROUND: Original code used strcpy which caused crashes
// Changed to strncpy to prevent overflow until proper fix deployed
strncpy(dest, src, sizeof(dest) - 1);

// SECURITY: Must validate length before allocation to prevent integer overflow
// If length is 0xFFFFFFFF, adding 1 wraps to 0, malloc(0) succeeds,
// then strcpy overflows heap
if (length > MAX_SAFE_SIZE) return ERROR;
```

---

### 4. Data Structure Comments

**Location:** At structure definitions
**Tool:** `set_decompiler_comment()` or struct definition
**Purpose:** Document structure layout and usage

**Template:**
```c
// Structure: <struct_name>
// Size: <N> bytes
// Alignment: <M> bytes
//
// PURPOSE:
//   <What this structure represents>
//
// FIELDS:
//   +0x00: <field1> (<type>) - <description>
//   +0x04: <field2> (<type>) - <description>
//   ...
//
// USAGE:
//   <How this structure is used>
//
// NOTES:
//   <Any important notes about layout, padding, etc.>
```

**Example:**
```c
// Structure: snmp_request
// Size: 276 bytes
// Alignment: 4 bytes
//
// PURPOSE:
//   Represents parsed SNMP request packet after BER decoding
//
// FIELDS:
//   +0x00: version (int32_t) - SNMP version (1, 2c, or 3)
//   +0x04: community (char[32]) - Community string for auth
//   +0x24: pdu_type (uint8_t) - PDU type (GET, SET, TRAP, etc.)
//   +0x25: padding[3] - Alignment padding
//   +0x28: request_id (uint32_t) - Request identifier
//   +0x2C: error_status (uint32_t) - Error status code
//   +0x30: error_index (uint32_t) - Index of error in variable bindings
//   +0x34: oid (char[128]) - Object identifier string
//   +0xB4: value_ptr (void*) - Pointer to variable binding value
//   +0xB8: value_len (size_t) - Length of value data
//
// USAGE:
//   Passed to handler functions after authentication.
//   Handlers read OID and construct response based on value.
//
// SECURITY NOTES:
//   - community field limited to 31 chars + null terminator
//   - oid field limited to 127 chars + null terminator
//   - value_ptr points to separately allocated memory (must be freed)
//
// NOTES:
//   - 3 bytes of padding after pdu_type for 4-byte alignment
//   - Structure layout matches network packet format closely
```

---

### 5. Algorithm Comments

**Location:** Before complex logic
**Tool:** `set_decompiler_comment()`
**Purpose:** Explain algorithms and protocols

**Template:**
```c
// ALGORITHM: <algorithm_name>
//
// DESCRIPTION:
//   <High-level description>
//
// STEPS:
//   1. <Step 1>
//   2. <Step 2>
//   3. <Step 3>
//   ...
//
// COMPLEXITY:
//   Time: O(<complexity>)
//   Space: O(<complexity>)
//
// NOTES:
//   <Implementation details, optimizations, etc.>
```

**Example:**
```c
// ALGORITHM: SNMP OID Lookup (Binary Search)
//
// DESCRIPTION:
//   Searches sorted MIB table for matching OID using binary search.
//   OIDs compared lexicographically as dot-separated integers.
//
// STEPS:
//   1. Parse OID string into integer array (e.g., "1.3.6.1.2" -> [1,3,6,1,2])
//   2. Binary search MIB table comparing OID prefixes
//   3. If exact match found, return associated value
//   4. If no match, return "no such object" error
//
// COMPLEXITY:
//   Time: O(log N) where N is number of MIB entries
//   Space: O(1) - search performed in-place
//
// NOTES:
//   - MIB table must be kept sorted for binary search to work
//   - Table sorted at initialization, not on each lookup
//   - Comparison function handles variable-length OIDs correctly
```

---

## 🎯 Comment Standards by Location

### Decompiler View Comments

**Tool:** `set_decompiler_comment(address, comment)`

**Best Practices:**
- Use `//` style comments (C++ single-line)
- Start with uppercase, use proper grammar
- Separate sections with blank comment lines
- Use `====` lines for major sections

**Example:**
```python
set_decompiler_comment(
    "0x401234",
    """// ============================================================================
// FUNCTION: handler_snmp_process_get
// ============================================================================
//
// PURPOSE:
//   Processes SNMP GET requests after authentication.
//
// SECURITY NOTES:
//   - OID validation performed before MIB lookup
//   - No bounds checking on OID string (VULNERABILITY!)
//
// ANALYSIS DATE: 2025-10-12
// ============================================================================
""")
```

### Disassembly View Comments

**Tool:** `set_disassembly_comment(address, comment)`

**Best Practices:**
- Use `;` style comments (assembly convention)
- Keep comments short and focused
- Comment per-instruction or per-block
- Highlight unusual instructions

**Example:**
```python
set_disassembly_comment("0x401234", "; Check community string")
set_disassembly_comment("0x401238", "; Jump if not equal (auth failed)")
set_disassembly_comment("0x40123C", "; SECURITY: Missing bounds check here!")
```

---

## 📊 Comment Density Guidelines

### Function-Level

- **Every function:** Header comment (mandatory)
- **Complex functions:** Inline comments every 5-10 lines
- **Simple functions:** Minimal inline comments

### Security-Critical Code

- **All vulnerabilities:** Detailed security annotation (mandatory)
- **All sanitizers:** Comment explaining validation logic
- **All sinks:** Comment noting input validation requirements

### Data Structures

- **All custom structs:** Structure comment
- **Complex layouts:** Field-by-field comments
- **Padding bytes:** Note alignment requirements

---

## ✅ Annotation Checklist

### Per Function
- [ ] Function header comment added
- [ ] Role documented (dispatcher/handler/sanitizer/sink/utility)
- [ ] Purpose clearly explained
- [ ] Parameters documented
- [ ] Return values documented
- [ ] Security notes added (if applicable)
- [ ] Complex logic explained with inline comments
- [ ] Assumptions documented
- [ ] Analysis date and analyst noted

### Per Vulnerability
- [ ] Vulnerability type (CWE) identified
- [ ] Risk clearly explained
- [ ] Attack scenario documented
- [ ] Root cause analyzed
- [ ] Exploitability assessed
- [ ] Mitigation steps provided
- [ ] Example fix shown
- [ ] CVE/CVSS noted (if applicable)

### Per Data Structure
- [ ] Structure purpose documented
- [ ] Size and alignment noted
- [ ] All fields documented
- [ ] Usage patterns explained
- [ ] Security implications noted

---

## ⚠️ Common Pitfalls

### DON'T

❌ **Don't state the obvious:**
```c
// Bad:
i = i + 1;  // Increment i

// Better (if comment needed):
loop_idx++;  // Move to next handler in table
```

❌ **Don't use vague comments:**
```c
// Bad:
// Process the data
process_data(buffer);

// Better:
// Validate OID format before MIB lookup to prevent crashes
validate_oid_format(oid_buffer);
```

❌ **Don't comment what you don't understand:**
```c
// Bad:
// TODO: Not sure what this does
mystery_function(param1, param2);

// Better (analyze first, then comment):
// Canonicalizes file path and checks against base directory
// Returns NULL if path escapes base directory
canonical_path = sanitize_path(user_path, base_dir);
```

❌ **Don't forget to update comments:**
```c
// Bad (comment doesn't match code):
// Check if length is less than 256
if (length >= 512) return ERROR;

// Better:
// Check if length exceeds buffer capacity (512 bytes)
if (length >= sizeof(buffer)) return ERROR;
```

### DO

✅ **Do explain intent:**
```c
// Good:
// Community string must match "public" for read access
// Note: Case-sensitive comparison
if (strcmp(community_str, "public") == 0) {
    // Grant read access
}
```

✅ **Do document assumptions:**
```c
// Good:
// ASSUMPTION: OID strings never exceed 128 characters
// This is NOT validated by the protocol - potential overflow!
strcpy(oid_buffer, request->oid);
```

✅ **Do highlight security issues:**
```c
// Good:
// SECURITY WARNING: strcpy used without bounds check
// If request->oid > 128 chars, buffer overflow occurs
// FIX: Replace with strncpy and validate length
strcpy(oid_buffer, request->oid);
```

✅ **Do provide context:**
```c
// Good:
// SNMP v1 uses plain-text community strings for authentication
// "public" allows read access, "private" allows read/write
// This is NOT secure - recommend upgrading to SNMPv3
if (validate_community(request->community) == 0) {
    // Authentication succeeded
}
```

---

## 🔄 Integration with Workflows

Annotation should happen throughout analysis:

1. **Discovery Phase:**
   - Add function header comments with basic info
   - Note unknowns with "TODO" or "ANALYZE"

2. **Classification Phase:**
   - Update header comments with role
   - Add caller/callee information

3. **Deep Analysis Phase:**
   - Add detailed inline comments
   - Document complex logic and algorithms
   - Add data structure comments

4. **Vulnerability Analysis Phase:**
   - Add comprehensive security annotations
   - Document all vulnerabilities with CWE/CVE
   - Provide fix recommendations

5. **Enhancement Phase:**
   - Update comments after renaming
   - Ensure consistency between names and comments
   - Add final analysis summary

Reference: See `common_workflows.md` → Workflow 11 (Comprehensive Code Documentation)

---

## 📚 Comment Templates Quick Reference

### Quick Function Header
```c
// FUNCTION: <name>
// PURPOSE: <brief description>
// SECURITY: <any security notes>
```

### Quick Security Note
```c
// SECURITY: CWE-<num> <type>
// Risk: <brief risk description>
// Fix: <brief fix description>
```

### Quick Inline Note
```c
// NOTE: <important observation>
// TODO: <something to investigate later>
// ASSUMPTION: <assumption made during analysis>
// WORKAROUND: <temporary fix explanation>
```

---

## 🎓 Comment Quality Metrics

### Good Comments
- Explain **why**, not just **what**
- Provide context not obvious from code
- Highlight security implications
- Document assumptions and edge cases
- Help future analysts avoid pitfalls

### Bad Comments
- Restate what code does
- Out of date or incorrect
- Vague or ambiguous
- Too verbose (overwhelming)
- Missing critical security info

---

**Last Updated:** 2025-10-12
**Status:** Complete
**Version:** 1.0
