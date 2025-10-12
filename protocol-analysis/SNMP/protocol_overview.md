# SNMP Protocol Overview

**Purpose:** Essential SNMP protocol knowledge for vulnerability analysis.

---

## 📋 SNMP Basics

### Protocol Purpose
**SNMP (Simple Network Management Protocol)** is used for network device management and monitoring.

- **Port:** UDP 161 (agent), UDP 162 (trap receiver)
- **Versions:** SNMPv1, SNMPv2c, SNMPv3
- **Model:** Manager-Agent architecture

---

## 📦 PDU Types

| PDU Type | Value | Direction | Purpose |
|----------|-------|-----------|---------|
| GET | 0xA0 | Manager→Agent | Retrieve single object value |
| GETNEXT | 0xA1 | Manager→Agent | Retrieve next object (MIB traversal) |
| RESPONSE | 0xA2 | Agent→Manager | Reply to GET/SET/GETNEXT |
| SET | 0xA3 | Manager→Agent | Modify object value (DANGEROUS!) |
| TRAP | 0xA4 | Agent→Manager | Asynchronous notification |
| GETBULK | 0xA5 | Manager→Agent | Bulk retrieval (v2c/v3 only) |
| INFORM | 0xA6 | Agent→Manager | Acknowledged TRAP (v2c/v3 only) |

**Security Focus:** SET requests are highest risk - can modify configuration.

---

## 🔐 Authentication

### SNMPv1/v2c (Community String)
```
Packet Format:
[Version][Community String][PDU]

Example:
Version: 1 (0x01)
Community: "public" (read-only) or "private" (read-write)
PDU: GET request for OID
```

**Security:** Plain-text authentication, easily intercepted.

### SNMPv3 (User-based Security Model)
- **Authentication:** MD5 or SHA
- **Encryption:** DES or AES
- **More secure:** But more complex, often misconfigured

---

## 🌳 OID Structure

**Object Identifier (OID):** Hierarchical tree structure identifying managed objects.

```
Format: dot-separated integers
Example: 1.3.6.1.2.1.1.1.0

Breakdown:
1         - ISO
1.3       - org
1.3.6     - dod
1.3.6.1   - internet
1.3.6.1.2 - mgmt
1.3.6.1.2.1 - mib-2
1.3.6.1.2.1.1 - system
1.3.6.1.2.1.1.1 - sysDescr
1.3.6.1.2.1.1.1.0 - sysDescr instance
```

**Common OID Prefixes:**
- `1.3.6.1.2.1.*` - Standard MIB-II objects
- `1.3.6.1.4.1.*` - Enterprise-specific (vendor MIBs)
- `1.3.6.1.4.1.9.*` - Cisco enterprise OIDs

---

## 📄 MIB (Management Information Base)

**MIB:** Database schema defining available objects and their OIDs.

### MIB Structure
```
Module ::= {
    Object1 (OID: 1.3.6.1.2.1.1.1) {
        Syntax: DisplayString
        Access: read-only
        Description: "System description"
    }
    Object2 (OID: 1.3.6.1.2.1.1.2) {
        Syntax: ObjectID
        Access: read-only
        Description: "System object ID"
    }
}
```

### MIB Files
- **Format:** ASN.1 syntax
- **Location:** Often in `/usr/share/snmp/mibs/` (Net-SNMP)
- **Security Risk:** If MIB OIDs map to file paths → path traversal

---

## 📦 Packet Structure (SNMPv1/v2c)

### Complete Packet
```
SNMP Message ::= SEQUENCE {
    version      INTEGER (0=v1, 1=v2c, 3=v3)
    community    OCTET STRING
    pdu          PDU
}
```

### PDU Structure
```
PDU ::= SEQUENCE {
    request-id      INTEGER
    error-status    INTEGER (0=noError, 1=tooBig, 2=noSuchName, ...)
    error-index     INTEGER
    variable-bindings  SEQUENCE OF {
        name  OBJECT IDENTIFIER (OID)
        value ANY (value for this OID)
    }
}
```

**Example GET Request:**
```
Version: 0 (SNMPv1)
Community: "public" (0x70 0x75 0x62 0x6C 0x69 0x63)
PDU Type: 0xA0 (GET)
Request ID: 12345
Error Status: 0
Error Index: 0
Variable Bindings: [
    {OID: 1.3.6.1.2.1.1.1.0, Value: NULL}
]
```

---

## 🔧 BER Encoding (Basic Encoding Rules)

SNMP uses BER/DER for encoding ASN.1 structures.

### BER TLV Structure
```
Tag | Length | Value

Tag: Type identifier (1 byte)
  - 0x02: INTEGER
  - 0x04: OCTET STRING
  - 0x06: OBJECT IDENTIFIER
  - 0x30: SEQUENCE
  - 0xA0-0xA6: PDU types

Length: Value length (1-N bytes)
  - 0x00-0x7F: Direct length
  - 0x81 <len>: Length in next 1 byte
  - 0x82 <len1> <len2>: Length in next 2 bytes
  - ...

Value: Actual data
```

**Security Focus:** Length field is attacker-controlled → integer overflow risk.

**Example:**
```
Encode "public" (community string):
Tag:    0x04 (OCTET STRING)
Length: 0x06 (6 bytes)
Value:  0x70 0x75 0x62 0x6C 0x69 0x63 ("public")

Result: 0x04 0x06 0x70 0x75 0x62 0x6C 0x69 0x63
```

---

## 🎯 High-Risk Operations

### 1. Community String Handling
```c
// RISKY: Fixed buffer + strcpy
char community[32];
strcpy(community, packet->community);  // Buffer overflow if > 32 bytes
```

### 2. OID Parsing
```c
// RISKY: No length validation
int parse_oid(char *oid_str) {
    while (*oid_str) {
        // Parse each digit
        // Integer overflow if OID component > INT_MAX
    }
}
```

### 3. BER Decoding
```c
// RISKY: Attacker-controlled length
uint32_t length = read_length(packet);
char *buffer = malloc(length);  // Integer overflow if length = 0xFFFFFFFF
memcpy(buffer, packet->data, length);  // Massive overflow
```

### 4. MIB File Access (Path Traversal)
```c
// RISKY: OID → file path without validation
char path[256];
sprintf(path, "/var/lib/snmp/mibs/%s.mib", oid_to_filename(oid));
FILE *f = fopen(path, "r");  // Path traversal if oid = "../../../../etc/passwd"
```

### 5. SET Request Processing
```c
// RISKY: SET may trigger system commands
if (pdu_type == SNMP_SET) {
    char cmd[512];
    sprintf(cmd, "sysctl %s=%s", oid, value);  // Command injection
    system(cmd);
}
```

---

## 🔍 SNMP Analysis Keywords

**When searching for SNMP code in Ghidra:**

### String Searches
```python
list_strings(filter="community", limit=50)
list_strings(filter="snmp", limit=100)
list_strings(filter="oid", limit=50)
list_strings(filter="mib", limit=50)
list_strings(filter="public", limit=20)
list_strings(filter="private", limit=20)
```

### Function Searches
```python
search_functions_by_name("snmp", limit=100)
search_functions_by_name("parse_pdu", limit=20)
search_functions_by_name("process_request", limit=50)
search_functions_by_name("decode", limit=50)
search_functions_by_name("handler", limit=100)
```

---

## 📚 Quick Reference

### SNMP Versions
- **v1:** Simple, insecure, plain-text community strings
- **v2c:** Enhanced ops (GETBULK), still plain-text auth
- **v3:** Secure (encrypted), but complex

### Common Ports
- **161/UDP:** Agent (receives requests)
- **162/UDP:** Manager (receives traps)

### Request Flow
```
Manager                    Agent
   |                         |
   |------- GET --------->   |
   |  (community="public")   |
   |                         | [Authenticate]
   |                         | [Parse OID]
   |                         | [Lookup value]
   |<----- RESPONSE ------   |
   |  (value=result)         |
```

### Security Checklist
- [ ] Community string stored securely?
- [ ] Community string bounds-checked?
- [ ] OID parsing validates length?
- [ ] BER length field checked for overflow?
- [ ] MIB file access validates paths?
- [ ] SET requests properly authorized?
- [ ] SET values sanitized before use?

---

**Created:** 2025-10-12
**Status:** Complete
**Version:** 1.0
**Next:** See `handler_patterns.md` for finding SNMP handlers
