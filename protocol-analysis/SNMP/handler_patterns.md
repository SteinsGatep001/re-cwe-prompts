# SNMP Handler Registration Patterns

**Purpose:** Identify how SNMP implementations register and dispatch PDU handlers.

---

## 🎯 Common Handler Patterns

### Pattern 1: Static Handler Table (Most Common)

**Structure:**
```c
struct snmp_handler {
    uint8_t pdu_type;          // 0xA0=GET, 0xA1=GETNEXT, 0xA3=SET, etc.
    int (*handler_func)(snmp_request*, snmp_response*);
    const char *name;
};

static struct snmp_handler handlers[] = {
    {0xA0, handle_get_request, "GET"},
    {0xA1, handle_getnext_request, "GETNEXT"},
    {0xA3, handle_set_request, "SET"},
    {0xA4, handle_trap, "TRAP"},
    {0, NULL, NULL}  // Terminator
};
```

**How to Find in Ghidra:**
```python
# 1. Search for PDU type constants
strings_pdu = list_strings(filter="GET", limit=50)
strings_pdu += list_strings(filter="SET", limit=50)

# 2. Look for arrays of structures with function pointers
structs = list_data_types(category="struct", limit=100)
for struct in structs:
    layout = mcp_ghidra_get_struct_layout(struct['name'])
    # Check if struct has: int field + function pointer + string
    
# 3. Find data arrays that match handler table pattern
data_items = list_data_items(limit=500)
for data in data_items:
    if 'handler' in data['name'].lower():
        # Check xrefs to see dispatcher usage
        xrefs = get_xrefs_to(data['address'])
```

---

### Pattern 2: Switch-Based Dispatch

**Structure:**
```c
int dispatch_pdu(snmp_pdu *pdu) {
    switch (pdu->type) {
        case 0xA0:  // GET
            return handle_get_request(pdu);
        case 0xA1:  // GETNEXT
            return handle_getnext_request(pdu);
        case 0xA3:  // SET
            return handle_set_request(pdu);
        case 0xA4:  // TRAP
            return handle_trap(pdu);
        default:
            return ERROR_INVALID_PDU;
    }
}
```

**How to Find in Ghidra:**
```python
# 1. Find dispatcher functions
dispatchers = search_functions_by_name("dispatch", limit=50)
dispatchers += search_functions_by_name("process_pdu", limit=50)

# 2. Decompile and look for switch on pdu->type
for func in dispatchers:
    code = decompile_function(func['name'])
    if 'switch' in code and ('0xa0' in code.lower() or '0xa1' in code.lower()):
        print(f"PDU dispatcher found: {func['name']}")
        
        # Get callees to find handlers
        handlers = get_function_callees(func['name'])
```

---

### Pattern 3: Runtime Registration (Net-SNMP Style)

**Structure:**
```c
// Handler function signature
typedef int (*snmp_handler_fn)(snmp_request*, snmp_response*);

// Registration function
int netsnmp_register_handler(uint8_t pdu_type, snmp_handler_fn handler, const char *name) {
    handler_registry[pdu_type] = handler;
}

// Initialization
void init_snmp_handlers() {
    netsnmp_register_handler(0xA0, handle_get, "GET");
    netsnmp_register_handler(0xA1, handle_getnext, "GETNEXT");
    netsnmp_register_handler(0xA3, handle_set, "SET");
}
```

**How to Find in Ghidra:**
```python
# 1. Search for registration functions
register_funcs = search_functions_by_name("register", limit=100)
register_funcs += search_functions_by_name("init_handler", limit=50)

# 2. For each registration function, find callers (initialization code)
for func in register_funcs:
    callers = get_function_callers(func['name'])
    for caller in callers:
        if 'init' in caller['name'].lower():
            print(f"Handler initialization: {caller['name']}")
            code = decompile_function(caller['name'])
            # Look for multiple register calls
```

---

## 🔍 Ghidra MCP Analysis Workflow

### Step 1: Find SNMP Entry Points

```python
# Search for SNMP-related strings
snmp_strings = list_strings(filter="snmp", limit=100)
community_strings = list_strings(filter="community", limit=50)

# Find functions that reference these strings
for string_item in community_strings:
    xrefs = get_xrefs_to(string_item['address'])
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        print(f"SNMP function: {func['name']} at {func['address']}")
```

### Step 2: Identify PDU Processing Function

```python
# Look for functions that:
# - Take a buffer as input
# - Parse PDU type (switch/if-else on 0xA0-0xA6)
# - Call different handlers based on type

candidates = search_functions_by_name("process", limit=100)
candidates += search_functions_by_name("parse", limit=100)
candidates += search_functions_by_name("handle", limit=100)

for func in candidates:
    code = decompile_function(func['name'])
    
    # Check for PDU type constants
    if any(const in code.lower() for const in ['0xa0', '0xa1', '0xa2', '0xa3']):
        print(f"PDU processor found: {func['name']}")
        
        # Rename for clarity
        rename_function(func['name'], f"dispatcher_snmp_pdu_{func['name']}")
```

### Step 3: Map Handlers

```python
# For each dispatcher, get all callees
dispatcher = "dispatcher_snmp_pdu_process"
handlers = get_function_callees(dispatcher, limit=50)

for handler in handlers:
    print(f"Handler: {handler['name']} at {handler['address']}")
    
    # Analyze handler purpose from code
    code = decompile_function(handler['name'])
    
    # Classify by operation
    if 'get' in code.lower():
        purpose = "GET handler"
    elif 'set' in code.lower():
        purpose = "SET handler"
    elif 'trap' in code.lower():
        purpose = "TRAP handler"
    else:
        purpose = "unknown handler"
    
    # Rename
    rename_function_by_address(handler['address'], f"handler_snmp_{purpose}")
```

### Step 4: Build Call Graph

```python
# Visualize request flow from entry to sinks
dispatcher = "dispatcher_snmp_pdu_process"
call_graph = get_function_call_graph(dispatcher, depth=4, direction="callees")

print("SNMP Request Flow:")
for edge in call_graph:
    print(f"  {edge}")
```

---

## 📊 Expected Handler Structure

Typical SNMP implementation has:

```
snmp_recv() / snmp_process_packet()
    ↓
parse_snmp_header()
    ↓
validate_community_string()
    ↓
dispatch_pdu() [DISPATCHER]
    ↓
    ├→ handle_get_request()     [HANDLER]
    │    ↓
    │    ├→ validate_oid()      [SANITIZER]
    │    ├→ mib_lookup()        [UTILITY]
    │    └→ build_response()    [UTILITY]
    │
    ├→ handle_set_request()     [HANDLER - DANGEROUS]
    │    ↓
    │    ├→ validate_oid()      [SANITIZER]
    │    ├→ validate_value()    [SANITIZER]
    │    ├→ mib_update()        [SINK]
    │    └→ trigger_action()    [SINK - may exec commands]
    │
    └→ handle_trap()            [HANDLER]
         ↓
         └→ log_trap()          [SINK]
```

---

## 🎯 Handler Identification Checklist

- [ ] Found SNMP packet entry point (recv/process)
- [ ] Identified community string validation
- [ ] Located PDU type dispatcher (switch or table lookup)
- [ ] Mapped all handler functions (GET, SET, GETNEXT, etc.)
- [ ] Traced each handler to sinks (file/network/exec operations)
- [ ] Built complete call graph
- [ ] Renamed all functions with role prefixes
- [ ] Documented handler registration mechanism

---

**Created:** 2025-10-12
**Next:** See `vulnerability_patterns.md` for common SNMP vulnerabilities
