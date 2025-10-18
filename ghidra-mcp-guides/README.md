# Ghidra MCP Guides

**Purpose:** Universal, reusable guidance for using Ghidra MCP tools in reverse engineering workflows.

---

## 📚 Guide Overview

This directory contains comprehensive guides for leveraging Ghidra MCP (Model Context Protocol) tools in systematic reverse engineering analysis. These guides are protocol-agnostic and case-independent, designed for maximum reusability.

### Files in This Directory

| File | Purpose | Audience |
|------|---------|----------|
| [tool_categories.md](tool_categories.md) | Complete catalog of 57 MCP tools organized by purpose | All users |
| [common_workflows.md](common_workflows.md) | Standard analysis workflows using MCP tools | Reverse engineers |
| [renaming_standards.md](renaming_standards.md) | Systematic naming conventions for functions/variables | Analysts |
| [annotation_guidelines.md](annotation_guidelines.md) | Code commenting and documentation standards | Security researchers |

---

## 🎯 Quick Start

### For First-Time Users
1. **Start with:** [tool_categories.md](tool_categories.md) - Understand what tools are available
2. **Then read:** [common_workflows.md](common_workflows.md) - Learn standard patterns
3. **Reference:** [renaming_standards.md](renaming_standards.md) + [annotation_guidelines.md](annotation_guidelines.md) - Improve code quality

### For Experienced Users
- **Workflow reference:** [common_workflows.md](common_workflows.md)
- **Standards reference:** [renaming_standards.md](renaming_standards.md)
- **Documentation reference:** [annotation_guidelines.md](annotation_guidelines.md)

---

## 🔧 What are Ghidra MCP Tools?

**Ghidra MCP** is a production-ready bridge that exposes Ghidra's reverse engineering capabilities through the Model Context Protocol, enabling:

- **57 MCP Tools** across 7 categories
- **100% Success Rate** - Production-tested reliability
- **Dual Mode Support** - Works with both PyGhidra Headless and Ghidra GUI
- **Real-time Analysis** - Live integration with Ghidra's analysis engine

### Tool Categories
1. **Core System Tools** (6 tools) - Connection, metadata, utilities
2. **Function Analysis** (19 tools) - Discovery, decompilation, relationships, modification
3. **Data Structure Tools** (16 tools) - Types, structures, unions, enums
4. **Data Analysis** (5 tools) - Strings, data items, cross-references
5. **Symbol Management** (7 tools) - Labels, globals, imports/exports
6. **Documentation Tools** (2 tools) - Comments in decompiler and disassembly
7. **Advanced Features** (2 tools) - Call graph analysis and visualization

---

## 📖 How to Use These Guides

### In Stage D Analysis
These guides are designed to be referenced during Stage D (Entrypoint Map) analysis workflows:

```
Phase 2: Entrypoint Discovery
└─ Reference: tool_categories.md (String Search, Function Analysis)

Phase 3: Deep Analysis
├─ Reference: common_workflows.md (Trace Dispatcher to Sink)
└─ Reference: tool_categories.md (Call Graph, Cross-references)

Phase 4: Code Enhancement
├─ Reference: renaming_standards.md (Systematic renaming)
└─ Reference: annotation_guidelines.md (Add comments)
```

### In Protocol-Specific Analysis
Combine these universal guides with protocol-specific templates:

```
Universal MCP Guidance (this directory)
    +
Protocol-Specific Patterns (e.g., SNMP, HTTP, SSH)
    +
Case-Specific Context (CVE details, firmware features)
    =
Complete Analysis Workflow
```

---

## 🔗 Related Documentation

### Within AnalystSage Project
- **Comprehensive Reference:** `tool-notes/Ghidra_MCP_Comprehensive.md` (569 lines)
- **Stage D Architecture:** `docs/stage_d/core/02-architecture.md`
- **Interactive RE Workflow:** `docs/stage_d/guides/10-interactive-reverse-engineering.md`

### External Resources
- **Ghidra MCP Project:** `work/ref/ghidra-mcp/README.md`
- **API Reference:** `work/ref/ghidra-mcp/docs/API_REFERENCE.md`
- **Development Guide:** `work/ref/ghidra-mcp/docs/DEVELOPMENT_GUIDE.md`

---

## ⚡ Key Concepts

### 1. MCP Endpoint
All tools are accessed through a unified endpoint:
- **Headless Mode:** `http://127.0.0.1:8765/mcp` (containerized PyGhidra)
- **GUI Mode:** `http://127.0.0.1:8765/mcp` (local Ghidra GUI with plugin)

Only one mode can run at a time on port 8765.

### 2. Tool Call Pattern
```python
# Generic pattern
result = mcp_client.call_tool(
    tool_name="<tool_name>",
    **parameters
)
```

### 3. Pagination
Most listing tools support pagination:
```python
# List functions in batches
batch_1 = list_functions(offset=0, limit=100)
batch_2 = list_functions(offset=100, limit=100)
```

### 4. Search vs List
- **List tools:** Enumerate all items (e.g., `list_functions`, `list_strings`)
- **Search tools:** Filter by pattern (e.g., `search_functions_by_name`, `list_strings(filter=...)`)

---

## 🎓 Learning Path

### Beginner → Intermediate
1. Read [tool_categories.md](tool_categories.md) - Understand what's available
2. Try basic workflows in [common_workflows.md](common_workflows.md):
   - Workflow 1: String Search → Xref → Decompile
   - Workflow 2: Function Renaming
3. Practice on a simple binary (e.g., hello world, simple HTTP server)

### Intermediate → Advanced
1. Study advanced workflows in [common_workflows.md](common_workflows.md):
   - Workflow 5: Dispatcher → Handler → Sink tracing
   - Workflow 6: Protocol handler registration analysis
2. Apply [renaming_standards.md](renaming_standards.md) systematically
3. Document findings using [annotation_guidelines.md](annotation_guidelines.md)
4. Analyze a real CVE case (e.g., SNMP vulnerability, HTTP path traversal)

---

## 💡 Best Practices

### DO
✅ Use pagination for large result sets (>100 items)
✅ Systematically rename functions/variables using standards
✅ Add security comments at vulnerability locations
✅ Build call graphs to understand control flow
✅ Trace from entry points to sinks

### DON'T
❌ Assume function names are accurate without verification
❌ Ignore cross-references when analyzing data flow
❌ Skip decompilation - assembly alone is not enough
❌ Forget to document your findings with comments
❌ Analyze functions in isolation - always check callers/callees

---

## 🆘 Troubleshooting

### MCP Connection Issues
**Problem:** `check_connection()` fails
**Solution:**
1. Check MCP mode status: `python3 analystsage_cli.py mcp-status`
2. Ensure correct mode is running (GUI or Headless)
3. Verify endpoint: `http://127.0.0.1:8765/mcp`

### Tool Call Failures
**Problem:** Tool returns error or empty result
**Solution:**
1. Verify program is loaded: `get_metadata()`
2. Check if analysis is complete: `run_auto_analysis()`
3. Confirm address/name exists before querying

### Performance Issues
**Problem:** Slow response times
**Solution:**
1. Use pagination (limit ≤ 100)
2. Filter searches (don't list all strings without filter)
3. Cache frequently accessed results
4. Use specific address lookups instead of full scans

---

## 🔄 Updates and Maintenance

**Current Version:** 1.0 (2025-10-12)
**MCP Version:** 1.5.0
**Tool Count:** 57 tools
**Status:** Production Ready

**Changelog:**
- 2025-10-12: Initial creation based on Ghidra MCP v1.2.0
- Synthesized from `work/ref/ghidra-mcp/` and `tool-notes/Ghidra_MCP_Comprehensive.md`

---

## 📬 Feedback

These guides are living documents. If you find:
- Missing workflows or use cases
- Unclear instructions
- Better practices or patterns

Please update this documentation or create an issue in the project repository.

---

**Created:** 2025-10-12
**Purpose:** Universal Ghidra MCP guidance for AnalystSage workflows
**Audience:** Reverse engineers, security researchers, vulnerability analysts
