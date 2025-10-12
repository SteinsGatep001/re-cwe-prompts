# GhidraSage Prompt Templates - Complete Index

**Last Updated:** 2025-10-12
**Purpose:** Central navigation hub for all reverse engineering templates and guides

---

## 🚀 Quick Start for AI Agents

### 👉 New to GhidraSage? Start Here:

**⚡ Fastest Start (30 seconds):**
```
Read: START_HERE.md (最简化上手指南)
```

**For SNMP CVE Analysis (GUI Mode - Phased Approach):**
```
For Users guiding AI Agents:
  Read: PHASED_PROMPTS_FOR_USER.md (分阶段提示词，逐步引导)

For AI Agents performing analysis:
  1. Read: START_HERE.md (快速上手)
  2. Read: protocol-analysis/SNMP/analysis_checklist.md (具体检查清单)
  3. Reference: Use this INDEX.md to find specific tools as needed
```

**For Complete SNMP Analysis (All-in-one):**
```
1. Read: master-prompts/ghidrasage_deep_analysis.md (5-phase workflow)
2. Read: protocol-analysis/SNMP/analysis_checklist.md (concrete steps)
3. Reference: Use this INDEX.md to find specific tools as needed
```

**For General CVE Analysis:**
```
1. Read: workflows/ (generic workflows)
2. Read: cwes/ (specific vulnerability patterns)
3. Reference: ghidra-mcp-guides/ for tool usage
```

---

## 📂 Document Structure Overview

```
prompts/re-cwe-prompts/
│
├── ⚡ START_HERE.md                 ← **NEW: 最快上手指南 (AI Agent直接用)**
├── 📖 PHASED_PROMPTS_FOR_USER.md   ← **NEW: 分阶段提示词 (用户引导AI Agent)**
├── 🗺️ INDEX.md                     ← **导航中心 (本文件)**
│
├── 🎯 master-prompts/              ← **NEW: AI Agent Orchestration**
│   ├── ghidrasage_deep_analysis.md   (Main workflow prompt)
│   ├── gui_mode_setup.md              (GUI configuration)
│   └── quality_checklist.md           (QA standards)
│
├── 🔧 ghidra-mcp-guides/           ← **NEW: Universal MCP Tool Guides**
│   ├── README.md                      (Guide overview)
│   ├── tool_categories.md             (57 tools catalog - 23KB)
│   ├── common_workflows.md            (14 reusable workflows - 32KB)
│   ├── renaming_standards.md          (Naming conventions - 15KB)
│   └── annotation_guidelines.md       (Comment standards - 19KB)
│
├── 🌐 protocol-analysis/           ← **NEW: Protocol-Specific Templates**
│   └── SNMP/
│       ├── README.md                  (SNMP analysis overview)
│       ├── protocol_overview.md       (SNMP basics)
│       ├── handler_patterns.md        (Find entry points)
│       ├── vulnerability_patterns.md  (Common SNMP vulns)
│       └── analysis_checklist.md      (5-phase workflow)
│
├── 📚 cwes/                        ← **CWE Pattern Library**
│   ├── CWE-22.md                      (Path Traversal)
│   ├── CWE-601.md                     (Open Redirect)
│   ├── CWE-79.md                      (XSS)
│   └── CWE-TEMPLATE.md                (Template for new CWEs)
│
├── 🔄 workflows/                   ← **Generic Analysis Workflows**
│   ├── discover_routes.md             (Find dispatchers/handlers)
│   ├── trace_to_fs_sinks.md           (Trace to file operations)
│   ├── gap_analysis_and_fix.md        (Apply CWE controls)
│   ├── generate_report.md             (Create reports)
│   └── write_reports.md               (Report templates)
│
├── 👥 roles/                       ← **Role Definitions**
│   └── README.md                      (Role-based analysis)
│
├── 📖 tool-notes/                  ← **Tool Documentation**
│   ├── IDA_MCP.md                     (IDA MCP commands)
│   ├── Ghidra.md                      (Ghidra tips)
│   └── Ghidra_MCP_Comprehensive.md    (Complete Ghidra MCP - 57 tools)
│
├── ✅ checklists/                  ← **Analysis Checklists**
│   ├── analysis.md                    (Generic checklist)
│   ├── fix_fs_guard.md                (FS guard fixes)
│   └── reporting.md                   (Reporting standards)
│
├── 📘 playbooks/                   ← **End-to-End Playbooks**
│   └── web_static_resources.md        (Static resource analysis)
│
├── 📝 cases/                       ← **Session Seeds**
│   ├── CWE-22_IDA_MCP_Session_Seed.md
│   └── CWE-22_IDA_MCP_Session_Seed_zh-CN.md
│
├── 📄 templates/                   ← **Report Templates**
│   ├── report_CWE_GENERIC.md
│   ├── summary_CWE_GENERIC.txt
│   └── target_info_template.json
│
├── 🎓 tutorials/                   ← **How-To Guides**
│   └── init_target_info.md
│
├── 🔬 probes/                      ← **Dynamic Testing**
│   ├── README.md
│   └── CWE-22/python_probe_prompt.md
│
├── 📦 captures/                    ← **Traffic Analysis**
│   ├── README.md
│   ├── har_replay_prompt.md
│   ├── curl_import_prompt.md
│   ├── burp_export_prompt.md
│   └── sanitization.md
│
├── 🐍 scripts/                     ← **Reference Scripts**
│   ├── README.md
│   └── http/
│       ├── common.py
│       ├── login.py
│       └── request.py
│
└── INDEX.md                        ← **This file**
```

---

## 🎯 Find What You Need - By Task

| Task | Document | Type |
|------|----------|------|
| **Complete SNMP analysis** | `master-prompts/ghidrasage_deep_analysis.md` | NEW |
| **Step-by-step SNMP checklist** | `protocol-analysis/SNMP/analysis_checklist.md` | NEW |
| **Understand MCP tools** | `ghidra-mcp-guides/tool_categories.md` | NEW |
| **Learn analysis workflows** | `ghidra-mcp-guides/common_workflows.md` | NEW |
| **Find SNMP handlers** | `protocol-analysis/SNMP/handler_patterns.md` | NEW |
| **Check SNMP vulnerabilities** | `protocol-analysis/SNMP/vulnerability_patterns.md` | NEW |
| **Rename functions** | `ghidra-mcp-guides/renaming_standards.md` | NEW |
| **Add security comments** | `ghidra-mcp-guides/annotation_guidelines.md` | NEW |
| **Generic path traversal** | `cwes/CWE-22.md` | EXISTING |
| **Find request handlers** | `workflows/discover_routes.md` | EXISTING |
| **Trace to file sinks** | `workflows/trace_to_fs_sinks.md` | EXISTING |
| **Gap analysis** | `workflows/gap_analysis_and_fix.md` | EXISTING |
| **Generate reports** | `workflows/generate_report.md` | EXISTING |
| **IDA MCP commands** | `tool-notes/IDA_MCP.md` | EXISTING |
| **Ghidra MCP reference** | `tool-notes/Ghidra_MCP_Comprehensive.md` | EXISTING |

---

## 🔍 Find What You Need - By Protocol/Technology

### SNMP (NEW - Complete Suite)
- **Overview:** `protocol-analysis/SNMP/README.md`
- **Protocol Basics:** `protocol-analysis/SNMP/protocol_overview.md`
- **Find Handlers:** `protocol-analysis/SNMP/handler_patterns.md`
- **Vulnerabilities:** `protocol-analysis/SNMP/vulnerability_patterns.md`
- **Checklist:** `protocol-analysis/SNMP/analysis_checklist.md`

### HTTP/Web
- **Static Resources:** `playbooks/web_static_resources.md`
- **Path Traversal:** `cwes/CWE-22.md`
- **Open Redirect:** `cwes/CWE-601.md`
- **XSS:** `cwes/CWE-79.md`
- **Scripts:** `scripts/http/`

### Generic (Any Protocol)
- **Discover Routes:** `workflows/discover_routes.md`
- **Trace to Sinks:** `workflows/trace_to_fs_sinks.md`
- **MCP Workflows:** `ghidra-mcp-guides/common_workflows.md`

---

## 📊 Document Priority for AI Agents

### 🔴 Critical (Load First)
1. **`master-prompts/ghidrasage_deep_analysis.md`** - Main orchestration (if doing SNMP)
2. **`protocol-analysis/SNMP/analysis_checklist.md`** - Step-by-step workflow (if doing SNMP)
3. **`workflows/discover_routes.md`** - Generic entry point discovery

### 🟡 High Priority (Load as Needed)
4. **`ghidra-mcp-guides/tool_categories.md`** - Tool reference (23KB)
5. **`ghidra-mcp-guides/common_workflows.md`** - Analysis patterns (32KB)
6. **`protocol-analysis/SNMP/vulnerability_patterns.md`** - SNMP vulns (7KB)
7. **`cwes/CWE-XX.md`** - Specific CWE patterns

### 🟢 Medium Priority (Reference)
8. **`ghidra-mcp-guides/renaming_standards.md`** - Naming conventions (15KB)
9. **`ghidra-mcp-guides/annotation_guidelines.md`** - Comment standards (19KB)
10. **`protocol-analysis/SNMP/protocol_overview.md`** - SNMP basics (7KB)

### ⚪ Low Priority (Background)
11. README files (overview/navigation)
12. Templates and examples
13. Scripts (reference implementation)

---

## 🎓 Learning Paths

### Path A: SNMP CVE Analysis (GUI Mode) - NEW
```
Time: 15 min reading + 4-5 hours analysis

1. [5 min]  master-prompts/ghidrasage_deep_analysis.md
            Purpose: Understand 5-phase workflow

2. [10 min] protocol-analysis/SNMP/analysis_checklist.md
            Purpose: Concrete action items

3. [On-demand references during analysis:]
   - ghidra-mcp-guides/tool_categories.md (tool lookup)
   - protocol-analysis/SNMP/handler_patterns.md (find entry points)
   - protocol-analysis/SNMP/vulnerability_patterns.md (vuln detection)
   - ghidra-mcp-guides/renaming_standards.md (rename functions)
   - ghidra-mcp-guides/annotation_guidelines.md (add comments)

4. Execute: Follow checklist in Ghidra GUI mode
```

### Path B: Generic Web CVE Analysis - EXISTING
```
Time: 10 min reading + variable analysis time

1. [5 min]  workflows/discover_routes.md
            Purpose: Find request handlers

2. [5 min]  workflows/trace_to_fs_sinks.md
            Purpose: Trace to dangerous operations

3. [On-demand:]
   - cwes/CWE-22.md (if path traversal)
   - cwes/CWE-601.md (if open redirect)
   - cwes/CWE-79.md (if XSS)
   - workflows/gap_analysis_and_fix.md (fix recommendations)

4. Execute: Use IDA MCP or Ghidra MCP
```

### Path C: Tool Mastery
```
Time: 45 min comprehensive reading

1. ghidra-mcp-guides/tool_categories.md
   Purpose: Learn all 57 MCP tools

2. ghidra-mcp-guides/common_workflows.md
   Purpose: Master 14 analysis workflows

3. tool-notes/Ghidra_MCP_Comprehensive.md
   Purpose: Deep dive into examples

4. Practice: Apply to real binaries
```

---

## 🔗 Document Relationships

### SNMP Analysis Flow
```
master-prompts/ghidrasage_deep_analysis.md (orchestration)
    ↓
protocol-analysis/SNMP/analysis_checklist.md (concrete steps)
    ↓
Phase 1 → ghidra-mcp-guides/tool_categories.md (tools)
Phase 2 → protocol-analysis/SNMP/handler_patterns.md (entry points)
Phase 3 → protocol-analysis/SNMP/vulnerability_patterns.md (vulns)
Phase 4 → ghidra-mcp-guides/renaming_standards.md (rename)
Phase 4 → ghidra-mcp-guides/annotation_guidelines.md (comment)
Phase 5 → master-prompts/quality_checklist.md (QA)
```

### Generic Web Analysis Flow
```
workflows/discover_routes.md (find handlers)
    ↓
workflows/trace_to_fs_sinks.md (trace to sinks)
    ↓
cwes/CWE-XX.md (check specific vulnerability)
    ↓
workflows/gap_analysis_and_fix.md (recommend fixes)
    ↓
workflows/generate_report.md (create report)
```

---

## 📏 Document Statistics

### New Documents (2025-10-12)
- **Ghidra MCP Guides:** 5 files, ~96KB
- **SNMP Protocol Analysis:** 5 files, ~39KB
- **Master Prompts:** 3 files (to be created)
- **Total New:** ~135KB of structured guidance

### Existing Documents
- **CWEs:** 4 files
- **Workflows:** 5 files
- **Tool Notes:** 3 files
- **Checklists:** 3 files
- **Other:** ~40 files

### Complete Index
- **Total Documents:** ~60 files
- **Total Size:** ~300KB structured guidance

---

## 🎯 Key Differences: New vs Existing

| Aspect | NEW (2025-10-12) | EXISTING |
|--------|------------------|----------|
| **Focus** | SNMP + Ghidra MCP | Generic Web + IDA MCP |
| **Structure** | 5-phase workflow | 4-step workflow |
| **Tools** | 57 Ghidra MCP tools | IDA MCP commands |
| **Depth** | Protocol-specific | Generic patterns |
| **Mode** | GUI + Headless | Primarily IDA |
| **Format** | Layered (Universal→Protocol→Case) | Flat (Generic→CWE) |

### When to Use NEW vs EXISTING

**Use NEW documents when:**
- ✅ Analyzing SNMP vulnerabilities
- ✅ Using Ghidra MCP tools
- ✅ Need systematic 5-phase workflow
- ✅ Want protocol-specific guidance
- ✅ Working in GUI mode

**Use EXISTING documents when:**
- ✅ Analyzing web applications
- ✅ Using IDA MCP tools
- ✅ Need quick CWE patterns
- ✅ Generic vulnerability analysis
- ✅ Already familiar with workflows

---

## 🔄 Workflow Integration

### Combining NEW + EXISTING

**Example: SNMP Path Traversal Analysis**
```
1. Start: master-prompts/ghidrasage_deep_analysis.md (NEW)
   → Understand 5-phase workflow

2. Protocol: protocol-analysis/SNMP/ (NEW)
   → SNMP-specific entry point discovery

3. Vulnerability: cwes/CWE-22.md (EXISTING)
   → Generic path traversal patterns

4. Tools: ghidra-mcp-guides/ (NEW)
   → Ghidra MCP tool usage

5. Report: workflows/generate_report.md (EXISTING)
   → Report generation
```

---

## 💡 Tips for AI Agents

### Efficient Document Loading
```python
# DON'T: Load everything at once
all_docs = [read(doc) for doc in all_documents]  # ❌ Wastes tokens

# DO: Load on-demand
master_prompt = read("master-prompts/ghidrasage_deep_analysis.md")
# ... execute Phase 1 ...
tools_guide = read("ghidra-mcp-guides/tool_categories.md")  # When needed
# ... execute Phase 2 ...
handler_guide = read("protocol-analysis/SNMP/handler_patterns.md")  # When needed
```

### Using This Index
```python
# Quick lookup pattern:
# 1. Check this INDEX.md "Find What You Need" section
# 2. Load only the specific document needed
# 3. Return to analysis

# Example: Need to rename a function
# INDEX → "Rename functions" → renaming_standards.md
naming_guide = read("ghidra-mcp-guides/renaming_standards.md")
# Read relevant section, apply, continue
```

### Cross-Referencing
```python
# Documents reference each other
# When you see: "See X.md for details"
# Use this INDEX to find full path

# Example from checklist:
# "Reference: handler_patterns.md"
# INDEX → Find "handler_patterns.md" → Load it
```

---

## 📞 Getting Help

### For Specific Topics

| Question | Document |
|----------|----------|
| How do GhidraSage stages work? | `../../ARCHITECTURE.md` |
| How to use Stage D? | `../../docs/stage_d/README.md` |
| What MCP tools are available? | `ghidra-mcp-guides/tool_categories.md` |
| How to find SNMP handlers? | `protocol-analysis/SNMP/handler_patterns.md` |
| What are common SNMP vulns? | `protocol-analysis/SNMP/vulnerability_patterns.md` |
| How to rename systematically? | `ghidra-mcp-guides/renaming_standards.md` |
| What are role definitions? | `roles/README.md` |
| How to generate reports? | `workflows/generate_report.md` |

---

## 🚧 Maintenance and Updates

### Adding New Content

**New Protocol Analysis:**
1. Create: `protocol-analysis/<PROTOCOL>/`
2. Copy structure from `SNMP/`
3. Update this INDEX.md

**New CWE Pattern:**
1. Copy: `cwes/CWE-TEMPLATE.md`
2. Fill in: CWE-specific patterns
3. Update this INDEX.md

**New Workflow:**
1. Create: `workflows/<workflow_name>.md`
2. Follow existing format
3. Update this INDEX.md

### Version History
- **v1.1 (2025-10-12):** Added SNMP + Ghidra MCP guides
- **v1.0 (Earlier):** Initial CWE + workflow templates

---

## 🎯 Summary: AI Agent Quick Reference

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  QUICK START FOR AI AGENTS                                 │
│                                                            │
│  SNMP CVE Analysis:                                        │
│    1. master-prompts/ghidrasage_deep_analysis.md           │
│    2. protocol-analysis/SNMP/analysis_checklist.md         │
│    3. Reference others as needed via this INDEX            │
│                                                            │
│  Generic CVE Analysis:                                     │
│    1. workflows/discover_routes.md                         │
│    2. workflows/trace_to_fs_sinks.md                       │
│    3. cwes/CWE-XX.md (specific vulnerability)              │
│                                                            │
│  Tool Reference:                                           │
│    - ghidra-mcp-guides/tool_categories.md (Ghidra)         │
│    - tool-notes/IDA_MCP.md (IDA)                           │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

**Created:** 2025-10-12
**Purpose:** Complete navigation hub for all GhidraSage prompt templates
**Coverage:** 60+ documents, 300KB+ structured guidance
**Status:** Active and maintained
