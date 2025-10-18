# Cases - Session Seeds & Analysis Guides

This directory contains **ready-to-use session seeds and phased analysis guides** for common reverse engineering and vulnerability analysis scenarios.

## Purpose

Cases serve as **starting templates** for AI-assisted analysis sessions. They provide:

1. **Session Seeds**: Quick-start prompts for specific CWE analysis with tool integrations (IDA MCP, Ghidra MCP)
2. **Phased Guides**: Step-by-step analysis workflows for complex protocols and vulnerability patterns
3. **Reference Templates**: Examples showing how to structure analysis sessions and guide AI agents

## Directory Contents

### Session Seeds (Tool-Specific Quick Starts)

- `CWE-22_IDA_MCP_Session_Seed.md` - Path traversal analysis session seed for IDA Pro MCP
- `CWE-22_IDA_MCP_Session_Seed_zh-CN.md` - Chinese version of the above

**Usage**: Copy-paste these seeds into your AI agent session to quickly bootstrap analysis with proper context and tool references.

### Phased Analysis Guides

- `SNMP_Analysis_Phased_Guide.md` - 5-phase deep analysis guide for SNMP vulnerabilities in embedded firmware
  - Phase 0: Initialization & connection verification
  - Phase 1: Context gathering (strings, imports, memory layout)
  - Phase 2: Entry point discovery (handlers, dispatchers, PDU routing)
  - Phase 3: Deep vulnerability analysis (CWE detection patterns)
  - Phase 4: Code optimization (renaming, annotations, comments)
  - Phase 5: Report generation (full analysis, vulnerability details, fix recommendations)

**Usage**: Use these guides to systematically walk AI agents through complex multi-hour analysis tasks. Send each phase prompt sequentially, waiting for completion before proceeding.

## When to Use Cases vs. Other Prompt Resources

### Use Cases When:
- Starting a new analysis session from scratch
- Need a complete, self-contained prompt for a specific scenario
- Want to guide an AI agent through a multi-phase analysis workflow
- Working with a specific tool integration (IDA MCP, Ghidra MCP)

### Use Workflows (`../workflows/`) When:
- Need modular, reusable analysis steps
- Building custom analysis sequences
- Integrating with existing processes

### Use CWE Guides (`../cwes/`) When:
- Learning about specific vulnerability patterns
- Understanding CWE detection strategies
- Reference material for pattern recognition

## Creating Custom Cases

When developing project-specific analysis guides:

1. **Use this directory as reference** - Study existing cases to understand structure and depth
2. **Create local versions** - Place custom cases in `prompts/local/` (see `../../local/README.md`)
3. **Extract common patterns** - If your custom prompts have broadly useful patterns, consider contributing them back to this directory

## Template Structure

Effective case templates should include:

1. **Clear objective**: What vulnerability or pattern are we analyzing?
2. **Tool context**: Which tools and MCP servers are required?
3. **Phase breakdown**: Logical steps with time estimates
4. **Verification checkpoints**: How to confirm each phase completed correctly
5. **Expected outputs**: What artifacts should be produced?
6. **Reference links**: Point to relevant CWE guides, workflows, and tool notes

## Integration with AnalystSage

These cases integrate with the AnalystSage pipeline:

- **Stage D (Interactive RE)**: Use phased guides during GUI-based deep analysis
- **MCP Integration**: Session seeds assume MCP servers are running (`check_connection()`)
- **Artifact Storage**: All outputs follow `work/cases/<vendor>/<case>/` structure
- **Report Generation**: Phase 5 templates align with Stage D reporting standards

## Contributing

To add new cases:

1. Follow existing naming conventions: `<Protocol/CWE>_<Tool>_<Type>.md`
2. Include time estimates for each phase
3. Reference existing workflow and CWE docs rather than duplicating content
4. Test prompts with actual AI agents before committing
5. Add entry to this README

## See Also

- `../workflows/` - Modular analysis workflows
- `../cwes/` - CWE-specific vulnerability patterns
- `../tool-notes/` - Tool-specific command references
- `../ghidra-mcp-guides/` - Ghidra MCP best practices
- `../../local/` - Project-specific custom prompts (gitignored)

---

**Note**: These cases are maintained as part of the `re-cwe-prompts` submodule. Local customizations should go in `prompts/local/` to avoid submodule conflicts.
