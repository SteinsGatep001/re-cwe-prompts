# IDA MCP Notes (Command Cheatsheet)

Quick reference for using the IDA Pro MCP server in role‑driven reverse engineering. Default tool notes path: `re-cwe-prompts/tool-notes/IDA_MCP.md`.

Kickoff Prompts
- One-line (template):
  - 使用 ida-pro-mcp，严格按 <MASTER.md 路径> 的步骤顺序执行，且通过 MCP 完成函数/变量角色化重命名、注释、设置原型与类型、必要时创建栈变量与声明结构体，结束后写入 reports/ 报告与摘要（避免敏感信息）。
- One-line（当前目标示例）:
  - 使用 ida-pro-mcp，严格按 docs/prompts/CWE-22/http-192.168.159.249-8010/MASTER.md 的步骤顺序执行，且通过 MCP 完成函数/变量角色化重命名、注释、设置原型与类型、必要时创建栈变量与声明结构体，结束后写入 reports/ 报告与摘要（避免敏感信息）。

- Expanded session directive (paste once, reusable):
  - 读取并遵循 <MASTER.md 路径>（CWE-22：MASTER → 01..06）。所有改名/注释/类型/结构体/栈变量创建均使用 MCP 接口完成：list_strings_filter、get_xrefs_to、decompile_function、get_callees、set_comment、rename_function、set_function_prototype、rename_local_variable、rename_stack_frame_variable、set_local_variable_type、set_stack_frame_variable_type、create_stack_frame_variable、declare_c_type、get_defined_structures、analyze_struct_detailed、convert_number。对相关函数与变量按“dispatcher/handler/sanitizer/sink/utility”角色进行命名与注释；在 FS sink 路径处执行 CWE‑22 审计（decode → segment validate → canonicalize(realpath) → prefix‑check → sink），缺失即在处理函数与 sink 处加注释说明。最后按 workflows/generate_report.md 和 write_reports.md 输出完整报告与简要摘要至 reports/。

Connection & Context
- `check_connection()` — verify plugin is running
- `get_metadata()` — IDB metadata (arch, bits, input file)
- `get_entry_points()` — list program entry points

Navigation & Discovery
- `list_strings_filter(count, offset, filter)` — search strings by regex/text
- `list_strings(count, offset)` — enumerate strings
- `get_xrefs_to(address)` — xrefs to string/code/data
- `disassemble_function(start_address)` — assembly listing

Decompile & Call Graph
- `decompile_function(address)` — decompile a function
- `get_callees(function_address)` — direct callees
- `get_callers(function_address)` — direct callers

Annotate & Naming
- `set_comment(address, comment)` — add disasm + pseudocode comment
- `rename_function(function_address, new_name)` — rename function
- `rename_local_variable(function_address, old_name, new_name)` — rename local
- `rename_global_variable(old_name, new_name)` — rename global

Types & Prototypes
- `set_function_prototype(function_address, prototype)` — set prototype
- `set_local_variable_type(function_address, variable_name, new_type)` — type local
- `set_global_variable_type(variable_name, new_type)` — type global
- `declare_c_type(c_declaration)` — add/update local type

Structures & Stack
- `get_defined_structures()` / `search_structures(filter)`
- `analyze_struct_detailed(name)` / `get_struct_info_simple(name)`
- `get_struct_at_address(address, struct_name)` — read struct fields
- `get_stack_frame_variables(function_address)` — list stack vars
- `create_stack_frame_variable(function_address, offset, variable_name, type_name)`
- `set_stack_frame_variable_type(function_address, variable_name, type_name)`
- `rename_stack_frame_variable(function_address, old_name, new_name)`
- `delete_stack_frame_variable(function_address, variable_name)`

Memory & Data Reads
- `read_memory_bytes(memory_address, size)` — raw bytes
- `data_read_{byte|word|dword|qword|string}(address)` — quick reads
- `get_global_variable_value_{by_name|at_address}` — compile‑time values

Unsafe (requires --unsafe)
- `dbg_get_registers`, `dbg_get_call_stack`, `dbg_start_process`, etc.

Fixed Prompt Stubs (copy/paste)
- Route discovery (strings → xrefs → handlers):
  - list_strings_filter count=500 filter="/(GET|POST|Storage|download|file|path|api|admin)/i"
  - For interesting string addresses: get_xrefs_to <addr>, decompile_function callers, get_callees
  - Tag functions by role with set_comment; rename_function only for generic names

- Sink tracing (handlers → sinks):
  - From handler functions, search pseudocode for open/fopen/stat/access/realpath/CreateFile
  - Expand 2–3 hops via get_callees; confirm data flow from request fields to sinks

- Guard audit (CWE‑22):
  - Ensure sequence before FS calls: decode → validate segments → canonicalize → prefix‑check → sink
  - Add comments at handler/sink when missing or out of order

Tips
- Flow: strings → xrefs → functions → callees; classify by role (dispatcher/handler/sanitizer/sink).
- Keep renames role‑based; avoid product/tool specific names (see `roles/README.md`).
- For detailed MCP API list and install notes, see `re-cwe-prompts/ref/ida-pro-mcp/README.md`.

Prompt Engineering
- LLMs hallucinate; be explicit about using MCP calls and avoid mental base conversions. Always use `convert_number` (ida-pro-mcp__convert_number) for number base conversions.
- Minimal starter prompt (adapt):
  - Your task is to analyze a target in IDA Pro using MCP. Strategy:
    - Inspect decompilation and add comments with findings
    - Rename variables and functions to sensible, role‑based names
    - Adjust variable/argument types if necessary (pointers/arrays)
    - If needed, view disassembly and annotate key instructions
    - NEVER convert numbers manually; call convert_number
    - Produce a short report at the end

Action Snippets (copy/paste with placeholders)
- Rename function to role name
  - Call ida-pro-mcp__rename_function with function_address "<addr>" and new_name "<Role_Descriptive_Name>"
- Add concise comment
  - Call ida-pro-mcp__set_comment with address "<addr>" and comment "role: <dispatcher|handler|sanitize|sink>; notes: <...>"
- Set function prototype
  - Call ida-pro-mcp__set_function_prototype with function_address "<addr>" and prototype "<ret> <name>(<params>)"
- Rename local/stack variable
  - For locals: call ida-pro-mcp__rename_local_variable with function_address "<addr>", old_name "<old>", new_name "<new>"
  - For params/stack: call ida-pro-mcp__rename_stack_frame_variable with function_address "<addr>", old_name "<old>", new_name "<new>"
- Set variable types
  - Local variable: ida-pro-mcp__set_local_variable_type with function_address "<addr>", variable_name "<name>", new_type "<type>"
  - Stack variable: ida-pro-mcp__set_stack_frame_variable_type with function_address "<addr>", variable_name "<name>", type_name "<type>"
- Create a missing stack variable
  - ida-pro-mcp__create_stack_frame_variable with function_address "<addr>", offset "<-0xN>", variable_name "<name>", type_name "<type>"
- Declare/adjust a struct or typedef
  - ida-pro-mcp__declare_c_type with c_declaration "struct <Name> { <fields>; };" (or typedef)
- Inspect structures
  - ida-pro-mcp__get_defined_structures; ida-pro-mcp__analyze_struct_detailed name "<Struct>"
- Read memory/strings (compile‑time known)
  - ida-pro-mcp__get_global_variable_value_{by_name|at_address}; fallback to data_read_* calls
- Convert number base safely
  - ida-pro-mcp__convert_number with text "<num>" and size "<1|2|4|8>"

Callee Documentation Pass (rename + annotate + prototype)
- Goal: 让“当前函数”及其直接被调用者（callees）都有清晰的角色化命名与注释，必要时补全原型与类型。
- One-shot directive（粘贴并替换 <FUNC_ADDR>）:
  - 调用 ida-pro-mcp__get_callees(function_address "<FUNC_ADDR>")，对每个 callee：
    1) ida-pro-mcp__decompile_function(<callee_addr>) 粗读功能
    2) 如名称通用（sub_*/unknown），ida-pro-mcp__rename_function(<callee_addr>, "<Role_Name>")
    3) ida-pro-mcp__set_comment(address "<callee_addr>", comment "role: <role>; purpose: <one-line>; upstream: <caller>; downstream: <sink/util>")
    4) 如果参数/返回类型明显：ida-pro-mcp__set_function_prototype(<callee_addr>, "<ret> <Name>(<params>)")
    5) 如需：rename_local_variable / rename_stack_frame_variable / set_local_variable_type / set_stack_frame_variable_type

Structure/Type Documentation Pass（结构体/类型补全）
- 需要为路径/请求/配置等数据建模时：
  1) 用 ida-pro-mcp__declare_c_type 定义/调整 `struct <Name> { ... };` 或 typedef。
  2) 将相关变量/全局设型：set_local_variable_type / set_global_variable_type。
  3) 用 ida-pro-mcp__get_xrefs_to_field(struct_name, field_name) 收集使用点并在调用处 set_comment 标注用途（读取/写入/验证）。
  4) 持续精炼字段名与类型；必要时重跑 declare_c_type 更新定义。

Function Purpose Comment（函数目的注释模板）
- 在函数入口或关键跳转前用 set_comment：
  - `role: <dispatcher|router|handler|utility|sanitize|sink>`
  - `purpose: <一句话功能描述>`
  - `inputs: <关键参数/全局/结构体字段>`
  - `outputs/effects: <返回值/副作用>`
  - `notes: <关键算法/边界/异常路径>`

Role‑Driven Rename Patterns
- Dispatcher: Router_<Area>_Dispatch
- Handler: Handler_<Area>_<Action>
- Sanitizer: Sanitize_<Input>_<Check>
- Sink wrapper: FS_Sink_<Operation>

CWE‑22 Guard Comment Template
- Requires: decode → segment validation → canonicalize(realpath) → base prefix → open
- Use set_comment at handler entry and sink callsite with this checklist and current status.

Workflow Links
- For discovery and tracing steps, see `workflows/discover_routes.md` and `workflows/trace_to_fs_sinks.md`.
- For report structure, see `workflows/generate_report.md` and `workflows/write_reports.md`.
