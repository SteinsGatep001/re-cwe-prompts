# 逆向工程 CWE 提示集（工具无关：IDA / Ghidra）

用途
- 本仓库提供“模式化、角色驱动”的提示文档，用于指导 AI Agent（如 Codex/Claude）结合反汇编器（IDA/Ghidra），在二进制程序中发现、分析并报告常见 Web 安全问题（CWE）。提示不依赖具体符号名，适用于不同项目与工具。

目录结构
- `cwes/` — CWE 指南（漏洞模式、来源/汇聚、风险信号、修复思路）
- `workflows/` — 通用工作流（发现路由、追踪到敏感汇聚点、差距分析与修复、生成报告）
- `INDEX.md` — 索引（链接 CWE 与工作流）
- `README_zh-CN.md` — 中文说明

快速上手
1) 选择一个 CWE 指南（如 `cwes/CWE-22.md`、`cwes/CWE-601.md`、`cwes/CWE-79.md`）。
2) 按顺序执行 `workflows/` 下的通用流程：
   - `discover_routes.md` — 通过字符串/XREF/反编译定位请求分发与静态处理逻辑；
   - `trace_to_fs_sinks.md` — 从分发→处理→工具函数→敏感汇聚点（2–3 跳）构建调用路径，并确认底层导入；
   - `gap_analysis_and_fix.md` — 结合该 CWE 的控制清单（如解码→校验→规范化→前缀约束→再访问），定位缺陷并给出修复方案；
   - `generate_report.md` — 生成包含静态+动态证据的角色化报告。

IDA / Ghidra 使用要点
- IDA Pro MCP：`list_strings_filter`、`get_xrefs_to`、`decompile_function`、`get_callees`、`set_comment`；
- Ghidra：字符串检索、引用分析、反编译、调用图/函数图、批注；思路一致，强调“角色”而非“函数名”。

通用建议
- 以“角色”（dispatcher/handler/sanitizer/sink）为核心组织分析；
- 关注解码/归一化与安全控制（校验、路径规范化、前缀约束）的顺序与位置；
- 在安全环境中用小脚本做最小化动态验证，辅助静态结论。

新增 CWE 指南
- 以 `cwes/CWE-TEMPLATE.md` 为样板编写，并在 `INDEX.md` 中添加索引。

