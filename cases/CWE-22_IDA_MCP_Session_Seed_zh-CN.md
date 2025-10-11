# CWE-22 会话种子（IDA MCP，通用）

用途
- 将此整段内容复制到已连接 IDA MCP 的 Codex/Claude 会话中，用“模式化/角色驱动”的方式执行通用的 CWE‑22 分析，无需依赖具体符号名。

说明
- 如果代理无法读取本地文件，请让我粘贴所需文档内容，或直接按下列计划继续。
- 输出保持简洁且可执行；仅添加必要的批注和基于“角色”的重命名。

起始提示（复制到另一会话）

"""
你已连接到 IDA MCP 环境。目标：依据 re‑cwe‑prompts，进行通用的 CWE‑22（目录穿越）分析。

上下文文件（只需浏览结构与小标题，无法读取也可继续）：
- re-cwe-prompts/INDEX.md
- re-cwe-prompts/cwes/CWE-22.md
- re-cwe-prompts/workflows/discover_routes.md
- re-cwe-prompts/workflows/trace_to_fs_sinks.md
- re-cwe-prompts/workflows/gap_analysis_and_fix.md
- re-cwe-prompts/workflows/generate_report.md
- re-cwe-prompts/workflows/write_reports.md

计划：
1) 校验 IDA MCP 连接与已载入二进制
2) 发现请求路由/分发器（不依赖具体名字）
3) 追踪到文件系统敏感汇聚点（sink）
4) CWE‑22 差距分析（解码→片段校验→规范化→前缀约束）
5) 批注与基于“角色”的重命名
6) 生成简要结论
7) 将报告与摘要写入 `reports/`

动作：
- 第1步（连接）
  - 调用 ida-pro-mcp__check_connection；若断开，请提示我打开 IDA 数据库并启动插件。

- 第2步（发现路由）— 参考 discover_routes.md
  - 字符串检索关键词："http"、"GET "、"POST "、".html"、"cgi"、".do"、"/api"、"/admin"、"domainName="、"Content-Type"（使用 ida-pro-mcp__list_strings_filter）。
  - 对每个可疑字符串地址，调用 ida-pro-mcp__get_xrefs_to 获取候选分发/处理函数。
  - 对每个候选函数，调用 ida-pro-mcp__decompile_function 与 ida-pro-mcp__get_callees。
  - 按“角色”标记（dispatcher/router/handler/sanitizer/utility），用 ida-pro-mcp__set_comment 批注；仅在名字很通用（如 sub_1234）时用 ida-pro-mcp__rename_function 重命名（如 Handler_StaticResource_Serve）。

- 第3步（追踪到 FS sinks）— 参考 trace_to_fs_sinks.md
  - 在处理函数的 2–3 层调用图中，搜索 FS API：open/fopen/stat/access/opendir/readFile/CreateFile/PathCombine/realpath。
  - 确认路径输入源自请求字段（URL 路径、查询、表单文件名等），必要时回溯字符串构造与解码。
  - 用注释记录每条 route→handler→utility→sink 链（每个函数各写一条，说明上下游）。

- 第4步（CWE‑22 差距分析）— 参考 gap_analysis_and_fix.md 与 CWE-22.md
  - 在任何 FS 调用之前检查控制序列：
    1) 解码/归一化（百分号编码、UTF‑8）
    2) 片段校验（禁止 ".."、"."；处理混合分隔符）
    3) 规范化/真实路径（realpath/绝对化）
    4) 前缀约束（限定在允许的基目录内）
  - 若缺失或顺序滞后（在 FS 调用之后才做），标记为可疑/漏洞，并在处理函数与 sink 处添加注释。

- 第5步（重命名/批注）
  - 将以 sub_ 开头且含义不明的函数重命名为角色化名称（例如 Router_Admin_Dispatch、Handler_StaticResource_Storage、FS_Sink_OpenRaw）。
  - 添加简短注释（例如："文件打开前需 解码→片段校验→realpath→前缀约束"）。

- 第6步（简要结论）
  - 概述受影响路由、可疑链路、缺失控制及修复主线（守卫函数伪代码）。
  - 结构参考 generate_report.md。

- 第7步（输出文件）— 参考 write_reports.md
  - 若无 `reports/` 目录则创建。
  - 写入完整 Markdown 报告：`reports/CWE-22_Report_<YYYYMMDD-HHMM>_<target>.md`
  - 写入简要 TXT 摘要：`reports/CWE-22_Summary_<YYYYMMDD-HHMM>_<target>.txt`
  - `<target>` 用目标 host:port 或 URL 替换。

按步骤执行，每一步给出所用的 IDA MCP 调用与简要结果；若未连通则暂停等待。
"""

