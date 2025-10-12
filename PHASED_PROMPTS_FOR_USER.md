# 分阶段提示词 - 给用户使用

**如何逐步引导 AI Agent 完成 SNMP 深度分析**

---

## 📋 使用说明

这个文件包含 **5 个独立的提示词**，对应 5 个分析阶段。

**使用方法：**
1. 启动 Ghidra GUI 并加载目标二进制文件
2. 启动新的 AI Agent 会话
3. **按顺序**给 AI Agent 发送下面的提示词
4. 等 Agent 完成当前阶段后，再发送下一阶段的提示词
5. 不要一次性发送所有提示词！

---

## 🚀 阶段 0：初始化 (给 Agent 的第一个提示)

```
你是一个专业的逆向工程师和安全研究员。

你的任务：在 Ghidra GUI 中完成 SNMP 漏洞深度分析。

首先，阅读这个文件了解整体流程：
prompts/re-cwe-prompts/START_HERE.md

然后，执行以下验证步骤：

1. 验证 MCP 连接：
   check_connection()

2. 获取程序元数据：
   metadata = get_metadata()
   print(f"程序: {metadata['program_name']}")
   print(f"架构: {metadata['architecture']}")

如果连接成功，告诉我你准备好进入阶段 1 了。
如果失败，告诉我具体的错误信息。
```

**预期输出：**
Agent 会执行验证命令，然后告诉你它准备好了。

---

## 📝 阶段 1：收集上下文 (预计 15 分钟)

**等 Agent 完成阶段 0 后，再发送这个提示：**

```
现在开始阶段 1：收集上下文

参考文档：
- prompts/re-cwe-prompts/protocol-analysis/SNMP/analysis_checklist.md
  只看 "Phase 1: Context Preparation" 部分

任务清单：

1. 收集 SNMP 相关字符串：
   - snmp_strings = list_strings(filter="snmp", limit=100)
   - community_strings = list_strings(filter="community", limit=50)
   - oid_strings = list_strings(filter="oid", limit=50)
   - mib_strings = list_strings(filter="mib", limit=50)

2. 收集导入函数（关注网络和文件操作）：
   - imports = list_imports(limit=200)
   - 筛选出包含 recv, send, socket, fopen, open, read, write 的函数

3. 获取内存布局：
   - segments = list_segments(limit=100)

4. 总结发现：
   - 报告找到多少个 SNMP 相关字符串
   - 列出 5-10 个最相关的导入函数
   - 创建笔记记录你的初步发现

完成后，告诉我：
- 你找到了多少个 SNMP 相关字符串
- 最相关的 5 个导入函数
- 你准备好进入阶段 2
```

**预期输出：**
Agent 会执行命令并报告统计数据，然后说准备好进入阶段 2。

---

## 🔍 阶段 2：发现入口点 (预计 30 分钟)

**等 Agent 完成阶段 1 后，再发送这个提示：**

```
现在开始阶段 2：发现入口点

参考文档：
- prompts/re-cwe-prompts/protocol-analysis/SNMP/handler_patterns.md
  只看前 3 个 Pattern 和 "Step 1-2"

目标：找到 SNMP 数据包处理的入口点和 PDU 分发器

任务：

1. 找到引用 "community" 字符串的函数：
   - 对每个 community_string：
     - 获取交叉引用 get_xrefs_to(string['address'])
     - 找到引用它的函数
     - 反编译这些函数

2. 识别 PDU 分发器：
   - 在反编译代码中查找 PDU 类型常量 (0xA0, 0xA1, 0xA3, 0xA4)
   - 查找 switch 语句或函数指针表
   - 找到处理不同 PDU 类型的分支逻辑

3. 映射处理函数：
   - 使用 get_function_callees() 找到分发器调用的所有函数
   - 识别哪个函数处理 GET (0xA0)
   - 识别哪个函数处理 SET (0xA3)
   - 识别哪个函数处理 TRAP (0xA4)

4. 构建初始调用图：
   - call_graph = get_function_call_graph(dispatcher_name, depth=3)

完成后，告诉我：
- SNMP 入口函数的名称和地址
- PDU 分发器的名称和地址
- GET/SET/TRAP 处理函数的名称和地址
- 调用图的简要描述
```

**预期输出：**
Agent 会找到入口点、分发器和主要处理函数，并报告它们的地址。

---

## 🔬 阶段 3：深度分析 (预计 2-3 小时)

**这是最关键的阶段。等 Agent 完成阶段 2 后，再发送：**

```
现在开始阶段 3：深度分析

这是最重要的阶段，你需要找到安全漏洞。

参考文档：
- prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md
  跳到 "Phase 3: Deep Analysis" 部分
- prompts/re-cwe-prompts/protocol-analysis/SNMP/vulnerability_patterns.md
  查看 5 种常见漏洞模式

任务分解：

### 3.1 分析处理函数注册机制 (30 分钟)
- 确定是静态表、switch 分发还是运行时注册
- 文档化 PDU 类型 → 处理函数的映射关系

### 3.2 分析 GET 处理函数 (30 分钟)
- 反编译 GET 处理函数
- 跟踪数据流：community → OID → 响应构建
- 检查输入验证和边界检查
- 识别被调用的函数（sanitizer/utility/sink）

### 3.3 分析 SET 处理函数 (45 分钟) ⚠️ 重点！
- 反编译 SET 处理函数
- 检查授权验证（是否需要 "private" community）
- 检查 OID 和 value 的验证
- **重点检查危险操作：**
  - 是否有 system()/popen() 调用？ → CWE-78 命令注入
  - 是否有 fopen() 且路径由 OID 构造？ → CWE-22 路径遍历
  - 是否有 strcpy()/sprintf() 且无长度检查？ → CWE-120 缓冲区溢出

### 3.4 漏洞检测 (45 分钟)
对每个处理函数，检查以下模式：

**CWE-120: 缓冲区溢出**
if ('strcpy' in code or 'sprintf' in code) and ('strlen' not in code):
    → 标记为漏洞

**CWE-22: 路径遍历**
if ('fopen' in code or 'open' in code) and ('realpath' not in code):
    → 标记为漏洞

**CWE-78: 命令注入**
if ('system' in code or 'popen' in code):
    → 标记为漏洞

**CWE-190: 整数溢出**
if ('malloc' in code and 'length' in code) and ('MAX' not in code):
    → 标记为漏洞

### 3.5 数据流分析 (30 分钟)
- 对每个漏洞，跟踪从入口到漏洞点的完整调用链
- 使用 get_function_callers() 回溯调用者
- 文档化攻击路径

完成后，报告：
- 你找到了几个漏洞
- 每个漏洞的类型 (CWE-XXX)
- 漏洞的位置（函数名 + 地址）
- 漏洞的严重性（高/中/低）
- 从入口到漏洞的调用链
```

**预期输出：**
Agent 会详细分析每个处理函数，识别漏洞，并报告完整的调用链。

---

## 🎨 阶段 4：代码优化 (预计 1 小时)

**等 Agent 完成阶段 3 后，再发送：**

```
现在开始阶段 4：代码优化

目标：系统性地重命名函数和变量，添加安全注释。

参考文档：
- prompts/re-cwe-prompts/ghidra-mcp-guides/renaming_standards.md
- prompts/re-cwe-prompts/ghidra-mcp-guides/annotation_guidelines.md

### 4.1 重命名关键函数 (30 分钟)

使用角色前缀重命名：

**分发器：**
rename_function_by_address(dispatcher_addr, "dispatcher_snmp_pdu_router")

**处理函数：**
rename_function_by_address(get_handler_addr, "handler_snmp_get_request")
rename_function_by_address(set_handler_addr, "handler_snmp_set_request")
rename_function_by_address(trap_handler_addr, "handler_snmp_trap")

**验证函数：**
rename_function_by_address(validate_addr, "sanitizer_validate_community")
rename_function_by_address(validate_oid_addr, "sanitizer_validate_oid")

**危险函数（sink）：**
rename_function_by_address(file_open_addr, "sink_mib_file_open")
rename_function_by_address(exec_addr, "sink_execute_command")

**漏洞函数：**
rename_function_by_address(vuln_addr, "VULN_buffer_overflow_strcpy")
rename_function_by_address(vuln2_addr, "VULN_path_traversal_fopen")

目标：重命名至少 50 个关键函数

### 4.2 重命名变量 (15 分钟)

在关键函数中重命名变量：
- iVar1 → pdu_type
- pcVar1 → community_str
- pcVar2 → oid_str
- pcVar3 → value_str
- local_100 → oid_buffer
- local_200 → value_buffer

目标：重命名至少 100 个变量

### 4.3 添加安全注释 (15 分钟)

对每个漏洞添加详细的安全注释：

set_decompiler_comment(vuln_addr, """
// ============================================================================
// 漏洞: CWE-120 缓冲区溢出
// ============================================================================
//
// 风险: strcpy() 使用时未进行长度检查
//
// 攻击场景:
//   1. 攻击者发送超长的 OID 字符串 (300+ 字节)
//   2. strcpy 将整个字符串复制到 256 字节的栈缓冲区
//   3. 栈溢出覆盖返回地址
//   4. 控制流被劫持，执行攻击者的 shellcode
//
// 修复建议:
//   1. 在复制前验证 OID 长度
//   2. 使用 strncpy 替代 strcpy
//   3. 确保缓冲区有空终止符
//
// 利用难度: 中 (需要 ROP 或 NX 绕过)
// 影响: 远程代码执行 (RCE)
// CVSS v3.1: 8.1 (高危)
// ============================================================================
""")

完成后，报告：
- 重命名了多少个函数
- 重命名了多少个变量
- 为多少个漏洞添加了注释
```

**预期输出：**
Agent 会系统性地重命名函数和变量，并为每个漏洞添加详细的安全注释。

---

## 📊 阶段 5：生成报告 (预计 30 分钟)

**最后阶段。等 Agent 完成阶段 4 后，再发送：**

```
现在开始阶段 5：生成报告

目标：生成 3 个完整的分析报告

参考报告模板：
- prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md
  查看 "Phase 5: Report Generation" 部分

### 5.1 生成完整分析报告

创建文件：`.work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`

包含以下章节：
1. 执行摘要（2-3 段）
2. 目标信息（二进制、架构、CVE）
3. 发现的入口点
4. 处理函数映射（PDU → 函数）
5. 发现的漏洞（每个漏洞一个小节）
6. 数据流分析（调用图）
7. 代码增强总结（重命名统计）
8. 建议措施

### 5.2 生成漏洞细节报告

创建文件：`.work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`

对每个漏洞，包含：
- 漏洞位置（函数名 + 地址 + 代码行）
- 受影响的代码（反编译的伪 C 代码）
- 攻击场景（逐步说明）
- PoC 代码（概念验证）
- 利用难度评估
- CVSS v3.1 评分（带计算过程）
- 参考资料（CWE 链接、CVE 链接）

### 5.3 生成修复建议报告

创建文件：`.work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`

分为三类建议：

**立即修复（关键）：**
- 每个漏洞的具体代码补丁
- 修改的文件和函数
- 测试方法

**短期改进（1-2 周）：**
- 全局替换不安全函数 (strcpy→strncpy)
- 添加全面的输入验证
- 加固认证机制

**长期加固（1-2 月）：**
- 迁移到 SNMPv3
- 实施模糊测试
- 代码审计和静态分析

### 5.4 保存证据文件

- 导出调用图：get_full_call_graph(format="mermaid")
- 保存到：`.work/cases/<vendor>/<case>/analysis/stage_d/evidence/call_graphs/`
- 对关键函数截图
- 保存反编译代码

### 5.5 更新 Stage D 摘要

创建文件：`.work/cases/<vendor>/<case>/summaries/stage_d_summary.json`

格式：
{
  "stage": "stage_d",
  "status": "completed",
  "analysis_mode": "gui",
  "entry_points": [...],
  "handlers_mapped": 4,
  "vulnerabilities_found": 3,
  "functions_renamed": 127,
  "variables_renamed": 243,
  "reports_generated": ["FULL_ANALYSIS_REPORT.md", ...]
}

完成后，报告：
- 3 个报告文件的路径
- 每个报告的页数或字数
- 证据文件的数量
- Stage D 摘要 JSON 的内容
```

**预期输出：**
Agent 会生成 3 个详细的分析报告和 stage_d_summary.json。

---

## ✅ 最终验证清单

**所有阶段完成后，发送这个提示让 Agent 自查：**

```
现在进行最终质量检查。

参考文档：
- prompts/re-cwe-prompts/protocol-analysis/SNMP/analysis_checklist.md
  查看 "Quality Assurance Checklist" 部分

检查以下项目：

### 完整性检查：
- [ ] 所有 SNMP 入口点都已识别并文档化
- [ ] 所有处理函数 (GET, SET, GETNEXT, TRAP) 都已分析
- [ ] 从入口到所有 sink 的完整调用图已构建
- [ ] 所有漏洞都有 CWE 编号
- [ ] 所有高风险函数都已重命名和注释

### 准确性检查：
- [ ] 函数分类正确 (dispatcher/handler/sanitizer/sink)
- [ ] 漏洞评估已通过代码审查验证
- [ ] 攻击场景技术上可行
- [ ] 修复建议已（尽可能）测试
- [ ] 漏洞列表中没有误报

### 文档检查：
- [ ] 所有关键处理函数都有函数头注释
- [ ] 所有漏洞位置都有安全注释
- [ ] 复杂逻辑有内联注释
- [ ] 所有报告都保存在正确位置 (.work/cases/)
- [ ] 证据链完整（代码+截图+调用图）

### 可重现性检查：
- [ ] 另一位分析师可以跟随你的分析
- [ ] 所有 MCP 工具命令都已文档化
- [ ] 所有假设都明确说明
- [ ] 所有发现都可追溯到证据

如果所有检查项都通过，报告：
"✅ 质量检查完成，分析结果准备提交"

如果有未通过的检查项，说明哪些项未通过以及原因。
```

---

## 📈 预期总时间线

| 阶段 | 时间 | 累计 |
|-----|------|-----|
| 阶段 0: 初始化 | 2 分钟 | 0:02 |
| 阶段 1: 收集上下文 | 15 分钟 | 0:17 |
| 阶段 2: 发现入口点 | 30 分钟 | 0:47 |
| 阶段 3: 深度分析 | 2-3 小时 | 3:47 |
| 阶段 4: 代码优化 | 1 小时 | 4:47 |
| 阶段 5: 生成报告 | 30 分钟 | 5:17 |

**总计:** 约 5 小时完成完整分析

---

## 💡 使用技巧

### 1. 按顺序进行
不要跳过阶段，不要一次性发送所有提示词。

### 2. 等待完成
每个阶段完成后，Agent 会明确告诉你"准备好进入下一阶段"。

### 3. 适时介入
如果 Agent 卡住了或偏离了方向，可以：
- 提醒它回到当前阶段的任务清单
- 提供额外的参考文档
- 简化任务分解

### 4. 保存中间结果
鼓励 Agent 在每个阶段结束时保存笔记和发现。

### 5. 灵活调整
如果某个阶段时间过长，可以分成更小的子任务。

---

## 🎯 成功标志

完成所有阶段后，你应该得到：

**产出物：**
- 3 个详细的分析报告 (总共 30-50 页)
- stage_d_summary.json
- 调用图文件
- 截图和反编译代码

**Ghidra 项目状态：**
- 50-150 个函数被重命名
- 100-300 个变量被重命名
- 所有漏洞都有详细的安全注释
- 所有关键函数都有文档头

**分析质量：**
- 至少找到 1 个真实漏洞
- 每个漏洞都有完整的调用链
- 修复建议具体可行
- 所有发现都有代码证据

---

**文档版本:** 1.0
**创建日期:** 2025-10-12
**用途:** 指导用户逐步引导 AI Agent 完成分析
**状态:** 可直接使用
