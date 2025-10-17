# START HERE - AI Agent 快速上手指南

**目标:** 在 Ghidra GUI 中完成 SNMP 漏洞深度分析

---

## 🚀 第一步：验证环境 (2分钟)

```python
# 1. 验证 MCP 连接
check_connection()

# 2. 获取程序信息
metadata = get_metadata()
print(f"✓ 正在分析: {metadata['program_name']}")
print(f"✓ 架构: {metadata['architecture']}")

# 如果上面的命令都成功了，继续下一步
# 如果失败，检查 Ghidra GUI 是否在运行
```

**✅ 如果连接成功** → 继续第二步
**❌ 如果失败** → 确保 Ghidra GUI 已启动并加载了目标二进制文件

---

## 📖 第二步：了解你的任务 (5分钟)

你需要完成 **5个阶段** 的分析：

```
阶段 1: 收集上下文 (15分钟)       ← 先做这个！
   ↓
阶段 2: 发现入口点 (30分钟)
   ↓
阶段 3: 深度分析 (2-3小时)        ← 最核心
   ↓
阶段 4: 代码优化 (1小时)
   ↓
阶段 5: 生成报告 (30分钟)
```

**不要一次性读完所有文档！** 按阶段读取需要的文档。

---

## 🎯 第三步：开始阶段 1 - 收集上下文

### 需要读取的文档 (按顺序)：

**3.1 首先读这个 (必读):**
```
prompts/re-cwe-prompts/protocol-analysis/SNMP/analysis_checklist.md
```
- 这是你的任务清单
- 只看 "Phase 1: Context Preparation" 部分
- 跟着清单执行每一项

**3.2 需要时参考 (可选):**
```
prompts/re-cwe-prompts/ghidra-mcp-guides/tool_categories.md
```
- 只在你不知道某个 MCP 工具怎么用时才看
- 用 Ctrl+F 搜索工具名称

### 阶段 1 的核心任务：

```python
# 1. 收集 SNMP 相关字符串
snmp_strings = list_strings(filter="snmp", limit=100)
print(f"找到 {len(snmp_strings)} 个 SNMP 相关字符串")

community_strings = list_strings(filter="community", limit=50)
print(f"找到 {len(community_strings)} 个 community 字符串")

# 2. 收集导入函数
imports = list_imports(limit=200)
print(f"找到 {len(imports)} 个导入函数")

# 3. 记录结果到文件
# 创建笔记文档记录你的发现
```

**完成标志:**
- ✅ 你知道了程序有哪些 SNMP 相关字符串
- ✅ 你知道了程序导入了哪些危险函数 (fopen, system, strcpy等)

---

## 🔍 第四步：开始阶段 2 - 发现入口点

### 需要读取的文档：

**4.1 必读:**
```
prompts/re-cwe-prompts/protocol-analysis/SNMP/handler_patterns.md
```
- 只看 "Step 1: Find SNMP Entry Points" 和 "Step 2: Identify PDU Processing Function"
- 跟着代码示例执行

### 阶段 2 的核心任务：

```python
# 1. 找到引用 "community" 字符串的函数
for string_item in community_strings:
    xrefs = get_xrefs_to(string_item['address'], limit=50)
    for xref in xrefs:
        func = get_function_by_address(xref['from_address'])
        if func:
            print(f"候选函数: {func['name']} at {func['address']}")

            # 反编译看看
            code = decompile_function(func['name'])

            # 检查是否包含 PDU 类型常量 (0xA0, 0xA1, 0xA3等)
            if '0xa0' in code.lower() or '0xa1' in code.lower():
                print(f"  ✓ 可能是 PDU 分发器!")
```

**完成标志:**
- ✅ 找到了 SNMP 数据包处理的入口函数
- ✅ 找到了 PDU 类型分发器 (dispatcher)
- ✅ 知道了 GET/SET/TRAP 等处理函数的名称

---

## 🔬 第五步：开始阶段 3 - 深度分析 (最重要！)

**现在才需要读完整的指导文档:**

```
prompts/re-cwe-prompts/master-prompts/ghidrasage_deep_analysis.md
```
- 直接跳到 "Phase 3: Deep Analysis" 部分
- 按照里面的代码示例逐步执行

**参考文档 (遇到问题时查看):**
```
prompts/re-cwe-prompts/protocol-analysis/SNMP/vulnerability_patterns.md
```
- 查看常见的 SNMP 漏洞模式
- 用这些模式检查你找到的处理函数

### 阶段 3 的关键检查点：

```python
# 对每个处理函数 (handler) 检查：

# ❗ CWE-120: 缓冲区溢出
if 'strcpy' in code or 'sprintf' in code:
    if 'strlen' not in code and 'sizeof' not in code:
        print("⚠️ 发现缓冲区溢出风险!")

# ❗ CWE-22: 路径遍历
if 'fopen' in code or 'open' in code:
    if 'realpath' not in code.lower():
        print("⚠️ 发现路径遍历风险!")

# ❗ CWE-78: 命令注入
if 'system' in code or 'popen' in code:
    print("⚠️ 发现命令注入风险!")
```

**完成标志:**
- ✅ 分析了所有处理函数 (GET, SET, TRAP等)
- ✅ 找到了至少 1 个漏洞
- ✅ 理解了从入口到漏洞的完整调用链

---

## 🎨 第六步：阶段 4 - 代码优化

**参考文档:**
```
prompts/re-cwe-prompts/ghidra-mcp-guides/renaming_standards.md
prompts/re-cwe-prompts/ghidra-mcp-guides/annotation_guidelines.md
```

### 核心任务：

```python
# 1. 重命名关键函数 (添加角色前缀)
rename_function_by_address(dispatcher_addr, "dispatcher_snmp_pdu_router")
rename_function_by_address(get_handler_addr, "handler_snmp_get_request")
rename_function_by_address(set_handler_addr, "handler_snmp_set_request")

# 2. 标记漏洞函数
rename_function_by_address(vuln_addr, "VULN_buffer_overflow_strcpy")

# 3. 添加安全注释
set_decompiler_comment(vuln_addr, """
// ============================================================================
// 漏洞: CWE-120 缓冲区溢出
// ============================================================================
// 风险: strcpy 没有进行长度检查
// 攻击: 发送超长 OID 字符串 → 缓冲区溢出 → 远程代码执行
// 修复: 使用 strncpy 并添加长度验证
// ============================================================================
""")
```

**完成标志:**
- ✅ 重命名了 50+ 个关键函数
- ✅ 所有漏洞函数都有 VULN_ 前缀
- ✅ 所有漏洞都添加了详细的安全注释

---

## 📊 第七步：阶段 5 - 生成报告

创建 3 个报告文件：

### 5.1 完整分析报告
路径: `work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`

```markdown
# SNMP 漏洞分析 - 完整报告

## 执行摘要
[2-3段总结你的发现]

## 目标信息
- 二进制文件: [名称]
- 架构: [架构]
- CVE: [如果适用]

## 发现的入口点
1. snmp_recv() at 0x00401000
2. process_snmp_packet() at 0x00402000

## 处理函数映射
- GET (0xA0) → handler_snmp_get_request
- SET (0xA3) → handler_snmp_set_request
- TRAP (0xA4) → handler_snmp_trap

## 发现的漏洞

### 1. CWE-120: GET 处理函数中的缓冲区溢出
- 位置: handler_snmp_get_request + 0x234
- 严重性: 高 (CVSS 8.1)
- 描述: [详细描述]
- 攻击场景: [攻击步骤]
- 修复方案: [代码补丁]

[继续其他漏洞...]
```

### 5.2 漏洞细节报告
路径: `work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`

包含每个漏洞的：
- 详细代码分析
- PoC (概念验证) 代码
- 利用难度评估
- CVSS 评分

### 5.3 修复建议报告
路径: `work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`

包含：
- 立即修复措施 (代码补丁)
- 短期改进建议
- 长期安全加固建议

---

## ✅ 完成检查清单

在提交分析结果前，检查：

- [ ] 完成了所有 5 个阶段
- [ ] 找到了至少 1 个漏洞并正确分类 (CWE-XXX)
- [ ] 重命名了 50+ 个函数 (带角色前缀)
- [ ] 重命名了 100+ 个变量
- [ ] 添加了详细的安全注释
- [ ] 生成了 3 个完整报告
- [ ] 保存了证据 (调用图、截图、反编译代码)

---

## 💡 关键提示

### ✅ 应该做的：
- **按阶段进行**：不要跳过阶段
- **按需读文档**：不要一次性读所有文档
- **验证发现**：每个漏洞都要有代码证据
- **边做边记录**：不要等到最后才写报告

### ❌ 不应该做的：
- 一开始就读 master prompt 的所有内容 (太长了)
- 跳过阶段 1 和 2 直接找漏洞 (会迷失方向)
- 没理解代码就重命名函数 (会造成混乱)
- 忘记保存证据 (调用图、截图等)

---

## 🆘 遇到问题？

| 问题 | 查看文档 |
|------|---------|
| 不知道某个 MCP 工具怎么用 | `ghidra-mcp-guides/tool_categories.md` |
| 找不到 SNMP 处理函数 | `protocol-analysis/SNMP/handler_patterns.md` |
| 不确定是不是漏洞 | `protocol-analysis/SNMP/vulnerability_patterns.md` |
| 不知道怎么重命名 | `ghidra-mcp-guides/renaming_standards.md` |
| 不知道怎么写注释 | `ghidra-mcp-guides/annotation_guidelines.md` |
| 找不到某个文档 | `INDEX.md` (导航中心) |

---

## 📝 快速命令参考

```python
# 最常用的 10 个命令

# 1. 搜索字符串
list_strings(filter="snmp", limit=100)

# 2. 搜索函数名
search_functions_by_name("snmp", limit=100)

# 3. 获取交叉引用
get_xrefs_to(address, limit=50)

# 4. 通过地址获取函数
get_function_by_address(address)

# 5. 反编译函数
decompile_function(func_name)

# 6. 获取被调用的函数
get_function_callees(func_name, limit=50)

# 7. 获取调用者
get_function_callers(func_name, limit=50)

# 8. 重命名函数
rename_function_by_address(address, new_name)

# 9. 添加注释
set_decompiler_comment(address, comment)

# 10. 构建调用图
get_function_call_graph(func_name, depth=4, direction="callees")
```

---

## 🚀 现在开始！

**第一个命令：**
```python
check_connection()
```

**如果成功** → 继续执行阶段 1
**如果失败** → 检查 Ghidra GUI 是否在运行

**预计总时间:** 4-5 小时完成完整分析

---

**文档版本:** 1.0
**创建日期:** 2025-10-12
**状态:** 可直接使用
**下一步:** 执行第一个命令验证 MCP 连接
