# 如何使用 AnalystSage 深度分析系统 - 完整指南

**目标读者:** 需要指导 AI Agent 完成 SNMP 漏洞深度分析的用户

---

## 📋 快速决策树

```
你想要...
│
├─ 🚀 最快开始，让 AI Agent 自己搞定？
│   → 给 Agent: START_HERE.md
│   → 优点: 最简单，Agent 自主性强
│   → 缺点: 对 Agent 能力要求高
│
├─ 📖 逐步引导 Agent，确保每个阶段都正确？
│   → 给自己看: PHASED_PROMPTS_FOR_USER.md
│   → 你按阶段给 Agent 发送提示词
│   → 优点: 可控性强，质量有保证
│   → 缺点: 需要你持续参与
│
└─ 📚 深入理解整个分析流程？
    → 阅读: master-prompts/analystsage_deep_analysis.md
    → 理解完整的 5 阶段工作流
    → 优点: 完全理解，可以自定义
    → 缺点: 文档较长 (500+ 行)
```

---

## 🎯 方案 A：最快开始 (推荐新手)

### 适用场景：
- 你信任 AI Agent 的能力
- 你想要快速得到结果
- 你不想花时间学习细节

### 操作步骤：

**1. 启动 Ghidra GUI**
```bash
cd /home/dev13/Documents/Tools/Develop/AI/AnalystSage
./analystsage-gui work/cases/<vendor>/<case_slug>
```

**2. 启动新的 AI Agent 会话**
(例如 Claude Code 的新会话)

**3. 给 Agent 发送第一个提示：**
```
你是一个专业的逆向工程师和安全研究员。

你的任务：在 Ghidra GUI 中完成 SNMP 漏洞深度分析。

首先，阅读这个快速上手指南：
prompts/re-cwe-prompts/START_HERE.md

然后按照指南逐步执行，完成所有 5 个阶段的分析。

开始吧！
```

**4. 等待 Agent 完成**
- Agent 会自主完成所有 5 个阶段
- 预计时间: 4-5 小时
- 你只需要在 Agent 遇到问题时提供帮助

### 预期输出：
- 3 个详细报告 (完整分析、漏洞细节、修复建议)
- stage_d_summary.json
- Ghidra 项目中重命名的函数和添加的注释

---

## 🎮 方案 B：分阶段引导 (推荐专业用户)

### 适用场景：
- 你想要掌控每个阶段
- 你想确保质量
- 你愿意投入时间参与

### 操作步骤：

**1. 启动 Ghidra GUI**
```bash
./analystsage-gui work/cases/<vendor>/<case_slug>
```

**2. 阅读分阶段提示词文档**
```
prompts/re-cwe-prompts/PHASED_PROMPTS_FOR_USER.md
```
这个文档包含 **6 个独立的提示词**，对应初始化 + 5 个分析阶段。

**3. 启动新的 AI Agent 会话**

**4. 按顺序给 Agent 发送提示词**

从文档中复制 "阶段 0：初始化" 的提示词，发送给 Agent：
```
你是一个专业的逆向工程师和安全研究员。

你的任务：在 Ghidra GUI 中完成 SNMP 漏洞深度分析。

首先，阅读这个文件了解整体流程：
prompts/re-cwe-prompts/START_HERE.md

然后，执行以下验证步骤：
...
(省略，完整内容见 PHASED_PROMPTS_FOR_USER.md)
```

**5. 等待 Agent 完成当前阶段**
Agent 会告诉你："我准备好进入阶段 1 了"

**6. 继续发送下一阶段的提示词**
从文档中复制 "阶段 1：收集上下文" 的提示词，发送

**7. 重复步骤 5-6**
直到完成所有 5 个阶段

### 优点：
- 你可以在每个阶段检查 Agent 的输出
- 如果某个阶段出错，可以及时纠正
- 更容易理解整个分析过程

### 预期时间线：
| 阶段 | Agent 执行时间 | 你的参与时间 |
|-----|-------------|-----------|
| 阶段 0: 初始化 | 2 分钟 | 2 分钟 (发送提示) |
| 阶段 1: 收集上下文 | 15 分钟 | 2 分钟 (检查输出 + 发送下一阶段) |
| 阶段 2: 发现入口点 | 30 分钟 | 5 分钟 (检查输出 + 发送下一阶段) |
| 阶段 3: 深度分析 | 2-3 小时 | 10 分钟 (检查输出 + 发送下一阶段) |
| 阶段 4: 代码优化 | 1 小时 | 5 分钟 (检查输出 + 发送下一阶段) |
| 阶段 5: 生成报告 | 30 分钟 | 10 分钟 (检查报告质量) |
| **总计** | **~5 小时** | **~35 分钟** |

---

## 📚 方案 C：深度学习模式 (推荐高级用户)

### 适用场景：
- 你想要完全理解整个分析流程
- 你可能需要自定义分析流程
- 你想要掌握系统设计原理

### 学习路径：

**1. 阅读架构设计文档**
```
work/docs/DEEP_REVERSE_ENGINEERING_OPTIMIZATION_PLAN.md
```
了解 3 层架构和 5 阶段工作流的设计理念

**2. 阅读完整的主提示词**
```
prompts/re-cwe-prompts/master-prompts/analystsage_deep_analysis.md
```
- 500+ 行完整的工作流程
- 包含所有阶段的详细代码示例
- 理解每个阶段的目标和方法

**3. 浏览 Ghidra MCP 工具文档**
```
prompts/re-cwe-prompts/ghidra-mcp-guides/tool_categories.md
```
了解 57 个 MCP 工具的功能

**4. 浏览 SNMP 协议分析文档**
```
prompts/re-cwe-prompts/protocol-analysis/SNMP/
```
- protocol_overview.md: SNMP 协议基础
- handler_patterns.md: 处理函数模式
- vulnerability_patterns.md: 常见漏洞模式

**5. 实践：自己设计分析流程**
基于你的理解，自己编写提示词给 Agent

### 预期时间：
- 学习时间: 2-3 小时
- 首次实践: 6-7 小时 (包含调试)
- 后续分析: 3-4 小时 (熟练后)

---

## 🔧 实际操作示例

### 示例 1：使用方案 A (最快开始)

**场景:** 你需要快速分析 CVE-2025-20362 (Cisco SNMP 漏洞)

```bash
# 1. 启动 Ghidra GUI
./analystsage-gui work/cases/cisco/CVE-2025-20362

# 2. 新 Claude 会话，发送：
你是专业逆向工程师，任务是分析 SNMP 漏洞。
读取: prompts/re-cwe-prompts/START_HERE.md
然后执行完整的 5 阶段分析。
```

**3-5 小时后，Agent 会给你：**
- `work/cases/cisco/CVE-2025-20362/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`
- `work/cases/cisco/CVE-2025-20362/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`
- `work/cases/cisco/CVE-2025-20362/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`

### 示例 2：使用方案 B (分阶段引导)

**场景:** 你想要确保每个阶段的质量

```bash
# 1. 启动 Ghidra GUI
./analystsage-gui work/cases/cisco/CVE-2025-20362

# 2. 阅读
cat prompts/re-cwe-prompts/PHASED_PROMPTS_FOR_USER.md

# 3. 新 Claude 会话，发送 "阶段 0" 提示词
你是专业逆向工程师...
(从 PHASED_PROMPTS_FOR_USER.md 复制)

# 4. Agent 执行，2 分钟后回复："准备好进入阶段 1"

# 5. 你检查 Agent 的输出，确认 MCP 连接成功

# 6. 发送 "阶段 1" 提示词
现在开始阶段 1：收集上下文...
(从 PHASED_PROMPTS_FOR_USER.md 复制)

# 7. Agent 执行 15 分钟，报告找到的 SNMP 字符串

# 8. 你检查统计数据，确认合理

# 9. 继续发送 "阶段 2" 提示词...

# 重复直到完成所有阶段
```

---

## 🚨 常见问题和解决方案

### Q1: Agent 说 "MCP 连接失败"
**原因:** Ghidra GUI 没有启动或 MCP 服务没有运行

**解决方案:**
```bash
# 检查 Ghidra GUI 是否在运行
ps aux | grep ghidra

# 重新启动 GUI
./analystsage-gui work/cases/<vendor>/<case>
```

### Q2: Agent 找不到 SNMP 入口点
**原因:** 可能不是 SNMP 程序，或者 SNMP 代码被混淆

**解决方案:**
- 给 Agent 额外提示: "搜索网络接收函数 (recv, recvfrom)"
- 提供更多上下文: "这是一个 SNMP agent 程序，监听 UDP 161 端口"

### Q3: Agent 重命名了太多函数，Ghidra 变慢了
**原因:** Agent 过度热心，重命名了不相关的函数

**解决方案:**
- 在阶段 4 提示中添加: "只重命名 SNMP 相关的关键函数，不超过 100 个"

### Q4: Agent 生成的报告太短，缺少细节
**原因:** Agent 可能跳过了某些步骤

**解决方案:**
- 使用方案 B (分阶段引导)，在每个阶段检查输出
- 或者给 Agent 额外提示: "报告应该包含 20-30 页的详细分析"

### Q5: Agent 说找到了漏洞，但我不确定是否准确
**原因:** 可能是误报，需要人工验证

**解决方案:**
- 检查 Agent 提供的证据 (反编译代码)
- 查看 `work/cases/<vendor>/<case>/analysis/stage_d/evidence/`
- 要求 Agent 提供更详细的利用场景

---

## 📊 质量检查清单

**完成分析后，检查以下项目：**

### 文件存在性检查：
- [ ] `work/cases/<vendor>/<case>/analysis/stage_d/reports/FULL_ANALYSIS_REPORT.md`
- [ ] `work/cases/<vendor>/<case>/analysis/stage_d/reports/VULNERABILITY_DETAILS.md`
- [ ] `work/cases/<vendor>/<case>/analysis/stage_d/reports/FIX_RECOMMENDATIONS.md`
- [ ] `work/cases/<vendor>/<case>/summaries/stage_d_summary.json`

### 报告质量检查：
- [ ] 完整分析报告至少 10 页
- [ ] 至少找到 1 个漏洞并有 CWE 编号
- [ ] 漏洞细节包含攻击场景和 PoC
- [ ] 修复建议有具体的代码补丁

### Ghidra 项目检查：
- [ ] 打开 Ghidra，看到至少 50 个函数被重命名
- [ ] 函数名包含角色前缀 (dispatcher_, handler_, VULN_等)
- [ ] 漏洞位置有详细的安全注释
- [ ] 调用图清晰可见

### stage_d_summary.json 检查：
- [ ] "status": "completed"
- [ ] "vulnerabilities_found" ≥ 1
- [ ] "functions_renamed" ≥ 50
- [ ] "reports_generated" 包含 3 个文件名

---

## 💡 最佳实践

### 1. 选择合适的方案
- **第一次使用:** 方案 B (分阶段引导)
- **熟悉流程后:** 方案 A (最快开始)
- **需要深度定制:** 方案 C (深度学习)

### 2. 保存中间结果
鼓励 Agent 在每个阶段结束时保存笔记：
```
在完成阶段 1 后，创建笔记文件：
work/cases/<vendor>/<case>/analysis/stage_d/deep_analysis/phase1_notes.md
```

### 3. 适时介入
不要等到最后才检查，在关键阶段介入：
- 阶段 2 完成：检查是否找到了正确的入口点
- 阶段 3 完成：检查是否找到了真实漏洞
- 阶段 5 完成：检查报告质量

### 4. 使用 Ghidra 快照
在开始分析前，保存 Ghidra 项目快照：
```bash
# Ghidra 会自动保存版本
# 如果 Agent 搞砸了，可以回滚
```

### 5. 文档导航技巧
当 Agent 说"我不知道怎么做 X"时，告诉它：
```
查看 INDEX.md 的 "Find What You Need - By Task" 部分
找到 X 对应的文档路径
```

---

## 🎯 总结

### 快速决策指南：

| 你的情况 | 推荐方案 | 预计时间投入 |
|---------|---------|-----------|
| 第一次使用 | 方案 B (分阶段) | 你: 35 分钟 + Agent: 5 小时 |
| 需要快速结果 | 方案 A (最快) | 你: 5 分钟 + Agent: 5 小时 |
| 想要深度理解 | 方案 C (学习) | 你: 2-3 小时学习 + 6-7 小时实践 |
| 对 Agent 能力有信心 | 方案 A (最快) | 你: 5 分钟 + Agent: 5 小时 |
| 需要确保质量 | 方案 B (分阶段) | 你: 35 分钟 + Agent: 5 小时 |

### 推荐工作流：

```
第一次分析 → 方案 B (学习过程，确保质量)
    ↓
理解流程后 → 方案 A (快速分析，信任 Agent)
    ↓
需要定制 → 方案 C (深度学习，自己设计)
```

---

## 📞 获取帮助

如果遇到问题：

1. **查看文档:**
   - `INDEX.md`: 找到相关文档
   - `START_HERE.md`: 快速参考
   - `PHASED_PROMPTS_FOR_USER.md`: 具体提示词

2. **检查日志:**
   - `work/logs/`: MCP 连接日志
   - Ghidra Console: 工具执行输出

3. **回滚和重试:**
   - Ghidra 有自动保存，可以回滚
   - 重新启动 Agent 会话，从失败的阶段重新开始

---

**文档版本:** 1.0
**创建日期:** 2025-10-12
**适用于:** AnalystSage v2.8+ with Stage D
**状态:** 生产就绪

祝你分析顺利！🎯
