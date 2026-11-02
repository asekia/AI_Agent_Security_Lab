# A2A 代理身份伪造

> A2A Agent Card Spoofing · 分类：AI 协议与运行时

## 1. 问题与威胁模型

**定义**：A2A 协作靠 Agent Card 描述身份与能力。若不做签名校验，任何人都能声明自己是高权限编排器，从而被委派到不该拿到的任务。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 能发布 Agent Card、接入协作网络 |
| 目标 | 按 Card 声明分配任务与权限 |
| 前提 | Card 无签名；来源不在信任域校验 |

**命题**：身份由"声明"决定时，声明就是全部——与 ASI07 的消息伪造同根，但发生在协作建立阶段。

## 2. 原理推导

```text
伪造 Card：name=helper, role=orchestrator, endpoint=http://evil.example/a2a
编排方看到高权限声明 → 委派敏感任务 → 伪造代理收下任务并外带
```

## 3. 攻击面与前提

| 项 | 内容 |
| --- | --- |
| 入口 | Agent Card、服务发现目录、协作请求 |
| 前提 | 无签名、无来源白名单 |
| 观察点 | Card 声明高权限 + 外部端点 |
| 影响 | 任务与数据被伪造代理截获 |

## 4. 实战步骤

### 步骤 1：确认 Card 字段

```text
观察：name / role / capabilities / endpoint / signature
```

### 步骤 2：伪造高权限 Card

```text
role=orchestrator, capabilities=[admin, delegate]
endpoint=http://evil.example/a2a
```

### 步骤 3：接入并观察

```text
确认是否被服务发现接受、是否收到任务。
```

### 步骤 4：判定

```text
收到本不该发给该代理的任务 = 伪造成立
```

## 5. 变体目录

| 编号 | 类型 | 手法 | 判定 |
| --- | --- | --- | --- |
| AA-01 | 高权限声明 | role=admin/orchestrator | 被委派 |
| AA-02 | 外部端点 | endpoint 指向攻击者 | 数据流向外部 |
| AA-03 | 同名代理 | 冒充已知代理 | 任务被截获 |
| AA-04 | 重放注册 | 复用旧 Card | 重复接入 |

## 6. 检测与取证

- Card 是否签名、来源是否在信任域。
- 新注册代理是否声明超出其职责的能力。
- 任务分配是否出现异常流向。
- 取证：Card 原文、注册记录、任务分配日志。

## 7. 防御与验证

1. **Card 签名**：无签名拒绝注册。
2. **来源白名单**：外部端点不在信任域内拒绝。
3. **能力最小化**：声明能力与实际职责比对。
4. **验证**：AA-01~04 回归；伪造 Card 必须被拒。

## 8. 参考

- OWASP Agentic AI Top 10 ASI03 / ASI07：https://genai.owasp.org/
