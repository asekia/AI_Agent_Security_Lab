# 已知 CVE 速查

> Known CVE Reference · 分类：AI 基础设施与供应链

## 1. 问题与威胁模型

**定义**：AI 基础设施组件的公开漏洞速查。推理框架与 MLOps 平台的已知问题，是"服务暴露即被利用"的主要来源。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 可访问目标端口，能识别组件版本 |
| 目标 | 未打补丁的推理框架 / MLOps 平台 |
| 前提 | 默认配置、默认认证缺失、版本未升级 |

**命题**：这类问题的处置重点不在"发现"，而在**清点与整改**：知道有哪些组件、是不是受影响版本、有没有对外暴露。

## 2. 原理推导

AI 基础设施漏洞的三个共性：

```text
默认无认证     → 服务起来就能被访问，不存在"先认证再利用"
反序列化面广   → pickle/dill/ZMQ 等格式在加载时执行对象
管理接口高权限 → 注册模型、提交任务、读制品，等价于代码执行
```

因此利用链通常很短：版本识别 → 默认端点 → 反序列化或管理接口 → RCE。

## 3. 攻击面与前提

| 组件 | 常见问题类型 | 前提 |
| --- | --- | --- |
| SGLang | pickle/dill/ZMQ 反序列化 RCE、SSRF、路径遍历 | 默认无认证 |
| MLflow | 默认凭据、制品路径遍历 RCE | 未认证或默认配置 |
| Ray | 仪表盘无认证，可提交任意任务 | 8265 暴露 |
| Jupyter | 未认证访问 → 代码执行 | token 未启用 |
| Kubeflow | 仪表盘/notebook 未授权 | 无 OIDC |
| TorchServe | 管理接口可注册恶意模型 | 8081 暴露 |
| Ollama / vLLM / SGLang | 默认无认证直接暴露 | 网关缺失 |

## 4. 实战步骤

### 步骤 1：识别版本

```text
响应头、错误页、/v1/models、/server_info、/metrics
```

版本决定可用漏洞集合，是后续所有判断的前提。

### 步骤 2：SGLang 核查清单

```text
CVE-2026-7301 / CVE-2026-7304   pickle 反序列化 RCE（CERT/CC VU#777338）
CVE-2026-7302                   路径遍历（同属 VU#777338）
CVE-2026-14890                  expert-parallel pickle RCE（VU#326070）
CVE-2026-3059 / CVE-2026-3060   多模态 pickle 反序列化（VU#665416）
GHSA-hvwj-8w5g-28rg             replay_request_dump.py 不安全 pickle.load
```

两条攻击面特征：`sglang serve` 不带 `--api-key/--admin-api-key` 时全部端点开放；`/server_info` 曾被发现序列化返回整个 ServerArgs（含 key 字段）。

### 步骤 3：MLflow 核查清单

```text
CVE-2026-2635    basic_auth.ini 默认凭据（Critical）
CVE-2026-2033    制品路径遍历 → RCE（High）
CVE-2023-6015    任意文件 PUT
CVE-2024-1558    路径遍历（以官方公告为准）
```

### 步骤 4：Ray / ShadowRay

```text
CVE-2023-48022：仪表盘/Job Submission API（8265）默认不认证，
                网络可达即可提交任意任务；维护方视为"受信网络设计"，补丁长期缺位。
```

ShadowRay 首轮战役（2024-03）：经 Shodan 定位暴露仪表盘，`/api/jobs/` 投递多阶段脚本（读 passwd → printenv → 云凭证横向 → XMRig 限 60% CPU 伪装内核线程）。ShadowRay 2.0（2025-11）：自传播蠕虫、LLM 动态生成载荷、cron/systemd 持久化、sockstress DDoS。

### 步骤 5：平台级事件

```text
Hugging Face Spaces（2024-06）：应用 Secrets 中的 HF 令牌泄露，
可访问私有模型与数据集。处置：吊销令牌 + 迁移 fine-grained 令牌。
```

## 5. 变体目录

| 编号 | 组件 | 漏洞类型 | 利用条件 |
| --- | --- | --- | --- |
| CV-01 | SGLang | 反序列化 RCE | 无认证 + 可达端点 |
| CV-02 | MLflow | 路径遍历 RCE | 未认证 |
| CV-03 | Ray | 任务提交 | 8265 暴露 |
| CV-04 | Jupyter | 代码执行 | token 未启用 |
| CV-05 | TorchServe | 恶意模型加载 | 8081 暴露 |

## 6. 检测与取证

- 组件版本是否落在受影响范围内。
- 是否仍沿用默认配置与默认凭据。
- 管理端点与信息端点是否可达、是否需要认证。
- 是否存在与生产无关但仍在运行的旧版本实例。
- 取证：版本字符串、端点响应、进程与容器镜像标签。

## 7. 防御与验证

1. 建立组件与版本清单，订阅厂商安全公告。
2. 默认凭据与默认配置在部署前统一整改，纳入上线检查。
3. 管理面不对外，统一走认证网关。
4. 对暴露服务定期复核，避免"搭完就忘"。
5. 修复优先级按"是否对外可达"排序，而不是只按评分。
6. **验证**：全量组件跑版本比对脚本；未认证访问管理端点必须 401。

## 8. 参考

- CERT/CC VU#777338 / VU#326070 / VU#665416：https://kb.cert.org/
- The Hacker News: ShadowRay 2.0（2025-11）：https://thehackernews.com/2025/11/shadowray-20-exploits-unpatched-ray.html
- MLflow 安全公告：https://github.com/mlflow/mlflow/security/advisories
