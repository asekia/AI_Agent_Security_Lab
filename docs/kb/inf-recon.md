# AI 基础设施侦察方法论

> AI Infrastructure Recon Methodology · 分类：AI 基础设施与供应链

## 1. 问题与威胁模型

**定义**：把 AI 资产发现拆成可重复的五个阶段：确定范围、识别服务、确认框架、梳理接口、形成可利用面清单。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 可访问目标网络或公开信息 |
| 目标 | 分散部署的推理服务、管理面板、向量库、编排平台、笔记本 |
| 前提 | 组件由不同团队搭建，缺少统一暴露面清点 |

**命题**：侦察的产物是资产清单，不是攻击本身。清单本身也是防守方最需要的资料——攻防看同一张图。

## 2. 原理推导

AI 暴露面比传统应用更分散：推理服务、管理面板、向量库、编排平台、笔记本各自独立，配置标准不一致。"搭完就忘"的服务是常态，因此系统化侦察比零散试探更有效。

五个阶段的输入输出：

```text
阶段 1 范围确定 → 域名、网段、云资源、公开文档    → 目标范围清单
阶段 2 服务识别 → 端口扫描、服务探测              → 暴露服务列表
阶段 3 框架确认 → 指纹、错误信息                  → 组件与版本清单
阶段 4 接口梳理 → 管理/数据/任务接口枚举          → 接口清单
阶段 5 面清单   → 版本 × 认证状态 × 可达范围      → 可利用面清单
```

## 3. 攻击面与前提

| 阶段 | 主要动作 | 工具 | 产出 |
| --- | --- | --- | --- |
| 1 | 被动收集 | Shodan/Censys/FOFA、GitHub dork | 范围与泄露凭证 |
| 2 | 主动扫描 | nmap + NSE、grpcurl | 暴露服务 |
| 3 | 指纹 | 响应头、错误页、JSON 结构 | 组件与版本 |
| 4 | 枚举 | curl、ffuf/feroxbuster | 接口与认证状态 |
| 5 | 汇总 | 人工比对 | 可利用面清单 |

## 4. 实战步骤

### 阶段 1：被动侦察

```text
Shodan/Censys/FOFA：port:5000 "MLflow"
                    port:8888 title:"Home Page - Select or create a notebook"
                    http.title:"Ray Dashboard"
GitHub dork：filename:.env MLFLOW_TRACKING_URI
             filename:.env HF_TOKEN
             filename:config.json model_name site:github.com
论文/工程博客：团队常写明所用框架与基础设施（AML.T0000）
DockerHub/GHCR：以组织名搜索 ML 镜像，公开镜像常带硬编码配置
招聘信息："MLflow 管理员""Kubeflow 平台工程师"
```

### 阶段 2：主动扫描

```text
nmap -p 5000,6333,6334,8000,8001,8002,8080,8265,8500,8501,8888,9000,11434,19530      -sV --script=http-title,http-headers <target>
grpcurl -plaintext <host>:8001 list     # gRPC 反射
curl http://<host>:8002/metrics         # Triton 指标
```

### 阶段 3：框架确认

```text
响应头：Server / NV-Status / TorchServe
响应体：platform / model_version_status / object:model
错误页：tensorinfo_map / mlflow 命名空间 / Databricks 异常
```

### 阶段 4：接口梳理

```text
/v1/models  /v2/models  /v2/health/ready
/api/2.0/mlflow/experiments/list  /api/2.0/mlflow/registered-models/list
/pipeline/apis/v1beta1/pipelines  /api/serve/deployments/
/v1/schema  /v1/meta  /api/kernels  /api/contents
/openapi.json  /docs  /graphql  /metrics
/api/tags  /api/show  /collections  /healthz  /ping
```

### 阶段 5：供应链复核

```text
模型下载源：Hugging Face Hub / PyTorch Hub（配置文件、笔记本、构建日志）
依赖清单：内部包名未注册 PyPI 即可被抢注（slopsquatting）
制品桶：S3/GCS/MinIO 是否公开可读
镜像仓库：是否可无凭据拉取
```

### 工具对照表

| 工具 | 用途 | 阶段 |
| --- | --- | --- |
| Shodan / Censys / FOFA | 全网侧 AI 服务横幅 | 1 |
| GitHub dork | 泄露凭证与配置 | 1 |
| Nmap（+NSE） | 端口发现与版本识别 | 2 |
| grpcurl | gRPC 交互与 schema dump | 2 |
| ffuf / feroxbuster | AI 专用词表枚举 | 2、3 |
| curl | 手工探测、头部分析、触发报错 | 3、4 |
| Nuclei | 错误配置模板扫描 | 2、3 |

## 5. 变体目录

| 编号 | 路径 | 特点 |
| --- | --- | --- |
| RC-01 | 纯被动 | 不触碰目标，靠公开数据 |
| RC-02 | 快扫 | 默认端口 + 指纹，分钟级 |
| RC-03 | 全量 | 五阶段 + 供应链复核 |
| RC-04 | 定点 | 已知组件版本，直接查 CVE |

## 6. 检测与取证

- 单一来源短时间访问大量不同端口，命中集中在框架默认端口。
- 对固定路径的批量请求（集合/实验/模型清单）。
- 响应状态分布高度一致（大量 404/401）——枚举而非正常使用。
- 缺少静态资源请求、却高频访问 API 的会话。
- 取证：源 IP、端口序列、路径列表、时间分布。

## 7. 防御与验证

1. 建立 AI 资产台账，定期与网络暴露面比对。
2. 统一部署入口，管理面不直接对外。
3. 关闭详细错误信息。
4. 对端口探测与路径枚举建立检测与告警。
5. **验证**：从外网扫默认端口应全部不可达；枚举行为应触发告警。

## 8. 参考

- MITRE ATLAS AML.T0000 / T0049：https://atlas.mitre.org/
- OWASP ASI04 代理供应链：https://genai.owasp.org/
