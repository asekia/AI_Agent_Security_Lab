# AI 基础设施侦察方法论

> AI Infrastructure Recon Methodology · 分类：AI 基础设施与供应链

## 1. 一句话定义

把 AI 资产发现拆成可重复的五个阶段：确定目标范围、识别暴露服务、确认框架与版本、梳理管理与数据接口、形成可利用面清单。

## 2. 机制与原理

- AI 基础设施的暴露面比传统应用更分散：推理服务、管理面板、向量库、编排平台、笔记本环境各自独立，配置标准不一致。
- 这些组件通常由不同团队在不同时间搭建，缺少统一的暴露面清点，容易留下"搭完就忘"的服务。
- 因此系统化的侦察比零散试探更有效：先建清单，再逐项确认。
- 侦察阶段的产物是**资产清单**，而不是直接攻击。清单本身也是防守方最需要的资料。

## 3. 五个阶段

| 阶段 | 目标 | 主要动作 | 产出 |
| --- | --- | --- | --- |
| 1 范围确定 | 明确资产边界 | 收集域名、网段、云资源、公开文档 | 目标范围清单 |
| 2 服务识别 | 找到暴露端点 | 端口扫描、服务探测 | 暴露服务列表 |
| 3 框架确认 | 判断组件与版本 | 指纹识别、错误信息分析 | 组件与版本清单 |
| 4 接口梳理 | 弄清可做什么 | 枚举管理接口、数据接口、任务提交面 | 接口清单 |
| 5 面清单形成 | 汇总可利用面 | 交叉比对版本与公开问题、确认认证状态 | 可利用面清单 |

## 4. 典型形态与示例

```text
阶段衔接（概念演示）
范围确定
  → 对范围内主机做端口扫描，重点覆盖推理与管理常用端口
服务识别
  → 对命中端口做协议识别，区分 HTTP / gRPC / 自定义协议
框架确认
  → 读取响应头与错误页，记录组件名称与版本
接口梳理
  → 访问常见管理路径，确认认证状态与可访问范围
面清单形成
  → 把"组件 + 版本 + 认证状态 + 可达范围"整理成表格
  → 标注每一项的验证方式与优先级

```

流量特征观察（防守方视角）：

```text
典型侦察特征
  单一来源在短时间内访问大量不同端口
  请求集中在各框架的默认端口
  对固定路径的批量请求（集合列表、实验列表、模型清单）
  响应状态分布高度一致（大量 404/401），说明在枚举而非正常使用
  缺少正常客户端应有的静态资源请求
```


### 五个阶段的操作细节

**阶段 1：被动侦察（不接触目标网络）**

| 渠道 | 做法 |
| --- | --- |
| Shodan / Censys / FOFA | 按 AI 服务横幅搜目标 IP 段：`port:5000 "MLflow"`；`port:8888 title:"Home Page - Select or create a notebook"`；`http.title:"Ray Dashboard"` |
| GitHub dork | `filename:.env MLFLOW_TRACKING_URI`；`filename:.env HF_TOKEN`；`filename:config.json model_name site:github.com`——MLflow 连接串与 HF 令牌的出现频率远超预期 |
| 论文与工程博客 | 团队常在论文里写明所用框架与基础设施——对应 AML.T0000（搜索受害者公开的研究资料） |
| DockerHub / GHCR | 以组织名搜索 ML 镜像，公开镜像常带硬编码配置 |
| 招聘信息 | "MLflow 管理员""Kubeflow 平台工程师"这类 JD 直接说明了部署内容 |

**阶段 2：主动扫描**

一条覆盖大部分 ML 组件端口的命令：

```text
nmap -p 5000,6333,8000,8001,8002,8080,8265,8500,8501,8888,9000,11434,19530 \
     -sV --script=http-title,http-headers <target>
```

- 对 8001 / 8500 等 gRPC 端口跟进 grpcurl——反射开启时可 dump 全部 schema
- 对每个发现的服务检查 `/metrics`（Triton 8002、TorchServe 8082，泄露部署拓扑）

**阶段 3：API 指纹识别**

用 ffuf / feroxbuster 对每个 HTTP 服务跑 AI 专用词表：

```text
/v1/models  /v2/models  /v2/health/ready
/api/2.0/mlflow/experiments/list  /api/2.0/mlflow/registered-models/list
/pipeline/apis/v1beta1/pipelines  /api/serve/deployments/
/v1/schema  /v1/meta  /api/kernels  /api/contents
/openapi.json  /docs  /graphql  /metrics
/api/tags  /api/show  /collections  /healthz  /ping
```

对每个 200 响应应用指纹技术：看响应头、解析 JSON 结构、故意发坏请求读报错。

**阶段 4：元数据提取**

对确认的 AI 服务跑枚举链：MLflow 五步链（见"MLOps 平台攻击面"）；Triton / TF Serving 的模型配置（张量规格与框架标识）；向量库的 schema 与集合（维度反推嵌入模型）；Jupyter 的内核清单与笔记本单元格中的明文凭证。

**阶段 5：供应链复核**

- 在配置、笔记本单元格与容器构建日志里找模型下载源（Hugging Face Hub / PyTorch Hub）；能向上游注入恶意模型或持有被窃 HF 令牌的攻击者，等于污染整条供应链
- 审计 requirements.txt / Pipfile：形如 `company-data-utils` 的内部包名若未注册到 PyPI，就是可被抢注的空位——slopsquatting。USENIX Security 2025 的研究测得 16 个代码生成模型产出中 19.7% 引用了不存在的包（开源模型 21.7%、商业模型 5.2%）
- 检查模型制品桶（S3 / GCS / MinIO）是否公开可读
- 检查容器镜像仓库是否存在无凭据拉取

### 工具对照表

| 工具 | 用途 | 阶段 |
| --- | --- | --- |
| Shodan / Censys / FOFA | 全网侧 AI 服务横幅搜索 | 1 |
| GitHub dork 搜索 | 公开仓库中的泄露凭证与配置 | 1 |
| Nmap（+NSE） | 端口发现与版本识别 | 2 |
| grpcurl | gRPC 交互；反射开启时 dump schema | 2 |
| ffuf / feroxbuster | AI 专用词表目录枚举 | 2、3 |
| curl | 手工 HTTP 探测、头部分析、触发报错 | 3、4 |
| MLOKit（IBM X-Force） | MLflow 枚举与模型抽取自动化 | 4 |
| Nuclei | AI 服务错误配置的模板化扫描 | 2、3 |

## 5. 检测与观察点

- 是否存在未被清点的暴露服务（"搭完就忘"的服务）。
- 暴露服务是否启用了认证。
- 错误页面是否回显版本与内部路径。
- 是否出现过扫描特征的来源。

## 6. 防御与改进

- 建立 AI 资产台账，定期与网络暴露面做比对，找出台账之外的服务。
- 统一部署入口，管理面不直接对外。
- 关闭详细错误信息，减少版本泄露。
- 对端口探测与路径枚举做检测与告警。
- 把侦察检测纳入日常监控，而不是只在事件后排查。

## 7. 与本项目的对应

| 本地位置 | 说明 |
| --- | --- |
| `web/app.py` | 本地服务入口，可对照暴露面清点 |
| `lab/banner.py` | 启动信息输出，可观察"默认配置会泄露什么" |

## 8. 参考

- MITRE ATLAS AML.T0000（Search Open Technical Databases）、AML.T0049：https://atlas.mitre.org/
- 内部培训笔记《llm 安全问题》
