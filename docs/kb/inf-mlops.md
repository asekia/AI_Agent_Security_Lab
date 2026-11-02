# MLOps 平台攻击面

> MLOps Platform Attack Surface · 分类：AI 基础设施与供应链

## 1. 一句话定义

模型之外的真实攻击面往往在 MLOps 平台：实验跟踪、模型注册、训练编排、交互式笔记本。这些平台通常权限很大、认证很弱，且被默认部署在内部网络中当作"可信"。

## 2. 机制与原理

- MLOps 平台的设计出发点是"方便协作"，因此常见形态是：默认无认证、界面直接可访问、能读取制品与凭证。
- 关键风险点是**凭证集中**：实验跟踪与编排平台会保存数据集路径、云凭证、模型仓库密钥，一旦可直接访问，等于拿到一串下游凭据。
- 常见组件的暴露面：
  - **MLflow**：跟踪与注册服务，默认端口 5000。后端存储配置中可能包含数据库与对象存储凭证。
  - **Kubeflow**：Kubernetes 上的 ML 工作流平台，仪表盘与 notebook 服务是主要入口。
  - **Ray**：分布式框架，仪表盘端口 8265。历史上出现过仪表盘暴露后被利用的公开案例（见 AML.CS0023）。
  - **Jupyter**：交互式环境，默认端口 8888。能执行代码即等于能访问其挂载的全部资源。
  - **Ray / Kubeflow / Argo 等编排面**：提交任务的能力往往等价于在其管理的集群上执行任意负载。

## 3. 攻击面与前提

| 组件 | 典型入口 | 可获取的能力 |
| --- | --- | --- |
| MLflow | 5000 端口、跟踪 API | 实验元数据、制品路径、后端存储凭证 |
| Kubeflow | 仪表盘、notebook 服务 | 集群内任务提交、镜像与数据访问 |
| Ray | 8265 仪表盘 | 集群任务提交、节点资源 |
| Jupyter | 8888 | 代码执行、挂载卷访问 |
| 训练编排 | 任务提交接口 | 以集群身份执行负载 |

成立前提基本一致：服务可达，且未启用认证或使用了默认弱口令。

## 4. 典型形态与示例

```text
1. 未认证访问
   直接访问仪表盘或 API，无需任何凭据即可读取实验列表与制品信息

2. 凭证提取
   从平台配置或实验参数中读取下游系统的凭据
   这类参数在提交训练任务时常被直接写入记录

3. 制品替换
   向模型注册表提交同名版本，等待下游部署流程自动拉取

4. 任务提交滥用
   利用编排接口提交任务，在集群内获得代码执行能力（见本分类的 CVE 速查页）

5. 笔记本横向
   交互式环境通常挂载了数据卷与集群凭据
   进入笔记本即可访问同环境内的其他资源

6. 枚举顺序（概念演示）
   识别平台类型与版本
   → 检查是否可直接访问
   → 读取实验与制品列表，寻找敏感参数
   → 确认注册表与存储的写入能力
   → 评估任务提交接口
```


### MLflow 枚举链（五步）

MLflow 把实验、模型、运行、制品集中在一处并通过干净的 REST API 暴露，是最优先的枚举目标：

```text
1. 列出全部实验
   POST /api/2.0/mlflow/experiments/search
   → 每个实验的名称与内部 ID；实验名常含项目代号与业务目标
     （如 fraud-detection-v3、rag-embeddings-tuning）

2. 列出已注册模型
   GET /api/2.0/mlflow/registered-models/list
   → 全部模型清单：名称、描述、创建时间

3. 提取模型版本
   GET /api/2.0/mlflow/model-versions/search
   → source 字段（制品 URI，常指向 s3://internal-ml-models-.../artifacts/）
   → user_id（创建者）、时间戳、阶段标签
     （Production / Staging / Archived，可区分生产与测试模型）

4. 搜索训练运行
   POST /api/2.0/mlflow/runs/search
   → 超参数、训练指标、自定义标签
     （团队常用标签存项目代号、Git 提交哈希、部署环境标识）

5. 列出可下载制品
   GET /api/2.0/mlflow/artifacts/list
```

五个调用即可把整个 ML 产品线映射完毕——前提是服务可达且未认证。

### 绕过认证的两个口子

- GraphQL 端点 `/graphql`：曾长期可绕过 REST API 的认证层，未认证即可查询 `mlflowSearchRuns`、`mlflowGetRun` 等内部接口，读出用户名、源码路径与项目详情。
- 调试参数：端点追加 `?debug=true` / `?verbose=1` 会触发原始堆栈——包含文件系统路径、库版本，偶尔还有从环境变量加载失败的硬编码凭据。
- 认证的历史也要注意：MLflow 2.x 之前默认完全无认证；加入认证功能后又出现过默认凭据问题（见 CVE 速查页 CVE-2026-2635）。

### 其他平台的入口细节

| 平台 | 细节 |
| --- | --- |
| Kubeflow | 仪表盘常在不配 OIDC 的情况下经 Kubernetes LoadBalancer / NodePort 直接暴露；未认证用户可创建 Jupyter 笔记本，而笔记本绑定的服务账号具有集群级权限——一条直通容器编排层的路径 |
| TorchServe | 8081 管理接口允许从任意 URL 动态注册模型；模型加载过程会执行初始化代码——加载恶意 `.mar` 存档即可能 RCE |
| SageMaker | `DirectInternetAccess: Enabled` 的笔记本实例可接受来自互联网的入站连接 |
| Jupyter | `GET /api/kernels` 列出运行中内核（名称、ID、最后活跃时间）；`GET /api/contents` 列出笔记本文件。数据科学家常把 MLflow 凭证、云存储密钥、Hugging Face 令牌明文写在单元格——这是从单点服务突破到整个系统的关键跳板 |

### 模型注册表为什么是最有价值的目标

注册表不只是模型文件的仓库，它保存完整的谱系：模型名、版本历史、阶段标签、创建时间、可链接到全部训练元数据的运行 ID、指向内部云存储的制品 URI、每位贡献者的用户 ID。IBM X-Force 记录的利用模式是：从一个 Jupyter 笔记本中找到 MLflow 凭证，随后对注册表做完整枚举并逐个抽走模型制品。注册表是那张"告诉攻击者其他所有数据在哪"的地图。

### 案例研究：IBM X-Force MLOKit 攻击链

IBM X-Force Red 在《Becoming the Trainer: Attacking ML Training Infrastructure》研究（含 TROOPERS 会议演讲与开源工具 MLOKit）中记录了完整链条：

```text
1. 对一名数据科学家做网络钓鱼 → 进入 Azure ML 环境
2. 在 Jupyter 笔记本单元格中发现明文 MLflow 凭证
3. 用 MLOKit 自动化枚举：
   list-models   枚举已注册模型
   download-model 提取版本元数据与制品标识
   —— 与上面的五步链路走同一批 REST API，但对服务器而言全是"正常认证请求"
4. 顺藤摸瓜：Jupyter → MLflow 跟踪服务器 → 模型注册表 → S3 制品桶
   三个组件环环相扣，任一被攻破即波及全局
5. 后续扩展模块：
   list-notebooks       枚举笔记本
   add-notebook-trigger 借生命周期配置执行代码
   poison-model         覆盖模型制品
```

这次事件的结论不是发现了什么 0day，而是：每个服务都"正常可达"，把它们连起来的凭证就躺在笔记本单元格里。IBM 团队同时发布了针对 Azure ML / SageMaker / MLflow 的检测规则。

## 5. 检测与观察点

- 平台是否启用了认证，是否存在默认口令。
- 实验参数与配置中是否明文保存凭证。
- 模型注册表是否允许任意来源提交版本。
- 任务提交接口是否对所有可达来源开放。
- 是否有从笔记本环境发起的、超出预期的集群操作。

## 6. 防御与改进

- 所有 MLOps 组件强制启用认证与授权，禁用默认凭据。
- 平台只对内部网络开放，通过统一入口提供访问。
- 实验参数与配置中禁止明文凭证，改用外部密钥管理。
- 模型注册表启用签名校验与提交审计，拒绝同名覆盖。
- 任务提交接口按角色授权，限制可使用的镜像与资源。
- 定期审计平台上的凭据引用与访问记录。

## 7. 与本项目的对应

| 本地位置 | 说明 |
| --- | --- |
| `lab/framework/registry.py` | 本地资源登记模块，对应"模型注册表"的概念 |
| `lab/multi_agent.py` | 多智能体编排，可对照任务提交面 |
| `web/app.py` | 本地服务入口，对应"未认证 DashBoard"的对照面 |

## 8. 参考

- MITRE ATLAS AML.CS0023（ShadowRay）：https://atlas.mitre.org/
- MITRE ATLAS AML.T0049（Exploit Public-Facing Application）：https://atlas.mitre.org/
- IBM X-Force: Becoming the Trainer — Attacking ML Training Infrastructure：https://www.ibm.com/
- 内部培训笔记《llm 安全问题》
