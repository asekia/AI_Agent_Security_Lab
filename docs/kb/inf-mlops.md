# MLOps 平台攻击面

> MLOps Platform Attack Surface · 分类：AI 基础设施与供应链

## 1. 问题与威胁模型

**定义**：模型之外的真实攻击面往往在 MLOps 平台：实验跟踪、模型注册、训练编排、交互式笔记本。这些平台权限大、认证弱，且被默认部署在"可信内网"。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 可访问内网或通过 SSRF/凭据泄露进入 |
| 目标 | MLflow / Kubeflow / Ray / Jupyter 等平台 |
| 前提 | 平台未认证或使用默认凭据；凭证以明文散落在笔记本与实验参数中 |

**命题**：关键风险是**凭证集中**——实验跟踪与编排平台保存数据集路径、云凭证、模型仓库密钥，一旦可直接访问，等于拿到一串下游凭据。

## 2. 原理推导

MLflow 把实验、模型、运行、制品集中在一处并通过 REST API 暴露，是最优先的枚举目标。攻击链是"枚举 → 提取制品 URI/用户 ID → 顺藤摸瓜到对象存储"：

```text
Jupyter 明文凭证 → MLflow 认证 → 注册表枚举 → 制品 URI → S3/MinIO → 模型与数据
```

无认证时中间几步可以跳过，直接从 MLflow 读到制品路径。

## 3. 攻击面与前提

| 组件 | 典型入口 | 可获取的能力 |
| --- | --- | --- |
| MLflow | 5000 端口、跟踪 API | 实验元数据、制品路径、后端存储凭证 |
| Kubeflow | 仪表盘、notebook 服务 | 集群内任务提交、镜像与数据访问 |
| Ray | 8265 仪表盘 | 集群任务提交、节点资源 |
| Jupyter | 8888 | 代码执行、挂载卷访问 |
| 训练编排 | 任务提交接口 | 以集群身份执行负载 |

## 4. 实战步骤

### 步骤 1：确认版本与认证状态

```text
curl -sv http://<host>:5000/
访问任意 API，观察是否返回 401 或直接返回数据。
```

### 步骤 2：MLflow 五步枚举

```text
1. 列出全部实验
   POST /api/2.0/mlflow/experiments/search
   → 实验名与内部 ID（常含项目代号）

2. 列出已注册模型
   GET /api/2.0/mlflow/registered-models/list
   → 模型清单：名称、描述、创建时间

3. 提取模型版本
   GET /api/2.0/mlflow/model-versions/search
   → source 字段（制品 URI，如 s3://internal-ml-models/.../artifacts/）
   → user_id、时间戳、阶段标签（Production / Staging / Archived）

4. 搜索训练运行
   POST /api/2.0/mlflow/runs/search
   → 超参数、指标、自定义标签（项目代号、Git 提交哈希、环境标识）

5. 列出可下载制品
   GET /api/2.0/mlflow/artifacts/list
```

五个调用即可映射整个 ML 产品线——前提是服务可达且未认证。

### 步骤 3：绕过认证的两个口子

```text
GraphQL：/graphql 曾长期绕过 REST 认证，未认证查询 mlflowSearchRuns / mlflowGetRun
调试参数：?debug=true / ?verbose=1 触发原始堆栈（路径、库版本、硬编码凭据）
```

### 步骤 4：其他平台入口

```text
Kubeflow：无 OIDC 的仪表盘经 LoadBalancer/NodePort 暴露 → 可创建 Jupyter
          笔记本绑定的服务账号有集群级权限
TorchServe：8081 管理接口从任意 URL 注册模型 → 恶意 .mar 加载即 RCE
SageMaker：DirectInternetAccess 开启的笔记本可接收入站连接
Jupyter：/api/kernels 列内核；/api/contents 列文件；单元格常含明文凭证
```

### 步骤 5：注册表谱系分析

```text
模型名 / 版本历史 / 阶段标签 / 时间戳 / 运行 ID / 制品 URI / 用户 ID
```

注册表是"告诉攻击者其他所有数据在哪"的地图。

## 5. 变体目录

| 编号 | 目标 | 手法 | 产出 |
| --- | --- | --- | --- |
| ML-01 | 未认证 MLflow | 五步枚举 | 实验/模型/制品路径 |
| ML-02 | 认证 MLflow | GraphQL / debug 参数 | 内部路径与凭据 |
| ML-03 | Kubeflow | 未授权创建 notebook | 集群内代码执行 |
| ML-04 | TorchServe | 8081 注册恶意模型 | RCE |
| ML-05 | Jupyter | 读取单元格明文凭证 | 下游系统访问 |

## 6. 检测与取证

- 平台是否启用认证，是否存在默认口令。
- 实验参数与配置中是否明文保存凭证。
- 模型注册表是否允许任意来源提交版本。
- 任务提交接口是否对所有可达来源开放。
- 取证：实验/模型列表、制品 URI、笔记本单元格原文（不读取凭据值）。

## 7. 防御与验证

1. 所有 MLOps 组件强制认证与授权，禁用默认凭据。
2. 平台只对内部网络开放，统一入口。
3. 实验参数与配置禁止明文凭证，改用密钥管理。
4. 注册表启用签名校验与提交审计，拒绝同名覆盖。
5. 任务提交按角色授权，限制镜像与资源。
6. **验证**：未认证访问所有平台 API 必须返回 401；注册表拒绝未签名提交。

## 8. 参考

- MITRE ATLAS AML.CS0023（ShadowRay）：https://atlas.mitre.org/
- MLflow Security Advisories：https://github.com/mlflow/mlflow/security/advisories
