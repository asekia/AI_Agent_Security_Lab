# 推理服务器指纹识别

> Inference Server Fingerprinting · 分类：AI 基础设施与供应链

## 1. 问题与威胁模型

**定义**：通过端口、响应头、错误信息与端点命名四类特征，判断目标上运行的是哪种推理框架，以及暴露了哪些管理接口。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 可从网络侧访问目标端口，可发送任意 HTTP/gRPC 请求 |
| 目标 | 推理服务与管理端点直接暴露，缺少统一网关 |
| 前提 | 默认端口/默认配置未被改动；错误信息未收敛 |

**命题**：指纹识别的目的不是攻击本身，而是确定"接下来该用哪套方法"。AI 基础设施的管理端点经常缺认证，识别正确就可能直接进入。

## 2. 原理推导

四类指纹的成因各不相同：

```text
端口       → 框架默认监听约定（vLLM 8000 / Ollama 11434 / Triton 8000-8002）
响应头     → HTTP 栈与框架注入的标识（Server / NV-Status / torchserve）
错误信息   → 开发期调试信息未关闭（tensorinfo_map / mlflow 命名空间）
端点命名   → 计算语义而非资源语义（/predict /infer /v1/models）
```

指纹的可靠性排序：错误信息 > 响应头 > 端点行为 > 端口（端口可被改，错误信息很难完全抹掉）。

## 3. 攻击面与前提

| 项 | 内容 |
| --- | --- |
| 入口 | 对外开放的推理端口与管理端口 |
| 前提 | 服务直接暴露、无认证或默认配置 |
| 观察点 | 默认端口 HTTP 服务、响应头标识、错误页版本串 |
| 影响 | 确定框架与版本，后续可针对已知问题定向测试 |

## 4. 实战步骤

### 步骤 1：端口初筛

```text
nmap -p 5000,6333,6334,8000,8001,8002,8080,8265,8500,8501,8888,9000,11434,19530 -sV <target>
```

记录命中的服务与版本。

### 步骤 2：请求头识别

```text
curl -sv http://<host>:5000/            # MLflow：Server 头 + 固定路径
curl -sv http://<host>:8080/            # TorchServe：Server: TorchServe/0.x.x
curl -I  http://<host>:8000/            # Triton：NV-Status
```

Triton 独门特征：请求头带 `endpoint-load-metrics-format: text` 时，响应头直接返回 CPU/GPU 利用率——其他框架做不到。

### 步骤 3：响应体指纹

```text
TF Serving : {"model_version_status": [{"version": "1", "state": "AVAILABLE"}]}
Triton     : {"name": "...", "versions": [...], "platform": "tensorflow_graphdef"}
OpenAI 兼容: {"object": "model", "id": "...", "created": ...}
MLflow     : 错误堆栈含 mlflow.server / mlflow.tracking
```

### 步骤 4：错误信息指纹

```text
向 TF Serving 发送整数列表 → 报错含 tensorinfo_map
向 Databricks 发坏 token  → io.jsonwebtoken.IncorrectClaimException
向 MLflow 发坏请求        → 堆栈引用 mlflow 命名空间与文件路径
```

### 步骤 5：端点命名枚举

```text
推理：/predict /invocations /infer /generate /embeddings /score
管理：/v1/models /v2/models /v2/health/ready
MLflow：/api/2.0/mlflow/（前缀唯一）
Kubeflow：/pipeline/apis/v1beta1/
```

标准字典（SecLists）不包含这些路径，需自行扩充。

### 步骤 6：gRPC 与指标

```text
grpcurl -plaintext <host>:8001 list     # 反射开启 → 全部服务与 schema
curl http://<host>:8002/metrics         # Triton 指标：模型名/版本/延迟/GPU
```

Prometheus 指标是被动情报：不调用推理 API 就能读出部署拓扑、哪些模型承压最重。

## 5. 变体目录

| 编号 | 指纹 | 观察点 | 可靠性 |
| --- | --- | --- | --- |
| IF-01 | 端口 | 默认监听 | 低（可改） |
| IF-02 | 响应头 | Server / NV-Status | 高 |
| IF-03 | 响应体 | platform / model_version_status | 高 |
| IF-04 | 错误信息 | tensorinfo_map / 命名空间 | 最高 |
| IF-05 | 端点命名 | /predict /v1/models | 中 |
| IF-06 | 指标 | /metrics 内容 | 高 |

## 6. 检测与取证

- 管理端口是否本应对外暴露（多数部署中答案是不应该）。
- 扫描特征：短时间内对多个端口的连续探测。
- 错误信息是否回显框架名称与具体版本。
- 无认证的管理端点是否可直接访问。

## 7. 防御与验证

1. 管理端口只对内部网络开放，不与推理端口共用对外入口。
2. 关闭不必要的管理端点，或前置统一认证网关。
3. 关闭详细错误信息，避免回显版本号。
4. 出口流量监控，识别批量端口探测。
5. **验证**：从外部扫默认端口应全部不可达；错误页不得出现框架名与版本。

## 8. 参考

- MITRE ATLAS AML.T0049：https://atlas.mitre.org/
- 各框架官方部署文档（默认端口与端点约定）
