# 推理服务器指纹识别

> Inference Server Fingerprinting · 分类：AI 基础设施与供应链

## 1. 一句话定义

通过端口、响应头、错误信息与端点命名这四类特征，判断目标上运行的是哪种推理框架，以及它暴露了哪些管理接口。

## 2. 机制与原理

- 推理框架大多有默认监听端口与固定的响应特征。当它们直接暴露在网络中时，很容易被识别。
- 四类可用指纹：
  1. **端口**：不同框架的默认监听端口不同。
  2. **响应头**：特定 HTTP 头只会在某些框架中出现。
  3. **错误信息**：异常响应常常带出框架名称与版本。
  4. **端点命名**：管理端点与推理端点的路径带有框架特色。
- 指纹识别的目的不是攻击本身，而是确定"接下来该用哪套方法继续"。
- 与普通 Web 指纹的区别在于：AI 基础设施的管理端点经常缺少认证，识别正确就可能直接进入。

## 3. 攻击面与前提

| 项 | 内容 |
| --- | --- |
| 入口 | 对外开放的推理端口与管理端口 |
| 成立前提 | 服务直接暴露、无认证或使用默认配置 |
| 观察点 | 默认端口上的 HTTP 服务；响应头中的框架标识；错误页中的版本字符串 |
| 影响 | 框架类型与版本被确定，后续可针对已知问题做定向测试 |

## 4. 典型形态与示例

### 推理服务

| 框架 | 常见端口 | 可识别特征 |
| --- | --- | --- |
| NVIDIA Triton | 8000 / 8001 / 8002 | 响应头含 `NV-Status`；8002 为指标端口，含 `endpoint-load-metrics-format` |
| TensorFlow Serving | 8500 / 8501 | 管理接口在 8501，响应中包含 `tensorinfo_map` |
| TorchServe | 8080 / 8081 / 8082 | `Server` 头含 `TorchServe/0.x.x` |
| MLflow | 5000 | 跟踪服务，页面与 API 路径固定 |
| Jupyter | 8888 | 登录页与 `/api` 路径固定 |
| Ray | 8265 | 仪表盘端口 |
| Ollama | 11434 | 本地模型服务接口 |
| vLLM | 8000 | 提供 OpenAI 兼容接口 |
| SGLang | 30000 | 默认服务端口 |
| LMDeploy | 23333 | 默认服务端口 |
| Xinference | 9997 | 默认服务端口 |
| llama.cpp server | 8080 | 轻量推理服务 |

### 向量数据库

| 组件 | 常见端口 | 说明 |
| --- | --- | --- |
| Qdrant | 6333 / 6334 | 6333 提供 HTTP，6334 提供 gRPC |
| Weaviate | 8080 | REST 与 GraphQL |
| Milvus | 19530 | gRPC |
| Chroma | 8000 | HTTP |

### 探测流程（概念演示）

```text
1. 端口探测，记录命中的服务
2. 对命中端口发起普通 GET，观察响应头与错误页
3. 在响应中寻找框架标识、版本字符串、内部路径
4. 访问常见管理路径，观察是否返回接口清单
5. 对管理端点做无认证访问测试
```


### 推理端点路径（按框架）

端口之外，路径本身也是指纹：

| 框架 | 端口 | 典型路径 |
| --- | --- | --- |
| vLLM | 8000 | `/v1/chat/completions`、`/v1/models` |
| Ollama | 11434 | `/api/chat`、`/api/generate`、`/v1/chat/completions` |
| SGLang | 30000 | `/v1/chat/completions`、`/v1/models`、`/health`、`/server_info` |
| LMDeploy | 23333 | `/v1/chat/completions`、`/v1/models` |
| Xinference | 9997 | `/v1/chat/completions`、`/v1/models` |
| llama.cpp server | 8080 | `/v1/chat/completions`、`/completion` |
| TorchServe | 8080 | `/predictions/{model_name}` |
| Triton | 8000 HTTP / 8001 gRPC | `/v2/models/{model}/infer`、`/v2/models/{model}/config` |
| TensorFlow Serving | 8500 gRPC / 8501 HTTP | `/v1/models/{model}/metadata` |
| Nginx / API 网关 | 443 | 通常转发到 `/v1/chat/completions` |

同时用 HTTP 与 gRPC 的原因：内部服务间传大包走 gRPC 更快，客户端接入走 REST 更方便。

### API 响应指纹

各框架返回的 JSON 结构不同，看响应即可识别对方是谁：

- 与 OpenAI 兼容的端点返回 `{"object": "model", "id": ..., "created": ...}`——看到 `"object": "model"` 即可把候选缩小到 vLLM / Ollama / LiteLLM 及其封装。
- TensorFlow Serving 返回 `{"model_version_status": [{"version": "1", "state": "AVAILABLE"}]}`。
- Triton 返回 `{"name": ..., "versions": [...], "platform": "tensorflow_graphdef"}`——`platform` 字段直接说明模型由哪个框架构建。
- MLflow 的错误堆栈会引用 `mlflow.server` / `mlflow.tracking` 命名空间——连报错都在报身份。

### 错误信息指纹

推理 API 对输入的张量结构与类型有严格要求。故意发送格式错误的请求，从报错里读框架：

- 对期望张量对象的 TensorFlow Serving 发送整数列表，报错包含 `tensorinfo_map`——该词几乎只出现在 TF Serving 的错误里。
- MLflow 的报错堆栈引用 `mlflow.server` / `mlflow.tracking` / databricks 命名空间；路径遍历类漏洞被触发时还会暴露服务器完整文件系统路径。
- Databricks Mosaic AI 遇到格式错误的令牌会抛出 Java 异常 `io.jsonwebtoken.IncorrectClaimException`，可直接定位问题组件。
- Triton 有独门特征：请求头带 `endpoint-load-metrics-format: text` 时，响应头直接返回 CPU / GPU 利用率——看到头部有 GPU 数据即在与 Triton 交互。
- 这套方法有效的原因：数据科学家开发期需要详细调试信息，框架默认开着详细报错，部署前很少关闭。

### gRPC 反射

对 8001 / 8500 等 gRPC 端口执行 `grpcurl -plaintext <host:port> list`：若服务启用了反射，任何客户端无需 proto 定义即可列出全部服务与方法——等于拿到完整 API 模式。

### 端点命名与词表

传统 REST 用资源命名（`/users`、`/accounts`），AI 端点用计算操作命名，对目录枚举非常友好：

- 推理：`/predict`、`/invocations`（SageMaker 命名惯例）、`/infer`、`/generate`、`/embeddings`、`/score`
- 模型管理：`/v1/models`、`/v2/models`、`/v2/health/ready`
- MLflow 内部：`/api/2.0/mlflow/`（该前缀唯一，其他框架没有）
- Kubeflow 管道：`/pipeline/apis/v1beta1/`

SecLists 等标准字典不包含这些路径——需要自行扩充进 ffuf / feroxbuster 的词表。

### Prometheus 指标 = 被动情报

推理服务器通常在独立端口暴露 `/metrics`（Triton 8002、TorchServe 8082），不碰推理 API 就能读出：

- 当前加载的模型名称与版本
- 推理请求数与延迟分位数
- 正在处理的批大小
- 每模型 GPU 内存占用

部署拓扑、哪些模型承压最重、GPU 资源分布——这些情报在"未调用模型"的情况下就能拿全。

## 5. 检测与观察点

- 管理端口是否本应对外暴露（多数部署中答案是不应该）。
- 是否存在扫描特征：短时间内对多个端口的连续探测。
- 错误信息是否回显框架名称与具体版本。
- 无认证的管理端点是否可以直接访问。

## 6. 防御与改进

- 管理端口只对内部网络开放，不与推理端口共用对外入口。
- 关闭不必要的管理端点，或在前面加统一的认证网关。
- 关闭详细错误信息输出，避免回显版本号。
- 在出口做流量监控，识别批量端口探测行为。
- 定期清点暴露面，确认没有遗留的默认端口服务。

## 7. 与本项目的对应

| 本地位置 | 说明 |
| --- | --- |
| `web/app.py` | 本地 Web 服务入口，可对照端口暴露方式 |
| `lab/framework/llm.py` | 模型调用层，对应"推理服务"的位置 |
| `lab/framework/registry.py` | 模型与资源登记，对应资产清点 |

## 8. 参考

- 内部培训笔记《llm 安全问题》
- MITRE ATLAS AML.T0049（Exploit Public-Facing Application）：https://atlas.mitre.org/
