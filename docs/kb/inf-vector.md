# 向量数据库枚举

> Vector Database Enumeration · 分类：AI 基础设施与供应链

## 1. 问题与威胁模型

**定义**：向量数据库常默认无认证、对外开放。枚举它可以得到集合结构、向量维度与元数据——足以推断业务范围与所用嵌入模型。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 可访问向量库端口 |
| 目标 | Qdrant / Weaviate / Milvus / Chroma 等 |
| 前提 | 未启用认证或使用默认配置 |

**命题**：向量库泄露的不是明文文档，而是**结构元数据**。集合名、维度、点数、字段名组合起来，等于一份业务与模型清单。

## 2. 原理推导

可枚举的信息分三层：

```text
结构层：集合名、向量维度、距离度量        → 系统组成
内容层：向量数量、元数据字段              → 业务规模与字段
语义层：维度 + 字段名 + 集合名            → 嵌入模型与业务领域
```

维度是强线索：768 维常见于 BERT/sentence-transformers 系；1536/3072 常见于商用嵌入 API。字段名暴露业务结构（客户标识、文档类型、租户编号）。

## 3. 攻击面与前提

| 组件 | 默认端口 | 可识别特征 |
| --- | --- | --- |
| Qdrant | 6333 / 6334 | 6333 HTTP，6334 gRPC |
| Weaviate | 8080 | REST 与 GraphQL |
| Milvus | 19530 | gRPC |
| Chroma | 8000 | HTTP（旧版本默认无认证） |

## 4. 实战步骤

### 步骤 1：识别组件

```text
curl -s http://<host>:6333/            # Qdrant 首页/版本
curl -s http://<host>:8080/v1/meta     # Weaviate 版本与已安装模块
```

### 步骤 2：列出集合

```text
Qdrant : GET /collections
Weaviate: GET /v1/schema
Chroma : GET /api/v1/collections（旧版本）
```

### 步骤 3：读取集合详情

```text
Qdrant : GET /collections/{name}
→ dim（维度）、distance（度量）、points_count（点数）
Weaviate: GET /v1/schema
→ 类定义、属性名、vectorizer 字段（直接说明嵌入模型）
```

### 步骤 4：推断业务与模型

```text
集合名 internal-hr-policies + 768 维 + 50,000 点
→ 内部 HR 政策文档、BERT 系嵌入模型、语料约 5 万条
```

### 步骤 5：未认证数据查询（若可用）

```text
Weaviate 未认证实例：schema 查询与数据查询全套可用
→ 直接读取文档内容，不止结构
```

## 5. 变体目录

| 编号 | 目标 | 端点 | 产出 |
| --- | --- | --- | --- |
| VDB-01 | Qdrant | /collections | 集合名、维度、点数 |
| VDB-02 | Weaviate | /v1/meta, /v1/schema | 模块、类、vectorizer |
| VDB-03 | Milvus | gRPC 反射 | 集合与 schema |
| VDB-04 | Chroma | /api/v1/collections | 集合列表（旧版无认证） |
| VDB-05 | 任意 | 数据查询接口 | 文档内容 |

## 6. 检测与取证

- 向量库端口是否对外可达，是否启用认证。
- 来自外部的结构枚举特征：连续请求集合列表与配置接口。
- 集合命名是否泄露租户或业务信息。
- 元数据中是否包含敏感字段。
- 取证：集合列表、维度/点数、字段名（不读取文档内容）。

## 7. 防御与验证

1. 向量库启用认证与授权，按租户划分命名空间并强制隔离。
2. 服务只对内部网络开放。
3. 最小化元数据字段：不写入与检索无关的业务标识。
4. 关闭不必要的枚举接口，限制集合列表可见范围。
5. **验证**：未认证请求集合列表必须返回 401；元数据中不得出现租户标识。

## 8. 参考

- OWASP Top 10 for LLM Applications (2025) LLM08：https://genai.owasp.org/llm-top-10/
- MITRE ATLAS AML.T0085：https://atlas.mitre.org/
