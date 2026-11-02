# 模型文件反序列化

> Model File Deserialization · 分类：AI 协议与运行时

## 1. 问题与威胁模型

**定义**：模型加载器使用能执行代码的格式（pickle/dill/joblib 等），加载时执行文件内的对象，实现任意代码执行。

**威胁模型**：

| 角色 | 能力 |
| --- | --- |
| 攻击者 | 能提供一个会被加载的模型文件 |
| 目标 | 加载器使用不安全反序列化格式 |
| 前提 | 未限制格式；未校验来源与签名 |

**命题**：危险的不是"模型参数"，而是**文件格式**——pickle 在还原对象时会调用 `__reduce__`，等于执行代码。

## 2. 原理推导

```text
pickle.load(f) → 解析字节流 → 调用 __reduce__ → 执行任意函数
```

安全格式（safetensors）只存张量，不含对象图，加载时不会执行代码。

## 3. 攻击面与前提

| 项 | 内容 |
| --- | --- |
| 入口 | 模型仓库、制品桶、用户上传 |
| 前提 | 允许 pickle/pkl/.pt/torch.load/joblib |
| 观察点 | 文件扩展名与加载方式 |
| 影响 | 加载即 RCE |

## 4. 实战步骤

### 步骤 1：确认加载格式

```text
观察：允许哪些扩展名？加载函数是 torch.load 还是 safetensors？
```

### 步骤 2：构造载荷（授权测试环境）

```text
在 pickle 中定义 __reduce__ 返回 (os.system, ("id",))
命名为 model.pkl 上传。
```

### 步骤 3：验证执行

```text
触发加载，观察命令是否执行。
```

### 步骤 4：判定

```text
加载时执行了文件内对象 = RCE 成立
```

## 5. 变体目录

| 编号 | 格式 | 危险点 | 判定 |
| --- | --- | --- | --- |
| MF-01 | pickle/pkl | __reduce__ | 代码执行 |
| MF-02 | torch.load | 默认 pickle 后端 | 代码执行 |
| MF-03 | joblib | pickle 封装 | 代码执行 |
| MF-04 | .bin/.pt | 可能仍是 pickle | 需核验 |

## 6. 检测与取证

- 上传文件的真实格式（魔数）与扩展名是否一致。
- 加载器是否启用 weights_only / safetensors。
- 取证：文件 hash、加载日志、进程树。

## 7. 防御与验证

1. **只允许 safetensors**：纯张量、无对象图。
2. **来源与签名**：模型文件签名校验。
3. **隔离加载**：在沙箱中加载，限制文件与网络。
4. **验证**：MF-01~04 回归；不安全格式必须被拒绝。

## 8. 参考

- OWASP Agentic AI Top 10 ASI05：https://genai.owasp.org/
- Hugging Face: pickle 安全指南：https://huggingface.co/docs/hub/security-pickle
