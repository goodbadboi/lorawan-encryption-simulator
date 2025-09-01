# Chapter 5.3: 推荐方案与场景适配

## 中文版本

### 5.3 推荐方案与场景适配

基于前文的性能-安全权衡分析，我们建立了面向不同应用场景的加密方案推荐框架。

#### 5.3.1 场景分类与推荐策略

**1. 低功耗周期上报（对称+短Tag）**
- **推荐方案**: ChaCha20-Poly1305-Lite
- **理由**: 最低能耗(3.13 mJ)，最小开销(16字节)，快速传输(0.155s)

**2. 稳定长会话（ECC混合）**
- **推荐方案**: Hybrid-ECC-AES  
- **理由**: 前向保密，平衡性能(87.1%安全评分)，适中能耗(3.20 mJ)

**3. 高合规与长寿命（过渡到ML-KEM混合）**
- **推荐方案**: Advanced-ECC-AES
- **理由**: 最高安全性(58.9%安全评分)，长期保护，合规认证

#### 5.3.2 与代表性工作对比

**表T7**展示了与R5–R7、R22–R24的数值与趋势对照，在性能指标、工程实现和部署成本方面进行对比。

### 5.3.1 工程复杂度与实现

- **依赖与代码规模**: 从2-5KB(AES-128-GCM)到40-60KB(Advanced-ECC-AES)
- **密钥管理**: 从简单密钥分发到复杂生命周期管理
- **升级成本**: 从低升级成本到高系统重构成本

**码L7（统计/CI）**再次引用以支撑可复现性。

## English Version

### 5.3 Recommended Schemes and Scenario Adaptation

Based on the performance-security trade-off analysis, we established an encryption scheme recommendation framework for different application scenarios.

#### 5.3.1 Scenario Classification and Recommendation Strategy

**1. Low-power Periodic Reporting (Symmetric + Short Tag)**
- **Recommended**: ChaCha20-Poly1305-Lite
- **Rationale**: Lowest energy consumption (3.13 mJ), minimal overhead (16 bytes), fast transmission (0.155s)

**2. Stable Long Sessions (ECC Hybrid)**
- **Recommended**: Hybrid-ECC-AES
- **Rationale**: Forward secrecy, balanced performance (87.1% security score), moderate energy (3.20 mJ)

**3. High Compliance and Long Lifespan (Transition to ML-KEM Hybrid)**
- **Recommended**: Advanced-ECC-AES
- **Rationale**: Highest security (58.9% security score), long-term protection, compliance certification

#### 5.3.2 Comparison with Representative Works

**Table T7** shows numerical and trend comparison with R5–R7, R22–R24 in performance metrics, engineering implementation, and deployment costs.

### 5.3.1 Engineering Complexity and Implementation

- **Dependencies and Code Size**: From 2-5KB (AES-128-GCM) to 40-60KB (Advanced-ECC-AES)
- **Key Management**: From simple key distribution to complex lifecycle management
- **Upgrade Cost**: From low upgrade cost to high system restructuring cost

**Code L7 (statistics/CI)** is cited again to support reproducibility.
