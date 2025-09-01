# T7: 场景推荐表详细说明 (Scenario Recommendation Table Details)

## 表格概述

**表T7**展示了不同LoRaWAN应用场景下加密方案的推荐排名和评分。该表格基于项目的实际仿真数据，综合考虑了性能指标、安全评分和场景特定需求。

## 表格结构

### 性能指标列
- **Energy (mJ)**: 平均能耗（毫焦耳）
- **ToA (s)**: 传输时间（秒）
- **Overhead (B)**: 加密开销（字节）
- **Success Rate (%)**: 传输成功率（百分比）

### 安全指标列
- **Security Score**: 安全评分（0-1，越高越好）
- **Attack Success Rate (%)**: 攻击成功率（百分比，越低越好）

### 场景评分列
- **low_power_periodic_score**: 低功耗周期上报场景评分
- **stable_long_session_score**: 稳定长会话场景评分
- **high_compliance_long_life_score**: 高合规长寿命场景评分

### 排名列
- **low_power_periodic_rank**: 低功耗场景排名
- **stable_long_session_rank**: 长会话场景排名
- **high_compliance_long_life_rank**: 高合规场景排名

## 场景权重分配

### 1. 低功耗周期上报 (Low-power Periodic Reporting)
- **能耗权重**: 50%
- **开销权重**: 30%
- **安全权重**: 20%
- **适用场景**: 电池供电设备，定期上报传感器数据

### 2. 稳定长会话 (Stable Long Sessions)
- **安全权重**: 40%
- **性能权重**: 40%
- **开销权重**: 20%
- **适用场景**: 需要前向保密的长期连接

### 3. 高合规长寿命 (High Compliance and Long Lifespan)
- **安全权重**: 60%
- **合规权重**: 30%
- **性能权重**: 10%
- **适用场景**: 需要长期安全保护的关键应用

## 推荐结果解读

### 低功耗周期上报场景
1. **ChaCha20-Poly1305-Lite**: 最高评分，最低能耗和开销
2. **AES-128-GCM**: 第二选择，平衡性能
3. **ChaCha20-Poly1305**: 第三选择，适中性能

### 稳定长会话场景
1. **Hybrid-ECC-AES**: 最高评分，提供前向保密
2. **AES-128-GCM**: 第二选择，综合性能最佳
3. **ChaCha20-Poly1305-Lite**: 第三选择，能效优先

### 高合规长寿命场景
1. **Advanced-ECC-AES**: 最高评分，最高安全性
2. **Hybrid-ECC-AES**: 第二选择，平衡安全与性能
3. **AES-128-GCM**: 第三选择，成熟稳定

## 工程指导意义

### 部署建议
1. **资源受限设备**: 选择ChaCha20-Poly1305-Lite
2. **标准应用**: 选择AES-128-GCM
3. **高安全需求**: 选择Hybrid-ECC-AES
4. **极端安全需求**: 选择Advanced-ECC-AES

### 升级路径
1. **从对称方案升级**: AES-128-GCM → Hybrid-ECC-AES
2. **从低功耗方案升级**: ChaCha20-Poly1305-Lite → AES-128-GCM
3. **向后量子过渡**: Advanced-ECC-AES → ML-KEM混合方案

## 数据来源

- **性能数据**: 来自`simulation_report.json`
- **安全数据**: 来自`security_report.json`
- **评分算法**: 基于加权组合的归一化指标

## 表格文件位置

- **CSV格式**: `results/scenario_recommendation_table_t7.csv`
- **图表版本**: `results/charts/scenario_recommendation_t7.png`
- **详细说明**: `results/t7_scenario_recommendation_table.md`

## 在论文中的引用

在5.3节"推荐方案与场景适配"中引用此表格：

```markdown
表T7展示了不同应用场景下加密方案的推荐排名。结果表明，ChaCha20-Poly1305-Lite在低功耗场景中表现最佳，
Hybrid-ECC-AES在长会话场景中提供最佳平衡，Advanced-ECC-AES在高合规场景中安全性最高。
这些推荐基于项目的实际仿真数据，为工程部署提供了数据驱动的决策支持。
```
