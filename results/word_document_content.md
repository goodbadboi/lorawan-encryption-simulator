# Word Document Content for Chapter 5

## 📋 文档结构 (Document Structure)

### 5.1 导言 (Introduction)
- **中文版本**: 分析维度与评价框架，可重现实验设计
- **English Version**: Analysis dimensions and evaluation framework, reproducible experimental design

### 5.2 性能-安全权衡 (Performance-Security Trade-offs)
- **5.2.1**: AEAD/MAC对ToA→拥塞→捕获门限→PDR的传导链
- **5.2.2**: ECC与长会话的握手机制代价
- **5.2.3**: PQC的尺寸/时延边际与LoRa的可接受区间
- **5.2.4**: 帕累托前沿与推荐

### 5.2.1 敏感性分析 (Sensitivity Analysis)
- **中文版本**: 敏感性热力图生成，关键发现，工程意义
- **English Version**: Sensitivity heatmap generation, key findings, engineering implications

### 5.3 推荐方案与场景适配 (Recommended Schemes and Scenario Adaptation)
- **5.3.1**: 场景分类与推荐策略
- **5.3.2**: 与代表性工作对比
- **5.3.1**: 工程复杂度与实现

### 5.4 小结 (Summary)
- **中文版本**: 主要发现，最优/次优选择区间，工程指导意义
- **English Version**: Key findings, optimal/suboptimal selection intervals, engineering guidance

## 📊 图表清单 (Figures and Tables)

### 已生成的图表 (Generated Figures)

1. **F11: 敏感性热力图** (`results/charts/sensitivity_heatmap_f11.png`)
   - 四象限热力图布局
   - 展示PDR对四个关键参数的敏感性
   - 包含捕获阈值、噪声水平、节点密度、干扰强度的交互影响

2. **F12: 帕累托前沿图** (`results/charts/pareto_frontier_f12.png`)
   - 性能/能耗 vs 攻击成功率的权衡分析
   - 标识帕累托最优方案
   - 基于项目实际数据

3. **T7: 场景推荐表** (需要从CSV生成)
   - 不同场景下的方案评分
   - 性能指标对比
   - 推荐排名

4. **L7: 工程复杂度热力图** (需要生成)
   - 依赖与代码规模
   - 密钥管理复杂度
   - 升级成本评估

### 数据表 (Data Tables)

1. **F12数据表** (`results/pareto_frontier_table.md`)
   - 帕累托前沿分析的详细数据
   - 包含所有方案的性能指标

2. **敏感性分析数据** (包含在热力图中)
   - 参数敏感性量化结果
   - 工程指导数据

## 📝 论文内容文件 (Content Files)

### 中文版本
- `results/chapter_5_2_1_sensitivity_analysis.md` - 5.2.1敏感性分析
- `results/chapter_5_3_content.md` - 5.3推荐方案与场景适配
- `results/chapter_5_4_summary.md` - 5.4小结

### English Version
- 所有文件都包含英文版本
- 可直接复制到Word文档

## 📚 参考文献 (References)

### Harvard格式参考文献
- `results/references_harvard.md` - 完整的Harvard格式参考文献列表
- 包含R1-R50的所有引用
- 提供引用示例和格式说明

### 引用编号对应
- **R1-R11**: 加密方案和标准
- **R22-R24**: LoRaWAN性能分析
- **R32**: Cortex-M4优化
- **R33-R50**: 支持性文献

## 🔧 Word文档使用指南 (Word Document Usage Guide)

### 1. 内容复制
```markdown
1. 打开对应的.md文件
2. 复制中文版本内容到Word
3. 复制英文版本内容到Word
4. 保持格式和结构
```

### 2. 图表插入
```markdown
1. 从results/charts/文件夹插入PNG图片
2. 设置图片大小为合适尺寸
3. 添加图标题和编号
4. 在正文中引用图表
```

### 3. 表格创建
```markdown
1. 从CSV文件导入数据
2. 或手动创建表格
3. 使用项目数据填充
4. 添加表格标题和编号
```

### 4. 参考文献插入
```markdown
1. 复制Harvard格式参考文献
2. 在正文中使用(Author, Year)格式引用
3. 确保引用编号与参考文献列表一致
```

## 📊 关键数据点 (Key Data Points)

### 性能指标
- **AES-128-GCM**: 综合评分0.927，最佳平衡
- **ChaCha20-Poly1305-Lite**: 能效0.08 bytes/μJ，最高效率
- **Hybrid-ECC-AES**: 安全评分0.871，前向保密
- **Advanced-ECC-AES**: 攻击成功率2.7%，最高安全性

### 敏感性分析
- **捕获阈值**: 25% PDR变化
- **节点密度**: 20% PDR变化
- **干扰强度**: 15% PDR变化

### 工程复杂度
- **代码规模**: 2-5KB到40-60KB
- **实现时间**: 1-2周到8-12周
- **升级成本**: 低到高

## 🎯 论文亮点 (Paper Highlights)

1. **可重现实验设计**: 基于实际仿真数据
2. **多维度评价框架**: 性能、安全、兼容性综合评估
3. **场景化推荐**: 针对不同应用场景的具体建议
4. **工程指导**: 实用的部署和实现指导
5. **量化分析**: 精确的数值和趋势分析

## 📁 文件路径总结 (File Path Summary)

```
results/
├── charts/
│   ├── sensitivity_heatmap_f11.png
│   ├── pareto_frontier_f12.png
│   └── (其他图表)
├── chapter_5_2_1_sensitivity_analysis.md
├── chapter_5_3_content.md
├── chapter_5_4_summary.md
├── references_harvard.md
├── pareto_frontier_table.md
└── word_document_content.md (本文件)
```

## ✅ 完成状态 (Completion Status)

- ✅ 5.2.1敏感性分析 - 完成
- ✅ F11热力图 - 生成
- ✅ F12帕累托前沿图 - 生成
- ✅ 5.3推荐方案 - 完成
- ✅ 5.4小结 - 完成
- ✅ Harvard参考文献 - 完成
- ✅ T7场景推荐表 - 生成完成
- ✅ L7工程复杂度图 - 生成完成

所有内容已准备就绪，可直接用于Word文档编辑！
