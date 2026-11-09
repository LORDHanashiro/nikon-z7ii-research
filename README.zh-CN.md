# Nikon Z7 II C1.70：真正10-bit N-Log机内录卡研究

[English](README.md)

**尚未实现真正的10-bit N-Log机内录制；原厂编码器是否具备10-bit能力也尚未证实。** 当前没有确认可持续访问的真实高位深N-Log帧源。8-bit扩展、模拟Log、修改元数据或合成测试均不算实现。

本仓库公开既有离线研究的描述性结论、地图、索引及自研工具，不发布固件。当前研究因像素来源、有效位、格式、帧所有权与硬件契约不足而受阻。本次整理没有开展新的固件逆向或实机实验。

入口：[研究结果](docs/findings.md)、[架构](docs/architecture.md)、[HDMI/N-Log](docs/hdmi-nlog.md)、[编码器](docs/encoder.md)、[RAW](docs/raw.md)、[纠错](docs/corrections.md)、[证据分级](docs/evidence.md)。

索引保留MAS/SLA/EX地址域、分析标签、ISA声明、关系和证据等级，不包含原厂指令字节、反汇编或反编译原文。AN_名称与部分结构是分析元数据，不是尼康原始符号。相同数值地址不等于同一模块、物理芯片或运行实例。

Ghidra恢复工具只导入标签、注释和部分类型；要求本地合法输入的完整SHA-256匹配，不修改固件字节、不创建虚构xref或强制函数边界。自研宿主工具只证明有限合成数据的软件性质，不证明相机像素、DMA、编码能力或写卡吞吐。

不提供固件、解密模块、密钥、RAM/NVRAM转储、设备身份、私人数据或Ghidra数据库。不包含第三方实现代码；来源与许可证见[THIRD_PARTY.md](THIRD_PARTY.md)。公开查看不自动授予通用开源许可，见[COPYRIGHT.md](COPYRIGHT.md)。

测试命令：`python3 -m unittest discover -s tests -v`。公开更新需先生成本地候选、完整历史审计和文件清单，再经确认推送；私有备份历史绝不并入公开仓库。
