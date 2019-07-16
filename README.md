# PacketCut
Packet CUT MTU

实现：对TCP数据包进行打包拆小包，需要重新计算checksum、seq

1. 使用libpcap通过网卡补包
2. 程序内设置MTU模拟拆包情况
