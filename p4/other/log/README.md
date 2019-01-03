# Basic Template P4 switch

這個資料夾提供的是基本的 P4_16，於 BMv2 上的模版程式碼。讓 P4 programmer 能夠快速的基於這份提供的架構上，來修改成符合自己情境、需求的 P4 腳本。

## 提供的功能

* 基本提供：
  * ipv4-forwarding
  * packet-in/packet-out

如何執行程式（*需要安裝 P4 相關的軟體相依性*）：

```bash
$ ./build.sh

... (some readable logging message ...)

======================================================================
Welcome to the BMV2 Mininet CLI!
======================================================================
Your P4 program is installed into the BMV2 software switch
and your initial runtime configuration is loaded. You can interact
with the network using the mininet CLI below.

To inspect or change the switch configuration, connect to
its CLI from your host operating system using this command:
  simple_switch_CLI --thrift-port <switch thrift port>

To view a switch log, run this command from your host OS:
  tail -f ...../mimir/p4/basic-p4-template/logs/<switchname>.log

To view the switch output pcap, check the pcap files in ...../mimir/p4/basic-p4-template/pcaps:
 for example run:  sudo tcpdump -xxx -r s1-eth1.pcap

To view the P4Runtime requests sent to the switch, check the
corresponding txt file in ...../mimir/p4/basic-p4-template/logs:
 for example run:  cat ...../mimir/p4/basic-p4-template/logs/s1-p4runtime-requests.txt

mininet> h1 ping h2
PING 10.0.2.2 (10.0.2.2) 56(84) bytes of data.
64 bytes from 10.0.2.2: icmp_seq=1 ttl=62 time=7.13 ms
64 bytes from 10.0.2.2: icmp_seq=2 ttl=62 time=5.96 ms
^C
--- 10.0.2.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 5.961/6.549/7.138/0.594 ms
mininet> exit
```