# Hash Collision 

本章節探討於所選擇的 Sketch 所使用的 `table size` 與 `hash algorithm` 之下，所造成 Hash collision 的量。

## 比較表

程式由 P4 的 software switch 來做摹擬，並透過 register 來製作對應的 key-value table，對 IP、Port 所造成的 Hash collision 做探討。

透過 tcpreplay 的方式，我們將一份於我自己實驗室電腦（IP: `140.116.245.247`）所錄製的流量 - 1.1G，整份 available packets 數量為 `1678982` 個，以 `100 mbps` 的速度於 software switch 與 mininet 的摹擬網路當中做測試。

IP collision 的來源是計算，在同樣的 flow id (srcIP & dstIP 所做的 hash) 下，其 srcIP, dstIP 與 packet 當中的 `ipv4.srcAddr`, `ipv4.dstAddr` 不同下所計的數值。 而 Port collision 也是一樣，基於 port id (srcPort & dstPort 所做的 hash) 下，其 srcPort, dstPort 與 packet 當中的 `l4_srcPort`, `l4_dstPort` 不同所寄的數值。

> 注意，這個數值只要 dst,src 有一個不同，就會累加（一個 packet 最多各（IP, Port）累加一次）

| Table size | Hash algorithm | IP Collision | Port Collision |
| :--- | :--- | :--- | :--- |
| 128 | crc16 | 0.66% (11159) | 2.83% (47553) |
| 512 | crc16 | 0.60% (10137) | 2.28% (38369) | 
| 1024 | crc16 | 0.61% (10341) | 2.16% (36321) | 
| 512 | crc32 | 0.609% (10226) | 2.13% (35772) |
| 1024 | crc32 | 0.58% (9763) | 2.02% (33989) |