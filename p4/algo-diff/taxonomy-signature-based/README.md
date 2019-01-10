# Taxonomy Signature

> refs: http://www.fukuda-lab.org/mawilab/classification/index.html#Mazel2014TRAC

## UDP network scan

在 refs 提及4個指標： 
* `number of packets`
* `number of src address`
* `number of dst address`
* `number of udp packets`

藉由這4個指標所獲得的值，來計算、判斷目前是否有攻擊發生。而我們實作的 prototype，則是以總 traffic 打到 bmv2，並透過所撰寫的 p4 program 內的 register，來觀察這些指標的數值，來判斷流量當中是否有這樣的攻擊 pattern 存在。（當然，這樣的判斷本應該放在 DP 內。 目前實驗上先不做判斷）

以 dataset 當中 12/12 號那筆測資來實驗，可以得到：

| nb_pkts | nb_src_addr | nb_dst_addr | nb_udp_pkts |
| :--- | :--- | :--- | :--- |
| 228410 | 482 | 453 | 38184 |

而在 refs 內定義： 
```
nb_src_addr < 5 
∧ nb_dst_addr >= 20 
∧ nb_packets/nb_dst_addr < 5 
∧ nb_udp_packets/nb_packets >= 0.8
```

簡單將第1、2 條件合併來看： nb_dst_addr/nb_src_addr >= 4，從收集到的資訊來看， 453/482 < 1。 而第3條件： 228410/453 大約等於 504，遠超過 5。 最後條件 - 38184/228410 = 0.167，遠小於 0.8。

綜上述的結果來看，依據 refs 所提到的數據來看，便可以宣稱沒有遭受 udp scan 攻擊。

> 注意： 使用 100 M 的速度下，packets 的數量與實際 pcap 內的數量差距挺大，尚未確認是否為 BMv2 本身的限制，抑或是速度過快的原因？ 
> 也有可能為使用 @atomic 所造成的讀寫 bottleneck ？ 
> 尚待釐清。
