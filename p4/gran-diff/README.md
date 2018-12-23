# Different method of data collection

我們針對幾個方向做探討：
* **per-packet**
  * 匹配以 Match/Action rule 為單位，每條 rule 對應到一個 counter（類似於 `DirectCounter` 的行為），必須維持一張很大的 table 來達到這項功能（確認所有 individual flow 的狀態）
  * 以及像是 In-band network telemetry 這樣的 streaming telemetry，將所有收集到的資訊以 "串流" 的型式回傳。
  * 這個好處是擁有 real-time 的特性、以及高精確度，但相對來說，Overhead 相對比較起來是大的。
* **sampling**
  * temporal（基於總時間間隔）
  * spatial （基於總封包數）
* **flowlet**
  * `temporal` [1]: A burst of packets from a given transport layer flow. Flowlets are characterized by a timeout value, `δ`, which is the minimum inter-flowlet spacing, i.e. , packet spacing within a flowlet is smaller than `δ`.
    * 所以該篇 paper 提出，需要額外指定 **MTBS**（Minimum Time Before Switch-ability），來確定這個切割方式，不會造成 packet reordering 的問題
    * 針對 MTBS 的 [紀錄](https://hackmd.io/s/S12jArqAm#MTBS)
  * `spatial` [2]: split "individual flow" spatially (e.g. by partitioning a monotonically increasing sequence number)
    * 概念上假如目前有一些很大的 flow 流經過我們的 switch，這表示該 flow 會佔用該 switch 上可用的 bandwidth 一段時間。這也是 LocalFlow 提出，`spatial splitting 會優於 temporal splitting` 的論點根據。
    * 所以我們必須依據他的 "量" 來做切割，解決這個問題，所以提出這樣針對 **spatially split**、以及 **local link balancing** 的作法。
    * 值得注意的是，LocalFlow 用的是計算每個 active flow 的速率（e.g. rate，透過去 query 每一筆 forwarding rules 上的 bytes counter 的數值），並且於特定的 interval 當中計算 rate 的變化
    * 之後基於這個數值，來做 scheduling algorithm 的 input (flow rate)，並根據算出來的結果、來更新 forwarding table，重置所有的 byte counter。

而在我們使用的情境上，則是利用這個 flowlet 的特性，來做 sampling 的加強。概念上是採用他以 timeout value 來取某個 flow 的採樣標準。並測試這樣的方式是否 **能有效提升收集資料的實用性**。
* 比起依據總數量來做 sampling 的版本、使用 flowlet 是針對不同的 flow 去做 **"有條件地"** sampling 的動作、相對其收集到的資料對於監控系統的興趣值會比起對總體做 sampling 要來的高。
* 並且基於 flowlet 的 temporal/spatial 特性，我們可以針對 **"active flow"** 來做收集
* 與 per-packet 做收集來看，我們便來比較 `Overhead 與 Accuracy`，在這之間取 tradeoff，作為比較的指標

再來考慮到我們收集的東西： 主要是用來分析 traffic 當中是否有 abnormal 存在。所以能夠以 active flow 作為收集對象，是很適合的。再來就是針對監控系統上的一個決策性的問題 - "Overhead 與 Accurary 之間取 tradeoff"。能否在能收集到我們感興趣的資料下、達到合理的資源使用量，也是我們要探討的對象。

## Reference 

[1] Srikanth Kandula, Dina Katabi, Shantanu Sinha, and Arthur Berger. 2007. Dynamic load balancing without packet reordering. SIGCOMM Comput. Commun. Rev. 37, 2 (March 2007), 51-62. DOI=http://dx.doi.org/10.1145/1232919.1232925

[2] Siddhartha Sen, David Shue, Sunghwan Ihm, and Michael J. Freedman. 2013. Scalable, optimal flow routing in datacenters via local link balancing. In Proceedings of the ninth ACM conference on Emerging networking experiments and technologies (CoNEXT '13). ACM, New York, NY, USA, 151-162. DOI: https://doi.org/10.1145/2535372.2535397