# Difference of algorithms

這部份主要探討使用不同的 anomaly detection algorithm 的各項指標比較 - 像是 `TP/FP rate`、`Detection time` ... 等等要素。有了基本的認知以及比較結果後，我們能更進一步地去探討 **是否能夠針對 DP/CP 之間合作來將原有的演算法做拆解，放到這兩個部份，以 DP 作為一個硬體加速來設計**。 而探討的對象則以不同的偵測演算法為主：
* TRW-CB
* entropy-based
* volume-based
* OpenWatch

## Categories of anomalies

| Anomaly Label | Definition | Traffic Feature Distribution Affected （該行為所造成分佈的影響） |
| :--- | :--- | :--- |
| Alpha Flows | Unusally large volume `point to point` flow | Source address, destination address (possibly ports) |
| DOS | Denial of Service Attack (distributed or single-source) | Destination address, source address |
| Flash Crowd | `Unusual burst` of traffic to single destination, from a "typical" distribution of sources | Destination address/port |
| Port Scan | Probes to many destination ports on a small set of destination address | Destination address / port |
| Network Scan | Probes to many destination addresses on a small set of destination ports | Destination address / port | 
| Outage Events | Traffic shifts due to equipment failures or maintenance | Mainly source & destination address |
| Point to multipoint | Traffic from single source to many destinations, e.g. content distribution | Source address, destination address |
| Worms | Scanning by worms for vulnerable hosts (special case of Network scan) | Destination address & port |


## 實作考量

DP 上的兩條分支：
* 異常偵測
    * 上報 controller 
        * CP 做資料彙整後判斷，將對應的 Match/Action rules 安裝於特定 switch 上
    * 直接做 volume-based detection
        * 當某個 counter 在一定時間內、或是一定量內大於某個 threshold 後，再做對應的處理：
            * 上報 controller
            * 或是透過 rate limit algorithm 先做第1層的管控

> volume-based & distance-based 需要先計算總量，再去決定 threshold