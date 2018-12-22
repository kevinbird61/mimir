# Difference of algorithms

這部份主要探討使用不同的 anomaly detection algorithm 的各項指標比較 - 像是 `TP/FP rate`、`Detection time` ... 等等要素。有了基本的認知以及比較結果後，我們能更進一步地去探討 **是否能夠針對 DP/CP 之間合作來將原有的演算法做拆解，放到這兩個部份，以 DP 作為一個硬體加速來設計**。 而探討的對象則以不同的偵測演算法為主：
* TRW-CB
* entropy
* OpenWatch

