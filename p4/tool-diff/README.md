# Difference of tools

這個部份主要探討 "使用工具上的不同" 對於 Anomaly detection 的差異。探討方向主要為 "polling-based"、"push-based"。(**這部份主要可以跟 OF 版本的實作來比對，以及跟將 detection algorithm 直接嵌入到 P4 program 內的版本做效能比較。**)

## Polling-based

* P4 + sFlow

## Push-based

* P4 + NetFlow
  * 這部份主要利用了 NetFlow 的設計，並將這個設計透過 P4 做開發，完成一套基於 BMv2 以及 python 版本的 P4Runtime controller/collector 做實現。

