# Queueing statistic 

這份資料夾內展示如何透過 v1model.p4 當中 standard_metadata 資訊來收集與 queueing 相關的資訊。像是 queueing timedelta 與 queueing depth。

而展示項目以取其 `avg` 、`max` 與 `min` 值為主。

目的在於後續其他 process 使用上可以觀察在其處理時間上，除了在 complete time 上有增加之外，對 queue 的影響有多少。

後續可以利用 recirculate 方式，來做 p4 `per-action` 或是 `per-control-block` 的測定 - 將每個 control block 透過 metadata 內所設定的 flag 來執行指定的 action 或是 control block、並在 egress 時透過 queueing_stat 模組收集其資訊，再透過 recirculate 方式回到 ingress，執行下一個測試。