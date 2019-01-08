# Baseline measurement for traffic in BMv2

基於流量特性，於 BMv2 上提供基本性質之分析 - 像是對 traffic 當中的 distribution 總變化量、或是其他有興趣的欄位數值變化，都放置於本專案內。

---

## Baseline


### Portscan-related

在 portscan 當中目前做了兩個版本 - volume/distance-based。 以相同的測資測試下，分別產生的總變量：

| Method | Table size | Hash Algorithm | Amount of Change | Avg amount (per slot) | 
| :--- | :--- | :--- | ---: | ---: | 
| Volume-based | 512 | crc16 | 139153 | 271.78 | 
| Distance-based | 512 | crc16 | 1091468 | 2131.77 |

而就變量來看，Volume-based 的數量會是 Distance-based 的 `7.84 倍`。 故在 Threshold 上， Volume-based 至少比 Distance-based 上要取至少 8 倍。

再回到 portscan 的兩個實驗，將倍數調整到 `1:8` 左右，可以看到，distance-based 回報的數量明顯下降，並且比 volume-based 的回報數還要低。
再來下一個調整： 將兩者的 threshold 拉高到平均值，再次進行實驗，觀察回報數。可以看到，兩者的回報數量降到 400 多，並且以 volume-based 的回報數略勝一籌。（由此可推知，在數據敏感度上，distance-based 的變量是較不敏感的。）

> 注意： 過多的回報數量，也許同時代表過高的 False Positive！

---