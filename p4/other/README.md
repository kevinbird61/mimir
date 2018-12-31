# 其他

額外收錄一些 Data Plane 上可行的操作 

* `rate limiting` algorithm
    * 目的： 作為當 DP 偵測到異常 hosts 時，對其做限速的動作（e.g. 使用 token bucket algorithm）
    * [基於 Leaky Bucket 的實作](https://en.wikipedia.org/wiki/Leaky_bucket)，抓其 as a queue 的想法來做，但詳細 wiki 當中的探討還需要花時間額外閱讀。 - [Source Code](leaky_bucket/)