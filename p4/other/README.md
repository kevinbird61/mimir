# 其他

額外收錄一些 Data Plane 上可行的操作 

* `rate limiting` algorithm
    * 目的： 作為當 DP 偵測到異常 hosts 時，對其做限速的動作（e.g. 使用 token bucket algorithm）
    * [基於 Leaky Bucket 的實作](https://en.wikipedia.org/wiki/Leaky_bucket)，抓其 as a queue 的想法來做，但詳細 wiki 當中的探討還需要花時間額外閱讀。 - [Source Code](leaky_bucket/)
* [`log`](https://zh.wikipedia.org/wiki/%E5%AF%B9%E6%95%B0) 運算 - 透過 bitwise operator

* [`Hamming-weight`](https://en.wikipedia.org/wiki/Hamming_weight)
* [`floating point (IEEE-754)`](http://jmiiv.blogspot.com/2008/08/ieee-754.html) 的操作
    * 參考： 可以搭配 stream processing 一起使用

* ValueSet（[P4Runtime](https://s3-us-west-2.amazonaws.com/p4runtime/docs/v1.0.0-rc4/P4Runtime-Spec.html#sec-valuesetentry), [P4-16](https://p4.org/p4-spec/docs/P4-16-v1.1.0-spec.html#sec-value-set)） 的使用
    * Dynamic Parser transition support
    * 尚未確認 BMv2 有無實作這部份的功能