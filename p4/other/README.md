# 其他

額外收錄一些 Data Plane 上可行的操作 

* `rate limiting` algorithm
    * 目的： 作為當 DP 偵測到異常 hosts 時，對其做限速的動作（e.g. 使用 token bucket algorithm）
    * [基於 Leaky Bucket 的實作](https://en.wikipedia.org/wiki/Leaky_bucket)，抓其 as a queue 的想法來做，但詳細 wiki 當中的探討還需要花時間額外閱讀。 - [Source Code](leaky_bucket/)
* [`log`](https://zh.wikipedia.org/wiki/%E5%AF%B9%E6%95%B0) 運算 - 透過 bitwise operator

* [`Hamming-weight`](https://en.wikipedia.org/wiki/Hamming_weight)
* [`floating point (IEEE-754)`](http://jmiiv.blogspot.com/2008/08/ieee-754.html) 的操作
    * 參考： 可以搭配 stream processing 一起使用
* [`hash collision` 的探討](hash-collision/)
    * 探討在不同 table size、以及不同的 hash algorithm 下，同一筆 pcap file 所產生的 Hash collision 次數。
* [time](time/)
    * 探討時間相關的操作（如 process-complete-time）

## P4-related 相關的規格（較少用到的操作）

* ValueSet（[P4Runtime](https://s3-us-west-2.amazonaws.com/p4runtime/docs/v1.0.0-rc4/P4Runtime-Spec.html#sec-valuesetentry), [P4-16](https://p4.org/p4-spec/docs/P4-16-v1.1.0-spec.html#sec-value-set)） 的使用
    * Dynamic Parser transition support
    * 尚未確認 BMv2 有無實作這部份的功能

* Data Structure - [Operations on List](https://p4.org/p4-spec/docs/P4-16-v1.1.0-spec.html#sec-list-exprs)
    * 看起來是定義了 list 的資料結構，提供 p4 programmer 於程式當中定義自己的 list 來做使用。
    * 目前還沒有於 p4-16 當中測試，看起來是一個類似於 register，但非 key-value 匹配的資料結構型態。適用於一連串資料（e.g. Linked-list）時使用。
    ```p4
    extern LearningProvider {
        void learn<T>(in T data);
    }
    LearningProvider() lp;

    lp.learn( { hdr.ethernet.srcAddr, hdr.ipv4.src } );
    ```
    > 這部份需要 target 支援才能夠使用。
* Parser - [header stacks](https://p4.org/p4-spec/docs/P4-16-v1.1.0-spec.html#sec-parse-header-stacks)
    * Header stack 的操作，適用於 segment routing、in-band network telemetry ... 等操作時使用。

* Parser - [operation on sets](https://p4.org/p4-spec/docs/P4-16-v1.1.0-spec.html#sec-set-exprs)
    * 除了透過 ValueSet 來做 runtime 的設定改動外，本身在 select 上也有特殊匹配方式：
        * Singleton (直接設定一個 exact 匹配值)
        * Universal (e.g. `default:`)
        * Masks ( a &&& b = `{ c of type bit<W> where a & b = c & b }`)
        * Ranges (`4w5 .. 4w8`)
        * Products （Multiple sets 結合一起匹配）：
        ```
        # Products: 
        select(hdr.ipv4.ihl,hdr.ipv4.protocol) {
            (4w0x5, 8w0x1): parse_icmp;
            (4w0x5, 8w0x6): parse_tcp;
            (4w0x5, 8w0x11): parse_udp;
            (_, _): accept; }
        ```