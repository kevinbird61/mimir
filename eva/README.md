# Evaluation 

這個資料夾主要放置與分析相關的程式碼、工具、腳本等等。像是分析資料收集的結果、或是對我們實驗用的 pcap file 做初步分析（e.g. 分析其內部是否不完全為 benign traffic）。

而與 profiling, performance measurement 相關的工具學習、使用紀錄，也可以放置於此。

## Programs 

* [read_pcap.out](read_pcap.c)
  * 分析 pcap file 的程式碼。
  * 呼叫 `make` 即可編譯，產生 `read_pcap.out`
  * 執行： `./read_pcap.out <your_pcap_file>`
  * 結果將會存放在 output/ 資料夾底下，分別會有：
    * `*_raw.txt`: 格式為 <key>-<對應的數量>，用來計算 flow distribution、service distribution、port distribution
    * `ip_without_counter.txt`: 單純紀錄 IP address 為主，用來做 ip prefix aggregation 程式的輸入。
* [plot.sh](plot.sh)
  * 相依於 read_pcap.out 的執行結果 - 於 output/ 底下輸出的 txt 來源檔。
  * 使用 gnuplot 來做繪製，使用的 gnuplot 腳本放置於 `scripts/`，將繪圖結果放置於 `images` 底下。
* [aggregate.py](aggregate.py)
  * 參考來源：https://adamkuj.net/blog/2014/04/08/a-utility-to-perform-ipv4-ipv6-prefix-aggregation/ 
  * 使用這支腳本程式，來對 read_pcap.out 輸出的 `ip_without_counter.txt` 做分析。
  * 主要功能為 ip prefix aggregation，察看該來源 pcap 的分散程度。（直接比較輸入與輸出的 entries 數量）

## Repository Layout 

```
.
├── images          # Output result of gnuplot under scripts/
├── manual          # Some discussions of IDS/algorithms ..., writing in readable files (e.g. Markdown)
├── output          # Output statistics of evaluation programs
├── third_party
│   └── cmap        # Library of map structure in C
└── scripts         # Plotting scripts of gnuplot
```

## Useful Reference/Resource

* [Linux 工具快速教程](https://linuxtools-rst.readthedocs.io/zh_CN/latest/index.html)
  * [工具參考篇](https://linuxtools-rst.readthedocs.io/zh_CN/latest/tool/index.html)
* [Snort 使用說明、與紀錄](manual/snort.md)

* [High-level tracing language of Linux eBPF - bpftrace](https://github.com/iovisor/bpftrace)
  * 暫時預定這套工具作為軟體上測量效能的依據（之後依據選擇的效能指標，可再變更使用工具）