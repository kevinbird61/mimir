# Evaluation 

這個資料夾主要放置與分析相關的程式碼、工具、腳本等等。像是分析資料收集的結果、或是對我們實驗用的 pcap file 做初步分析（e.g. 分析其內部是否不完全為 benign traffic）。

而與 profiling, performance measurement 相關的工具學習、使用紀錄，也可以放置於此。

## Repository Layout 

```
.
├── images          # Output result of gnuplot under scripts/
├── manual          # Some discussions of IDS/algorithms ..., writing in readable files (e.g. Markdown)
├── output          # Output statistics of evaluation programs
├── lib             # Useful libraries
├── utils           # Utilities
│   ├── sort.cc     # sort & extract our statistics 
├── third_party
│   ├── hash        # Library of hash algorithms
│   └── cmap        # Library of map structure in C
└── scripts         # Plotting scripts of gnuplot
```

## Programs 

呼叫 `make` 來編譯以下幾隻以 C 為主的程式：
1. [read_pcap.out](read_pcap.c)
   * 分析 pcap file 的程式碼。
   * 執行： `./read_pcap.out <your_pcap_file>`
   * 若需要將結果輸出，則呼叫 `./read_pcap.out`，結果將會存放在 output/ 資料夾底下，分別會有：
     * `*_raw.txt`: 格式為 <key>-<對應的數量>，用來計算 flow distribution、service distribution、port distribution
     * `ip_without_counter.txt`: 單純紀錄 IP address 為主，用來做 ip prefix aggregation 程式（e.g. `aggregate.py`）的輸入。 
2. [hash_pcap.out](hash_pcap.c)
   * 探討 hash collision 的影響
   * 執行： `./hash_pcap.out <your_pcap_file>`
   * 顯示目前該 pcap 封包內容對於所選的 *Table size*, *Hash algorithm* 所造成的 collision 數量。
3. [port_diff.out](port_diff.c)
   * 探討使用 difference counter 與 hamming distance/weight 的 detection 影響。
   * 以及探討使用 Moving Average 與 Entropy 對於 detection 的影響。
   * 執行： `./port_diff.out -f <your_pcap_file>`
     * 若有需要將 report 的資訊印出，則需加上 `-d` 的 option。
   * 顯示使用的方法以及對應回報的數量。
4. [heavy_hitter.out](heavy_hitter.c)
   * 探討 heavy hitter 與 sketch (`t` x `k`) / non-sketch (`1` x `k`) 之間的差異。 （t 為 distinct hash algorithm 數量，k 為 Table size）
   * 執行： `./heavy_hitter.out -f <your_pcap_file>`
5. [sort.out](utils/sort.cc)
   * 用來對 output 底下的測資做排序、抽取。
   * 需要使用 `read_pcap_w.out`（透過 `make read_pcap_w.out` 編譯產生），呼叫模式與 `read_pcap.out` 相同。 
   * 執行： `./sort.out -p -f <raw statistics input file>`
     * -p: 輸入檔案的 key value 皆為 `int` 
     * -i: 輸入檔案的 key 為 `string`， value 為 `int`（舉例來說，輸入為 output/ip_raw.txt）
     * -e <level>: 指定輸出檔案內容（可以選擇欲輸出的量，可用 `-h` 了解更多）
     * -f <file>: 指定輸入檔案（輸出檔案會與輸入放在同一個資料夾下，並加上前綴 `sorted_`）
   * 搭配 `make plot_read_pcap` 來將處理過後測資放到 `images/` 資料夾底下。


其他輔助程式：
* [aggregate.py](aggregate.py)
  * 參考來源：https://adamkuj.net/blog/2014/04/08/a-utility-to-perform-ipv4-ipv6-prefix-aggregation/ 
  * 使用這支腳本程式，來對 read_pcap.out 輸出的 `ip_without_counter.txt` 做分析。執行： `./aggregate.py -c -f output/ip_without_counter.txt > output/aggregate.txt`
  * 主要功能為 ip prefix aggregation，察看該來源 pcap 的分散程度。（直接比較輸入與輸出的 entries 數量）

## Useful Reference/Resource

* [Linux 工具快速教程](https://linuxtools-rst.readthedocs.io/zh_CN/latest/index.html)
  * [工具參考篇](https://linuxtools-rst.readthedocs.io/zh_CN/latest/tool/index.html)
* [Snort 使用說明、與紀錄](manual/snort.md)

* [High-level tracing language of Linux eBPF - bpftrace](https://github.com/iovisor/bpftrace)
  * 暫時預定這套工具作為軟體上測量效能的依據（之後依據選擇的效能指標，可再變更使用工具）