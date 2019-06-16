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

## Build 

* dependencies
```sh
sudo apt install libpcap-dev
```
* build all executable files
```sh
make
```

## Programs 

呼叫 `make` 來編譯以下幾隻以 C 為主的程式：
1. [read_pcap.out](src/read_pcap.c)
   * 分析 pcap file 的程式碼。
   * 執行： `./read_pcap.out <your_pcap_file>`
   * 若需要將結果輸出，則呼叫 `make read_pcap_w.out && ./read_pcap_pcap.out <your pcap file>`，結果將會存放在 output/ 資料夾底下，分別會有：
     * `*_raw.txt`: 格式為 <key>-<對應的數量>，用來計算 flow distribution、service distribution、port distribution
     * `ip_without_counter.txt`: 單純紀錄 IP address 為主，用來做 ip prefix aggregation 程式（e.g. `aggregate.py`）的輸入。 
2. [hash_pcap.out](src/hash_pcap.c)
   * 探討 hash collision 的影響
   * 執行： `./hash_pcap.out <your_pcap_file>`
   * 顯示目前該 pcap 封包內容對於所選的 *Table size*, *Hash algorithm* 所造成的 collision 數量。
3. [port_diff.out](src/port_diff.c)
   * 探討使用 difference counter 與 hamming distance/weight 的 detection 影響。
   * 以及探討使用 Moving Average 與 Entropy 對於 detection 的影響。
   * 執行： `./port_diff.out -f <your_pcap_file>`
     * 若有需要將 report 的資訊印出，則需加上 `-d` 的 option。
   * 顯示使用的方法以及對應回報的數量。
4. [heavy_hitter.out](src/heavy_hitter.c)
   * 探討 heavy hitter 與 sketch (`t` x `k`) / non-sketch (`1` x `k`) 之間的差異。 （t 為 distinct hash algorithm 數量，k 為 Table size）
   * 執行： `./heavy_hitter.out -f <your_pcap_file>`
5. [sort.out (C++)](utils/sort.cc)
   * 用來對 output 底下的測資做排序、抽取。
   * 需要使用 `read_pcap_w.out`（透過 `make read_pcap_w.out` 編譯產生），呼叫模式與 `read_pcap.out` 相同。 
   * 執行： `./sort.out -p -f <raw statistics input file>`
     * -p: 輸入檔案的 key value 皆為 `int` 
     * -i: 輸入檔案的 key 為 `string`， value 為 `int`（舉例來說，輸入為 output/ip_raw.txt）
     * -e <level>: 指定輸出檔案內容（可以選擇欲輸出的量，可用 `-h` 了解更多）
     * -f <file>: 指定輸入檔案（輸出檔案會與輸入放在同一個資料夾下，並加上前綴 `sorted_`）
   * 搭配 `make plot_read_pcap` 來將處理過後測資放到 `images/` 資料夾底下。
   * 使用範例（展示從 `測資生產` 到 `繪製圖表`）：
     ```
     $ make read_pcap_w.out                            # 產生測資 （output/）
     $ ./read_pcap_w.out <target pcapfile>             # 讀取欲分析的 pcap 檔
     $ ./sort.out -p -e 2 -f output/tcp_raw.txt        # 將輸出的 raw 資料排序、或是針對值大小做過濾，輸出成另一筆新的分析測資
     $ ./sort.out -p -e 1 -f output/udp_raw.txt   
     $ make plot_read_pcap                             # 對過濾過的測資繪製圖表（images/）
     ```
6. [entro.out](utils/entropy.cc)
   * 用來計算某個 pcap file 所擁有的 entropy 值 (並且經過 normalize 過後，其值必定落在 0 到 1 之間)
   * 愈接近 0，表示變異度（每個 sample 與其他 sample 之間）不大；反之，則變異度愈大。
   * 執行與結果顯示：
   ```
     $ ./entro.out -f ../../CTU-13-Dataset/1/botnet-capture-20110810-neris.pcap 
     ===========================================================
     [Entropy] IPv4 source address: 0.19688
     ===========================================================
     [Entropy] IPv4 destination address: 0.496343
     ===========================================================
     [Entropy] TCP source Port: 0.648968
     ===========================================================
     [Entropy] TCP destination Port: 0.406591
     ===========================================================
     [Entropy] UDP source Port: 0.404979
     ===========================================================
     [Entropy] UDP destination Port: 0.33612
   ```
7. [pktlen.out](utils/pktlen.cc)
   * 用 hamming weight 來對以 ipv4 source address 作為 key 之 packet 所持有的 `packet length`，觀察是否能藉由 packet length 的變化中，偵測出 botnet 資訊。 
   * 執行與結果顯示：
   ```
     $ ./pktlen.out -f ../../CTU-13-Dataset/1/botnet-capture-20110810-neris.pcap 
     Leverage Hamming distance and Sketching to inspect packet length and find out the botnet.
     ===========================================================
     Threshold: MEAN + 3*STD
     ===========================================================
     [IP: 147.32.80.9] -> 20772
     [IP: 147.32.84.165] -> 220955
     [IP: 184.154.132.106] -> 54169
     [IP: 213.246.53.125] -> 80789
     ===========================================================
     Report ratio: 1.2378e-05
     ===========================================================
     ===========================================================
     Threshold: MEAN + 2*STD
     ===========================================================
     [IP: 147.32.80.9] -> 20772
     [IP: 147.32.84.165] -> 220955
     [IP: 184.154.132.106] -> 54169
     [IP: 212.117.171.138] -> 13535
     [IP: 213.246.53.125] -> 80789
     ===========================================================
     Report ratio: 1.54725e-05
     ===========================================================
     ===========================================================
     Threshold: MEAN + STD
     ===========================================================
     [IP: 147.32.80.9] -> 20772
     [IP: 147.32.84.165] -> 220955
     [IP: 174.133.57.141] -> 5261
     [IP: 184.154.132.106] -> 54169
     [IP: 212.117.171.138] -> 13535
     [IP: 213.246.53.125] -> 80789
     [IP: 65.55.196.251] -> 5289
     ===========================================================
     Report ratio: 2.16615e-05
     ===========================================================
   ```
   > 上述使用的 pcap file 中，botnet 的來源位置為 `147.32.84.165`。
   > 除了使用 mean 與 STD 來找，也可以嘗試使用 TOP-N 來找。
8. [sdiff.out](utils/statistical_diff.cc)
   * 利用顯著性差異的概念來實作。（詳情可以看原始碼開頭的註解）
   ```
     $ ./sdiff.out -f ../../CTU-13-Dataset/1/botnet-capture-20110810-neris.pcap
     [Stat Diff - Candidate] IPv4 srcAddr: 147.32.80.9
     [Stat Diff - Candidate] IPv4 srcAddr (Extreme): 147.32.84.165
     [Stat Diff - Candidate] IPv4 srcAddr (Extreme): 184.154.132.106
     [Stat Diff - Candidate] IPv4 srcAddr: 212.117.171.138
     [Stat Diff - Candidate] IPv4 srcAddr (Extreme): 213.246.53.125
     [Stat Diff] IPv4 srcAddr number: 5
   ```
9. [birth.out](utils/birthday.cc)
   * 計算生日悖論的公式。並提供 P（在某個執行次數下，發生碰撞的機率） 與 N（在某個碰撞機率下，發生碰撞所需最小執行次數） 的計算
   * 計算發生碰撞機率下，最小執行次數：
   ```
     $ ./birth.out -n -1 65536 -2 0.5
     (Collisiton Probability) P: 0.5
     (Hashing space) d: 65536
     (Minimal number of execution that can cause collision) N( 0.5 ): 301.417
   ```
   * 計算某個執行次數下，發生碰撞機率：
   ```
     $ ./birth.out [-p] -1 1024 -2 21 
     (Number of execution that can cause collision) N: 21
     (Hashing space) d: 1024
     (Collisiton Probability) P( 21 ): 0.185416
   ```

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