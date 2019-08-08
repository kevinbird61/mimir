# Dataset 

紀錄所使用到的測資其相關資訊。

## 測資詳細資訊

### Available Machine

* IMSLab server 1: `kevin.imslab.org`, 140.116.245.247
* IMSLab server 2: `imslab.org`, 140.116.245.253
* DNS server: `dns.csie.ncku.edu.tw`, 140.116.246.2


#### 💻 IMSLab server 1

| 測資名稱 | Packet 數量 | Unique Hosts | 備註 | 載點 | 
| :--- | :--- | :--- | :--- | :--- |
| packet_record_12_12_ncku_csie_imslab_1941958.pcap | 1941958 | 10432 | 錄製於 NCKU CSIE IMSLAB server 1, 2018/12/12 | [📁 google](https://drive.google.com/file/d/1NPkV__3PUOWRnKQFlPF3JPIsXtYV1t2R/view?usp=sharing) |
| packet_record_1_7_ncku_csie_imslab_5M.pcap | 5000000 | 3008 | 錄製於 NCKU CSIE IMSLAB server 1, 2019/1/7 | [📁 google](https://drive.google.com/file/d/1oJPSlny-jN-TBZxnqYxGVBFrpaBBa-y8/view?usp=sharing) |
| packet_record_1_8_ncku_csie_imslab_1day.pcap | 16163020 (10 G) | 4487 | 錄製於 NCKU CSIE IMSLAB server 1, 錄製時間為一整天, 2019/1/8 | [📁 google](https://drive.google.com/file/d/1AYkUjAOGVleQHmhr1M_W_rKDg2_eULEw/view?usp=sharing) |
| packet_record_1_8_ncku_csie_imslab_1week.pcap | 111323720 (80 G) | 26020 | 錄製於 NCKU CSIE IMSLAB server 1, 錄製時間為一週, 2019/1/8~15 | [📁 google](https://drive.google.com/file/d/191nGqocQJGbKDnJ5nnI4CDAAlDMSzOZf/view?usp=sharing) |

* IP, TCP, UDP 分析

| 測資名稱 | Unique src IP | Unique dst IP | Unique TCP | Unique src TCP port | Unique dst TCP port | Unique UDP | Unique src UDP port | Unique dst UDP port |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| packet_record_1_8_ncku_csie_imslab_1week.pcap | 26010 | 25584 | 43501 | 43474 | 43093 | 14665 | 14516 | 225 |
| packet_record_12_12_ncku_csie_imslab_1941958.pcap | 10422 | 10377 | 26941 | 26940 | 26927 | 7747 | 7686 | 84 |
| packet_record_1_7_ncku_csie_imslab_5M.pcap | 2999 | 2984 | 14569 | 14566 | 14567 | 1382 | 1360 | 37 |

#### 💻 IMSLab server 2

| 測資名稱 | Packet 數量 | Unique Hosts | 備註 | 載點 | 
| :--- | :--- | :--- | :--- | :--- |
| packet_record_1_8_imslab_org_1day.pcap | 900710 | 5867 | 錄製於 NCKU CSIE IMSLAB server 2, 錄製時間為一整天, 2019/1/8 | [📁 google](https://drive.google.com/file/d/1LEs58vzjojSwHJHT_rIdz3OAjeIt-FHq/view?usp=sharing) |
| packet_record_1_9_imslab_org_3day.pcap | 2885968 | 14999 | 錄製於 NCKU CSIE IMSLAB server 2, 錄製時間為 3 天, 2019/1/9~12 | [📁 google](https://drive.google.com/file/d/1dVeB1akriHTqAtnXIQE8T97i4zjPjohP/view?usp=sharing) |
| packet_record_1_7_imslab_org_5M.pcap | 5000000 | 25665 | 錄製於 NCKU CSIE IMSLAB server 2, 2019/1/7 | [📁 google](https://drive.google.com/file/d/1BhzG3MHfSFzPTjPPa0AISwp1qL1focfB/view?usp=sharing) |

* IP, TCP, UDP 分析

| 測資名稱 | Unique src IP | Unique dst IP | Unique TCP | Unique src TCP port | Unique dst TCP port | Unique UDP | Unique src UDP port | Unique dst UDP port |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| packet_record_1_7_imslab_org_5M.pcap | 25654 | 25503 | 55713 | 55710 | 50553 | 51300 | 51262 | 51126 |

#### 💻 DNS server 

| 測資名稱 | Packet 數量 | Unique Hosts | 備註 | 載點 | 
| :--- | :--- | :--- | :--- | :--- |
| packet_record_1_7_ncku_csie_dns_0.5M.pcap | 500000 | 6112 | 錄製於 NCKU CSIE 機房 DNS server，2019/1/7 | [📁 google](https://drive.google.com/file/d/15ZZaJUmp0qAdp70gSBnYQ0zdi2ZYcUQT/view?usp=sharing) |
| packet_record_1_7_ncku_csie_dns_1M.pcap | 1000000 | 10045 | 錄製於 NCKU CSIE 機房 DNS server, 2019/1/7 | [📁 google](https://drive.google.com/file/d/1w3fDADnzFfwaL1kjBf0A3PVzYDVIMx7v/view?usp=sharing) |
| packet_record_1_8_ncku_csie_dns_1day.pcap | 3269768 | 21199 | 錄製於 NCKU CSIE 機房 DNS server, 錄製時間為一整天, 2019/1/8 | [📁 google](https://drive.google.com/file/d/1IQQY8kqQ8uwfUgAOC9rfUgFRrc03uch2/view?usp=sharing) |
| packet_record_1_9_ncku_csie_dns_3day.pcap | 10665410 | 42487 | 錄製於 NCKU CSIE 機房 DNS server, 錄製時間為 3 天, 2019/1/9~1/12 | [📁 google](https://drive.google.com/file/d/1E81nUsLczgatLAfRFoUKeTYAPRxKWuma/view?usp=sharing) |

* IP, TCP, UDP 分析

| 測資名稱 | Unique src IP | Unique dst IP | Unique TCP | Unique src TCP port | Unique dst TCP port | Unique UDP | Unique src UDP port | Unique dst UDP port |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| packet_record_1_7_ncku_csie_dns_0.5M.pcap | 6064 | 4645 | 9272 | 8513 | 3191 | 18680 | 18540 | 16725 |
| packet_record_1_7_ncku_csie_dns_1M.pcap | 9992 | 8150 | 15381 | 14446 | 8584 | 33461 | 33418 | 30391 |
| packet_record_1_9_ncku_csie_dns_3day.pcap | 42432 | 30546 | 52266 | 51765 | 40395 | 64007 | 63938 | 63961 |



### 額外測資

> 網路上額外找的測資，統一整理於此。

| 測資名稱 | Packet 數量 | Unique Hosts | 備註 | 載點 | 
| :--- | :--- | :--- | :--- | :--- |
| LBNL-FTP-PKT (all.tcpdump) | 3264050 | 6152 | 為 benign traffic (FTP server) | [LBNL-FTP-PKT](https://ee.lbl.gov/anonymized-traces.html) | 
| CTU-13-dataset (anomaly) | 多個 pcap 檔案 | x | 多個 botnet traffic 流量提供，作為 anomaly traffic | [📁 google](https://drive.google.com/file/d/1nWr_Fs_n7gQ0nGx-iMyC0joZC3DqvXFp/view?usp=sharing) |
| UNB 2016 (DoS) | | | | [DoS Dataset](https://www.unb.ca/cic/datasets/dos-dataset.html) |
| UNB 2018 (多種不同種類的攻擊) | | | | [CSE-CIC-IDS2018 on AWS](https://www.unb.ca/cic/datasets/ids-2018.html) |
| CAIDA 2016 | | | 骨幹網路的流量 (benign)，需要額外提交申請程序 | [CAIDA - passive 2016 dataset](http://www.caida.org/data/passive/passive_2016_dataset.xml) |

* IP, TCP, UDP 分析

| 測資名稱 | Unique src IP | Unique dst IP | Unique TCP | Unique src TCP port | Unique dst TCP port | Unique UDP | Unique src UDP port | Unique dst UDP port |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| LBNL-FTP-PKT (all.tcpdump) | 6152 | 6152 | 12922 | 12922 | 12922 | 0 | 0 | 0 |

* [Botnet 相關測資下載: https://www.unb.ca/cic/datasets/index.html](https://www.unb.ca/cic/datasets/index.html)
    * 其測資有標示哪些為 anomalies，可依據給予的指示作為 ground truth 來判斷執行結果的正確性。

## 延伸閱讀

* [High Volume of GRE traffic](https://badpackets.net/high-volume-of-protocol-47-gre-traffic-from-hinet-as3462-found/)
* [Traces available in the Internet Traffic Archive](http://ita.ee.lbl.gov/html/traces.html)
* [Publicly available PCAP files](https://www.netresec.com/?page=pcapfiles)
* [Malware Traffic Analysis - source pcap files for traffic analysis exercise](http://malware-traffic-analysis.net/training-exercises.html)