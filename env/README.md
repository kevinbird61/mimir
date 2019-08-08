# Environmnet 

> Building our testing virtual network.

![](https://i.imgur.com/m0LjNmf.png)

## Login directly

```bash
$ docker pull kevinbird61/vnet
$ docker run -it --privileged kevinbird61/vnet
```

## Build with one command 

> 建立虛擬拓樸後，便可以啟動 P4 BMv2 在設定好的 interface 來對流量進行實驗，測試所提出的方法是否符合預期。 (執行 P4 腳本的說明於 `p4/README.md`)

* 啟動 N 個 hosts + 1 victim
```bash
$ go run build.go -b N
```

* 啟動 N 個 hosts + 1 victim，並將當中一半的 hosts 執行 ddos 攻擊程式
```bash
$ go run build.go -b N -ddos
```

* 查看其他支援
```
$ go run build.go -h 
```

* 清除現有建立所有 container (reset)
```
$ go run build.go -c
```

## 使用說明

* 在建立 N 個 hosts 後，攻擊的模擬便已經開始 (預設下會執行數分鐘)。 可以透過 docker commands 進到想看的 container 中，檢視目前該 host 執行的狀況。
    * 環境中攻擊者會執行該 image 中的 ddos.go 腳本，對 victim 開始進行攻擊
    * 而剩餘的 host 則會執行 iperf 作為 benign 的 background traffic
* container 命名規則
    * 攻擊者: `user_a` 開頭，後面加上編號 (注意: index 從 0 開始)。 舉例來說，運行 `go run build.go -b 8 -ddos` 時，此時有 4 個 attacker 與 4 個 benign，假設想看 attacker 3， 則該 container name 便是 `user_v2` (index 從 0 開始)
    * 正常者: `user_v`
    * 受害者: `victim`
* 執行的 docker 指令:
    ```bash
    $ docker exec -i -t <container-name> /bin/bash
    ```
* 在 victim 中執行了 tcpdump 的錄製程式，會在模擬開始時執行，將所有模擬中的封包都錄製下來。 在實驗結束後，可以將該錄製的 pcap file 從 container 當中拿出來，或是利用 container 內已預先放置的 gdrive (google drive CLI) 來把該 pcap file 上傳到你的雲端。