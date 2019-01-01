# Volume-based Detection 

本篇試作 volume-based 的偵測於 Dataplane 上，並基於 DSL - P4 語言來實作。概念解釋：從 anomaly traffic 當中，可以看到大多數的問題流量都是針對幾個 field 上來影響，像是 Src/Dest IP/Port 為主。

以目前實作的設計，共使用了兩個 Key-Value Table。我們是以 srcIP, dstIP 為輸入，使用 CRC16 的 Hash algorithm 產生的輸出作為 Key ID 來使用。第一張 Table 是裝 srcPort, dstPort 作為輸入並使用 CRC16 產生的輸出作為 Value，作為 Port Distribution 的暫存器使用； 而另一個 Table 則是紀錄當目前進入的封包當中 srcPort, dstPort 透過 CRC16 計算出來的值，與 Port Distribution 當中匹配該 key ID 的 Port Distribution 的值不同時（p.s. 這部份可以再想辦法優化，而非直接比較上一次的結果），便累加一次，是為 Difference Counter 的存在。

而當第2張 table 當中的 Diff Counter 超過所設定時，則進一步由 DP 來做處理 - 例如直接將封包丟棄、或是使用 rate limiting 的方式來做流量管理，以及上報給 controller 做進一步的分析等處理方式。

在本實驗當中，為了展示功能為主，所以選擇將封包在達標時直接 drop 掉，來做後續展示使用。

## Run

本實驗進行方式： （用 tmux ）開啟兩個視窗後，先運行 `./build.sh` 將 mininet 給運行起來、並將 p4 program 部署於各個 switch 上，完成後即會進入到 mininet CLI 當中。再來透過另一個視窗，呼叫 `./configure.sh` 將所需要的 configuration 一併安裝於 target switches。這時候便可以回到 mininet CLI 當中，呼叫 `xterm h1 h2`，將這兩個 virtual host 給叫出來。於 h2 上運行 `./receiver.sh`，並於 h1 當中運行 `./scanner.sh` 作為 port scanning 的流量產生器。觀察兩個 xterm 視窗內所顯示的內容，可以看到，因為預設的 configuration 是設 threshold 為 10，所以在一段時間後， scanner 視窗內的訊息仍繼續傳輸，但 receiver 的則會停下來。原因可以看到在 scanner.sh 中設定傳輸次數為 20 次，所以在中間時，便會將後續的封包都丟掉。而在沒有設定 inter-arrival time 來做輔助之下，這樣便會持續封住這組 srcIP, dstIP。