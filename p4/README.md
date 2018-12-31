# P4 Version

這部份主要是由 P4 來實現各項探討因素、以及對應的實驗。我們簡單分類為 3 個導向：
* 所使用的演算法不同
* 所使用的系統不同
* 所使用的工具不同

並且在不同資料粒度下的 **資料收集** 方向做探討：
* **per-packet**
* **sampling**
* **flowlet**

作為後續討論的方向。

---

額外收錄一些 Data Plane 上可行的操作 - 像是加強版的 firewall （e.g. 俱備 learning 功能）、或是透過 stateful 結果來做出反應。 這部份會當作我們後續實作 IDS 當中 DP 與 CP 之間搭配時的參考依據：

* rate limiting (針對流量做限速功能)
* P4 額外針對 target 所設計的匹配方式（類似於 Digest 這樣的設計，能夠讓我們以這樣的新工具，來對舊方法做優化），例如： [Action Profile and Selector](https://github.com/jafingerhut/p4-guide/tree/master/action-profile-and-selector)

---

最後，總結以上各種面向的實驗、研究與探討後，我們便能夠選取我們最適合的部份，作為我們所提出的 IDS 的系統架構設計：

* MIMIR Overview