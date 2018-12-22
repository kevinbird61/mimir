# Difference of systems

這部份主要探討的對象是我們所使用的系統架構，以兩個主要方向來做實驗： "single-switch"、以及 "multi-switches"。而這樣的比較主要對我們所使用的情境做實驗 - 像是比較 `是否使用多台 switches 來做收集，會有更好的收集效率、以及這樣的動作是否能夠將單台的負載平均分攤到多台同個 domain 底下的 switches`，以及可能產生的問題： `這樣多台的設計、是否會造成多餘的 communication cost？ 或是反而能夠利用像是 INT-based 的架構設計，來達到高效率、且即時的資料收集`。

## Single switch

* Thin-switch
  * switch + local controller + remote controller

## Multiple switches

* INT-based 