# 注意事項

* 在 topology.json 當中透過 runtime_json 給予 switch 指定 pre-installed rules，會造成後續 DigestEntry 無法使用的情形。
  * 情境： 在 flowlet 的實驗過程當中，我事先使用了 ipv4 forwarding 相關的 flowrules（於 topology.json 當中），而這導致我在後續在該情境下於 report.p4 中欲呼叫使用 digest 時產生無法送出的問題（在 s1.log 當中可以看到 bmv2 觸發了 digest 的條件，卻仍然無法從 controller 端看到收到的 digest 訊息）
  * 目前為了實驗，所以拔除了 pre-installed 的 flowrules。digest 功能便恢復。