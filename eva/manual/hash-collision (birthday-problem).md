# 生日悖論

> This part will need to install the chrome extension: [**`Github with MathJax`**](https://chrome.google.com/webstore/detail/github-with-mathjax/ioemnmodlmafdkllaclgeombjnmnbima/related), then can see the correct mathematic formula 

探討 hash collision 時，我們參考 birthday problem 所提供的論述作為主要理論基礎。 

以生日問題來看，可以看成是在 `d 個相異數` 中 `隨機選取 N 次`，且至少兩數相同的機率：

$$
P(N, d) \approx 1 - e^{-\frac{N(N-1)}{2d}}\\
$$

而這個機率，便是將 hash space 看成是 d 的 hash function，至少需要 N 次才發生碰撞的機率。

## 反算問題

對兩側取 log 後移項，便可以得到： 在 hash space 為 d 的情況下，發生碰撞的機率為 P 時，至少要嘗試 N 次，如下：

$$
N(P, d) \approx \sqrt{2d\ln{\frac{1}{1-P}}}
$$

對於確定的機率 P，來找到最大的 N(P) 滿足所有機率小於給出的 P(N)； 或是找出最小的 N(P) 滿足所有的機率都大於給出的 P(N)

舉例來說，若我們的將 hash result 設定在 2 bytes 大小，那麼可以帶入到上面的公式：

$$
d=2^{16} \\
N(2^{16}) \approx \sqrt{1.386 \times 2^{16}} \approx 301.38
$$

推得 `只要嘗試 320 次，就會有高達 50% 的機率會發生碰撞`，稱之為 birthday attack 的情形，也是暴力法的一種。 防止這樣的攻擊，為增加 Hash string 的大小直到確保 N(d) 夠大，能在有限的時間內難以跑到的數目。

但量子電腦已被證明只需要 $\sqrt[3]{2d}$ 次就很有可能發生碰撞。 [ref](https://link.springer.com/chapter/10.1007/BFb0054319)

## 對於 Data plane 上的考量

由於我們會使用到 hash table 作為保存資料的手段，那麼 hash collision 的問題勢必會對於結果造成影響： 像是不同的 flow ，hash 到同一個位置造成其 value 錯誤的累加，進而造成 FP rate 的提升（但實質上不影響 TP，而是提高 detection 的敏感度）。
那麼我們就得對這個現象來做討論，來挑選我們我們 hash space。

舉例來看，我們若以 1024 格作為 table size， 並且以 IPv4 source address 作為 hash input，則 hash space 為 1024。

$$
d=2^{10} \\
N(2^{10}) \approx \sqrt{1.386 \times 2^{10}} \approx 37.68
$$

經過計算，只需要 34 ~ 35 次便會出現 collision 。

而 sketching 的資料結構，則提供了一定效果的 mitigation - 利用 k 個不同的 hashing function，對同一個 input 做 hash，依序填入到不同的位置（k, hi(k)）之上。（`注意： k 為不同的 hash function，hi 則是其 hash 產生的 value`）然後同個 input 下，在這 k 個位置上選擇最小的作為這個 input 的 value，來消弭掉 hash collision 所造成的誤加。

> 這部份尚未探討 hash function 的行為，若 hash function 所產生的 result 有分佈上的差異性存在，那麼對於 collision 勢必產生一定的影響。

因此，我們必須要在有限的空間下，來將這部份的影響降到最低。

## Reference

* [2018q1 Homework3 (list)](https://hackmd.io/HXDppaI2QGGTkOzlQg2plw?view)
* [生日問題](https://zh.wikipedia.org/wiki/%E7%94%9F%E6%97%A5%E5%95%8F%E9%A1%8C)