### Environment Settings

##### Server side

WMNLab Ubuntu Server

iPerf-3.9

##### UE side

小米 10T （同上一次）

iPerf-3.1

### Methodology

##### 控制變因

以 iPerf3 從 Server 傳送固定週期的封包，由手機透過 4G/5G 接收（Downlink），使用 tcpdump 記錄成 .pcap file

電信商：台灣大哥大（預付卡 計量型 60GB）

關閉 Wi-Fi

Duration for each setting: 130 seconds ⇒ 移動的情境下，前 10 秒 setup 後尚未開始騎車，末 10 秒抵達終點停車（可去頭去尾分析）

packet length: 250 bytes

##### 操縱變因

(TCP, UDP) x (4G, 5G) x (moving, stationary) x period

UDP ⇒ /sbin/iperf3.1 -c [Server IP] -p [Port Num] **-u** -V -R -t 130 -l 250 -b 20k

TCP ⇒ /sbin/iperf3.1 -c [Server IP] -p [Port Num] -V -R -t 130 -l 250 -b 20k

4G only

(如圖 4G only)

5G

(如圖 5G)

stationary ⇒ EE2-249

moving ⇒ 騎車繞行全球變遷中心＆海洋研究所

(如圖 moving_site)

Period: 0.1, 0.2, 0.3, ..., 1, 2, 3, ..., 10 (sec) ⇒ 19種週期

透過 iperf3 **-l (length)**, **-b (bitrate)** 參數設置

以每隔 0.3 秒傳送一個封包為例

**-l 250** 代表每個封包塞 250 bytes 的 payload

**-b 6666** 代表 data rate 設為 6,666 bps

相當於 3.33 packets per second，即我們想設定的 0.3 sec 的週期

此外，我們也檢查，iperf3 在每秒傳送複數個封包時，會以什麼樣的 traffic 傳送？會是在一秒內的開頭盡可能一次傳出？還是以固定週期每 0.3 秒傳送一個封包？

(如圖 period_check)

檢查結果如圖，週期非常的固定，只有些微的誤差（可忽略）

