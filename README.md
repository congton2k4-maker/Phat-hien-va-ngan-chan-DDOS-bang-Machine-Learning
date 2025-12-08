# 🛡️ Demo ML – DDoS Detection 2025

SDN Floodlight + Mininet + Machine Learning

Tài liệu này hướng dẫn toàn bộ quy trình từ cài đặt Floodlight, thu thập dữ liệu, huấn luyện mô hình Machine Learning, đến chạy demo realtime phát hiện & chặn tấn công DDoS (HTTP Flood).

## Mục lục

- **Tổng quan**
- **Yêu cầu hệ thống**
- **1. Cài đặt Floodlight**
- **2. Thu thập dữ liệu để train ML**
- **3. Huấn luyện mô hình Machine Learning**
- **4. Demo realtime phát hiện & chặn DDoS**
- **5. Theo dõi traffic bằng Wireshark**
- **File đầu ra**
- **Ghi chú & khuyến nghị**

## Tổng quan

Kho chứa này chứa script để: tạo topology Mininet, tạo traffic bình thường & DDoS, thu thập flow stats từ Floodlight, huấn luyện mô hình ML, và chạy realtime detection với khả năng push flow rule để chặn host tấn công.

Mọi lệnh trong hướng dẫn được chạy từ thư mục gốc `source/` trừ khi có ghi chú khác.

## Yêu cầu hệ thống

- Hệ điều hành mục tiêu: Ubuntu 22.04 (đề xuất)
- Python 3.10
- JDK 1.8 (cho Floodlight)
- Quyền sudo cho một số lệnh Mininet/Wireshark

Lưu ý: hướng dẫn cài Floodlight có thể theo video hướng dẫn (khuyến nghị). Sau khi Floodlight chạy, kiểm tra controller:

```
http://localhost:8080/wm/core/controller/switches/json
```

## 1. Cài đặt Floodlight

Làm theo hướng dẫn tương ứng (video hoặc tài liệu Floodlight). Các bước tổng quát:

- Cài JDK 1.8
- Clone Floodlight và build
- Chạy Floodlight controller

Sau khi cài thành công, dùng Mininet để tạo switch + host và xác thực Floodlight đã thấy switch (trên URL ở trên).

## 2. Thu thập dữ liệu để train ML

Bạn cần 2 terminal (tất cả chạy từ thư mục `source/`):

- Terminal A — Thu thập traffic (bình thường và DDoS) → ghi vào CSV
- Terminal B — Tạo traffic (bình thường hoặc DDoS)

⭐ Thu thập traffic bình thường

Terminal B – tạo traffic bình thường

```bash
sudo python3 mininet/generate_normal_traffic.py
```

Terminal A – thu thập dữ liệu

```bash
python3 controller/collect_training_stats_floodlight.py --interval 5 --label 0
```

Khuyến nghị: thu đến khi file CSV đạt khoảng ~500 KB.

🔥 Thu thập traffic DDoS

Terminal B – tạo traffic DDoS

```bash
sudo python3 mininet/generate_ddos_traffic.py
```

⚠️ Script DDoS chạy rất nhanh → label `1` có thể chiếm nhiều dòng hơn `0`. Chỉ chạy 1–2 giây rồi dừng để cân bằng dataset.

Terminal A – thu thập dữ liệu DDoS

```bash
python3 controller/collect_training_stats_floodlight.py --interval 5 --label 1
```

Sau khi hoàn tất, dataset sẽ ở thư mục `output/` (ví dụ: `output/FlowStatsfile.csv`).

## 3. Huấn luyện mô hình Machine Learning

Chuyển về thư mục gốc `source/`, rồi chạy:

```bash
python3 machinelearning/ML_trainer.py --csv output/FlowStatsfile.csv
```

Kết quả (trong cùng thư mục `source/` hoặc thư mục do script chỉ định):

- `model.pkl` — mô hình ML đã huấn luyện
- `metadata.pkl` — threshold, feature list, scaler, medians
- 3 ảnh đánh giá hiệu năng (e.g., ROC, confusion matrix)

## 4. Demo realtime phát hiện & chặn DDoS

Cần 3 Terminal, tất cả mở tại thư mục `source/`.

- Terminal A — Chạy ML realtime để phát hiện/chặn DDoS
- Terminal B — Collector realtime → ghi vào `output/PredictFlowStatsfile.csv`
- Terminal C — Chạy topology bằng Mininet

Các bước chi tiết:

1) Terminal C — Khởi chạy topology

```bash
python3 mininet/topology.py
```

Trong CLI của Mininet, khởi xterm cho host:

```bash
xterm h1 h2 h3
```

2) Trên các xterm của host:

- h1 — khởi chạy HTTP server

```bash
cd mininet
python3 -m http.server 80
```

- h2 — ping đều đến h1

```bash
csh mininet/ping.csh
```

- h3 — script DDoS (chạy sau khi collector realtime bắt đầu)

```bash
sh mininet/ddos_no_flood.csh
```

3) Terminal B — Thu thập traffic realtime

```bash
python3 controller/collect_realtime_traffic_ml.py
```

Kiểm tra file `output/PredictFlowStatsfile.csv` được cập nhật theo chu kỳ.

4) Terminal A — Chạy mô hình ML realtime

```bash
python3 realtime_floodlight_ML.py \
  --model model.pkl \
  --predict-file output/PredictFlowStatsfile.csv \
  --interval 2 \
  --detect-window 12 \
  --required-hits 3
```

5) Khi collector & ML realtime đang chạy, khởi tấn công từ h3 (xterm của h3):

```bash
sh mininet/ddos_no_flood.csh
```

Nếu đúng trình tự, Terminal A (realtime ML) sẽ ghi nhận và in ra thông báo như:

```
Push flow...
```

→ Luật *block* sẽ được cài vào switch để chặn hoàn toàn DDoS từ host tấn công. Bạn có thể thử `curl http://h1` từ host bị chặn và sẽ không nhận được phản hồi.

## 5. Theo dõi traffic bằng Wireshark

Khởi chạy Wireshark (trên máy chạy Mininet / controller):

```bash
sudo wireshark
```
