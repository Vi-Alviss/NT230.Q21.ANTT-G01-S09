# NT230.Q21.ANTT - G01 - S09: Binary Packing

Đồ án môn **Cơ Chế Hoạt Động Của Mã Độc (NT230.Q21.ANTT)** - Học kỳ II, Năm học 2025-2026  
Trường Đại học Công nghệ Thông tin - ĐHQG TP.HCM

---

## Thành viên nhóm G01

| MSSV | Họ và tên |
|------|-----------|
| 23520538 | Phạm Huy Hoàng |
| 23521265 | Nguyễn Minh Quân |
| 23521343 | Nguyễn Ngọc Sáng |
| 23521791 | Ngô Thái Vinh |

---

## Mô tả đề tài

Đề tài nghiên cứu kỹ thuật **Binary Packing** -- một phương pháp che giấu mã độc bằng cách mã hóa hoặc nén payload và giải nén tại runtime để vượt qua các công cụ phát hiện tĩnh. Nhóm xây dựng một mẫu thực nghiệm hoàn chỉnh bao gồm quá trình tạo mã độc, thực thi và phát hiện.

---

## Cấu trúc thư mục

```
.
├── attacker-resource.zip       # Tài nguyên dùng để tạo mã độc (pipeline.py, stub.cpp, ...)
├── README.md
│
├── malware/                    # Các mẫu mã độc thực tế dùng để kiểm tra công cụ
│   ├── 8eef23a3...zip          # UPX.exe        - VECT Ransomware, packed bằng UPX
│   ├── 43cee7b6...zip          # NETReactor.exe - PureHVNC/PureLogsStealer, packed bằng .NET Reactor
│   ├── d606048b...zip          # Themida.exe    - packed bằng Themida
│   ├── c37a58f4...zip          # Aspack.exe     - Worm.Ramnit, packed bằng ASPack
│   ├── ccb89fc3...zip          # Confuser.exe   - AgentTesla/RedLine, obfuscated bằng ConfuserEx
│   ├── 757810be...zip          # AgentTesla.exe - Agent Tesla RAT, không dùng packer
│   ├── 39b8a86b...zip          # RLPack.exe     - CyberGate RAT, packed bằng RLPack
│   └── executable-extract-this.zip  # payload.exe và stub.exe do nhóm tự tạo
│
└── tool/                       # Công cụ BinaryPackingDetector
    ├── packing_detector.py     # Script chính
    ├── models.py               # Data models
    ├── reporter.py             # Xuất kết quả (console / JSON)
    ├── analyzers/              # Các module phân tích
    │   ├── entropy.py          # Phân tích entropy
    │   ├── pe_sections.py      # Phân tích PE section
    │   ├── imports.py          # Phân tích import API
    │   ├── signatures.py       # Nhận diện packer signature
    │   └── dotnet.py           # Phân tích .NET assembly
    └── *.json                  # Kết quả phân tích từng mẫu
```

---

## Hướng dẫn sử dụng công cụ

### Yêu cầu

```bash
pip install pefile
```

### Chạy phân tích

```bash
# Phân tích một file, xuất kết quả ra console
python packing_detector.py <đường_dẫn_file>

# Phân tích một file, xuất kết quả ra JSON
python packing_detector.py <đường_dẫn_file> --json <tên_output>.json

# Ví dụ
python packing_detector.py /home/kali/nt230-tool/malware/stub.exe --json stub.json
```

### Mức rủi ro

| Score | Risk Level |
|-------|------------|
| ≤ 3   | LOW        |
| 4 – 9 | MEDIUM     |
| ≥ 10  | HIGH       |

---

## Nguồn mẫu mã độc

Các mẫu mã độc được tải từ kho lưu trữ công khai [MalwareBazaar](https://bazaar.abuse.ch) phục vụ mục đích nghiên cứu và học thuật. File trong thư mục `malware/` được đặt tên theo SHA256 hash gốc và nén có mật khẩu `infected` theo chuẩn MalwareBazaar.

> ⚠️ **Cảnh báo:** Các file trong thư mục `malware/` là mã độc thực tế. Chỉ giải nén và thực thi trong môi trường máy ảo cô lập. Nhóm không chịu trách nhiệm nếu sử dụng sai mục đích.

---

## Môi trường thực nghiệm

- **Attacker:** Kali Linux (IP: 10.211.4.110)
- **Victim:** Windows 10 64-bit (IP: 10.211.4.1)
- Hai máy chạy trong môi trường máy ảo cô lập
