# Nhật ký thí nghiệm Reviewer (tập dev, 190 finding; tập test chưa chạy)

| ID | Cấu hình | Lý do đổi | Kết quả (bị loại: nhiễu/thật; OR, p) | Ghi chú |
|---|---|---|---|---|
| C1 | qwen2.5-coder:3b, v1, JSON | Cấu hình đầu | 4/4; OR 1,43; p 0,72 | Prompt viết sau khi đã xem ca 00063 |
| C2 | v2, JSON | Quy tắc theo loại lỗi, cấm nhắc TP/FP | 5/16; OR 0,40; p 0,10 | Chưa có num_predict; 2 timeout; lập luận bị cụt |
| C3 | v2nomsg, JSON | Bỏ thông báo của SAST khỏi prompt | 9/20; OR 0,58; p 0,23 | Chưa có num_predict; 1 timeout |
| C4 | v2nomsg_text, text, num_predict 500 | Sửa giao thức đầu ra (bỏ ép JSON) | 38/46; OR 1,31; p 0,38 | 21 fail-open (15 length, 6 stop); khác C3 ở nhiều yếu tố |
| C5 | như C4, chỉ đổi parser (regex neo TP/FP + CONFIDENCE) | Giảm fail-open do sai định dạng | 38/48; OR 1,22; p 0,56 | 18 fail-open (16 length, 2 stop); 168/169 ca giống C4; có lưu raw_output; Ollama không tái lập tuyệt đối (1 ca lệch) |
| C5b | thử trên 16 ca length của C5: repeat_penalty 1,2 / 1,3 (last_n 256) | 16 ca bị lặp vô hạn, không có dòng quyết định | fail-open 16 → 1 (1,2) và 0 (1,3); 9 FP / 7 TP ở 1,3 | Chưa chấm đúng/sai; mẫu chọn lọc; chọn 1,3 cho C6 |
| C6 | như C5 + repeat_penalty 1,3, repeat_last_n 256 | Hết vòng lặp (C5b) | 26/47; OR 0,67; p 0,226 | 11 fail-open; 83/190 verdict đổi so với C5. Lần chạy đầu (OR 0,48, p 0,017) bị loại vì file có sẵn 10 dòng không rõ nguồn. Kind A: nhiễu bị loại 26/79, thật 31/84. Kind B: thật bị loại 16/27 (dev không có nhiễu ở CWE-326/328). Kết quả nhạy với tham số giải mã; dừng tinh chỉnh 3B |
| C7 | qwen2.5-coder:7b (cùng prompt/parser như C5, không repeat_penalty), chạy trên Kaggle T4 | Thử model lớn hơn cùng họ | 10/22; OR 0,59; p 0,239 | 0 fail-open; 8,56 s/finding; loại 32/190 (nhiễu 10, thật 22); precision sau khoảng 0,563 (trước 0,584); cùng digest model với bản local, Ollama 0.40.13 trên Kaggle nên không đảm bảo trùng bit với lần chạy local |
| C7-note | phân tích lỗi C7 | Hiểu vì sao loại lỗi thật | Lỗi thật bị loại: Kind B 16/27, Kind A 6/84; (FP, high) đúng 10/31 | 7B nhận ra DES/SHA-1 yếu nhưng vẫn FP vì "không do người dùng điều khiển" (áp quy tắc Kind A vào Kind B); confidence không dùng được làm ngưỡng; giả thuyết định tuyến Kind B ra khỏi LLM chọn sau khi xem dev, chưa kiểm chứng; dev không có nhiễu CWE-326/328 |
| C8 | C7 (7B, prompt/parser như C5) + phân loại bằng luật cho Kind B (4 luật Semgrep DES/DESede/MD5/SHA-1 + literal thuật toán yếu → TP, source=rule_based) | 7B áp quy tắc luồng dữ liệu vào lỗi thuật toán yếu, loại nhầm 16/27 | 10/6; OR 2,54 (CI 0,88-6,83); p 0,110 | Phát lại ngoại tuyến từ C7 (không gọi LLM); giữ 105/111 lỗi thật (94,6%), precision 0,603; luật khớp 27/27 trên dev và đều là lỗi thật, nhưng dev không có nhiễu CWE-326/328; quy tắc thiết kế sau khi xem dev nên có thể lạc quan; lọc nhiễu Kind A không đổi (10/79) |

### C9: 7B + luật Kind B + ngữ cảnh callee (dev, đơn vị đếm: finding, n=190)
- Cấu hình: qwen2.5-coder:7b (Kaggle T4), prompt reviewer_v3callee_text (= v2nomsg_text + callee_context, đã bỏ comment), parser v2, --rule-triage, findings_file=tier1_findings_callee.json, tag c9, không repeat_penalty.
- Ngữ cảnh: doSomething lấy từ mã nguồn (141 trong file, 8 ca thing gồm Thing1 và Thing2), chỉ mã, không dùng nhãn. Finding không có callee cho prompt giống hệt prompt cũ (kiểm chứng bằng so chuỗi và số token).
- Kết quả gộp: bị loại 21 nhiễu / 14 thật, OR 2,51; giữ 97/111 lỗi thật (87,4%); precision 0,626; 9,17 giây mỗi finding. 1 fail-open (length, BenchmarkTest01731, là lỗi thật), giữ nguyên và không chạy lại. Luật Kind B xử lý 27/27.
- Phép so sạch (163 finding không qua luật): OR C7 1,88 so với C9 1,81. OR gộp bị luật Kind B làm tăng.
- Nhóm có callee (132): C7 loại 3 nhiễu / 4 thật, C9 loại 17 nhiễu / 13 thật, OR 1,36 (p Fisher 0,536). Nhóm đối chứng không callee (31): 4/31 verdict đổi, nhiễu giải mã.
- Kết luận: callee làm model nói FP nhiều hơn nhưng không tăng khả năng phân biệt. Giả thuyết "giới hạn ở đầu vào" chưa được ủng hộ ở 7B. Cả OR gộp 2,51 (p ≈ 0,014, ước tính tay) lẫn các p khác đều chưa hiệu chỉnh đa so sánh, chỉ là gợi ý.
- Hạn chế nhãn (phát hiện sau C9, hậu nghiệm): nhãn gán theo test case + CWE, không theo dòng. 7 finding path traversal trong dev bị Semgrep báo tại dòng vô hại `fos = null;` (4 nhãn thật, 3 nhiễu). Ở C9, 3 trong 14 ca "loại nhầm thật" thuộc nhóm này (đã xác nhận 00624, 00788: dòng >> khớp file gốc, không phải lỗi đánh số). Verdict của model trên nhóm này không nhất quán (nhiễu 2/3 giữ TP, thật 3/4 loại FP). Chưa sửa nhãn; nếu cần chỉ làm như phân tích độ nhạy riêng, ghi rõ là hậu nghiệm.
- Mâu thuẫn lập luận-verdict (C9, heuristic từ khóa, chưa hiệu chỉnh): ~14/162 verdict LLM (4 FP nhưng lập luận nghiêng vulnerable, 10 TP nhưng nghiêng safe). Đã xác nhận bằng mắt 01000 và 01034: raw_output có đúng 1 dòng DECISION, parser đúng; lỗi ở model. Tác động tối đa nếu sửa hết: +3 thật giữ, +7 nhiễu loại; không đổi kết luận. Không theo hướng tách bước vì lý do này.

### C10: 14B + luật Kind B + ngữ cảnh callee (dev, đơn vị đếm: finding, n=190)
- Cấu hình: qwen2.5-coder:14b (Kaggle T4), prompt reviewer_v3callee_text, parser v2, --rule-triage, findings_file=tier1_findings_callee.json, tag c10, không repeat_penalty. Chỉ đổi model so với C9.
- Kết quả gộp: bị loại 48 nhiễu / 7 thật; giữ 104/111 lỗi thật (93,7%); precision 0,770; 17,5 giây mỗi finding; 0 fail-open. Luật Kind B xử lý 27/27.
- Phép so sạch (163 finding không qua luật): OR C9 1,81 so với C10 17,0 (p Fisher ≈ 4e-13, chưa hiệu chỉnh). Nhóm có callee (132): 1,36 so với 18,8. Nhóm không callee (31): 9,0 so với 58,7 (nhóm nhỏ, CI rộng).
- Kết luận: giới hạn của C9 nằm ở năng lực model (7B), không phải ở luồng hay prompt. Chưa tách được đóng góp của callee ở 14B; cần đối chứng 14B với prompt v2nomsg_text. Một lần chạy, một seed, trên dev dùng chung nhiều cấu hình: coi là gợi ý mạnh, chưa phải kết luận cuối. Confidence high đúng 151/188 ở 14B (7B khoảng 0,52 đến 0,62), chưa dùng làm ngưỡng.

### C11: 14B không callee + luật Kind B (dev, đơn vị đếm: finding, n=190)
- Cấu hình: qwen2.5-coder:14b (Kaggle T4), prompt reviewer_v2nomsg_text, parser v2, --rule-triage, findings gốc tier1_findings.json, tag c11. So với C10 chỉ khác prompt/ngữ cảnh (không callee).
- Kết quả gộp: loại 27 nhiễu / 6 thật; giữ 105/111 lỗi thật (94,6%); precision 0,669; 14,7 giây mỗi finding. 1 fail-open (length, 9fb77669, là lỗi thật), giữ nguyên, không chạy lại.
- Phép so sạch (163 finding không qua luật): OR C11 6,75 so với C10 17,0. Nhóm có callee (132): loại nhiễu 16/67 so với 37/67, loại nhầm thật 3/65 so với 4/65. Nhóm không callee (31): giống hệt từng ca giữa C11 và C10 (14B tái lập khi prompt giống hệt).
- Kết luận: ở 14B, callee giúp loại thêm ~21 nhiễu mà gần như không mất lỗi thật; ở 7B (C9) callee không tăng phân biệt. Cả năng lực model lẫn ngữ cảnh đều đóng góp. Một lần chạy, một seed, dev dùng chung nhiều cấu hình, p chưa hiệu chỉnh: gợi ý mạnh, chưa phải kết luận cuối.
