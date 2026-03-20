# Tài Liệu Triển Khai Hệ Thống WAF Bảo Vệ OWASP Juice Shop

Tài liệu này hướng dẫn chi tiết từng bước xây dựng hệ thống proxy Nginx tích hợp ModSecurity (WAF) để bảo vệ ứng dụng web mục tiêu (OWASP Juice Shop) theo đúng 5 yêu cầu chuẩn kỹ thuật.

---

## [SV 1] Hạ tầng & Mạng: Docker Compose và Mạng Ảo Cô Lập (2.0đ)

**Mục tiêu:** Chạy ứng dụng web mục tiêu (Juice Shop) và WAF hoàn toàn trên nền tảng Docker, đảm bảo Juice Shop bị cô lập và không thể bị truy cập trực tiếp từ bên ngoài ngoại trừ đi qua WAF.

**Cách thực hiện (Step-by-Step):**
1. Tạo kiến trúc thư mục chứa dự án: 
   Sẽ có 2 thành phần chính: thư mục `owasp_juice_shop/` chứa app mục tiêu, thư mục `waf/` chứa Nginx proxy.
2. Thiết lập Mạng Nội Bộ (Docker Network): 
   Trong file `docker-compose.yml`, tạo cấu hình cấp mạng ảo kiểu bridge:
   ```yaml
   networks:
     app_network:
       driver: bridge
   ```
3. Khởi tạo dịch vụ backend (Juice Shop): 
   Juice Shop lắng nghe trên cổng `3000`. **Không ánh xạ cổng này (không dùng `ports`)** ra máy host, mà chỉ kết nối khối này vào `app_network`. Việc này gọi là "Cô lập hạ tầng", kẻ tấn công đứng ngoài Host không thể trực tiếp chọc vào IP:3000.
4. Cấu hình khối mạng cho WAF kết nối tới Backend: 
   Chỉ cho khối WAF mở cổng ra ngoài (`ports: 80 và 443`), sau đó gắn WAF chung mạng `app_network`. WAF có thể gọi Juice Shop dễ dàng thông qua hostname là tên dịch vụ: `http://owasp_juice_shop:3000`.

---

## [SV 2] Reverse Proxy: Nginx Proxy & Chứng Chỉ SSL/TLS An Toàn (2.0đ)

**Mục tiêu:** Cài đặt Nginx làm Proxy ngược tiếp nhận mọi connection, điều hướng sang Juice Shop; cấu hình HTTPS nâng cao để chống nghe lén.

**Cách thực hiện:**
1. Khởi tạo Chứng chỉ nội bộ bằng OpenSSL: 
   ```bash
   mkdir ssl && cd ssl
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/CN=localhost"
   openssl dhparam -out dhparam.pem 2048 # Trao đổi khóa an toàn
   ```
2. Cấu hình Nginx kết nối SSL (file `default.conf`): 
   Mount các chứng chỉ vừa tạo vào `/etc/nginx/ssl`. Thiết lập Nginx lắng nghe Port SSL (ví dụ `8443`) và trỏ đường dẫn tới `.crt` và `.key`.
3. Tăng cường chuẩn mã hóa (Hardening SSL/TLS): 
   Trong `default.conf`, tiến hành loại bỏ giao thức cũ, chỉ dùng **TLS 1.2 và TLS 1.3**:
   ```nginx
   ssl_protocols TLSv1.2 TLSv1.3;
   ssl_prefer_server_ciphers on;
   ssl_session_tickets off;
   # Cấu hình HSTS ép buộc trình duyệt chỉ dùng HTTPS
   add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
   ```
4. Cấu hình Reverse Proxy Block:
   Ở khối `location /`, sử dụng `proxy_pass http://owasp_juice_shop:3000;` để chuyển tiếp nội dung từ backend về cho người dùng. Kèm theo đó phải giữ nguyên IP gốc của client bằng `proxy_set_header X-Real-IP`.

---

## [SV 3] Core WAF: Tích hợp ModSecurity & OWASP CRS (2.0đ)

**Mục tiêu:** Bật module ModSecurity trên Nginx và triển khai bộ luật chuẩn công nghiệp ModSecurity Core Rule Set (OWASP CRS).

**Cách thực hiện:**
1. Khai báo module ở hệ thống gốc:
   Ở dòng đầu tiên của file `nginx.conf`, yêu cầu tải module ModSecurity gốc:
   `load_module modules/ngx_http_modsecurity_module.so;`
2. Kích hoạt ModSecurity Engine:
   Trong template `modsecurity.conf`, cấu hình biến nội bộ để ép hệ thống nhận diện đây là Tường lửa chủ động: `modsecurity on;`.
3. Cài đặt OWASP CRS:
   Thêm các file luật OWASP CRS vào Docker container. Bên trong `modsecurity_rules_file`, trỏ một biến Include để nó nạp tự động toàn bộ CRS (ví dụ file `crs-setup.conf` và các tệp luật bên dưới thư mục `owasp-crs/rules/`). Ngay từ lúc này, hệ thống Nginx đã biết chặn những từ khóa cơ bản như `<script>`, `UNION SELECT`.

---

## [SV 4] Virtual Patching: Viết 3 Custom Rules Chặn Đích Danh (2.0đ)

**Mục tiêu:** Áp dụng phương pháp "Vá giả lập" (Virtual Patching). Viết riêng 3 Custom rules cho WAF để vá nhanh các lỗ hổng cụ thể trên Owasp Juice Shop mà không cần sửa code backend.

**Cách thực hiện (Tạo file `REQUEST-999-CUSTOM-VIRTUAL-PATCHES.conf`):**

**Rule 1: Chặn đứng SQL Injection trên chức năng Đăng Nhập (`/rest/user/login`)**
*Mô tả: Lỗ hổng cho phép bypass authentication bằng cách truyền `' or 1=1--` vào chuỗi email.*
```apache
SecRule REQUEST_URI "@contains /rest/user/login" \
    "id:100001,phase:2,deny,status:403,log,msg:'Virtual Patch: SQLi Blocked on Login Page',chain"
    SecRule ARGS:email "@rx (?:'|%27)\s*(?:OR|or|\|\|)\s*(?:1=1|true)"
```

**Rule 2: Chặn Cross-site Scripting (XSS) hiển nhiên ở chức năng Tìm Kiếm (`/rest/products/search`)**
*Mô tả: Kẻ tấn công thường chèn thẻ `iframe` hoặc `script` vào thanh Query Parameter `q=`.*
```apache
SecRule REQUEST_URI "@contains /rest/products/search" \
    "id:100002,phase:2,deny,status:403,log,msg:'Virtual Patch: XSS Blocked on Search Query',chain"
    SecRule ARGS:q "@rx (?i)(?:<script.*?>|<iframe.*?>|javascript:)"
```

**Rule 3: Chặn LFI/Path Traversal Nhắm Vào Thư Mục Hình Ảnh (`/ftp`)**
*Mô tả: Kẻ tấn công có thể chèn `../../` vào thư mục để đọc được file cấu hình bí mật ở thư mục mẹ.*
```apache
SecRule REQUEST_URI "@beginsWith /ftp" \
    "id:100003,phase:1,deny,status:403,log,msg:'Virtual Patch: Directory Traversal Blocked on FTP Path'"
    SecRule REQUEST_FILENAME "@rx (?:/\.\.(?:/|%2f)|\.\.(?:/|%2f))"
```
*Cách apply: Mount file Custom Rules này vào con đường cuối cùng mà OWASP CRS gọi tới trong container WAF.*

---

## [SV 5] Hardening Host: Rate Limiting & Tường Lửa Iptables/UFW (2.0đ)

**Mục tiêu:** Chống lại kỹ thuật vét cạn (Brute-force/DoS) từ Nginx và cắt đứt hoàn toàn những truy cập bất hợp pháp vòng qua WAF ở lớp máy chủ Hệ điều hành (Host OS).

**Khâu 1: Rate Limiting trên Nginx (Chống DoS/Brute-force)**
* Cấu hình vùng nhớ (Zone) trong khối `http` ở file `nginx.conf`:
  `limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;` (Mỗi IP cấp phát bộ nhớ 10MB theo dõi, chỉ được quét 10 requests/s).
* Kích hoạt vào endpoint cụ thể trong `default.conf` ở khối `location /`:
  `limit_req zone=req_limit_per_ip burst=30 nodelay;`
  Từ đó, nếu có tool Scan lỗ hổng tự động bắn phá tốc độ cao, Nginx lập tức trả về lỗi **429 (Too Many Requests)**.

**Khâu 2: Cấp Tường lửa mức Hệ Điều Hành (OS Firewall - UFW/Iptables) để ngăn Bypass**
Dù đã áp dụng Docker Network (SV 1) nhưng đôi khi môi trường Docker tự chọc thủng iptables đưa cổng ra ngoài host sai lệch. Giải pháp bọc lót cuối cùng ở mức máy chủ vật lý Host (Ví dụ trên máy Ubuntu/Debian):

1. Từ chối mọi truy cập vào tất cả các cổng theo mặc định:
   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   ```
2. Chỉ mở đúng cổng 80 và 443 cho WAF Nginx (và cổng SSH để quản trị):
   ```bash
   sudo ufw allow 22/tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```
3. Chặn cứng cổng 3000 (Backend) để tránh lọt traffic, chỉ Docker network của Nginx mới được quyền nói chuyện với cổng 3000:
   ```bash
   sudo ufw deny 3000/tcp
   sudo ufw enable
   ```
Khóa chặt toàn hệ thống! Mọi hacker buộc phải đi qua "cửa trước" (cổng 80/443) -> đập mặt vào Nginx TLS -> phân tích qua ModSecurity WAF -> Cấu hình giới hạn Rate Limiting, trước khi kịp nhìn thấy cái tên OWASP Juice Shop.
