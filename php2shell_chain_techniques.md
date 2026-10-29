# PHP2Shell — Mỗi Chain dùng kỹ thuật gì — mapping rõ ràng

---

## Chain A: Code Injection (không phải memory corruption)

```
Kỹ thuật: File Content Injection + Local File Inclusion
```

Chain A KHÔNG dùng UAF, heap spray, hay bất kỳ memory corruption nào. Nó đơn giản là:

```
Ghi PHP code vào file → include file đó → PHP chạy code

Cụ thể:
1. [Session Fixation] — control SID qua POST body (bypass use_only_cookies)
2. [Unsanitized Input to File] — tên file ghi thẳng vào session file, không filter
3. [Local File Inclusion] — app include session file → execute injected code
```

Tương đương trong thế giới khác:

* Web: Log poisoning + LFI (ghi payload vào access.log rồi include)
* Linux: Write to `/tmp/cron.d/` → cron execute

Đây là chain đơn giản nhất, không cần hiểu memory.

---

## Chain B: Use-After-Free + Heap Spray + Function Pointer Overwrite

```
Kỹ thuật:
├── Use-After-Free (đọc memory đã free)
├── Heap Spray (chiếm vùng freed bằng controlled data)
└── Function Pointer Overwrite (ghi đè handler → hijack execution)
```

Từng bước mapping:

```
1. [Heap Overflow/Confusion]
   unserialize() với 2000+ entries → overflow VAR_ENTRIES_MAX (1018)
   → var_entries chunk bị đẩy ra ngoài expected range

2. [Use-After-Free]  ← CORE BUG
   var_destroy() Phase 1: efree(var_entries)     → FREE
   var_destroy() Phase 2: __destruct()            → USE pointer cũ
   → __destruct gọi inner unserialize('R:1500;') 
   → R:1500 = reference tới entry trong var_hash ĐÃ FREE
   → ĐỌC VÙNG MEMORY ĐÃ FREE

3. [Heap Spray]
   Inner unserialize spray strings cùng size với var_entries
   → emalloc cấp phát vào ĐÚNG vùng vừa free
   → Attacker kiểm soát nội dung vùng đó

4. [Function Pointer Overwrite]  ← RCE PRIMITIVE
   Dùng /proc/self/mem ghi đè var_dump->handler = zif_system
   → var_dump("id") thực ra gọi system("id")
```

Tương đương iOS:

* UAF: giống IOMobileFrameBuffer UAF (CVE-2021-30883)
* Heap spray: giống IOSurface property spray
* Function pointer overwrite: giống overwrite vtable trong kernel object

---

## Chain C: Type Confusion + Deserialization Attack

```
Kỹ thuật:
├── Type Confusion (handler mismatch = đọc data bằng sai format)
├── Deserialization Attack (inject serialized object → __destruct)
└── State Leak Across Requests (PS(serializer) không reset)
```

Từng bước:

```
1. [State Leak / Stale State]
   PS(serializer) không reset giữa FPM requests
   → Worker bị "nhiễm" php_serialize handler từ request trước

2. [Type Confusion]  ← CORE BUG
   Writer dùng php_serialize: data = upload_progress|a:1:{s:4:"name";s:10:"x|O:Evil..."}
   Reader dùng php:          gặp | → tách → deserialize phần sau |
   
   CÙNG BYTES, HIỂU KHÁC NHAU:
   - php_serialize nghĩ: | là ký tự bình thường trong filename string
   - php nghĩ:           | là delimiter giữa key và serialized value
   → Object Evil được tạo ra ngoài ý muốn

3. [Deserialization Attack / POP Chain]
   Decode FAIL (trailing data) → nhưng PHP_VAR_UNSERIALIZE_DESTROY
   vẫn gọi __destruct trên object đã tạo
   → __destruct → POP gadget chain → system() / file_put_contents() → RCE
```

Tương đương:

* iOS: Type confusion (CVE-2023-32434) — kernel cast object sai type
* Java: Deserialization attack (Apache Commons, ysoserial)
* .NET: BinaryFormatter deserialization → POP gadget → RCE

---

## Chain D: longjmp Abuse + Stale Global State + Use-After-Free + Heap Spray

```
Kỹ thuật:
├── Resource Exhaustion (trigger OOM)
├── longjmp Abuse (skip stack cleanup)
├── Stale Global State (EG() invalid sau longjmp)
├── Use-After-Free (shutdown đọc stale EG pointers)
└── Heap Spray (chiếm vùng stale → control execution)
```

Từng bước:

```
1. [Resource Exhaustion]
   POST với 5000 headers × 500 bytes
   → PHP emalloc cho mỗi header → vượt memory_limit → OOM
   
   HOẶC: chunked transfer (no Content-Length) → bypass post_max_size
   HOẶC: nested array bomb → exponential memory

2. [longjmp Abuse]  ← CORE BUG #1
   OOM → zend_out_of_memory() → zend_bailout() → longjmp()
   
   longjmp NHẢY QUA tất cả:
   ✗ Không gọi destructor
   ✗ Không free local variables
   ✗ Không unwind stack frames
   ✗ Không reset global state
   
   → EG() globals (objects_store, error_handler, etc.) ở trạng thái GIỮA CHỪNG

3. [Stale Global State]  ← CORE BUG #2
   Apache mod_php bắt longjmp → GỌI php_request_shutdown() BẤT CHẤP
   
   Shutdown code assumes EG() valid:
   → zend_objects_store_destroy(EG(objects_store))  // objects_store CHƯA INIT XONG
   → zend_stack_destroy(EG(user_error_handlers))    // error handlers STALE

4. [Use-After-Free]
   Shutdown dereference EG() pointers → trỏ vào:
   - Vùng partially initialized (chứa garbage)
   - Vùng đã free bởi code trước longjmp
   → READ/WRITE vào controlled memory

5. [Heap Spray]
   Multipart fields TRƯỚC OOM đã emalloc nhiều chunks
   → Attacker kiểm soát nội dung các chunks đó
   → Khi shutdown đọc stale pointer → đọc vào controlled data
   → Fake object/vtable → hijack execution → RCE
```

Tương đương iOS:

* longjmp abuse: XNU exception handling path (hiếm)
* Stale globals: giống kernel panic recovery path leaving state dirty
* UAF + heap spray: classic iOS kernel exploitation pattern

Chain D là chain đặc biệt nhất — kỹ thuật longjmp abuse cực hiếm trong exploitation, cả kernel lẫn userspace.

---

## Chain E: Stale State Across Requests + Use-After-Free + Heap Spray

```
Kỹ thuật:
├── Resource Exhaustion (trigger OOM trong session_start)
├── longjmp Abuse (skip unserialize cleanup)
├── Cross-Request State Leak (BG() persist qua requests)  ← ĐẶC TRƯNG
├── Race Condition (rfc1867 chạy trước RINIT)
├── Use-After-Free (đọc stale BG pointers)
└── Heap Spray (chiếm freed memory)
```

Từng bước:

```
1. [Resource Exhaustion]
   Tạo session file 30MB → session_start() → php_var_unserialize(30MB)
   → emalloc cho unserialize data → OOM

2. [longjmp Abuse]
   OOM → zend_bailout() → longjmp
   → php_var_unserialize_init() ĐÃ set BG(unserialize).level = 1
   → longjmp skip PHP_VAR_UNSERIALIZE_DESTROY
   → BG(unserialize) giữ stale pointers

3. [Cross-Request State Leak]  ← CORE BUG
   FPM worker SỐNG SÓT (OOM post-startup)
   → Worker nhận request mới
   → BG(unserialize) VẪN GIỮ state từ request cũ
   
   iOS equivalent: kernel port reference survive across process death

4. [Race Condition / Ordering Bug]
   Request mới xử lý theo thứ tự:
   ① rfc1867 handler (upload progress)    ← ĐỌC BG() — STALE!
   ② PHP_RINIT_FUNCTION(basic)            ← RESET BG() — QUÁ MUỘN!
   
   Handler chạy TRƯỚC reset → window để exploit

5. [Use-After-Free]
   rfc1867 thấy BG(unserialize).level = 1 → "đang unserialize"
   → Truy cập BG(unserialize).data → DANGLING POINTER
   → Đọc/ghi vùng memory đã free từ request trước

6. [Heap Spray]
   Request consumer gửi multipart data lớn
   → emalloc cho multipart fields → chiếm vùng freed
   → Khi rfc1867 đọc stale BG → đọc vào controlled data
   → Fake object → __destruct → RCE
```

---

## Tổng kết: Bản đồ kỹ thuật

```
                    Code       Type        UAF     Heap    longjmp   Stale    Race
                  Injection  Confusion            Spray    Abuse    State   Condition
                  
Chain A:            ██                                                
Chain B:                                   ██      ██                         
Chain C:                       ██                                    ██       
Chain D:                                   ██      ██       ██       ██       
Chain E:                                   ██      ██       ██       ██       ██
```

```
Từ dễ → khó:

Chain A ──── Web-level bug (injection + LFI, ai cũng hiểu)
Chain C ──── Logic bug (type confusion + deserialization, cần hiểu PHP internals)
Chain B ──── Memory bug (UAF, cần hiểu heap)
Chain E ──── Memory + Logic + Race (UAF + stale state + ordering, cần hiểu FPM lifecycle)
Chain D ──── Memory + Exception handling (UAF + longjmp, cần hiểu Zend engine + Apache module)
```

Chain D và E dùng nhiều kỹ thuật nhất, cũng là 2 chain nguy hiểm nhất (zero/near-zero dependency).
