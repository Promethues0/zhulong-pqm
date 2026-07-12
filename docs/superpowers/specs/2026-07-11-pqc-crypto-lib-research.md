# 配套参考：PQC/国密密码库调研数据（引擎三张字典）

> 本文件是 [PQC 识别引擎设计](2026-07-11-pqc-recognition-and-distributed-discovery-design.md) 的数据附录。
> 由 10 库并行调研（PQMagic/pqcrypto-cn、SymCrypt、openHiTLS、AWS-LC、铜锁 Tongsuo、OpenSSL 3.5+、liboqs/oqs-provider、BoringSSL、GmSSL）+ IANA「TLS Supported Groups」官方注册表逐条校验合成。日期 2026-07-11。
> `cryptoref/` 包的 Go 表按本文件落地；标 ⚠ 的条目是引擎必须特殊处理的坑。

---

## 0. 验收包 0x11EE 判定（最重要结论）

抓包里到 `:1443` 的 `0x11EE` = **IANA #4590 `curveSM2MLKEM768`**（SM2 ECDHE + ML-KEM-768 国密混合组，draft-yang-tls-hybrid-sm2-mlkem-03，DTLS-OK=N Rec=N）。实现方**几乎可断定是铜锁 Tongsuo 8.5+**（`tlsgroups.h` 定义 `OSSL_TLS_GROUP_ID_curveSM2MLKEM768=0x11EE` 并默认启用；该草案本身即铜锁阵营主导）。

三重依据：
1. **尺寸逐字节吻合**：client key_share 1249B = 65B SM2 未压缩点 ‖ 1184B ML-KEM-768 封装公钥；server 1153B = 65B ‖ 1088B ML-KEM 密文；共享密钥 = SM2 ECDH x坐标(32B) ‖ ML-KEM ss(32B) = 64B。
2. **⚠ 尺寸不能作判据**：`0x11EB(SecP256r1MLKEM768)` 的 client(1249B)/server(1153B) 与 0x11EE **完全相同**。身份**只能靠码点本体判定**，尺寸启发式在此失效。
3. **排除法归因铜锁**：OpenSSL 3.5 / BoringSSL / AWS-LC / SymCrypt(SChannel) / oqs-provider 均不实现 0x11EE；openHiTLS 的 `HITLS_NamedGroup` 枚举无此项；GmSSL 仅在头文件定义枚举与 trace 名（`TLS_curve_sm22mlkem768`）但握手不协商（截至 3.3.0-dev）。公开生态里真正能在握手中发出该 key_share 的只有铜锁（或"PQMagic 供 ML-KEM 原语 + 国密协议库"的等价组合栈）。
4. **时间指纹**：draft-02 时代该组曾用临时私用码点 `0xFEFE`，-03 起才获正式 0x11EE。见 0xFEFE = 旧版铜锁部署。

**引擎规则**：见 0x11EE ⇒ 标注「国密 PQC 混合(curveSM2MLKEM768, IANA 4590)」，`KexSafety=hybrid`，归因铜锁 Tongsuo 系，置信度高。

---

## A. named_group_table（TLS 命名组码点）

码点是 TLS `supported_groups`/`key_share` 里的 2 字节标识。`kind`：classical=纯经典 / hybrid=经典+PQC / pqc=纯后量子。`is_iana`：是否 IANA 正式分配。

### A.1 经典基线组（IANA）

| 码点 | 名称 | kind | share 尺寸 | 备注 |
|---|---|---|---|---|
| 0x0015 | secp224r1 | classical | 57B | IANA#21 Rec=D。注意 #19=secp192r1、#20=secp224k1 |
| 0x0017 | secp256r1 | classical | 65B | IANA#23 Rec=Y |
| 0x0018 | secp384r1 | classical | 97B | IANA#24 Rec=Y |
| 0x0019 | secp521r1 | classical | 133B | IANA#25 Rec=**N**（勿与 P-256/384 的 Rec=Y 混同） |
| 0x001A-1C | brainpoolP{256,384,512}r1 | classical | 65/97/129B | IANA#26-28 RFC7027；TLS1.3 版 =#31-33(RFC8734) |
| 0x001D | x25519 | classical | 32B | IANA#29 Rec=Y。OpenSSL≥3.5/BoringSSL 默认双 key_share 之二 |
| 0x001E | x448 | classical | 56B | IANA#30 |
| 0x0022-28 | GC256A/B/C/D + GC512A/B/C (GOST) | classical | - | IANA#34-40 RFC9189 Rec=N（**正式登记**，非私有） |
| 0x0029 | curveSM2 | classical | 65B | IANA#41 RFC8998（**正式 IANA 码点**，非铜锁私有）。GmSSL 3.x TLS1.3 唯一默认组；国密栈经典指纹 |

### A.2 IANA PQC 与混合组（当前主线）

| 码点 | 名称 | kind | client/server 尺寸 | 备注 |
|---|---|---|---|---|
| 0x0200 | MLKEM512 | pqc | 800B / ct 768B | IANA#512 draft-connolly。⚠撞号史见 §D.1 |
| 0x0201 | MLKEM768 | pqc | 1184B / ct 1088B | IANA#513 |
| 0x0202 | MLKEM1024 | pqc | 1568B / ct 1568B | IANA#514 |
| 0x11EB | SecP256r1MLKEM768 | hybrid | 1249B / 1153B | IANA#4587 Rec=N。⚠与 0x11EE 尺寸完全相同，只能靠码点区分 |
| **0x11EC** | **X25519MLKEM768** | hybrid | 1216B / 1120B | **IANA#4588 Rec=Y——注册表唯一 Recommended=Y 的 PQC 组**。当前互联网主流(OpenSSL≥3.5/Chrome131+/AWS-LC 默认)。字节序 ML-KEM(1184) 在前 ‖ X25519(32)，与 0x6399 相反 |
| 0x11ED | SecP384r1MLKEM1024 | hybrid | 1665B / 1665B | IANA#4589 Rec=N，最高安全档 |
| **0x11EE** | **curveSM2MLKEM768** | hybrid | 1249B / 1153B | **IANA#4590 国密 SM2+ML-KEM 混合**。公开生态唯一默认实现=铜锁 Tongsuo 8.5+。见 §0 |

### A.3 已废弃 / 历史 IANA 码点（识别旧流量用）

| 码点 | 名称 | kind | 尺寸 | 备注 |
|---|---|---|---|---|
| 0x6399 | X25519Kyber768Draft00 (OBSOLETE) | hybrid | 1216B / 1120B | IANA#25497 Rec=D。2023-24 Chrome116-130/Cloudflare 大规模部署，被 0x11EC 取代。X25519(32) 在前 ‖ Kyber768(1184) |
| 0x639A | SecP256r1Kyber768Draft00 (OBSOLETE) | hybrid | 1249B | IANA#25498 Rec=D。被 0x11EB 取代 |
| 0x4138 | CECPQ2 (X25519+NTRU-HRSS-701) | hybrid | ≈1189B | **非 IANA**，BoringSSL 私有 16696（2018-2023）。仅历史指纹 |
| 0xFEFE | curveSM2MLKEM768 (draft-02 临时码点) | hybrid | 1249B | **非 IANA**，-03 起改正式 0x11EE。见此=旧版铜锁 |
| 0x0512/0x0768/0x1024 | MLKEM512/768/1024 (早期虚荣码点) | pqc | 800/1184/1568B | **非 IANA**，draft-connolly -00~-02。见 0x0768=极旧实验栈 |

### A.4 OQS 私有码点段（liboqs/oqs-provider）

⚠ 全段落在 IANA 私用/未分配区，**可被 `OQS_CODEPOINT_*` 环境变量运行时改写**——字典匹配须留逃逸口。选列（全表在调研输出，实现时录全）：

| 码点(段) | 覆盖 | kind |
|---|---|---|
| 0x023A/023C/023D | kyber512/768/1024 (OQS legacy 纯 Kyber) | pqc |
| 0x2F39-2F3D,0x2F90 | x25519/p256/p384/p521/x448 _kyber* (OQS legacy 混合) | hybrid |
| 0x2F4B-2F4D,0x2FB6/2FB7 | p256/p384/p521_mlkem*, x25519/x448_mlkem* | hybrid |
| 0xFE10-0xFE17 | bikel1/3/5 及混合 | pqc/hybrid |
| 0xFE20-0xFE22 | bp256/384/512_mlkem* (Brainpool 混合) | hybrid |
| 0xFE23-0xFE32 | frodo640/976/1344 (aes/shake) 及混合 | pqc/hybrid |
| 0xFE33-0xFE3A | hqc1/3/5 及混合 | pqc/hybrid |

### A.5 GREASE（必须识别为噪声）

⚠ 16 个形如 `0x?A?A` 的值（0x0A0A,0x1A1A,…,0xFAFA，RFC 8701）是 IANA 保留的 GREASE 噪声，BoringSSL/Chrome 每连接随机注入一个，key_share 载荷固定 1B(0x00)。**引擎必须识别为噪声，绝不能记为未知 PQC 组。**

---

## B. lib_detection_table（进程×加密库映射）

soname/包名 → 库 → 是否具 PQC 能力 → 起始版本。用于主机 Agent 判某进程加载的库能否 PQC。⚠ 标记处需多重消歧。

| soname / 包名 | 库 | PQC | 起始版本 | 关键判据/坑 |
|---|---|---|---|---|
| libcrypto.so.3 / libssl.so.3 | **OpenSSL 3.x** | 视版本 | **3.5.0**(2025-04) | ⚠soname 3.0→3.7 不变，**必须读版本串 ≥3.5**（`strings` 查 `OpenSSL 3.5` 或 `X25519MLKEM768`）；3.0-3.4 无原生 PQC。默认组 X25519MLKEM768 |
| libcrypto.so.3 / libssl.so.3（**同 soname 歧义**） | **铜锁 Tongsuo** | ✓ | **8.5.0**(2026-03) | ⚠OpenSSL 3.5.4 底座，soname 与原生 OpenSSL 不可区分。**三重消歧**：①版本串 `Tongsuo 8.5.0`/`TONGSUO_*` 符号 ②SMTC provider/SDF/TSAPI 国密符号 ③流量出现 0x11EE。唯一默认启用 SM2+ML-KEM 的库 |
| libhitls_crypto.so / libhitls_tls.so | **openHiTLS** (OpenAtom) | ✓ | ≥0.3.x(待核，0.4.0 完整) | 国产 TLS：ML-KEM/ML-DSA/SLH-DSA/XMSS/FrodoKEM/McEliece/Composite + 国密 SM2/3/4/9 与 TLCP。**不实现 0x11EE**。符号 `CRYPT_EAL_*`/`CRYPT_PKEY_ML_KEM`。TLS 组仅 3 个 IANA 混合(0x11EB/EC/ED) |
| libgmssl.so.3 | **GmSSL 3.x**(关志/北大) | 视版本 | **3.2.0**(2026-06) | ⚠SOVERSION 恒 3：3.1.x(无 PQC) 与 3.2+(有) 同名，**读版本串** `GmSSL 3.2+` 或符号 `kyber_encap`/`sphincs_`。PQC=Kyber768(实为 ML-KEM 构造)+SM3 方言 SPHINCS+/XMSS/LMS。**TLS 只协商 0x0029 curveSM2，不发 PQC 组** |
| libcrypto.so / libssl.so（无版本后缀） | **BoringSSL**(Google) | ✓ | rolling | 无 SOVERSION 是与 OpenSSL 的区分点。Android `/system/lib64/libcrypto.so`。多静态链接→符号扫 `MLKEM768_encap`/`MLDSA65_sign`。0x11EC 默认 Chrome131。无国密 |
| libcrypto.so.1 / libcrypto-awslc.so.1 | **AWS-LC** | ✓ | ≈v1.30(2024) | SOVERSION=1，distro 加 `-awslc` 后缀。符号 `AWS_LC_*`。组 0x11EB/EC/ED+0x0200-02。载体 rustls+aws-lc-rs、s2n-tls。无国密、无 0x11EE |
| libsymcrypt.so.103 | **SymCrypt**(微软) | ✓ | v103.5.0(2024-09) | soname 主版本 103 即 ABI 判据。ML-DSA 自 103.7，SLH-DSA 未实现。**无 SM 系、无中国 PQC**——命中即可排除国密栈 |
| symcryptprovider.so | SCOSSL provider | ✓ | v1.9.0 | 装于 OpenSSL modules 目录，注册 0x11EB/EC/ED+0x0200-02 |
| oqsprovider.so | **oqs-provider**(OQS) | ✓ | 全版本 | ⚠通常**静态内嵌 liboqs**（进程无 liboqs.so 不代表无 OQS）。经 openssl.cnf 激活，**装了≠启用**。私有码点可被环境变量改写 |
| liboqs.so.9/.7/.6/.3 | **liboqs** | ✓ | 全版本 | SOVERSION 随 minor 递增(0.8→so.3,0.12→so.7,0.16→so.9)。静态链接查符号 `OQS_KEM_*`。官方声明勿用于生产 |
| libpqmagic_std.so | **PQMagic**(pqcrypto-cn，上海交大郁昱团队) | ✓ | 全版本 | 中国 PQC 库：ML-KEM/ML-DSA/SLH-DSA + **自研 Aigis-enc/Aigis-sig/SPHINCS-Alpha**，全算法可选 SM3 哈希模式。⚠无 SOVERSION、无 dpkg/rpm、版本仅见 PyPI(`pqmagic`)——主机侧只能靠 soname 存在性判定，判不了版本。**本身不做 TLS**，TLS 归因看调用它的协议库 |
| bcryptprimitives.dll / schannel.dll | SymCrypt 静态嵌入 + SChannel | ✓ | Win11 24H2 / Server 2025 | ⚠PQC 组默认关闭，需注册表/组策略启用——**检测到≠在用** |
| dpkg: libssl3t64 (Debian13/Ubuntu25.10) | OpenSSL 3.5.x | ✓ | 随 3.5.0 | ⚠Ubuntu 24.04 LTS 仍是 3.0.13 无 PQC |
| rpm: openssl-libs (Fedora43+) | OpenSSL 3.5/3.6 | ✓ | Fedora43 | ⚠RHEL 9/10 为 3.0/3.2.x（红帽回移能力需 rpm changelog 单独核实）；Fedora≤42 为 3.2.x 无 |

---

## C. pqc_algo_table（算法→CBOM 标识）

用于评分与 CBOM。`is_cn`=中国自研 PQC。⚠ 标注处为 OID 语义碰撞或识别缺口。

### C.1 KEM（密钥封装）

| 算法 | 参数集 | OID | is_cn | 备注 |
|---|---|---|---|---|
| **ML-KEM** (FIPS 203) | 512/768/1024 | 2.16.840.1.101.3.4.4.{1,2,3} | 否 | 当前事实标准。ek=800/1184/1568B, ct=768/1088/1568B。载体几乎全库 |
| Kyber (R3，废弃) | 512/768/1024 | 1.3.6.1.4.1.22554.5.6.{1,2} (OQS legacy) | 否 | 与 ML-KEM 不互操作。TLS 遗留 0x6399/639A/023x |
| Kyber-768 GmSSL 方言 | KYBER_K=3 | 2.16.840.1.101.3.4.22.4 (GmSSL 私设，非官方) | 否 | GmSSL 3.2。实为 ML-KEM 流程但⚠ CBOM 不能与官方 ML-KEM-768 OID 互认（互操作 KAT 未官方验证） |
| **Aigis-enc** | 1/2/3/4 | **无公开 OID**(缺口) | **是** | ★中国自研 MLWE KEM(郁昱团队 PKC2020)，Kyber 变体密钥更小。仅 PQMagic，SM3/SHAKE 双哈希 |
| FrodoKEM | 640/976/1344 ×AES/SHAKE | 无标准 OID | 否 | liboqs+openHiTLS。⚠旧版曾占 0x0200-02 与 ML-KEM 撞号 |
| BIKE / HQC / Classic McEliece / NTRU-Prime(sntrup761) | 各级 | 多无 | 否 | liboqs（HQC 因安全疑虑 0.9.0 默认禁）。sntrup761x25519 是 OpenSSH 默认 PQC kex——**SSH 侧发现价值高** |
| Composite ML-KEM | draft-lamps 复合 | 草案 OID 未核实 | 否 | SymCrypt v103.11 |

### C.2 签名

| 算法 | 参数集 | OID | is_cn | 备注 |
|---|---|---|---|---|
| **ML-DSA** (FIPS 204) | 44/65/87 | 2.16.840.1.101.3.4.3.{17,18,19} | 否 | 载体几乎全库。TLS sigalg 0x0904/0905/0906。**安恒签名机 10.50.93.6 实测在用** |
| Dilithium (R3 遗留) | 2/3/5 | 1.3.6.1.4.1.2.267.7.* | 否 | 已废弃，旧证书仍可能带 |
| **Aigis-sig** | 1/2/3 | **无公开 OID**(缺口) | **是** | ★中国自研格签名(郁昱团队 PKC2020)，Dilithium 变体。仅 PQMagic。**安恒 Aigis-sig 密码机 10.50.93.7 实测在用** |
| **SLH-DSA** (FIPS 205) | SHA2/SHAKE ×{128,192,256}{s,f} | 2.16.840.1.101.3.4.3.20-.31 | 否 | ⚠OID .3.20 被 GmSSL 挪用标其 SM3-SPHINCS+——**须按载体库消歧**。SymCrypt 未实现 |
| SPHINCS+ (R3 遗留) | sphincs{sha2,shake}* | 1.3.9999.6.* (OQS legacy) | 否 | liboqs 0.16.0 起仅 SLH-DSA |
| **SPHINCS-Alpha** | SHA2/SHAKE×128/192/256×f/s + 128 SM3 | **无公开 OID**(缺口) | **是** | ★中国方案(CRYPTO2023)，SPHINCS+ 改进。仅 PQMagic |
| SPHINCS+-SM3 (GmSSL 方言) | 128s | 2.16.840.1.101.3.4.3.20 (⚠GmSSL 挪用) | 否 | GmSSL 3.2。SM3 底座本地化，与 NIST SLH-DSA 不互操作 |
| XMSS / XMSS^MT | RFC8391 + GmSSL SM3 方言 | 1.3.6.1.5.5.7.6.34/.35 | 否 | 有状态哈希签名。SymCrypt/openHiTLS/liboqs/GmSSL |
| LMS / HSS | RFC8554 + GmSSL SM3 方言 | 1.2.840.113549.1.9.16.3.17 | 否 | ⚠类型码 14 官方=SHA-256，GmSSL 复用装 SM3——按「GmSSL SM3-LMS 方言」建档 |
| Falcon | 512/1024/padded | 1.3.9999.3.* | 否 | liboqs/oqs-provider |
| Composite ML-DSA | MLDSA{44,65,87}+经典 | LAMPS 草案未核实；OQS 1.3.9999.7.5-.8 | 否 | openHiTLS/SymCrypt≥103.12/oqs-provider |
| MAYO/CROSS/UOV/SNOVA/MQOM | NIST 附加签名轮 | OQS 私有弧未核实 | 否 | 出现频率低，字典兜底 |

### C.3 特殊标记

| 项 | 说明 |
|---|---|
| **LAC** (is_cn) | 中国 CACR 竞赛格基 KEM。⚠**全部 8 个被研库均未实现**（否定性结论）。真机/固件出现属私有实现，需人工建档 |
| **SM3 作为 PQC 哈希底座** (is_cn) | 本身非 PQC，但 PQC 算法哈希组件被换成 SM3（PQMagic 全系 SM3 模式、GmSSL SM3 方言）是「国密化 PQC」强指纹。CBOM 应将「PQC×SM3」组合单独标注且注明非标互操作 |

---

## D. 引擎必须处理的工程规则（gaps 蒸馏）

**D.1 同码点撞号 → 按 key_share 尺寸消歧**
- `0x0200/0x0201/0x0202`：现=ML-KEM(800/1184/1568B)，但 oqs-provider≤0.5.x 曾=Frodo640aes/640shake/976aes(≈9616/9616/15632B)。遇旧 OQS 栈按尺寸区分。

**D.2 同尺寸不同码点 → 必须读码点本体**
- `0x11EB`(SecP256r1MLKEM768) 与 `0x11EE`(curveSM2MLKEM768) 的 client(1249B)/server(1153B) **完全相同**。尺寸启发式在此失效，身份靠码点。

**D.3 尺寸启发式兜底（未知码点用）**
- client key_share **>1000B ⇒ 基本必是格基 KEM**（经典最大 P-521=133B）。未知码点+大 key_share ⇒ 标「疑似 PQC/混合，码点未确认」。
- ~1216B 且含 32B 分量特征 ⇒ 疑似 X25519 系混合；~1249B 且含 65B 分量 ⇒ 疑似 P-256/SM2 系混合。

**D.4 GREASE 逃逸**：`0x?A?A` 全部当噪声丢弃（§A.5）。

**D.5 OQS 码点可被环境变量改写**：未知码点 + 进程在场 OQS 库 ⇒ 提示「可能是 OQS_CODEPOINT_* 改写值」。

**D.6 Tongsuo soname 三重消歧**：`libcrypto.so.3` 单靠 soname 会把铜锁误判成 OpenSSL；须叠加版本串/国密符号/0x11EE 流量（§B）。

**D.7 OID 双语义按载体库消歧**：`2.16.840.1.101.3.4.3.20` = NIST SLH-DSA-SHA2-128s 也 = GmSSL SM3-SPHINCS+；LMS 类型码 14 = SHA-256(官方) 也 = SM3(GmSSL)。CBOM 结合发现该资产的库来源判语义。

**D.8 「装了≠在用」**：oqs-provider 装了未必在 openssl.cnf 激活；SChannel PQC 组 Win11 24H2 默认关闭。检测到库能力 ≠ 运行时启用——配置面与运行态需交叉验证（对应设计 §4.3 的 drift 标记）。

---

## E. 待补缺口（需真机/人工确认）

1. **Aigis-enc/Aigis-sig/SPHINCS-Alpha 无公开 OID** → 证书/CBOM 无法靠 OID 识别。需从 PQMagic 源码编码器或**安恒真机(10.50.93.7 Aigis-sig 密码机)导出的证书/密钥实物**提取实测补录。
2. openHiTLS 引入 PQC 的精确起始版本未核实（≥0.3.x，confidence low）——需逐版 diff `crypt_algid.h`。
3. PQMagic 称支持 OpenSSH PQC kex 但未给算法名——SSH 侧字典缺该条目，需实测其 OpenSSH 补丁。
4. 0x11EE 归因铜锁高置信；「PQMagic+国密协议库组合栈也能发 0x11EE」为推理非实证——归因非铜锁栈需抓库指纹佐证。
5. GmSSL 3.2 Kyber-768 与 FIPS 203 ML-KEM 互操作 KAT 未官方声明——若引擎要把它归入 ML-KEM 桶，先跑 KAT。
6. 标「≈推算」的 size_hint（约 20 项混合变体）为点长+份额相加推算值，未经抓包实测校准。
7. RHEL 9/10 OpenSSL 是否有红帽回移的部分 PQC 能力未核实——判「无 PQC」前需 rpm changelog 确认。
8. 中国自研 PQC 字典目前只有 PQMagic 一族（Aigis/SPHINCS-Alpha）有实现载体；LAC、SCloud 等其余 CACR 项目需扩展研究面。
