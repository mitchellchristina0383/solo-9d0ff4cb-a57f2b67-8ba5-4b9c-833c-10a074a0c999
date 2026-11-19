# lab.test 主从权威 DNS（Python / FastAPI / SQLite）

网络管理员批量更新 `lab.test` 仪器地址的最小可用主从权威 DNS：

- **主节点**（`dnslab/master_app.py`）：通过 HTTP API（Swagger UI 在 `/docs`）维护 A 记录全集；
  每次发布（单条增删改或整体批量替换）在**一个 SQLite 事务**内完成记录变更、
  SOA 序列号递增（从 1 开始每次 +1）、并落一份带 SHA-256 校验和的**不可变快照**。
- **从节点**（`dnslab/slave_app.py`）：经 HTTP 从主节点拉取整份快照，校验通过且序列号
  严格更新后才生效；以 UDP 回答 `A` / `SOA` 查询，对域内不存在的名字回答 `NXDOMAIN`
  （authority 带本版 SOA），域外查询 `REFUSED`。
- **退役 IP 封存工作流**（主节点 `/seals`，全部可在 `/docs` 操作）：退役仪器的 IPv4
  地址在重新分配给新设备前必须经过"封存 → 从节点核对 → TTL 等待 → 解除"全流程，
  防止从节点缓存未同步、客户端缓存未过期时地址被提前复用。详见下文。

## 一致性保证

| 场景 | 行为 |
|---|---|
| 发布与拉取交错 | 快照是主节点单事务读出的不可变版本；从节点要么整体应用某版本，要么不应用 |
| 并发同步 | 从节点同步串行化；应用前在锁内复查序列号，最终版本一定是见过的最大序列号 |
| 中途断流 / 数据被改 | 传输中断 → 拉取报错；SHA-256 校验失败 → 拒绝；现役版本不受影响 |
| 迟到旧版 | 序列号 ≤ 现役版本的一律拒绝（`applied: false`），不会覆盖新版 |
| 记录与 SOA 同版 | 每条应答都由同一个不可变 `ZoneData` 对象生成，SOA 序列号与记录同属一版 |
| 主节点失联 | 从节点继续用最后一次成功同步的版本应答；`/sync` 报 502 但不影响应答 |
| 从节点重启 | 启动时从 SQLite 恢复最后成功版本，无需先同步即可应答 |
| 初次同步失败 | 没有任何版本时回答 `SERVFAIL`（不可用），绝不凭空应答 |

## 退役 IP 封存工作流（`/seals`，均可在 `/docs` 操作）

退役仪器的 IPv4 地址要分给新设备时，必须等从节点同步、再等客户端缓存过期。流程：

| 步骤 | API | 规则 |
|---|---|---|
| 1. 主区移除地址 | `PUT/DELETE /records/...` | 封存前主区任何记录都不得再使用该地址，否则封存返回 409 |
| 2. 登记封存 | `POST /seals/{ip}`，body `{"ttl": N}` | 在 `/docs` 登记地址与历史 A 记录的 **TTL 上界**（秒）；记录封存时的主区序列号；同一地址同时只能有一条生效封存（409） |
| 3. 写回保护 | `PUT /records/...`、`POST /records/bulk` | 封存生效期间，单条增改与整批替换只要包含该地址一律 **409**，事务回滚、区域不变；删除与无关写入不受影响 |
| 4. 值班员核对 | `POST /seals/{ip}/verify`，body 可选 `{"slave_url": ...}` | 拉取从节点**现役快照**：其序列号 `>=` 封存时主区版本**且**快照中已无该地址，才把**首次确认时间**写库；只写一次 |
| 5. 失联/落后 | 同上 | 从节点不可达、无现役版本（503）、序列号落后或地址仍在 → `confirmed:false`，封存保持等待，已记下的确认时间不变 |
| 6. TTL 等待 | `GET /seals/{ip}` | 自首次确认起等满登记的 TTL；状态与 `wait_reason`（等待原因）、`earliest_release_at`（最早解除时间）随时可查 |
| 7. 解除封存 | `POST /seals/{ip}/release` | 未确认或 TTL 未满 → 409（含剩余秒数/最早解除时间）；满足后才置为 `released`，历史行保留 |
| 8. 重新分配 | `PUT /records/...` | 解除后地址可写给新设备；同一地址之后允许再次封存（新一轮生命周期） |

关键不变量：

- **并发互斥**：封存、发布、解除共用同一把进程内写锁 + SQLite `BEGIN IMMEDIATE`
  事务，并有 `seals_one_active` 部分唯一索引兜底；并发发布与封存冲突时**恰好一方成功**，
  不会双方都成功也不会双失败。
- **确认时间幂等持久**：首次确认时间只在满足条件且库中为 `NULL` 时写入；重复核对、
  主节点重启都保留原值（封存状态持久化在主节点 SQLite）。
- **核对不阻塞发布**：对从节点的 HTTP 访问在写锁之外进行，慢/失联从节点不会卡住正常发布。
- 默认核对的从节点由主节点环境变量 `SLAVE_URL` 指定（Compose 中为
  `http://slave:8000`），每次核对也可用 `slave_url` 临时指定其他从节点。

```bash
# 1) 仪器退役：主区移除 10.20.30.40（改指新地址或删除记录）
curl -X PUT http://localhost:8000/records/old-inst.lab.test \
  -H 'Content-Type: application/json' -d '{"ip": "10.20.30.99"}'

# 2) 登记封存：历史 A 记录 TTL 上界 300s（封存时主区必须已无该地址）
curl -X POST http://localhost:8000/seals/10.20.30.40 \
  -H 'Content-Type: application/json' -d '{"ttl": 300}'

# 3) 封存期间写回会被拒（单条 / 整批同理，HTTP 409）
curl -X PUT http://localhost:8000/records/new-dev.lab.test \
  -H 'Content-Type: application/json' -d '{"ip": "10.20.30.40"}'

# 4) 先让从节点同步，再由值班员核对（序列号达标且无该地址才记首次确认）
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'
curl -X POST http://localhost:8000/seals/10.20.30.40/verify \
  -H 'Content-Type: application/json' -d '{"slave_url": "http://slave:8000"}'

# 5) 查看等待原因与最早解除时间；TTL 未满解除会被 409 拒绝
curl http://localhost:8000/seals/10.20.30.40
curl -X POST http://localhost:8000/seals/10.20.30.40/release

# 6) 解除后把地址分给新设备
curl -X PUT http://localhost:8000/records/new-dev.lab.test \
  -H 'Content-Type: application/json' -d '{"ip": "10.20.30.40", "ttl": 300}'
```

## 运行

### Docker Compose（推荐）

```bash
docker compose up --build
```

- 主节点 API / 文档： http://localhost:8000/docs
- 从节点 API / 文档： http://localhost:8001/docs
- 从节点 DNS： `dig @127.0.0.1 -p 5353 host1.lab.test A` ／ `dig @127.0.0.1 -p 5353 lab.test SOA`

从节点数据在命名卷 `slave-data` 中，`docker compose restart slave` 后仍用最后版本应答。

### 本地（无 Docker）

```bash
pip install -r requirements.txt
MASTER_DB=/tmp/master.db SLAVE_URL=http://127.0.0.1:8001 \
  uvicorn dnslab.master_app:app --port 8000 &
SLAVE_DB=/tmp/slave.db MASTER_URL=http://127.0.0.1:8000 DNS_PORT=5353 \
  uvicorn dnslab.slave_app:app --port 8001 &
```

## 使用（均可在 `/docs` 中操作）

```bash
# 批量发布仪器地址（一次事务、一个新序列号）
curl -X POST http://localhost:8000/records/bulk -H 'Content-Type: application/json' -d '{
  "records": [
    {"name": "host1.lab.test", "ip": "10.0.0.1"},
    {"name": "host2.lab.test", "ip": "10.0.0.2", "ttl": 60}
  ]}'

# 单条增改 / 删除
curl -X PUT  http://localhost:8000/records/host3.lab.test -H 'Content-Type: application/json' -d '{"ip": "10.0.0.3"}'
curl -X DELETE http://localhost:8000/records/host2.lab.test

# 查看主节点现役序列号 / 完整快照
curl http://localhost:8000/zone/serial
curl http://localhost:8000/zone/snapshot

# 从节点：发起同步、查看现役序列号
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'
curl http://localhost:8001/status
```

`POST /sync` 可选参数：`{"serial": N}` 拉取指定历史版本（主节点保留最近
`KEEP_VERSIONS=100` 版，主要用于测试迟到旧版）；`{"url": ...}` 覆盖快照来源。
设 `SYNC_INTERVAL=秒数` 可让从节点周期自动同步（默认 0，仅手动）。

## 自测

```bash
python tests/selftest.py        # 主从 DNS 基线自测（需要已安装 requirements.txt）
python tests/seal_selftest.py   # 退役 IP 封存工作流端到端自测
```

`selftest.py` 拉起真实主从进程，覆盖：初次同步失败报不可用、发布/同步/应答、
批量更新原子切换、迟到旧版拒绝、断流与校验和损坏、并发发布+同步交错（序列号单调、
最终内容逐条一致）、主节点失联、从节点重启、新从节点+主失联、`/docs` 可用性与主恢复后的同步。

`seal_selftest.py` 用真实主节点 + 两个从节点（其中一个故意停在旧版本模拟同步落后）覆盖：

- 主区仍有地址时拒绝封存、地址移除后登记并记录 TTL 上界与封存时序列号；
- 封存期间单条增改、整批替换写回该地址均 409 且区域不变，删除/无关写入正常；
- 并发发布 vs 封存冲突**恰好一方成功**；
- 同步落后（从节点序列号低于封存版本/地址仍在）时核对不确认、不写首次确认时间；
- 从节点追上且无该地址后才确认，重复核对保留同一首次确认时间；
- 从节点失联时继续等待且确认时间不丢；
- TTL 未等满提前解除被 409 拒绝，等满后解除、地址可重新分配、可再次封存；
- 主节点重启后封存状态、首次确认时间、写回保护全部保留；`/docs` 暴露全部封存接口。

## 目录

```
dnslab/dnsproto.py    最小 DNS 线格式编解码与应答逻辑（仅标准库）
dnslab/master_app.py  主节点 FastAPI 应用（含 /seals 退役 IP 封存工作流）
dnslab/slave_app.py   从节点 FastAPI 应用 + UDP DNS 服务
tests/selftest.py     主从 DNS 基线端到端自测
tests/seal_selftest.py 封存工作流端到端自测（同步落后 / 提前解除 / 重启等）
Dockerfile / docker-compose.yml
```

## 已知限制

- 仅 UDP、仅 `A`/`SOA`/`ANY` 查询；不支持 TCP、EDNS、IXFR/AXFR、DNSSEC、NOTIFY。
- 序列号比较用简单“严格大于”（本系统序列号从 1 单调 +1，未实现 RFC 1982 回绕比较）。
- 快照为全量传输，适合 lab 规模；超大区域需增量机制。
- 从节点应用快照时的 SQLite 写入在事件循环内完成，记录数极大时会短暂阻塞循环（lab 规模无感）。
- 主节点 `/debug/snapshot/truncated`、`/debug/snapshot/corrupt` 仅用于故障注入测试，生产应移除。
- 封存按 IPv4 地址维度生效：同一地址被任意记录引用都会被拦截；不支持按名称/掩码段封存。
- 封存的 TTL 上界需人工在 `POST /seals/{ip}` 时填写，系统不自动回溯历史记录的 TTL。
- `POST /seals/{ip}/verify` 为值班员手动触发（或由外部调度周期调用），主节点不会主动轮询从节点。
- 封存历史行（含已 `released`）不做自动清理，长期运行需配合归档策略。
