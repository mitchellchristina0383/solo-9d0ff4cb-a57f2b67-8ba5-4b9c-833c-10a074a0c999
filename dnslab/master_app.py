"""Master (primary) authoritative node for the lab.test zone.

Publishes the full set of A records over HTTP (manageable via /docs):
- every publish (single upsert/delete or bulk replace) runs in one SQLite
  transaction that also bumps an incrementing SOA serial and stores an
  immutable, checksummed snapshot of the whole zone;
- slaves pull /zone/snapshot and apply it atomically;
- /zone/snapshot?serial=N serves older versions (kept up to KEEP_VERSIONS)
  so late/arbitrary pulls can be exercised;
- /debug/snapshot/truncated and /debug/snapshot/corrupt exist only to let
  tests simulate a broken transfer / tampered payload.

Retired-instrument IPv4 addresses go through a *seal* workflow before they
can be handed to new equipment:
- POST /seals/{ip} registers the address with the upper bound of the
  historical A record's client-cache TTL; the master zone must already be
  free of that address (the record was deleted/republished away);
- while a seal is active neither a single upsert nor a bulk replace may
  write that address back (HTTP 409); publishes and sealing take the same
  write lock/transaction, so a conflict has exactly one winner;
- POST /seals/{ip}/verify asks an operator-named slave for its live
  snapshot: once its serial is >= the serial at sealing time and the
  address is gone there too, the first confirmation time is recorded once
  and never overwritten (repeated checks, master restart all keep it);
- a seal can be released only after that first confirmation plus the
  registered TTL have elapsed; GET /seals explains the wait reason and the
  earliest release time.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import asynccontextmanager, closing
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

ZONE = "lab.test"
DB_PATH = os.environ.get("MASTER_DB", "/data/master.db")
DEFAULT_TTL = 300
KEEP_VERSIONS = int(os.environ.get("KEEP_VERSIONS", "100"))
# Slave used by POST /seals/{ip}/verify unless the request overrides `slave_url`.
DEFAULT_SLAVE_URL = os.environ.get("SLAVE_URL", "http://slave:8000").rstrip("/")
SLAVE_FETCH_TIMEOUT = float(os.environ.get("SLAVE_FETCH_TIMEOUT", "10"))

SOA_TEMPLATE = {
    "mname": "ns1.lab.test.",
    "rname": "hostmaster.lab.test.",
    "refresh": 7200,
    "retry": 3600,
    "expire": 1209600,
    "minimum": 300,
}

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Serializes publishes inside this process; SQLite serializes across processes.
_publish_lock = threading.Lock()


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with closing(connect()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS records(
                name TEXT PRIMARY KEY,
                ip   TEXT NOT NULL,
                ttl  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta(
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS versions(
                serial     INTEGER PRIMARY KEY,
                snapshot   TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seals(
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                ip                 TEXT NOT NULL,
                ttl                INTEGER NOT NULL,
                sealed_at          REAL NOT NULL,
                seal_serial        INTEGER NOT NULL,
                status             TEXT NOT NULL,
                first_confirm_at   REAL,
                confirm_slave      TEXT,
                confirm_slave_serial INTEGER,
                released_at        REAL,
                last_check_at      REAL,
                last_check_detail  TEXT
            );
            -- At most one non-released seal per address; released rows stay as history.
            CREATE UNIQUE INDEX IF NOT EXISTS seals_one_active
                ON seals(ip) WHERE status = 'active';
            """
        )
        row = conn.execute("SELECT value FROM meta WHERE key='serial'").fetchone()
        if row is None:
            # Version 1: the empty zone, so a serial always exists.
            conn.execute("INSERT INTO meta(key, value) VALUES('serial', '1')")
            snap = _snapshot_json(1, [])
            conn.execute(
                "INSERT INTO versions(serial, snapshot, created_at) VALUES (1, ?, ?)",
                (json.dumps(snap), time.time()),
            )
        conn.commit()


def _records(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT name, ip, ttl FROM records ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def _current_serial(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT value FROM meta WHERE key='serial'").fetchone()["value"])


def _snapshot_json(serial: int, records: list[dict]) -> dict:
    payload = {
        "zone": ZONE,
        "serial": serial,
        "soa": {**SOA_TEMPLATE, "serial": serial},
        "records": records,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {**payload, "sha256": digest}


def _publish_locked(conn: sqlite3.Connection) -> dict:
    """Bump the serial and store an immutable snapshot of the current records.

    Must be called inside conn's transaction, with _publish_lock held.
    """
    serial = _current_serial(conn) + 1
    snap = _snapshot_json(serial, _records(conn))
    conn.execute("UPDATE meta SET value=? WHERE key='serial'", (str(serial),))
    conn.execute(
        "INSERT INTO versions(serial, snapshot, created_at) VALUES (?, ?, ?)",
        (serial, json.dumps(snap), time.time()),
    )
    conn.execute(
        "DELETE FROM versions WHERE serial NOT IN "
        "(SELECT serial FROM versions ORDER BY serial DESC LIMIT ?)",
        (KEEP_VERSIONS,),
    )
    return snap


# --------------------------------------------------------------------------
# IP seals (retired-address quarantine)
# --------------------------------------------------------------------------

def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _active_seal_for_ips(conn: sqlite3.Connection, ips: list[str]) -> Optional[sqlite3.Row]:
    """Return the active seal (if any) whose address is in `ips`."""
    if not ips:
        return None
    placeholders = ",".join("?" for _ in ips)
    return conn.execute(
        f"SELECT * FROM seals WHERE status='active' AND ip IN ({placeholders})",
        ips,
    ).fetchone()


def _seal_view(row: sqlite3.Row) -> dict:
    """Project a seal row, adding the computed wait reason / release time."""
    ttl = int(row["ttl"])
    first_confirm = row["first_confirm_at"]
    earliest_release = (first_confirm + ttl) if first_confirm is not None else None
    now = time.time()
    if row["status"] == "released":
        status, reason = "released", "seal already released"
    elif first_confirm is None:
        status = "awaiting_confirmation"
        reason = (
            "waiting for slave confirmation: no slave snapshot at or above "
            f"seal serial {row['seal_serial']} has confirmed the address is gone"
        )
    elif now < earliest_release:
        status = "waiting_ttl"
        reason = (
            f"TTL hold: {ttl}s must elapse after the first slave confirmation "
            f"({_iso(first_confirm)}) so cached A records expire"
        )
    else:
        status = "releasable"
        reason = "confirmation and TTL hold satisfied; the seal may be released"
    return {
        "id": row["id"],
        "ip": row["ip"],
        "ttl_seconds": ttl,
        "status": status,
        "sealed_at": _iso(row["sealed_at"]),
        "seal_serial": row["seal_serial"],
        "first_confirm_at": _iso(first_confirm),
        "confirm_slave": row["confirm_slave"],
        "confirm_slave_serial": row["confirm_slave_serial"],
        "earliest_release_at": _iso(earliest_release),
        "released_at": _iso(row["released_at"]),
        "last_check_at": _iso(row["last_check_at"]),
        "last_check_detail": row["last_check_detail"],
        "wait_reason": reason,
    }


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    n = name.strip().rstrip(".").lower()
    if not n:
        raise HTTPException(400, "empty name")
    if n != ZONE and not n.endswith("." + ZONE):
        raise HTTPException(400, f"name {n!r} is outside zone {ZONE}")
    for label in n.split("."):
        if not _LABEL_RE.match(label):
            raise HTTPException(400, f"bad label {label!r} in name {n!r}")
    return n


def validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except ValueError:
        raise HTTPException(400, f"invalid IPv4 address {ip!r}")


def validate_ttl(ttl: int) -> int:
    if not (0 <= ttl <= 2**31 - 1):
        raise HTTPException(400, f"ttl {ttl} out of range")
    return ttl


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

class RecordPut(BaseModel):
    ip: str
    ttl: int = Field(DEFAULT_TTL, ge=0, le=2**31 - 1)


class RecordIn(BaseModel):
    name: str
    ip: str
    ttl: int = Field(DEFAULT_TTL, ge=0, le=2**31 - 1)


class BulkReplace(BaseModel):
    records: list[RecordIn]


class SealRequest(BaseModel):
    # Upper bound of the historical A record's client-cache TTL (seconds).
    ttl: int = Field(..., ge=0, le=2**31 - 1)


class SealVerifyRequest(BaseModel):
    # Which slave to ask; defaults to the master's configured DEFAULT_SLAVE_URL.
    slave_url: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="lab.test DNS master",
    description="Publishes the full A-record set of lab.test with an "
    "incrementing SOA serial; slaves pull /zone/snapshot. Also manages the "
    "retired-address seal workflow under /seals (see POST /seals/{ip}).",
    version="1.1.0",
    lifespan=lifespan,
)


@app.get("/")
def root() -> dict:
    with closing(connect()) as conn:
        serial = _current_serial(conn)
    return {"service": "dns-master", "zone": ZONE, "serial": serial}


@app.get("/records")
def list_records() -> dict:
    with closing(connect()) as conn:
        return {"serial": _current_serial(conn), "records": _records(conn)}


@app.put("/records/{name}")
def put_record(name: str, body: RecordPut) -> dict:
    """Create or update one A record and publish a new zone version."""
    n = normalize_name(name)
    ip = validate_ip(body.ip)
    ttl = validate_ttl(body.ttl)
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        sealed = _active_seal_for_ips(conn, [ip])
        if sealed is not None:
            conn.rollback()
            raise HTTPException(
                409,
                f"address {ip} is under an active seal (id={sealed['id']}); "
                "it must not be written back until the seal is released",
            )
        conn.execute(
            "INSERT INTO records(name, ip, ttl) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET ip=excluded.ip, ttl=excluded.ttl",
            (n, ip, ttl),
        )
        snap = _publish_locked(conn)
        conn.commit()
    return {"serial": snap["serial"], "record": {"name": n, "ip": ip, "ttl": ttl}}


@app.delete("/records/{name}")
def delete_record(name: str) -> dict:
    """Delete one A record and publish a new zone version."""
    n = normalize_name(name)
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute("DELETE FROM records WHERE name=?", (n,))
        if cur.rowcount == 0:
            conn.rollback()
            raise HTTPException(404, f"no such record {n!r}")
        snap = _publish_locked(conn)
        conn.commit()
    return {"serial": snap["serial"], "deleted": n}


@app.post("/records/bulk")
def bulk_replace(body: BulkReplace) -> dict:
    """Atomically replace the whole A-record set (one new zone version)."""
    items: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for r in body.records:
        n = normalize_name(r.name)
        if n in seen:
            raise HTTPException(400, f"duplicate name {n!r} in bulk request")
        seen.add(n)
        items.append((n, validate_ip(r.ip), validate_ttl(r.ttl)))
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        sealed = _active_seal_for_ips(conn, [ip for _, ip, _ in items])
        if sealed is not None:
            conn.rollback()
            raise HTTPException(
                409,
                f"bulk replace blocked: address {sealed['ip']} is under an "
                f"active seal (id={sealed['id']})",
            )
        conn.execute("DELETE FROM records")
        conn.executemany("INSERT INTO records(name, ip, ttl) VALUES (?, ?, ?)", items)
        snap = _publish_locked(conn)
        conn.commit()
    return {"serial": snap["serial"], "records": len(items)}


@app.get("/zone/serial")
def zone_serial() -> dict:
    """The currently published SOA serial."""
    with closing(connect()) as conn:
        return {"serial": _current_serial(conn)}


@app.get("/zone/versions")
def zone_versions() -> dict:
    with closing(connect()) as conn:
        rows = conn.execute("SELECT serial FROM versions ORDER BY serial").fetchall()
    return {"serials": [r["serial"] for r in rows]}


@app.get("/zone/snapshot")
def zone_snapshot(serial: Optional[int] = None) -> dict:
    """Full zone snapshot: latest version, or a specific kept version."""
    with closing(connect()) as conn:
        if serial is None:
            row = conn.execute(
                "SELECT snapshot FROM versions ORDER BY serial DESC LIMIT 1"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT snapshot FROM versions WHERE serial=?", (serial,)
            ).fetchone()
    if row is None:
        raise HTTPException(
            404, "no such serial" if serial is not None else "no version published yet"
        )
    return json.loads(row["snapshot"])


# --------------------------------------------------------------------------
# retired-address seal workflow
# --------------------------------------------------------------------------

def _get_seal_row(conn: sqlite3.Connection, ip: str) -> Optional[sqlite3.Row]:
    # One active row at most; the latest row is the most recent historical one.
    return conn.execute(
        "SELECT * FROM seals WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)
    ).fetchone()


@app.post("/seals/{ip}", status_code=201)
def create_seal(ip: str, body: SealRequest) -> dict:
    """Register a retired address with its historical A-record TTL upper bound.

    Precondition enforced in the same write transaction as publishes:
    - the address must no longer appear anywhere in the master zone;
    - no other active seal may hold the same address.
    """
    addr = validate_ip(ip)
    ttl = validate_ttl(body.ttl)
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT id FROM seals WHERE ip=? AND status='active'", (addr,)
        ).fetchone()
        if existing is not None:
            conn.rollback()
            raise HTTPException(409, f"address {addr} already has an active seal")
        holder = conn.execute(
            "SELECT name FROM records WHERE ip=?", (addr,)
        ).fetchall()
        if holder:
            conn.rollback()
            raise HTTPException(
                409,
                f"cannot seal {addr}: still present in the master zone on "
                + ", ".join(r["name"] for r in holder),
            )
        serial = _current_serial(conn)
        now = time.time()
        cur = conn.execute(
            "INSERT INTO seals(ip, ttl, sealed_at, seal_serial, status) "
            "VALUES (?, ?, ?, ?, 'active')",
            (addr, ttl, now, serial),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM seals WHERE id=?", (cur.lastrowid,)).fetchone()
    return _seal_view(row)


@app.get("/seals")
def list_seals(include_released: bool = False) -> dict:
    """All seals (or only active ones), each with its wait reason."""
    with closing(connect()) as conn:
        if include_released:
            rows = conn.execute("SELECT * FROM seals ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM seals WHERE status='active' ORDER BY id DESC"
            ).fetchall()
    return {"seals": [_seal_view(r) for r in rows]}


@app.get("/seals/{ip}")
def get_seal(ip: str) -> dict:
    """Detail of one address's (latest) seal: wait reason, earliest release."""
    addr = validate_ip(ip)
    with closing(connect()) as conn:
        row = _get_seal_row(conn, addr)
    if row is None:
        raise HTTPException(404, f"no seal registered for {addr}")
    return _seal_view(row)


@app.post("/seals/{ip}/verify")
def verify_seal(ip: str, body: Optional[SealVerifyRequest] = None) -> dict:
    """Operator check against a slave's live snapshot.

    Records the first confirmation time exactly once, and only when:
    - the slave serves a serial >= the serial at sealing time, and
    - the sealed address no longer appears in the slave's active snapshot.
    A slave that is unreachable / not yet serving a version leaves the seal
    untouched (the operator keeps waiting); re-checks and restarts preserve
    an already recorded confirmation.
    """
    addr = validate_ip(ip)
    slave_url = (body.slave_url if body and body.slave_url else DEFAULT_SLAVE_URL).rstrip("/")
    # Cheap pre-check so a typo'd address 404s without taking the write lock.
    with closing(connect()) as conn:
        row = _get_seal_row(conn, addr)
        if row is None:
            raise HTTPException(404, f"no seal registered for {addr}")
        if row["status"] != "active":
            raise HTTPException(409, f"seal for {addr} is not active")
        seal_serial = row["seal_serial"]
        seal_id = row["id"]

    # Network I/O happens OUTSIDE the publish lock: an unreachable slave must
    # not stall publishes. The seal row is re-checked under the lock afterwards.
    try:
        resp = httpx.get(f"{slave_url}/zone", timeout=SLAVE_FETCH_TIMEOUT)
        fetch_error: Optional[str] = None
    except Exception as exc:
        resp = None
        fetch_error = f"slave unreachable: {exc}"

    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _get_seal_row(conn, addr)
        if row is None or row["status"] != "active" or row["id"] != seal_id:
            conn.rollback()
            raise HTTPException(409, f"seal for {addr} changed during verification")
        now = time.time()
        if fetch_error is not None:
            conn.execute(
                "UPDATE seals SET last_check_at=?, last_check_detail=? WHERE id=?",
                (now, fetch_error, seal_id),
            )
            conn.commit()
            return {
                "confirmed": False,
                "reachable": False,
                "reason": fetch_error,
                "seal": _seal_view(_get_seal_row(conn, addr)),
            }
        if resp.status_code != 200:
            detail = f"slave returned HTTP {resp.status_code} (no active version yet?)"
            conn.execute(
                "UPDATE seals SET last_check_at=?, last_check_detail=? WHERE id=?",
                (now, detail, seal_id),
            )
            conn.commit()
            return {
                "confirmed": False,
                "reachable": True,
                "reason": detail,
                "seal": _seal_view(_get_seal_row(conn, addr)),
            }
        zone = resp.json()
        slave_serial = zone.get("serial")
        present = any(r.get("ip") == addr for r in zone.get("records", []))
        if not isinstance(slave_serial, int) or slave_serial < seal_serial:
            detail = (
                f"slave serial {slave_serial} is behind the seal-time serial "
                f"{seal_serial}; keep waiting for synchronization"
            )
        elif present:
            detail = (
                f"address {addr} still present in the slave snapshot "
                f"(serial {slave_serial}); keep waiting"
            )
        else:
            # Confirmation conditions met. Record the first time only.
            if row["first_confirm_at"] is None:
                conn.execute(
                    "UPDATE seals SET first_confirm_at=?, confirm_slave=?, "
                    "confirm_slave_serial=?, last_check_at=?, last_check_detail=? WHERE id=?",
                    (now, slave_url, slave_serial, now,
                     f"confirmed by {slave_url} at serial {slave_serial}", seal_id),
                )
            else:
                conn.execute(
                    "UPDATE seals SET last_check_at=?, last_check_detail=? WHERE id=?",
                    (now,
                     f"re-confirmed by {slave_url} at serial {slave_serial}; "
                     "first confirmation time kept", seal_id),
                )
            conn.commit()
            return {
                "confirmed": True,
                "reachable": True,
                "reason": f"slave {slave_url} at serial {slave_serial} no longer "
                          f"contains {addr}",
                "seal": _seal_view(_get_seal_row(conn, addr)),
            }
        conn.execute(
            "UPDATE seals SET last_check_at=?, last_check_detail=? WHERE id=?",
            (now, detail, seal_id),
        )
        conn.commit()
        return {
            "confirmed": False,
            "reachable": True,
            "reason": detail,
            "seal": _seal_view(_get_seal_row(conn, addr)),
        }


@app.post("/seals/{ip}/release")
def release_seal(ip: str) -> dict:
    """Release a seal only after first confirmation + the registered TTL."""
    addr = validate_ip(ip)
    with _publish_lock, closing(connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _get_seal_row(conn, addr)
        if row is None:
            conn.rollback()
            raise HTTPException(404, f"no seal registered for {addr}")
        if row["status"] != "active":
            conn.rollback()
            raise HTTPException(409, f"seal for {addr} is already released")
        if row["first_confirm_at"] is None:
            conn.rollback()
            raise HTTPException(
                409,
                f"cannot release {addr}: no slave confirmation recorded yet; "
                f"seal-time serial is {row['seal_serial']}",
            )
        earliest = row["first_confirm_at"] + row["ttl"]
        now = time.time()
        if now < earliest:
            conn.rollback()
            raise HTTPException(
                409,
                f"cannot release {addr}: TTL hold ends at {_iso(earliest)} "
                f"({int(earliest - now)}s left); wait for cached A records to expire",
            )
        conn.execute(
            "UPDATE seals SET status='released', released_at=? WHERE id=?",
            (now, row["id"]),
        )
        conn.commit()
        row = _get_seal_row(conn, addr)
    return _seal_view(row)


# --------------------------------------------------------------------------
# test-only fault injection
# --------------------------------------------------------------------------

def _latest_snapshot_bytes() -> bytes:
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT snapshot FROM versions ORDER BY serial DESC LIMIT 1"
        ).fetchone()
    if row is None:
        raise HTTPException(404, "no version published yet")
    return row["snapshot"].encode()


@app.get("/debug/snapshot/truncated")
def debug_truncated() -> StreamingResponse:
    """Drops the connection in the middle of the body (simulates断流)."""
    raw = _latest_snapshot_bytes()
    half = raw[: max(1, len(raw) // 2)]

    def gen():
        yield half
        raise RuntimeError("simulated upstream disconnect")

    return StreamingResponse(gen(), media_type="application/json")


@app.get("/debug/snapshot/corrupt")
def debug_corrupt() -> dict:
    """Returns a syntactically valid snapshot with a wrong checksum."""
    snap = json.loads(_latest_snapshot_bytes())
    snap["sha256"] = "0" * 64
    return snap
