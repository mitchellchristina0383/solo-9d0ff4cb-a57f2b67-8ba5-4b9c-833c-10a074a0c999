#!/usr/bin/env python3
"""End-to-end self-test for the retired-address seal (quarantine) workflow.

Spins up the real master + slave uvicorn processes on loopback and drives
the whole lifecycle over HTTP (and DNS/UDP where relevant):

  1. sealing requires the address to be absent from the master zone;
  2. while a seal is active, single upsert AND bulk replace writing that
     address back are rejected (409); deletes/unrelated writes still work;
  3. a concurrent publish-vs-seal race on a free address has exactly one
     winner (never both, never neither);
  4. slave lag: verification stays unconfirmed while the slave serial is
     behind the seal-time serial / the address is still served;
  5. first confirmation is recorded once, after the slave has caught up
     past the seal serial and the address is gone; repeated checks keep it;
  6. an unreachable slave keeps the seal waiting and preserves the time;
  7. early release (before first_confirm + TTL) is refused, then accepted;
  8. master restart keeps the seal state and the first confirmation time;
  9. after release the address can be written again, and can be re-sealed.

Run:  python tests/seal_selftest.py
Env:  PYBIN (python with fastapi/uvicorn/httpx installed, default sys.executable)
      MASTER_PORT (18090) SLAVE_PORT (18091) SLAVE_DNS_PORT (15360)
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from dnslab import dnsproto  # noqa: E402

PYBIN = os.environ.get("PYBIN", sys.executable)
MASTER_PORT = int(os.environ.get("MASTER_PORT", "18090"))
SLAVE_PORT = int(os.environ.get("SLAVE_PORT", "18091"))
SLAVE_DNS_PORT = int(os.environ.get("SLAVE_DNS_PORT", "15360"))

MASTER = f"http://127.0.0.1:{MASTER_PORT}"
SLAVE = f"http://127.0.0.1:{SLAVE_PORT}"
SLAVE2_PORT = int(os.environ.get("SLAVE2_PORT", "18092"))
SLAVE2_DNS_PORT = int(os.environ.get("SLAVE2_DNS_PORT", "15361"))
SLAVE2 = f"http://127.0.0.1:{SLAVE2_PORT}"

# Short TTL so the "wait full TTL then release" path finishes quickly.
SEAL_TTL = 3
SEALED_IP = "10.5.0.9"

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    RESULTS.append((bool(cond), name, detail))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not cond else ""))


def http(method: str, url: str, body: dict | None = None, timeout: float = 10.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw or b"{}")
            except ValueError:
                return resp.status, {"_raw": raw[:200].decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return None, {"error": str(e)}


def dns_query(name: str, qtype: int, port: int, timeout: float = 3.0) -> dict:
    xid = 0x2233
    qname = dnsproto.encode_name(name)
    query = struct.pack("!HHHHHH", xid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    _rxid, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    return {"rcode": flags & 0xF, "answer_count": an, "raw": data.hex()}


class Node:
    def __init__(self, name: str, module: str, port: int, env: dict, logdir: str):
        self.name, self.module, self.port = name, module, port
        self.env, self.logdir = env, logdir
        self.proc = None

    def start(self):
        log = open(os.path.join(self.logdir, f"{self.name}.log"), "ab")
        self.proc = subprocess.Popen(
            [PYBIN, "-m", "uvicorn", self.module, "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=REPO, env={**os.environ, **self.env}, stdout=log, stderr=subprocess.STDOUT,
        )

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None


def wait_http(url: str, node: Node, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not node.alive():
            return False
        status, _ = http("GET", url, timeout=2)
        if status == 200:
            return True
        time.sleep(0.25)
    return False


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="dnslab-seal-")
    print(f"# workdir: {tmp}")
    master_db = os.path.join(tmp, "master.db")
    slave_db = os.path.join(tmp, "slave.db")
    slave_env = {
        "SLAVE_DB": slave_db,
        "MASTER_URL": MASTER,
        "DNS_PORT": str(SLAVE_DNS_PORT),
        "SYNC_INTERVAL": "0",
    }
    slave = Node("slave", "dnslab.slave_app:app", SLAVE_PORT, slave_env, tmp)
    slave2 = Node("lag-slave", "dnslab.slave_app:app", SLAVE2_PORT, {
        "SLAVE_DB": os.path.join(tmp, "slave2.db"),
        "MASTER_URL": MASTER,
        "DNS_PORT": str(SLAVE2_DNS_PORT),
        "SYNC_INTERVAL": "0",
    }, tmp)
    master = Node("master", "dnslab.master_app:app", MASTER_PORT,
                  {"MASTER_DB": master_db, "SLAVE_URL": SLAVE}, tmp)
    # A dead port used to simulate an unreachable slave.
    dead_url = "http://127.0.0.1:9"

    try:
        master.start()
        slave.start()
        assert wait_http(f"{MASTER}/zone/serial", master), "master did not start"
        assert wait_http(f"{SLAVE}/status", slave), "slave did not start"
        # ---- 1. baseline zone with the soon-to-be-retired address ----------
        print("\n== 1. publish baseline, sync slave ==")
        st, body = http("POST", f"{MASTER}/records/bulk", {"records": [
            {"name": "host1.lab.test", "ip": SEALED_IP},
            {"name": "host2.lab.test", "ip": "10.5.0.2", "ttl": 60},
        ]})
        check("baseline bulk accepted", st == 200, f"got {st} {body}")
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("slave synced baseline", st == 200 and body.get("applied") is True, f"got {st} {body}")
        # A second slave is also brought to the baseline; it will be deliberately
        # kept behind to model synchronization lag.
        slave2.start()
        assert wait_http(f"{SLAVE2}/status", slave2), "lag slave did not start"
        st, body = http("POST", f"{SLAVE2}/sync", {})
        check("lag slave synced baseline", st == 200 and body.get("applied") is True, f"got {st} {body}")
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("slave serves the retired address before retirement", r["rcode"] == 0 and r["answer_count"] == 1, str(r))

        # ---- 2. cannot seal while the address is still in the master zone --
        print("\n== 2. seal precondition: address absent from master ==")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}", {"ttl": SEAL_TTL})
        check("seal refused while address still in zone (409)", st == 409, f"got {st} {body}")

        # Retire the instrument: move host1 elsewhere (one new serial), then seal.
        st, body = http("PUT", f"{MASTER}/records/host1.lab.test", {"ip": "10.5.0.10"})
        retire_serial = body.get("serial")
        check("retirement publish accepted", st == 200 and isinstance(retire_serial, int), f"got {st} {body}")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}", {"ttl": SEAL_TTL})
        check("seal created once address absent", st == 201 and body.get("ip") == SEALED_IP, f"got {st} {body}")
        seal = body
        check("seal records TTL upper bound", seal.get("ttl_seconds") == SEAL_TTL, json.dumps(seal))
        check("seal records the master serial at sealing time",
              seal.get("seal_serial") == retire_serial, json.dumps(seal))
        check("new seal is awaiting confirmation",
              seal.get("status") == "awaiting_confirmation" and seal.get("first_confirm_at") is None,
              json.dumps(seal))
        check("seal view explains the wait and has no release time yet",
              "waiting for slave confirmation" in seal.get("wait_reason", "")
              and seal.get("earliest_release_at") is None, json.dumps(seal))
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}", {"ttl": SEAL_TTL})
        check("duplicate active seal refused (409)", st == 409, f"got {st} {body}")
        st, body = http("GET", f"{MASTER}/seals/{SEALED_IP}")
        check("GET /seals/{ip} lists the active seal", st == 200 and body.get("ip") == SEALED_IP, f"got {st}")
        st, body = http("GET", f"{MASTER}/seals")
        check("GET /seals lists active seals",
              st == 200 and any(s.get("ip") == SEALED_IP for s in body.get("seals", [])), json.dumps(body))

        # ---- 3. sealed address cannot be written back: single + bulk -------
        print("\n== 3. sealed address write-back blocked (single & bulk) ==")
        st, body = http("PUT", f"{MASTER}/records/newdev.lab.test", {"ip": SEALED_IP})
        check("single upsert of sealed IP -> 409", st == 409, f"got {st} {body}")
        st, body = http("POST", f"{MASTER}/records/bulk", {"records": [
            {"name": "host2.lab.test", "ip": "10.5.0.2"},
            {"name": "newdev.lab.test", "ip": SEALED_IP},
        ]})
        check("bulk replace containing sealed IP -> 409", st == 409, f"got {st} {body}")
        # The blocked bulk must not have changed anything.
        st, body = http("GET", f"{MASTER}/records")
        names = {r["name"] for r in body.get("records", [])}
        check("blocked bulk left the zone untouched (no newdev)", "newdev.lab.test" not in names, json.dumps(sorted(names)))
        st, body = http("PUT", f"{MASTER}/records/host2.lab.test", {"ip": "10.5.0.22"})
        check("unrelated single publish still works under seal", st == 200, f"got {st} {body}")
        st, body = http("DELETE", f"{MASTER}/records/host2.lab.test")
        check("delete still works under seal", st == 200, f"got {st} {body}")

        # ---- 4. concurrent publish vs seal: exactly one winner -------------
        print("\n== 4. concurrent publish vs seal conflict ==")
        race_ip = "10.6.0.7"
        outcomes = {}

        def do_publish():
            st, b = http("PUT", f"{MASTER}/records/race.lab.test", {"ip": race_ip})
            outcomes["publish"] = (st, b)

        def do_seal():
            # Tiny stagger so both genuinely contend for the write transaction.
            time.sleep(0.01)
            st, b = http("POST", f"{MASTER}/seals/{race_ip}", {"ttl": SEAL_TTL})
            outcomes["seal"] = (st, b)

        t1, t2 = threading.Thread(target=do_publish), threading.Thread(target=do_seal)
        t1.start(); t2.start(); t1.join(); t2.join()
        pub_ok = outcomes["publish"][0] == 200
        seal_ok = outcomes["seal"][0] == 201
        check("exactly one of publish/seal wins", (pub_ok, seal_ok) in [(True, False), (False, True)],
              f"publish={outcomes.get('publish')} seal={outcomes.get('seal')}")
        if seal_ok:
            # Seal won: a later publish of that IP must now be blocked too.
            st, b = http("PUT", f"{MASTER}/records/race2.lab.test", {"ip": race_ip})
            check("seal winner keeps the address protected afterwards", st == 409, f"got {st} {b}")
            st, b = http("POST", f"{MASTER}/seals/{race_ip}/release", )
            check("cannot release before any confirmation", st == 409, f"got {st} {b}")
        else:
            # Publish won: sealing a zone-present address must have failed 409.
            check("publish winner means seal failed with 409 (address present)",
                  outcomes["seal"][0] == 409, str(outcomes["seal"]))
            # Clean up so the race address can be reused later in the run.
            http("DELETE", f"{MASTER}/records/race.lab.test")

        # ---- 5. verification while a slave is lagging ----------------------
        print("\n== 5. slave lag: confirmation withheld until caught up ==")
        # slave2 was never synced past the baseline: its serial is below the
        # seal-time serial and its snapshot still contains the retired address.
        st, lag = http("GET", f"{SLAVE2}/zone")
        check("lag slave really behind the seal serial",
              st == 200 and lag.get("serial", 0) < retire_serial
              and any(r.get("ip") == SEALED_IP for r in lag.get("records", [])),
              json.dumps(lag))
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/verify", {"slave_url": SLAVE2})
        check("lagging slave -> not confirmed", st == 200 and body.get("confirmed") is False, f"got {st} {body}")
        check("lag reason mentions serial/behind", "behind" in body.get("reason", ""), body.get("reason", ""))
        check("no first confirmation recorded while lagging",
              body["seal"].get("first_confirm_at") is None, json.dumps(body["seal"]))
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE2_DNS_PORT)
        check("lagging slave still answers an A record", r["answer_count"] >= 1, str(r))

        # The main slave catches up: latest version is past seal serial and no
        # longer contains the sealed address.
        st, body = http("POST", f"{SLAVE}/sync", {})
        check("main slave catches up to latest", st == 200 and body.get("serial") >= retire_serial, f"got {st} {body}")
        st, szone = http("GET", f"{SLAVE}/zone")
        check("caught-up slave snapshot no longer contains the sealed IP",
              all(r.get("ip") != SEALED_IP for r in szone.get("records", [])), json.dumps(szone))
        r = dns_query("host1.lab.test", dnsproto.QTYPE_A, SLAVE_DNS_PORT)
        check("DNS now answers (host1 moved to its new address)", r["rcode"] == 0, str(r))

        # A second lagging angle: bring slave2 forward but to a version that
        # still predates the seal serial is impossible after catch-up; instead
        # confirm that catching slave2 up flips it to confirmed too.
        st, body = http("POST", f"{SLAVE2}/sync", {})
        check("lag slave catches up when finally allowed to sync",
              st == 200 and body.get("serial") >= retire_serial, f"got {st} {body}")

        # ---- 6. first confirmation recorded once and kept ------------------
        print("\n== 6. first confirmation recorded once; repeats keep the time ==")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/verify", {"slave_url": SLAVE})
        check("verify after catch-up -> confirmed", st == 200 and body.get("confirmed") is True, f"got {st} {body}")
        first = body["seal"].get("first_confirm_at")
        check("first confirmation time now set", first is not None, json.dumps(body["seal"]))
        check("status becomes waiting_ttl with earliest release time",
              body["seal"].get("status") == "waiting_ttl"
              and body["seal"].get("earliest_release_at") is not None, json.dumps(body["seal"]))
        check("TTL-hold wait reason mentions cache expiry",
              "TTL" in body["seal"].get("wait_reason", ""), body["seal"].get("wait_reason", ""))
        time.sleep(1.05)
        st, body2 = http("POST", f"{MASTER}/seals/{SEALED_IP}/verify", {"slave_url": SLAVE})
        check("repeated verification stays confirmed", body2.get("confirmed") is True, f"got {st} {body2}")
        check("first confirmation time preserved on repeated checks",
              body2["seal"].get("first_confirm_at") == first,
              f"{first} vs {body2['seal'].get('first_confirm_at')}")
        check("confirming slave identity/serial recorded",
              body2["seal"].get("confirm_slave") == SLAVE
              and isinstance(body2["seal"].get("confirm_slave_serial"), int), json.dumps(body2["seal"]))

        # ---- 7. unreachable slave keeps waiting, keeps the time ------------
        print("\n== 7. unreachable slave: keep waiting, preserve confirmation ==")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/verify", {"slave_url": dead_url})
        check("unreachable slave -> not confirmed, reachable=false",
              st == 200 and body.get("confirmed") is False and body.get("reachable") is False, f"got {st} {body}")
        check("confirmation time survives a failed check",
              body["seal"].get("first_confirm_at") == first, json.dumps(body["seal"]))
        check("failure reason recorded on the seal",
              "unreachable" in (body["seal"].get("last_check_detail") or ""), json.dumps(body["seal"]))

        # ---- 8. early release refused; full-TTL release accepted -----------
        print("\n== 8. early release refused; release after TTL ==")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/release")
        if st == 409:
            check("release before TTL elapses -> 409", True)
        else:  # timing dependent: if TTL already elapsed, accept and re-check below
            check("release before TTL elapses -> 409", False, f"got {st} {body}")
        # Wait until first_confirm + TTL has fully elapsed.
        st, detail = http("GET", f"{MASTER}/seals/{SEALED_IP}")
        earliest = detail["seal"]["earliest_release_at"] if "seal" in detail else detail.get("earliest_release_at")
        # Poll until the view itself says releasable (source of truth).
        deadline = time.time() + SEAL_TTL + 10
        releasable = False
        while time.time() < deadline:
            st, view = http("GET", f"{MASTER}/seals/{SEALED_IP}")
            if view.get("status") == "releasable":
                releasable = True
                break
            time.sleep(0.25)
        check("seal becomes releasable once full TTL elapses", releasable, json.dumps(view))
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/release")
        check("release after TTL accepted", st == 200 and body.get("status") == "released", f"got {st} {body}")
        check("released seal keeps its history (first confirm + released_at)",
              body.get("first_confirm_at") == first and body.get("released_at") is not None, json.dumps(body))
        st, body = http("GET", f"{MASTER}/seals")
        check("released seal hidden from active-only listing",
              all(s.get("ip") != SEALED_IP for s in body.get("seals", [])), json.dumps(body))
        st, body = http("GET", f"{MASTER}/seals?include_released=true")
        check("released seal visible with include_released=true",
              any(s.get("ip") == SEALED_IP and s.get("status") == "released"
                  for s in body.get("seals", [])), json.dumps(body))

        # ---- 9. after release the address is reusable; can be re-sealed ----
        print("\n== 9. address reusable after release; re-seal works ==")
        st, body = http("PUT", f"{MASTER}/records/newdev.lab.test", {"ip": SEALED_IP})
        check("sealed IP can be assigned to new equipment after release", st == 200, f"got {st} {body}")
        st, body = http("DELETE", f"{MASTER}/records/newdev.lab.test")
        check("cleanup delete ok", st == 200, f"got {st} {body}")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}", {"ttl": 1})
        check("address can be sealed again after release", st == 201, f"got {st} {body}")
        second_seal_id = body.get("id")
        st, view = http("GET", f"{MASTER}/seals/{SEALED_IP}")
        check("re-seal starts a fresh, unconfirmed lifecycle",
              view.get("id") == second_seal_id and view.get("first_confirm_at") is None
              and view.get("status") == "awaiting_confirmation", json.dumps(view))

        # ---- 10. master restart: state and confirmation time persist -------
        print("\n== 10. master restart preserves seal state ==")
        # Bring the slave past the second seal's seal serial first.
        st, sync_body = http("POST", f"{SLAVE}/sync", {})
        st, seal_view = http("GET", f"{MASTER}/seals/{SEALED_IP}")
        check("slave synced past the second seal serial",
              st == 200 and isinstance(sync_body.get("serial"), int)
              and sync_body["serial"] >= seal_view["seal_serial"],
              f"sync={json.dumps(sync_body)} seal={json.dumps(seal_view)}")
        # Confirm the second seal so we have a confirmation time to preserve.
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/verify", {"slave_url": SLAVE})
        check("second seal confirmed before restart", st == 200 and body.get("confirmed") is True, f"got {st} {body}")
        persisted_first = body["seal"].get("first_confirm_at")
        # Write-back protection must still hold across the restart.
        st, before = http("PUT", f"{MASTER}/records/x.lab.test", {"ip": SEALED_IP})
        check("write-back blocked before restart", st == 409, f"got {st} {before}")
        master.stop()
        time.sleep(0.5)
        master.start()
        assert wait_http(f"{MASTER}/zone/serial", master), "master did not restart"
        st, view = http("GET", f"{MASTER}/seals/{SEALED_IP}")
        check("after restart: seal still active with same id (not released)",
              st == 200 and view.get("id") == second_seal_id
              and view.get("status") in ("awaiting_confirmation", "waiting_ttl", "releasable")
              and view.get("released_at") is None,
              json.dumps(view))
        check("after restart: first confirmation time preserved",
              view.get("first_confirm_at") == persisted_first,
              f"{persisted_first} vs {view.get('first_confirm_at')}")
        st, body = http("PUT", f"{MASTER}/records/x.lab.test", {"ip": SEALED_IP})
        check("after restart: write-back still blocked (409)", st == 409, f"got {st} {body}")
        st, body = http("POST", f"{MASTER}/seals/{SEALED_IP}/verify", {"slave_url": SLAVE})
        check("after restart: verification still works and keeps time",
              st == 200 and body.get("confirmed") is True
              and body["seal"].get("first_confirm_at") == persisted_first, f"got {st} {body}")

        # ---- 11. /docs exposes the seal endpoints --------------------------
        print("\n== 11. /docs and openapi expose the seal workflow ==")
        st, _ = http("GET", f"{MASTER}/docs")
        check("/docs reachable", st == 200)
        st, spec = http("GET", f"{MASTER}/openapi.json")
        paths = spec.get("paths", {})
        expected = ["/seals/{ip}", "/seals", "/seals/{ip}/verify", "/seals/{ip}/release"]
        missing = [p for p in expected if p not in paths]
        check("openapi exposes all seal endpoints", st == 200 and not missing, f"missing: {missing}")

    finally:
        slave2.stop()
        slave.stop()
        master.stop()

    failed = [r for r in RESULTS if not r[0]]
    print(f"\n{'=' * 60}\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed; logs in {tmp}")
    if failed:
        print("FAILED:")
        for _, name, detail in failed:
            print(f"  - {name}  {detail}")
        return 1
    print("ALL SEAL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
