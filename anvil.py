#!/usr/bin/env python3
"""
Anvil — Process State Sweep (PSS).

Local host snapshot:
  - Running processes (with cmdline + UID + cwd)
  - Listening sockets (with owning PID)
  - Loaded kernel modules / kexts
  - Suspicious indicators (setuid binaries with non-root file ownership,
    unsigned binaries on macOS, processes running as root that listen on
    high-risk ports, etc.)

Token protocol (when ANVIL_MANAGED=1):
  __VANTAGE_LOG__     <message>
  __VANTAGE_ERR__     <message>
  __VANTAGE_STATUS__  <json>
  __VANTAGE_FINDING__ <json>
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError:
    _us = None

try:
    import pr0t31n_tool_runner as _ur
except ImportError:
    _ur = None

try:
    import pr0t31n_event_log as _el
except ImportError:
    _el = None

_MANAGED = os.environ.get("ANVIL_MANAGED", "") == "1"
_findings: list = []

_fdb = None
_db_path = os.environ.get("PR0T31N_FINDINGS_DB")
if _db_path:
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_findings_db
        _fdb = pr0t31n_findings_db.FindingsDB(_db_path)
    except Exception:
        _fdb = None

# §13: run dir + §13b run-dir logger (scan.log/scan.log.json/errors.log/...).
# Both set in main() once the run directory is known.
_RUN_DIR: Optional[Path] = None
_RUNLOG = None

# §13b findings.csv column set (universal core fields)
_CSV_FIELDS = ["id", "tool", "title", "datetime", "ip", "port", "hostname",
               "risk", "command", "description", "output_file", "affected",
               "cves", "service", "catalogue_id", "remediation", "sources"]


def _rel(p) -> str:
    """Relativize an evidence path against the run dir (§13c). Falls back to the
    input when relativization isn't possible."""
    if not p:
        return ""
    if _us is not None and _RUN_DIR is not None:
        try:
            r = _us.to_relative_output_file(p, str(_RUN_DIR))
            if r:
                return r
        except Exception:
            pass
    return str(p)


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        print(f"{token}:{msg}", flush=True)
    else:
        print(msg, flush=True)


def log(msg: str) -> None:
    _tok("__VANTAGE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    _tok("__VANTAGE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    _tok("__VANTAGE_STATUS__",
         json.dumps({"phase": phase, "label": label, "state": state, "step": step}))


def finding(*, title: str, severity: str, description: str,
             data: dict | None = None, output_file: str = "") -> None:
    # §13c/§14i: reference the evidence output AND its §14 .log sibling, both
    # run-dir-relative. The snapshot file (output_file) is written by run_tool,
    # which also emits "<output_file>.log".
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    if _us is not None:
        rec = _us.make_finding(
            tool="anvil", title=title, risk=severity.upper(),
            description=description, ip="127.0.0.1", port=0,
            command=(data or {}).get("command", ""),
            output_file=of_rel,
            affected=(data or {}).get("affected", ""),
            remediation=(data or {}).get("remediation", ""),
            sources="anvil", catalogue_id=(data or {}).get("catalogue_id", ""),
        )
    else:
        rec = {
            "id": str(uuid.uuid4()),
            "tool": "anvil",
            "title": title,
            "risk": severity.upper(),
            "description": description,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "output_file": of_rel,
            "data": data or {},
        }
    _findings.append(rec)
    if _fdb:
        try:
            _fdb.insert_finding(rec)
        except Exception:
            pass
    _tok("__VANTAGE_FINDING__", json.dumps(rec))
    _flush_findings()


def _flush_findings():
    if _RUN_DIR is None:
        return
    try:
        if _us is not None:
            out = [_us.augment_finding(dict(f), tool="anvil") for f in _findings]
            _us.atomic_write_json(_RUN_DIR / "findings.json", out)
        else:
            (_RUN_DIR / "findings.json").write_text(
                json.dumps(_findings, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── Snapshot phases ───────────────────────────────────────────────────────────

def snapshot_processes(output_dir: Path) -> list:
    status("processes", "Process snapshot", "running")
    out_file = output_dir / "processes.txt"
    cmd = ["ps", "-eo", "pid,ppid,uid,user,start,cmd"]
    try:
        if _ur is not None:
            cp = _ur.run_tool(cmd, output_file=str(out_file),
                                timeout=30, tool_name="ps",
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out_file.write_text(cp.stdout or "", encoding="utf-8")
    except Exception as exc:
        err(f"ps failed: {exc}")
        status("processes", "Process snapshot", "error")
        return []

    procs: list = []
    for line in (cp.stdout or "").splitlines()[1:]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        pid, ppid, uid, user, start, cmd_str = parts
        procs.append({"pid": int(pid), "ppid": int(ppid), "uid": int(uid),
                       "user": user, "start": start, "cmd": cmd_str})

    log(f"Captured {len(procs)} process(es)")

    # Detect long-running root shells (often residual reverse-shells)
    for p in procs:
        if p["uid"] == 0 and re.search(r"\b(bash|sh|nc|ncat|python|perl|ruby|socat)\b",
                                          p["cmd"]):
            if re.search(r"-l\b|--listen|reverse|-i\s*>\s*/dev/tcp|/dev/tcp",
                           p["cmd"]):
                finding(title=f"Root shell with listener/reverse-shell heuristics (PID {p['pid']})",
                         severity="HIGH",
                         description=("Process running as root has command-line indicators "
                                       "of a listening or reverse shell."),
                         data={"catalogue_id": "ANVIL-PROC-001",
                               "affected": f"pid={p['pid']}",
                               "command": p["cmd"][:200]},
                         output_file=str(out_file))
    status("processes", "Process snapshot", "complete")
    return procs


def snapshot_sockets(output_dir: Path, processes: list) -> None:
    status("sockets", "Listening socket snapshot", "running")
    out_file = output_dir / "sockets.txt"
    ss = shutil.which("ss")
    netstat = shutil.which("netstat")
    cmd: list = []
    if ss:
        cmd = [ss, "-tulpn"]
    elif netstat:
        cmd = [netstat, "-tulpn"]
    else:
        err("ss / netstat not installed — skipping socket snapshot")
        status("sockets", "Listening socket snapshot", "skipped")
        return
    try:
        if _ur is not None:
            cp = _ur.run_tool(cmd, output_file=str(out_file),
                                timeout=30, tool_name=Path(cmd[0]).name,
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out_file.write_text(cp.stdout or "", encoding="utf-8")
    except Exception as exc:
        err(f"socket snapshot failed: {exc}")
        status("sockets", "Listening socket snapshot", "error")
        return

    proc_by_pid = {p["pid"]: p for p in processes}
    listening: list = []
    for line in (cp.stdout or "").splitlines():
        m = re.search(r"(?:LISTEN|UNCONN).*?[\s:](\d+)\s+.*?users:\(\(\"[^\"]+\",pid=(\d+)", line)
        if m:
            port = int(m.group(1))
            pid  = int(m.group(2))
            listening.append({"port": port, "pid": pid,
                                "user": (proc_by_pid.get(pid) or {}).get("user", "?")})
    log(f"Listening sockets: {len(listening)}")

    risky_ports = {21, 23, 25, 2049, 5432, 3306, 6379, 27017, 11211, 9200}
    for s in listening:
        if s["port"] in risky_ports and s["user"] == "root":
            finding(title=f"High-risk service listening as root on port {s['port']}",
                     severity="MEDIUM",
                     description=("A historically-exploitable service is listening as root. "
                                   "Confirm authentication, firewall, and patch level."),
                     data={"catalogue_id": "ANVIL-NET-010",
                           "affected": f"port={s['port']} pid={s['pid']}"},
                     output_file=str(out_file))
    status("sockets", "Listening socket snapshot", "complete")


def snapshot_modules(output_dir: Path) -> None:
    status("modules", "Kernel-module snapshot", "running")
    out_file = output_dir / "modules.txt"
    if sys.platform.startswith("linux"):
        lsmod = shutil.which("lsmod")
        if not lsmod:
            err("lsmod not available — skipping")
            status("modules", "Kernel-module snapshot", "skipped")
            return
        cmd = [lsmod]
    elif sys.platform == "darwin":
        kextstat = shutil.which("kextstat")
        if not kextstat:
            err("kextstat not available — skipping")
            status("modules", "Kernel-module snapshot", "skipped")
            return
        cmd = [kextstat]
    else:
        log("Module snapshot supported on Linux/macOS only")
        status("modules", "Kernel-module snapshot", "skipped")
        return

    try:
        if _ur is not None:
            cp = _ur.run_tool(cmd, output_file=str(out_file),
                                timeout=30, tool_name=Path(cmd[0]).name,
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        out_file.write_text(cp.stdout or "", encoding="utf-8")
        log(f"Module list captured ({len(cp.stdout.splitlines())} entries)")
    except Exception as exc:
        err(f"module snapshot failed: {exc}")
    status("modules", "Kernel-module snapshot", "complete")


def scan_setuid(output_dir: Path) -> None:
    status("setuid", "Setuid binary scan", "running")
    out_file = output_dir / "setuid_binaries.txt"
    if not sys.platform.startswith(("linux", "darwin")):
        log("Setuid scan supported on Linux/macOS only")
        status("setuid", "Setuid binary scan", "skipped")
        return
    find = shutil.which("find")
    if not find:
        status("setuid", "Setuid binary scan", "skipped")
        return
    # Scan common system paths only — avoid full FS scan
    scan_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
                 "/bin", "/sbin", "/opt"]
    cmd = [find] + scan_dirs + ["-xdev", "-perm", "-4000", "-type", "f"]
    try:
        if _ur is not None:
            cp = _ur.run_tool(cmd, output_file=str(out_file),
                                timeout=120, tool_name="find",
                                errors_log=(str(_RUN_DIR / "errors.log")
                                            if _RUN_DIR is not None else None))
        else:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        binaries = [b for b in (cp.stdout or "").splitlines() if b]
        out_file.write_text("\n".join(binaries), encoding="utf-8")
        log(f"Setuid binaries: {len(binaries)}")
    except Exception as exc:
        err(f"setuid scan failed: {exc}")
        status("setuid", "Setuid binary scan", "error")
        return

    # Detect binaries not owned by root (rare and suspicious)
    for b in binaries:
        try:
            st = os.stat(b)
            if st.st_uid != 0:
                finding(title=f"Setuid binary not owned by root: {b}",
                         severity="HIGH",
                         description=("A setuid binary is owned by a non-root user; "
                                       "compromising that user grants root-equivalent "
                                       "execution privileges."),
                         data={"catalogue_id": "ANVIL-SUID-001",
                               "affected": b,
                               "owner_uid": st.st_uid},
                         output_file=str(out_file))
        except OSError:
            continue
    status("setuid", "Setuid binary scan", "complete")


# ── Output helpers (§13b) ──────────────────────────────────────────────────────

def _risk_counts(findings: list) -> dict:
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = str(f.get("risk", "")).upper()
        if r in rc:
            rc[r] += 1
    return rc


def _write_findings_csv(path: Path, findings: list) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()
            for fd in findings:
                w.writerow({k: fd.get(k, "") for k in _CSV_FIELDS})
    except Exception as exc:
        err(f"findings.csv write failed: {exc}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(prog="anvil",
                                  description="Anvil — Process State Sweep")
    p.add_argument("--client-short", default="default")
    p.add_argument("--client-name", default="", help="Full client name (defaults to --client-short)")
    p.add_argument("--engagement-name", default="anvil run", help="Engagement name for meta.json")
    p.add_argument("--project", help="Override project output directory")
    p.add_argument("--skip-setuid", action="store_true",
                    help="Skip setuid scan (slow on large filesystems)")
    p.add_argument("--version", action="store_true")
    args = p.parse_args()

    if args.version:
        print(VERSION)
        return 0

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.project:
        project_dir = Path(args.project)
    elif _us is not None:
        project_dir = _us.universal_run_dir(args.client_short, "anvil",
                                              year=datetime.now().strftime("%Y"),
                                              ts=ts)
    else:
        project_dir = Path.cwd() / f"anvil_{args.client_short}_{ts}"
    project_dir.mkdir(parents=True, exist_ok=True)

    # §13/§13b: publish the run dir + bring up the run-dir event logger
    global _RUN_DIR, _RUNLOG
    _RUN_DIR = project_dir
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
        except Exception:
            _RUNLOG = None

    if _us is not None:
        _us.write_meta(project_dir, _us.make_meta(
            tool="anvil", version=VERSION,
            client_short=args.client_short,
            client_name=(args.client_name or args.client_short),
            engagement_name=args.engagement_name,
            target=socket.gethostname()))

    log(f"Anvil v{VERSION} PSS starting — host: {socket.gethostname()}")

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    procs = snapshot_processes(project_dir)
    snapshot_sockets(project_dir, procs)
    snapshot_modules(project_dir)
    if not args.skip_setuid:
        scan_setuid(project_dir)
    ended_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Persist findings universally. NB: write via augment_finding (no run_dir)
    # rather than write_universal_findings — finding() already set output_file to
    # a run-dir-relative comma-joined "<snapshot>,<snapshot>.log" pair (§14i), and
    # write_universal_findings' run_dir relativization would wipe a multi-path /
    # already-relative output_file string.
    if _us is not None:
        out = [_us.augment_finding(dict(f), tool="anvil") for f in _findings]
        _us.atomic_write_json(project_dir / "findings.json", out)
        _write_findings_csv(project_dir / "findings.csv", out)
        try:
            summary = _us.make_summary(
                tool="anvil", version=VERSION,
                scan_start=started_at, scan_end=ended_at,
                target=socket.gethostname(),
                success=True, total_findings=len(out),
                risk_counts=_risk_counts(out))
            _us.write_summary(project_dir, summary)
        except Exception as exc:
            err(f"summary.json write failed: {exc}")
    else:
        (project_dir / "findings.json").write_text(
            json.dumps(_findings, indent=2), encoding="utf-8")
        _write_findings_csv(project_dir / "findings.csv", _findings)

    log(f"Anvil complete — {len(_findings)} finding(s) — output: {project_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
