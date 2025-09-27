#!/usr/bin/env python3
# scanner_complete.py
# Async network scanner (Day 3 complete)
# - async ping (create_subprocess_exec)
# - tcp-liveness fallback (asyncio.open_connection)
# - async port scan
# - async banner grabbing (HTTP HEAD)
# Usage examples:
#   python scanner_complete.py --network 192.168.1.0/28
#   python scanner_complete.py -n 192.168.1.0/24 -p 22,80,443 -c 200 -o results.csv

import asyncio
import platform
import ipaddress
import argparse
import time
import csv
from typing import List, Dict, Tuple, Optional

SYSTEM = platform.system().lower()

# ------------------ Async helpers ------------------
async def async_ping(ip: str, timeout_ms: int = 500) -> bool:
    """Ping using system ping asynchronously. Returns True if reply."""
    if SYSTEM == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # On many Unix, -W expects seconds (int). Convert ms -> s minimum 1s.
        timeout_s = max(1, int(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        rc = await proc.wait()
        return rc == 0
    except Exception:
        return False

async def async_tcp_check(ip: str, port: int = 80, timeout_s: float = 0.6) -> bool:
    """
    Try TCP connect (async) as liveness check.
    Returns True if connection succeeded.
    """
    try:
        coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout_s)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def async_port_check(ip: str, port: int, timeout_s: float = 0.6) -> Tuple[int, bool]:
    """Async check port open (returns (port, bool))."""
    try:
        coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout_s)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except Exception:
        return port, False

async def async_banner_grab_http(ip: str, port: int = 80, timeout_s: float = 1.0) -> str:
    """
    If port likely HTTP, send a minimal HEAD request and read response.
    Return received bytes decoded (header snippet) or empty string.
    """
    try:
        coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout_s)
        # Send HTTP HEAD
        req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout_s)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""

# ------------------ Scanning logic ------------------
async def ping_scan_cidr(network_cidr: str, timeout_ms: int = 500, concurrency: int = 200,
                         tcp_fallback_ports: Optional[List[int]] = None) -> List[str]:
    """
    Ping-scan CIDR concurrently.
    If ICMP blocked, optionally try TCP fallback ports (list) to detect alive host.
    Returns list of alive IP strings.
    """
    net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    alive: List[str] = []
    sem = asyncio.Semaphore(concurrency)

    async def worker(ip: str):
        async with sem:
            ok = await async_ping(ip, timeout_ms=timeout_ms)
            if ok:
                return ip
            # try tcp fallback if provided
            if tcp_fallback_ports:
                for p in tcp_fallback_ports:
                    if await async_tcp_check(ip, port=p, timeout_s=max(0.2, timeout_ms/1000.0)):
                        return ip
            return None

    tasks = [asyncio.create_task(worker(ip)) for ip in hosts]
    for t in asyncio.as_completed(tasks):
        res = await t
        if res:
            alive.append(res)
            print(f"[+] Alive: {res}")
    return alive

async def port_scan_host(ip: str, ports: List[int], timeout_s: float = 0.6, concurrency: int = 200) -> Dict[int, bool]:
    """
    Scan list of ports on a host concurrently (async).
    Returns dict port->bool.
    """
    sem = asyncio.Semaphore(concurrency)
    results: Dict[int, bool] = {}

    async def worker(p: int):
        async with sem:
            return await async_port_check(ip, p, timeout_s=timeout_s)

    tasks = [asyncio.create_task(worker(p)) for p in ports]
    for t in asyncio.as_completed(tasks):
        p, ok = await t
        results[p] = ok
    return results

async def banner_scan_host(ip: str, open_ports: List[int], timeout_s: float = 1.0, concurrency: int = 50) -> Dict[int, str]:
    """
    For ports that are open, attempt banner grabbing (HTTP only for port 80/8080/443 if wanted).
    Returns dict port->banner (string; empty if none).
    """
    sem = asyncio.Semaphore(concurrency)
    results: Dict[int, str] = {}

    async def worker(port: int):
        async with sem:
            if port in (80, 8080):  # HTTP-ish
                return port, await async_banner_grab_http(ip, port=port, timeout_s=timeout_s)
            # otherwise, attempt a small recv (some services return banner)
            try:
                coro = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(coro, timeout=timeout_s)
                # some services send banner automatically
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                except Exception:
                    data = b""
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return port, data.decode(errors="ignore").strip()
            except Exception:
                return port, ""

    tasks = [asyncio.create_task(worker(p)) for p in open_ports]
    for t in asyncio.as_completed(tasks):
        p, banner = await t
        results[p] = banner
    return results

# ------------------ Runner & CLI ------------------
def parse_ports(text: str) -> List[int]:
    return [int(x.strip()) for x in text.split(",") if x.strip()]

def run_async(coro):
    return asyncio.run(coro)

def save_results_csv(path: str, results: Dict[str, Dict]):
    """
    results: { ip: {"open_ports": [p...], "banners": {p: str}} }
    CSV columns: ip, open_ports, banners_json (simple joined)
    """
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "open_ports", "banners"])
            for ip, data in results.items():
                open_ports = ";".join(map(str, data.get("open_ports", [])))
                banners = " | ".join(f"{p}:{(data.get('banners') or {}).get(p,'' )}" for p in data.get("open_ports", []))
                w.writerow([ip, open_ports, banners])
        print(f"[i] Saved CSV to {path}")
    except Exception as e:
        print(f"[!] Failed to save CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description="Async Network Scanner - complete (Day 3)")
    parser.add_argument("--network", "-n", required=True, help="CIDR network or single IP")
    parser.add_argument("--ports", "-p", default="22,80,443,8080,3306", help="Comma separated ports to scan")
    parser.add_argument("--ping-timeout", type=int, default=500, help="Ping timeout ms")
    parser.add_argument("--port-timeout", type=float, default=0.6, help="Port connect timeout seconds")
    parser.add_argument("--concurrency", "-c", type=int, default=200, help="Max concurrent tasks")
    parser.add_argument("--tcp-fallback", "-f", default="", help="Comma list of ports to try as tcp-liveness fallback (e.g. 80,443)")
    parser.add_argument("--out", "-o", help="CSV output path")
    args = parser.parse_args()

    try:
        _ = ipaddress.ip_network(args.network, strict=False)
    except Exception as e:
        print(f"[!] Invalid network: {e}")
        return

    ports = parse_ports(args.ports)
    tcp_fallback = [int(x.strip()) for x in args.tcp_fallback.split(",") if x.strip()] if args.tcp_fallback else None

    t0 = time.time()
    print(f"[i] Ping-scanning {args.network} (timeout={args.ping_timeout}ms, concurrency={args.concurrency})")
    alive = run_async(ping_scan_cidr(args.network, timeout_ms=args.ping_timeout, concurrency=args.concurrency, tcp_fallback_ports=tcp_fallback))
    print(f"[i] Found {len(alive)} alive hosts. Elapsed: {time.time()-t0:.2f}s")

    results: Dict[str, Dict] = {}
    for ip in alive:
        print(f"[i] Scanning ports on {ip} ...")
        open_map = run_async(port_scan_host(ip, ports, timeout_s=args.port_timeout, concurrency=args.concurrency))
        open_ports = [p for p, ok in open_map.items() if ok]
        banners = {}
        if open_ports:
            # try banner grab for known web ports only to save time
            web_ports = [p for p in open_ports if p in (80, 8080)]
            other_ports = [p for p in open_ports if p not in web_ports]
            if web_ports:
                b_res = run_async(banner_scan_host(ip, web_ports, timeout_s=1.0))
                banners.update(b_res)
            # optionally quick banner for other ports (cheap)
            if other_ports:
                other_b = run_async(banner_scan_host(ip, other_ports, timeout_s=0.6))
                banners.update(other_b)
        results[ip] = {"open_ports": open_ports, "banners": banners}
        print(f"    → {ip} open: {open_ports if open_ports else 'none'}")

    total = time.time() - t0
    print(f"\n=== Summary ===\nAlive hosts: {len(alive)}\nTotal time: {total:.2f}s")

    if args.out:
        save_results_csv(args.out, results)

if __name__ == "__main__":
    main()
