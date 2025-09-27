# app.py
import streamlit as st
import pandas as pd
import io
import time
from typing import List
from scanner_complete import run_async, ping_scan_cidr, port_scan_host, banner_scan_host, parse_ports  # assumes scanner_complete.py in same folder

st.set_page_config(page_title="Mini Network Scanner", layout="wide")
st.title("FPT Telecom - Mini Network Scanner")

# Side instructions / safety
with st.sidebar:
    st.header("Instructions & Safety")
    st.markdown("""
    - **Only scan networks you own or have permission to scan.**
    - For demo, prefer a small CIDR (e.g. `/28`) or a single IP.
    - Default concurrency is conservative — if you use `/24`, be careful.
    """)
    st.markdown("**Quick tips**")
    st.write("- Use `--tcp-fallback` (80/443) for devices blocking ICMP.")
    st.write("- If app is slow, reduce concurrency or scan smaller range.")

# Input panel
col1, col2 = st.columns([1, 2])

with col1:
    network = st.text_input("Network (CIDR) or single IP", value="192.168.1.0/28")
    ports_text = st.text_input("Ports (comma-separated)", value="22,80,443,8080,3306")
    ping_timeout = st.number_input("Ping timeout (ms)", min_value=100, max_value=5000, value=500, step=100)
    port_timeout = st.number_input("Port timeout (s)", min_value=0.1, max_value=5.0, value=0.6, step=0.1)
    concurrency = st.number_input("Concurrency (max tasks)", min_value=10, max_value=1000, value=200, step=10)
    tcp_fallback_text = st.text_input("TCP fallback ports (for ICMP blocked)", value="80,443")
    out_name = st.text_input("CSV output filename (optional)", value="results.csv")
    scan_button = st.button("Start Scan")

with col2:
    st.markdown("### Scan log")
    log = st.empty()
    st.markdown("---")
    st.markdown("### Results")
    result_area = st.empty()

# Helper: small validation and warnings
def hosts_count_hint(cidr: str):
    try:
        import ipaddress
        net = ipaddress.ip_network(cidr, strict=False)
        return max(0, net.num_addresses - 2)
    except Exception:
        return None

count = hosts_count_hint(network)
if count is not None and count > 256:
    st.warning(f"Cảnh báo: network có ~{count} hosts. Khuyến cáo scan /28 hoặc ít hosts nếu chạy từ Streamlit.")
elif count is not None:
    st.info(f"Network contains ~{count} hosts.")

# Run scan when button clicked
if scan_button:
    # parse ports
    try:
        ports = parse_ports(ports_text)
        tcp_fallback = [int(x.strip()) for x in tcp_fallback_text.split(",") if x.strip()]
    except Exception as e:
        st.error(f"Port format error: {e}")
        st.stop()

    # clear previous area
    result_area.empty()
    log.empty()

    # show spinner and progress
    with st.spinner("Starting async ping scan... (this runs server-side)"):
        t0 = time.time()
        log.text("Ping scanning... (this may take a while)")
        # run ping scan via the scanner module (async)
        try:
            alive = run_async(ping_scan_cidr(network, timeout_ms=ping_timeout, concurrency=concurrency, tcp_fallback_ports=tcp_fallback))
        except Exception as e:
            st.error(f"Scan failed: {e}")
            st.stop()

        log.text(f"Ping-scan done. Found {len(alive)} alive hosts. Elapsed: {time.time()-t0:.2f}s")

        # If none found, show message
        if not alive:
            st.info("No alive hosts found.")
            st.stop()

        # For each alive host, run port scan and gather banners
        rows = []
        results = {}
        total_hosts = len(alive)
        progress_bar = st.progress(0)
        for i, ip in enumerate(alive, start=1):
            log.text(f"Scanning ports on {ip} ({i}/{total_hosts}) ...")
            try:
                open_map = run_async(port_scan_host(ip, ports, timeout_s=port_timeout, concurrency=concurrency))
            except Exception as e:
                open_map = {p: False for p in ports}
                st.warning(f"Port scan failed for {ip}: {e}")

            open_ports = [p for p, ok in open_map.items() if ok]
            banners = {}
            if open_ports:
                # try banners for web ports quickly
                web_ports = [p for p in open_ports if p in (80, 8080)]
                other_ports = [p for p in open_ports if p not in web_ports]
                if web_ports:
                    b_res = run_async(banner_scan_host(ip, web_ports, timeout_s=1.0))
                    banners.update(b_res)
                if other_ports:
                    other_b = run_async(banner_scan_host(ip, other_ports, timeout_s=0.6))
                    banners.update(other_b)

            results[ip] = {"open_ports": open_ports, "banners": banners}
            rows.append({"ip": ip, "open_ports": ",".join(map(str, open_ports)) if open_ports else "-", "banners": "; ".join(f"{p}:{(banners.get(p) or '')[:80]}" for p in open_ports)})
            progress_bar.progress(i / total_hosts)

        # show table
        df = pd.DataFrame(rows)
        result_area.dataframe(df, use_container_width=True)

        # CSV download
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        csv_bytes = csv_buf.getvalue().encode("utf-8")
        st.download_button("Download CSV", data=csv_bytes, file_name=out_name, mime="text/csv")

        st.success(f"Scan finished in {time.time()-t0:.2f}s. Found {len(results)} alive hosts.")

