#!/usr/bin/env python3
import asyncio
import time
import signal
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

import aiohttp
import yaml
from prometheus_client import Gauge, Counter, start_http_server

# ---------------------------
# Prometheus metrics
# ---------------------------
PAN_EXPORTER_UP = Gauge(
    "pan_exporter_up",
    "Exporter running (1=yes)",
)

PAN_EXPORTER_POLL_DURATION = Gauge(
    "pan_exporter_poll_duration_seconds",
    "Time spent polling a firewall",
    ["fw"],
)

PAN_EXPORTER_POLL_SUCCESS = Gauge(
    "pan_exporter_last_poll_success",
    "Whether the last poll succeeded (1/0)",
    ["fw"],
)

PAN_EXPORTER_LAST_POLL_TS = Gauge(
    "pan_exporter_last_poll_timestamp_seconds",
    "Unix timestamp of last poll attempt",
    ["fw"],
)

PAN_EXPORTER_ERRORS = Counter(
    "pan_exporter_poll_errors_total",
    "Total polling errors",
    ["fw", "stage"],
)

# Main tunnel metric you’ll graph
PAN_VPN_TUNNEL_UP = Gauge(
    "pan_vpn_tunnel_up",
    "Tunnel status derived from current SAs (1=up, 0=down)",
    ["fw", "tunnel", "peer"],
)

PAN_VPN_TUNNEL_SA_COUNT = Gauge(
    "pan_vpn_tunnel_sa_count",
    "Count of SAs/entries observed for a tunnel (best-effort)",
    ["fw", "tunnel", "peer"],
)

# Helps when you want a clean “current state” (remove old tunnels that disappear)
KNOWN_LABELS: Dict[str, set] = {
    "tunnel": set(),  # stores (fw,tunnel,peer) keys
}


# ---------------------------
# Config + models
# ---------------------------
@dataclass
class Firewall:
    name: str
    host: str
    api_key: str
    verify_ssl: bool = True


@dataclass
class Settings:
    poll_interval_seconds: int
    request_timeout_seconds: int
    max_concurrency: int
    listen_host: str
    listen_port: int
    firewalls: List[Firewall]


def load_settings(path: str) -> Settings:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    fws = []
    for fw in data.get("firewalls", []):
        fws.append(
            Firewall(
                name=str(fw["name"]),
                host=str(fw["host"]),
                api_key=str(fw["api_key"]),
                verify_ssl=bool(fw.get("verify_ssl", True)),
            )
        )

    return Settings(
        poll_interval_seconds=int(data.get("poll_interval_seconds", 30)),
        request_timeout_seconds=int(data.get("request_timeout_seconds", 10)),
        max_concurrency=int(data.get("max_concurrency", 15)),
        listen_host=str(data.get("listen_host", "0.0.0.0")),
        listen_port=int(data.get("listen_port", 9109)),
        firewalls=fws,
    )


# ---------------------------
# PAN-OS XML API helpers
# ---------------------------
def build_op_cmd_xml(cmd: str) -> str:
    # PAN-OS XML API expects <show>...</show> etc as the cmd parameter.
    # cmd should be something like: "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>"
    return cmd


async def panos_xml_op(
    session: aiohttp.ClientSession,
    fw: Firewall,
    cmd_xml: str,
    timeout_s: int,
) -> str:
    """
    Calls PAN-OS XML API op endpoint:
      https://<fw>/api/?type=op&cmd=<...>&key=<api_key>
    """
    url = f"https://{fw.host}/api/"
    params = {
        "type": "op",
        "cmd": build_op_cmd_xml(cmd_xml),
        "key": fw.api_key,
    }

    async with session.get(url, params=params, timeout=timeout_s, ssl=fw.verify_ssl) as resp:
        text = await resp.text()
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}: {text[:200]}")
        return text


def parse_ipsec_sa(xml_text: str) -> List[Tuple[str, str]]:
    """
    Best-effort parsing of 'show vpn ipsec-sa' output.
    Returns a list of (tunnel_name, peer_ip) pairs.
    Different PAN-OS versions/outputs differ; we search broadly.
    """
    out: List[Tuple[str, str]] = []
    root = ET.fromstring(xml_text)

    # Common structure: <response status="success"><result>...</result></response>
    result = root.find(".//result")
    if result is None:
        return out

    for entry in result.findall(".//entry"):
        # Look for tunnel name in <name> or <tunnel> or <tunnel-name>
        tunnel = (
            (entry.findtext("name") or "")
            or (entry.findtext("tunnel") or "")
            or (entry.findtext("tunnel-name") or "")
        ).strip()

        peer = (
            (entry.findtext("peer") or "")
            or (entry.findtext("peer-ip") or "")
            or (entry.findtext("peer_address") or "")
            or (entry.findtext("peer-address") or "")
        ).strip()

        if tunnel:
            out.append((tunnel, peer or "unknown"))

    # Some outputs are table-like text rather than entry lists.
    # If we got nothing, fall back to a very rough text scan.
    if not out:
        txt = "".join(result.itertext())
        # Heuristic: many outputs include "tunnel." names and peer IPs.
        # We won't over-parse here; leaving empty is better than lying.
        # You can refine after you paste a sample output.
        return []

    return out


def parse_ike_sa(xml_text: str) -> List[Tuple[str, str]]:
    """
    Best-effort parsing of 'show vpn ike-sa' output.
    Returns list of (tunnel_or_profile, peer_ip) — depends on output.
    We mainly use this as supplemental info.
    """
    out: List[Tuple[str, str]] = []
    root = ET.fromstring(xml_text)
    result = root.find(".//result")
    if result is None:
        return out

    for entry in result.findall(".//entry"):
        name = (entry.findtext("name") or entry.findtext("gateway") or "").strip()
        peer = (
            (entry.findtext("peer") or "")
            or (entry.findtext("peer-ip") or "")
            or (entry.findtext("peer-address") or "")
        ).strip()
        if name:
            out.append((name, peer or "unknown"))
    return out


# ---------------------------
# Polling + metric update
# ---------------------------
def clear_old_tunnel_metrics():
    # Remove labelsets we previously published but no longer see.
    # prometheus_client doesn't have "delete all", but we can delete known labelsets.
    for key in list(KNOWN_LABELS["tunnel"]):
        fw, tunnel, peer = key
        try:
            PAN_VPN_TUNNEL_UP.remove(fw, tunnel, peer)
            PAN_VPN_TUNNEL_SA_COUNT.remove(fw, tunnel, peer)
        except KeyError:
            pass
        KNOWN_LABELS["tunnel"].discard(key)


async def poll_one_firewall(
    session: aiohttp.ClientSession,
    fw: Firewall,
    timeout_s: int,
) -> Dict[Tuple[str, str], int]:
    """
    Returns mapping {(tunnel, peer): sa_count}
    """
    # Commands (XML form of the CLI command)
    cmd_ipsec = "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>"
    cmd_ike = "<show><vpn><ike-sa></ike-sa></vpn></show>"

    # Pull IPsec SAs (most important for "tunnel up")
    xml_ipsec = await panos_xml_op(session, fw, cmd_ipsec, timeout_s)
    ipsec_pairs = parse_ipsec_sa(xml_ipsec)

    # Optional: pull IKE SAs for extra visibility (not used for tunnel metric yet)
    # If it fails, don’t fail the entire poll.
    try:
        _ = await panos_xml_op(session, fw, cmd_ike, timeout_s)
    except Exception:
        pass

    # Count SAs per tunnel/peer
    counts: Dict[Tuple[str, str], int] = {}
    for tunnel, peer in ipsec_pairs:
        counts[(tunnel, peer)] = counts.get((tunnel, peer), 0) + 1
    return counts


async def poll_loop(settings: Settings, stop_event: asyncio.Event) -> None:
    PAN_EXPORTER_UP.set(1)

    timeout = aiohttp.ClientTimeout(total=settings.request_timeout_seconds)
    connector = aiohttp.TCPConnector(limit=0)  # we control concurrency via semaphore
    sem = asyncio.Semaphore(settings.max_concurrency)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        while not stop_event.is_set():
            # We clear old tunnel metrics each cycle to avoid stale tunnels
            clear_old_tunnel_metrics()

            tasks = []
            for fw in settings.firewalls:
                tasks.append(_poll_fw_wrapped(session, fw, settings, sem))

            await asyncio.gather(*tasks, return_exceptions=True)

            # sleep until next tick or stop
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=settings.poll_interval_seconds)
            except asyncio.TimeoutError:
                pass

    PAN_EXPORTER_UP.set(0)


async def _poll_fw_wrapped(
    session: aiohttp.ClientSession,
    fw: Firewall,
    settings: Settings,
    sem: asyncio.Semaphore,
) -> None:
    PAN_EXPORTER_LAST_POLL_TS.labels(fw=fw.name).set(time.time())

    start = time.time()
    async with sem:
        try:
            counts = await poll_one_firewall(session, fw, settings.request_timeout_seconds)

            # Publish tunnel metrics: up if we saw at least one SA entry for tunnel
            for (tunnel, peer), sa_count in counts.items():
                PAN_VPN_TUNNEL_UP.labels(fw=fw.name, tunnel=tunnel, peer=peer).set(1)
                PAN_VPN_TUNNEL_SA_COUNT.labels(fw=fw.name, tunnel=tunnel, peer=peer).set(sa_count)
                KNOWN_LABELS["tunnel"].add((fw.name, tunnel, peer))

            # If a firewall returns zero tunnels, we still treat poll as success
            PAN_EXPORTER_POLL_SUCCESS.labels(fw=fw.name).set(1)

        except ET.ParseError:
            PAN_EXPORTER_POLL_SUCCESS.labels(fw=fw.name).set(0)
            PAN_EXPORTER_ERRORS.labels(fw=fw.name, stage="xml_parse").inc()
        except asyncio.TimeoutError:
            PAN_EXPORTER_POLL_SUCCESS.labels(fw=fw.name).set(0)
            PAN_EXPORTER_ERRORS.labels(fw=fw.name, stage="timeout").inc()
        except Exception:
            PAN_EXPORTER_POLL_SUCCESS.labels(fw=fw.name).set(0)
            PAN_EXPORTER_ERRORS.labels(fw=fw.name, stage="request").inc()
        finally:
            PAN_EXPORTER_POLL_DURATION.labels(fw=fw.name).set(time.time() - start)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/firewalls.yml", file=sys.stderr)
        sys.exit(2)

    settings = load_settings(sys.argv[1])

    # Start metrics HTTP server
    start_http_server(settings.listen_port, addr=settings.listen_host)

    stop_event = asyncio.Event()

    def _handle_stop(*_args):
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    asyncio.run(poll_loop(settings, stop_event))


if __name__ == "__main__":
    main()
