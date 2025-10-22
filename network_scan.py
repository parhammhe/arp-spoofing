import ipaddress
from typing import Iterable, List, Tuple, Dict

import scapy.all as scapy
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed


def compute_local_ipv4_network_and_iface() -> Tuple[str, ipaddress.IPv4Network]:
    """Detect the default interface and derive its IPv4 network using Scapy's routing table.

    Returns a tuple of (interface_name, IPv4Network).
    Raises RuntimeError if an IPv4 network cannot be determined.
    """
    interface_name = scapy.conf.iface

    try:
        interface_ip = scapy.get_if_addr(interface_name)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "Unable to determine local interface IPv4 address. Ensure your active interface has an IPv4 address."
        ) from exc

    interface_addr = ipaddress.IPv4Address(interface_ip)

    def to_ipv4_str(value: object) -> str:
        if isinstance(value, int):
            return str(ipaddress.IPv4Address(value))
        return str(value)

    def build_network(net_value: object, mask_value: object) -> ipaddress.IPv4Network | None:
        try:
            # If mask provided as prefix length (0..32)
            if isinstance(mask_value, int) and 0 <= mask_value <= 32:
                return ipaddress.IPv4Network(f"{to_ipv4_str(net_value)}/{mask_value}", strict=False)
            # Normal case: netmask in dotted form or int
            return ipaddress.IPv4Network((to_ipv4_str(net_value), to_ipv4_str(mask_value)), strict=False)
        except Exception:
            return None

    candidates: List[ipaddress.IPv4Network] = []

    # Walk Scapy's routing table and collect all routes that contain our interface IP
    for route in getattr(scapy.conf.route, "routes", []):
        if len(route) < 2:
            continue
        net_raw = route[0]
        mask_raw = route[1] if len(route) > 1 else 0

        network = build_network(net_raw, mask_raw)
        if network is None:
            continue

        if interface_addr in network:
            candidates.append(network)

    if not candidates:
        raise RuntimeError("Unable to determine local IPv4 network from routing table.")

    # Prefer the most specific non-/32 network; if none, fall back to the most specific network
    non_host = [n for n in candidates if n.prefixlen < 32]
    best_network = max(non_host or candidates, key=lambda n: n.prefixlen)

    return interface_name, best_network


def detect_default_gateway_ipv4() -> str | None:
    """Best-effort detection of the default IPv4 gateway from Scapy's routing table."""
    def to_ipv4_str(value: object) -> str:
        if isinstance(value, int):
            return str(ipaddress.IPv4Address(value))
        return str(value)

    def build_network(net_value: object, mask_value: object) -> ipaddress.IPv4Network | None:
        try:
            if isinstance(mask_value, int) and 0 <= mask_value <= 32:
                return ipaddress.IPv4Network(f"{to_ipv4_str(net_value)}/{mask_value}", strict=False)
            return ipaddress.IPv4Network((to_ipv4_str(net_value), to_ipv4_str(mask_value)), strict=False)
        except Exception:
            return None

    candidates: List[Tuple[int, str]] = []  # (prefixlen, gateway_ip)

    for route in getattr(scapy.conf.route, "routes", []):
        if len(route) < 3:
            continue
        net_raw, mask_raw, gw_raw = route[:3]
        network = build_network(net_raw, mask_raw)
        if network is None:
            continue
        gw_ip = to_ipv4_str(gw_raw)
        # Skip empty gateways
        if gw_ip in ("0.0.0.0", "0"):
            continue
        candidates.append((network.prefixlen, gw_ip))

    if not candidates:
        return None

    # Prefer the true default (/0) if present; else choose the least specific route
    for prefixlen, gw_ip in candidates:
        if prefixlen == 0:
            return gw_ip
    return min(candidates, key=lambda t: t[0])[1]


def chunked(iterable: Iterable[str], chunk_size: int) -> Iterable[List[str]]:
    """Yield lists of size up to chunk_size from an iterable."""
    chunk: List[str] = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def perform_arp_scan(interface_name: str, network: ipaddress.IPv4Network, batch_size: int = 64, workers: int = 8) -> List[Dict[str, str]]:
    """Scan the given IPv4 network via ARP to discover active hosts.

    Returns a list of dicts: {"ip": ip_str, "mac": mac_str}.
    """
    # Generate all usable host IPs in the network
    host_ips: List[str] = [str(host_ip) for host_ip in network.hosts()]

    discovered: Dict[str, str] = {}
    batches: List[List[str]] = list(chunked(host_ips, batch_size))

    with tqdm(total=len(host_ips), desc="ARP scanning", unit="ip", leave=False) as progress:
        def srp_batch(ip_batch: List[str]) -> List[Tuple[str, str]]:
            packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_batch)
            answered, _ = scapy.srp(packet, iface=interface_name, timeout=1, verbose=False)
            return [(received.psrc, received.hwsrc) for _sent, received in answered]

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_size = {executor.submit(srp_batch, ip_batch): len(ip_batch) for ip_batch in batches}
            for future in as_completed(future_to_size):
                try:
                    results = future.result()
                    for ip, mac in results:
                        discovered[ip] = mac
                finally:
                    progress.update(future_to_size[future])

    # Convert to a stable, sorted list by IP address
    def ip_sort_key(ip_str: str) -> Tuple[int, int, int, int]:
        return tuple(int(part) for part in ip_str.split("."))  # type: ignore[return-value]

    results: List[Dict[str, str]] = [
        {"ip": ip, "mac": discovered[ip]} for ip in sorted(discovered.keys(), key=ip_sort_key)
    ]

    return results


def main() -> None:
    interface_name, network = compute_local_ipv4_network_and_iface()

    # Compute a non-negative host count for display
    if network.prefixlen <= 30:
        hosts_count = max(0, network.num_addresses - 2)
    else:
        hosts_count = network.num_addresses

    gateway_ip = detect_default_gateway_ipv4()

    print(f"Active interface: {interface_name}")
    print(f"Scanning network: {network} (hosts: {hosts_count})")
    if gateway_ip:
        print(f"Default gateway (router): {gateway_ip}")
    else:
        print("Default gateway (router): not found")
    print("Using 8 workers and batch size 64")

    try:
        results = perform_arp_scan(interface_name, network, batch_size=64, workers=8)
    except PermissionError as exc:
        print(
            "Error: insufficient permissions to send ARP frames. Run your IDE or Python as Administrator and ensure Npcap is installed on Windows."
        )
        raise exc

    if not results:
        print("No active hosts discovered.")
        return

    print(f"Discovered {len(results)} device(s):")
    for entry in results:
        print(f"  {entry['ip']:15}  {entry['mac']}")

    # Also print just the IP list (useful for quick copy/paste)
    ip_list = [entry["ip"] for entry in results]
    print("\nIP list:")
    print(ip_list)


if __name__ == "__main__":
    main() 