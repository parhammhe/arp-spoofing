import sys
from typing import List, Dict, Any

from tqdm import tqdm

try:
    import scapy.all as scapy
except Exception as exc:  # noqa: BLE001
    raise RuntimeError("Scapy is required to list interfaces. Please install dependencies with 'uv sync'.") from exc


def list_npcap_devices() -> List[str]:
    try:
        return scapy.get_if_list()
    except Exception:
        return []


def list_windows_interfaces() -> List[Dict[str, Any]]:
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:
        return []

    try:
        return get_windows_if_list()  # type: ignore[no-any-return]
    except Exception:
        return []


def print_interfaces() -> None:
    active_iface = getattr(scapy.conf, "iface", None)

    npcap_devices = list_npcap_devices()
    print("Npcap device names (use these for -i):")
    if not npcap_devices:
        print("  No Npcap devices found.")
    else:
        for name in npcap_devices:
            marker = "  (active)" if active_iface and name == active_iface else ""
            print(f"  {name}{marker}")

        # Copy/paste-ready block
        print("\nCopy/paste-ready interface names (use with -i):")
        for name in npcap_devices:
            print(f'"{name}"')

    if sys.platform == "win32":
        win_ifaces = list_windows_interfaces()
        if win_ifaces:
            print("\nWindows interfaces (details):")
            for iface in tqdm(win_ifaces, desc="Collecting", unit="iface", leave=False):
                desc = str(iface.get("description", ""))
                name = str(iface.get("name", ""))
                guid = str(iface.get("guid", ""))
                mac = str(iface.get("mac", "N/A"))
                ipv4 = str(iface.get("ip", iface.get("ipv4", "N/A")))
                netmask = str(iface.get("netmask", iface.get("ipv4_mask", "N/A")))
                guid_trimmed = guid.strip("{}") if guid else ""
                npf = f"\\Device\\NPF_{guid_trimmed}" if guid_trimmed else "N/A"
                active_mark = " (active)" if active_iface and npf == active_iface else ""
                print(
                    f"\nDesc: {desc}\nName: {name}\nGUID: {guid}\nMAC: {mac}\nIPv4: {ipv4}\nNetmask: {netmask}\nNpcap: {npf}{active_mark}"
                )
        else:
            print("\nNo detailed Windows interface information available.")

    if active_iface:
        print(f"\nActive interface detected by Scapy: {active_iface}")


def main() -> None:
    print_interfaces()


if __name__ == "__main__":
    main() 