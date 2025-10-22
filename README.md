# ARP Spoofing Tool

#### Description

This tool demonstrates how to perform an ARP spoofing attack on a Local Area Network (LAN) using Python and the `Scapy` library. The ARP spoofing attack redirects network traffic from the victim to the attacker by sending forged ARP responses, allowing for a Man-in-the-Middle (MITM) attack. The attacker impersonates the router or gateway to intercept the victim's traffic and forward it through the attacker's machine.

With this script, you can simulate a MITM attack, allowing the attacker to intercept non-encrypted traffic from the target device.

#### How ARP Spoofing Works

1. The attacker sends fake ARP responses to both the victim and the router, associating the attacker's MAC address with the router's IP address.
2. This causes the victim to send its traffic to the attacker, believing it to be the router.
3. The attacker forwards the traffic to the actual router, intercepting and potentially manipulating the data.

#### Scenario

For this example:
- **Victim**: Windows 10 machine (`192.168.1.130`)
- **Attacker**: Kali Linux machine (`192.168.1.111`)
- **Router**: Default gateway (`192.168.1.1`)

#### Steps:

1. The victim sends an ARP request to find the MAC address of the router.
2. The attacker sends a fake ARP response, claiming that the attacker's MAC address is associated with the router's IP.
3. The victim updates its ARP table with the attacker's MAC address, redirecting traffic to the attacker instead of the router.

#### Forwarding Traffic

To prevent a Denial of Service (DoS) situation where the victim loses internet access, you need to enable IP forwarding on the attacker's machine. This allows the attacker to pass traffic between the victim and the router, maintaining the internet connection while still intercepting traffic.

To enable IP forwarding on Linux:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

#### Usage

Make sure to specify the correct IP addresses and the network interface.

#### Command Line Version:
```bash
sudo ./spoofer.py -t <target_ip> -s <spoofed_ip> -i <interface>
```

#### Example (Command Line):
```bash
sudo ./spoofer.py -t 192.168.1.130 -s 192.168.1.1 -i eth0
```

- `-t` or `--target`: The victim's IP address.
- `-s` or `--spoof`: The IP address you want to spoof (e.g., the router).
- `-i` or `--interface`: The network interface to use (e.g., `eth0`, `wlan0`).

#### GUI Version:
```bash
python main.py --gui
```

The GUI version provides a user-friendly interface with the following features:
- Automatic network interface detection
- Network scanning to discover active devices
- Device name resolution (hostname and vendor identification)
- Visual selection of target and gateway IPs
- Start/Stop controls for the spoofing process
- Status display area

#### Automatic Discovery Options (Command Line):

The command-line version also supports automatic discovery:
- `-a` or `--auto`: Enable automatic mode (auto-detect interface, scan for targets, and detect gateway)
- `--auto-interface`: Automatically detect network interface
- `--auto-target`: Automatically scan for and select target
- `--auto-gateway`: Automatically detect gateway IP
- `--scan-only`: Only scan the network and list discovered devices, then exit

#### Examples (Automatic Discovery):

Fully automatic mode:
```bash
sudo ./spoofer.py --auto
```

Scan network only:
```bash
sudo ./spoofer.py --scan-only
```

Automatic interface detection:
```bash
sudo ./spoofer.py --auto-interface -t 192.168.1.100 -s 192.168.1.1
```

Automatic target selection:
```bash
sudo ./spoofer.py --auto-target -s 192.168.1.1 -i eth0
```

Automatic gateway detection:
```bash
sudo ./spoofer.py --auto-gateway -t 192.168.1.100 -i eth0
```

When the program is interrupted (e.g., by pressing `CTRL+C`), the script will automatically restore the ARP tables of the victim and the router to their original state.

#### Troubleshooting Device Detection Issues

If the tool cannot detect devices on your network, please refer to our detailed [TROUBLESHOOTING.md](TROUBLESHOOTING.md) guide for comprehensive solutions to common issues.

#### Setup

1. (Optional) Set up a virtual environment:
   ```bash
   virtualenv -p python3 <env_name>
   source <env_name>/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

#### Dependencies

- **Scapy**: A powerful Python library for packet crafting and network analysis.
- **argparse**: For command-line argument parsing.
- **colorama**: For adding colored output to terminal messages.
- **tqdm**: For progress bars during network scanning.
- **tkinter**: For the graphical user interface (usually included with Python).

#### Credits

- **Original Author**: [David E Lares](https://twitter.com/davidlares3)
- **Updated by**: Halil İbrahim ([denizhalil.com](https://denizhalil.com))

#### License

- [MIT License](https://opensource.org/licenses/MIT)
