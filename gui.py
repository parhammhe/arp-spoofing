#!/usr/bin/python

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket
import scapy.all as scapy
from spoofer import ArpSpoofer
from network_scan import compute_local_ipv4_network_and_iface, detect_default_gateway_ipv4, perform_arp_scan
from interface_list import list_npcap_devices

class ArpSpoofingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoofing Tool")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables
        self.target_ip = tk.StringVar()
        self.spoof_ip = tk.StringVar()
        self.interface = tk.StringVar()
        self.spoofing_thread = None
        self.spoofer = None
        self.is_spoofing = False
        
        # Create GUI elements
        self.create_widgets()
        
        # Populate initial values
        self.populate_initial_values()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="ARP Spoofing Tool", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Interface selection
        ttk.Label(main_frame, text="Network Interface:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.interface_combo = ttk.Combobox(main_frame, textvariable=self.interface, width=30)
        self.interface_combo.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(0, 10))
        self.interface_combo.bind("<<ComboboxSelected>>", self.on_interface_selected)
        
        refresh_btn = ttk.Button(main_frame, text="Refresh Interfaces", command=self.refresh_interfaces)
        refresh_btn.grid(row=1, column=2, pady=5)
        
        # Network scan section
        scan_frame = ttk.LabelFrame(main_frame, text="Network Scan", padding="10")
        scan_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        scan_frame.columnconfigure(0, weight=1)
        
        scan_btn = ttk.Button(scan_frame, text="Scan Network", command=self.scan_network)
        scan_btn.grid(row=0, column=0, pady=5)
        
        # Device list
        self.device_list = ttk.Treeview(scan_frame, columns=("IP", "MAC", "Name"), show="headings", height=8)
        self.device_list.heading("IP", text="IP Address")
        self.device_list.heading("MAC", text="MAC Address")
        self.device_list.heading("Name", text="Device Name")
        self.device_list.column("IP", width=120)
        self.device_list.column("MAC", width=150)
        self.device_list.column("Name", width=200)
        self.device_list.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        self.device_list.bind("<<TreeviewSelect>>", self.on_device_selected)
        
        # Scrollbar for device list
        scrollbar = ttk.Scrollbar(scan_frame, orient=tk.VERTICAL, command=self.device_list.yview)
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.device_list.configure(yscrollcommand=scrollbar.set)
        
        # Target selection
        ttk.Label(main_frame, text="Target IP:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.target_entry = ttk.Entry(main_frame, textvariable=self.target_ip, width=30)
        self.target_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(0, 10))
        
        # Gateway/Spoof IP
        ttk.Label(main_frame, text="Gateway IP:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.spoof_entry = ttk.Entry(main_frame, textvariable=self.spoof_ip, width=30)
        self.spoof_entry.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(0, 10))
        
        # Auto-detect gateway button
        auto_gateway_btn = ttk.Button(main_frame, text="Auto-Detect Gateway", command=self.auto_detect_gateway)
        auto_gateway_btn.grid(row=4, column=2, pady=5)
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=5, column=0, columnspan=3, pady=20)
        
        # Start/Stop buttons
        self.start_btn = ttk.Button(control_frame, text="Start Spoofing", command=self.start_spoofing)
        self.start_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Spoofing", command=self.stop_spoofing, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        # Status text area
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        self.status_text = scrolledtext.ScrolledText(status_frame, height=10, state=tk.DISABLED)
        self.status_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    def populate_initial_values(self):
        # Populate interfaces
        self.refresh_interfaces()
        
        # Try to auto-detect gateway
        self.auto_detect_gateway()
    
    def refresh_interfaces(self):
        try:
            interfaces = list_npcap_devices()
            if interfaces:
                self.interface_combo['values'] = interfaces
                # Set default interface if available
                if not self.interface.get() and interfaces:
                    self.interface.set(interfaces[0])
        except Exception as e:
            self.update_status(f"Error refreshing interfaces: {e}")
    
    def on_interface_selected(self, event=None):
        # This method is called when an interface is selected from the combobox
        pass
    
    def scan_network(self):
        if not self.interface.get():
            messagebox.showerror("Error", "Please select a network interface first.")
            return
            
        # Disable scan button during scan
        scan_btn = self.device_list.master.winfo_children()[0]  # Get the scan button
        scan_btn.config(state=tk.DISABLED)
        self.update_status("Scanning network...")
        self.root.update()
        
        try:
            # Get network information
            _, network = compute_local_ipv4_network_and_iface()
            
            # Perform ARP scan
            results = perform_arp_scan(self.interface.get(), network)
            
            # Clear existing items
            for item in self.device_list.get_children():
                self.device_list.delete(item)
            
            if not results:
                self.update_status("No active hosts discovered on the network.")
                messagebox.showinfo("Scan Complete", "No active hosts discovered on the network.")
                scan_btn.config(state=tk.NORMAL)
                return
            
            # Add devices to list with names
            for entry in results:
                ip = entry['ip']
                mac = entry['mac']
                name = self.get_device_name(ip, mac)
                self.device_list.insert("", tk.END, values=(ip, mac, name))
            
            self.update_status(f"Network scan complete. Discovered {len(results)} device(s).")
            messagebox.showinfo("Scan Complete", f"Discovered {len(results)} device(s) on the network.")
        except PermissionError as e:
            self.update_status("Permission error during network scan.")
            self.update_status("Please run this application as Administrator.")
            self.update_status("Also ensure Npcap is installed on Windows systems.")
            messagebox.showerror("Permission Error", 
                               "Insufficient permissions to send ARP frames.\n"
                               "Please run this application as Administrator and ensure Npcap is installed.")
        except Exception as e:
            self.update_status(f"Error during network scan: {e}")
            messagebox.showerror("Scan Error", f"Error during network scan: {e}")
        finally:
            scan_btn.config(state=tk.NORMAL)
    
    def get_device_name(self, ip, mac):
        # Try to get hostname via reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            pass
        except Exception:
            pass
        
        # Try to identify device by MAC address vendor
        vendor = self.get_vendor_from_mac(mac)
        if vendor:
            return vendor
        
        # If no name can be determined, return "Unknown Device"
        return "Unknown Device"
    
    def get_vendor_from_mac(self, mac):
        # This is a simplified vendor lookup
        # In a real implementation, you would use a more comprehensive OUI database
        vendor_map = {
            "00:50:56": "VMware",
            "00:0c:29": "VMware",
            "08:00:27": "Oracle VirtualBox",
            "00:1b:21": "Intel Corporate",
            "00:1c:bf": "Intel Corporate",
            "00:21:cc": "Intel Corporate",
            "00:24:d7": "Intel Corporate",
            "00:1e:67": "Intel Corporate",
            "00:1f:3b": "Intel Corporate",
            "00:22:fa": "Intel Corporate",
            "28:c6:3f": "Intel Corporate",
            "2c:41:38": "Intel Corporate",
            "30:3a:64": "Intel Corporate",
            "3c:fd:fe": "Intel Corporate",
            "40:a3:cc": "Intel Corporate",
            "44:1e:a1": "Intel Corporate",
            "44:85:00": "Intel Corporate",
            "48:45:20": "Intel Corporate",
            "4c:34:88": "Intel Corporate",
            "50:9a:4c": "Intel Corporate",
            "54:14:73": "Intel Corporate",
            "58:91:cf": "Intel Corporate",
            "5c:51:4f": "Intel Corporate",
            "5c:c9:d3": "Intel Corporate",
            "60:57:18": "Intel Corporate",
            "64:51:06": "Intel Corporate",
            "6c:88:14": "Intel Corporate",
            "74:e5:0b": "Intel Corporate",
            "78:4b:87": "Intel Corporate",
            "7c:b0:c2": "Intel Corporate",
            "80:9b:20": "Intel Corporate",
            "84:3a:4b": "Intel Corporate",
            "88:53:2e": "Intel Corporate",
            "8c:70:5a": "Intel Corporate",
            "90:2e:1c": "Intel Corporate",
            "94:c6:91": "Intel Corporate",
            "98:4b:e1": "Intel Corporate",
            "9c:eb:e8": "Intel Corporate",
            "a0:36:9f": "Intel Corporate",
            "a0:88:69": "Intel Corporate",
            "a0:d3:c1": "Intel Corporate",
            "b4:b6:76": "Intel Corporate",
            "b8:bf:83": "Intel Corporate",
            "c8:34:8e": "Intel Corporate",
            "d4:ae:52": "Intel Corporate",
            "d8:cb:8a": "Intel Corporate",
            "dc:53:60": "Intel Corporate",
            "e8:2a:ea": "Intel Corporate",
            "f4:06:69": "Intel Corporate",
            "00:60:97": "3Com",
            "00:05:69": "VMware",
            "00:0c:29": "VMware",
            "00:1c:14": "VMware",
            "00:1a:6b": "Universal Global Scientific Industrial Co., Ltd.",
            "00:1b:63": "Apple",
            "00:1c:b3": "Apple",
            "00:1d:4f": "Apple",
            "00:1e:c2": "Apple",
            "00:1f:5b": "Apple",
            "00:1f:f3": "Apple",
            "00:21:e9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6c": "Apple",
            "00:25:00": "Apple",
            "00:26:4a": "Apple",
            "00:26:b0": "Apple",
            "00:26:bb": "Apple",
            "02:26:bb": "Apple",
        }
        
        # Check if MAC address prefix matches any known vendor
        mac_prefix = mac[:8].lower()
        return vendor_map.get(mac_prefix, "Unknown Vendor")
    
    def auto_detect_gateway(self):
        try:
            gateway_ip = detect_default_gateway_ipv4()
            if gateway_ip:
                self.spoof_ip.set(gateway_ip)
                self.update_status(f"Auto-detected gateway: {gateway_ip}")
            else:
                self.update_status("Could not auto-detect gateway")
        except Exception as e:
            self.update_status(f"Error detecting gateway: {e}")
    
    def on_device_selected(self, event=None):
        selection = self.device_list.selection()
        if selection:
            item = self.device_list.item(selection[0])
            values = item['values']
            if values:
                self.target_ip.set(values[0])  # Set target IP from selected device
                self.update_status(f"Selected target: {values[0]} ({values[2]})")
    
    def start_spoofing(self):
        # Validate inputs
        if not self.target_ip.get():
            messagebox.showerror("Error", "Please enter or select a target IP.")
            return
            
        if not self.spoof_ip.get():
            messagebox.showerror("Error", "Please enter or auto-detect a gateway IP.")
            return
            
        if not self.interface.get():
            messagebox.showerror("Error", "Please select a network interface.")
            return
        
        # Disable start button and enable stop button
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start spoofing in a separate thread
        self.is_spoofing = True
        self.spoofing_thread = threading.Thread(target=self.run_spoofing)
        self.spoofing_thread.daemon = True
        self.spoofing_thread.start()
    
    def stop_spoofing(self):
        self.is_spoofing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.update_status("Spoofing stopped.")
    
    def run_spoofing(self):
        try:
            self.update_status(f"Starting ARP spoofing: {self.target_ip.get()} -> {self.spoof_ip.get()}")
            self.spoofer = ArpSpoofer(self.target_ip.get(), self.spoof_ip.get(), self.interface.get())
            self.spoofer.run()
        except Exception as e:
            self.update_status(f"Error during spoofing: {e}")
            messagebox.showerror("Spoofing Error", f"Error during spoofing: {e}")
        finally:
            self.is_spoofing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
    
    def update_status(self, message):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.config(state=tk.DISABLED)
        self.status_text.see(tk.END)  # Scroll to the end
        self.root.update_idletasks()

def main():
    root = tk.Tk()
    app = ArpSpoofingGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
