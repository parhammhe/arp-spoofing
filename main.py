def main():
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        try:
            import tkinter as tk
            from gui import ArpSpoofingGUI
            root = tk.Tk()
            app = ArpSpoofingGUI(root)
            root.mainloop()
        except ImportError as e:
            print("GUI dependencies not available:", e)
            print("Please ensure tkinter is installed.")
        except Exception as e:
            print("Error starting GUI:", e)
    else:
        print("ARP Spoofing Tool")
        print("=================")
        print("This tool demonstrates ARP spoofing attacks on LAN networks.")
        print("")
        print("For GUI version, run:")
        print("  python main.py --gui")
        print("")
        print("For command-line version, run:")
        print("  sudo python spoofer.py -t <target_ip> -s <spoof_ip> -i <interface>")
        print("")
        print("For automatic discovery, run:")
        print("  sudo python spoofer.py --auto")
        print("")
        print("To scan network without spoofing:")
        print("  sudo python spoofer.py --scan-only")
        print("")
        print("If devices are not detected, please refer to TROUBLESHOOTING.md")


if __name__ == "__main__":
    main()
