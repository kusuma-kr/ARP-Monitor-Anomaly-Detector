from scapy.all import sniff, ARP, conf
from detector import process_arp_event


def process_packet(packet):

    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    if arp.op not in [1, 2]:
        return

    ip = arp.psrc
    mac = arp.hwsrc

    operation = "request" if arp.op == 1 else "reply"

    print(
        f"[ARP] IP: {ip} | "
        f"MAC: {mac} | "
        f"Operation: {operation}"
    )

    anomaly = process_arp_event(
        ip_address=ip,
        mac_address=mac,
        operation=operation,
        interface="live"
    )

    if anomaly:

        print("\n" + "=" * 50)
        print("⚠️ POTENTIAL ARP ANOMALY DETECTED")
        print("=" * 50)

        print("IP:", anomaly["ip_address"])
        print("Old MAC:", anomaly["old_mac"])
        print("New MAC:", anomaly["new_mac"])
        print("Severity:", anomaly["severity"])
        print("Description:", anomaly["description"])

        print("=" * 50)


def start_monitoring(interface):

    print("\n" + "=" * 50)
    print("       ARP MONITOR & ANOMALY DETECTOR")
    print("=" * 50)

    print("Selected interface:")
    print(interface)

    print("\nMonitoring ARP traffic...")
    print("Press CTRL+C to stop.\n")

    sniff(
        iface=interface,
        filter="arp",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":

    print("\nAvailable Scapy interfaces:\n")

    interfaces = list(conf.ifaces.values())

    for number, interface in enumerate(interfaces, start=1):

        print(
            f"{number}. "
            f"{interface.name}"
        )

        print(
            f"   IP: {interface.ip}"
        )

        print(
            f"   MAC: {interface.mac}"
        )

        print()

    try:

        choice = int(
            input("Enter interface number: ")
        )

        selected = interfaces[choice - 1]

        print("\nSelected:")
        print(selected.name)

        start_monitoring(selected)

    except ValueError:

        print("Please enter a valid number.")

    except IndexError:

        print("Invalid interface number.")

    except KeyboardInterrupt:

        print("\nMonitoring stopped.")