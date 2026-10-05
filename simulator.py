from detector import process_arp_event


def normal_scenario():

    print("\n=== NORMAL ARP SCENARIO ===")

    events = [
        ("192.168.1.10", "AA:BB:CC:11:22:33"),
        ("192.168.1.20", "DD:EE:FF:44:55:66"),
        ("192.168.1.10", "AA:BB:CC:11:22:33"),
        ("192.168.1.20", "DD:EE:FF:44:55:66")
    ]

    for ip, mac in events:

        anomaly = process_arp_event(
            ip,
            mac,
            "reply",
            "simulation"
        )

        if anomaly:
            print("Anomaly:", anomaly)
        else:
            print(f"Normal: {ip} -> {mac}")


def abnormal_scenario():

    print("\n=== ABNORMAL ARP SCENARIO ===")

    # Original mapping
    process_arp_event(
        "192.168.1.50",
        "AA:BB:CC:11:22:33",
        "reply",
        "simulation"
    )

    print(
        "Original mapping: "
        "192.168.1.50 -> AA:BB:CC:11:22:33"
    )

    # Changed MAC
    anomaly = process_arp_event(
        "192.168.1.50",
        "11:22:33:44:55:66",
        "reply",
        "simulation"
    )

    if anomaly:

        print("\n⚠️ POTENTIAL ARP ANOMALY")

        print("IP:", anomaly["ip_address"])
        print("Old MAC:", anomaly["old_mac"])
        print("New MAC:", anomaly["new_mac"])
        print("Severity:", anomaly["severity"])
        print("Description:", anomaly["description"])


if __name__ == "__main__":

    print("ARP Monitor Simulation")

    print("\n1. Normal Scenario")
    print("2. Abnormal Scenario")

    choice = input("\nSelect option: ")

    if choice == "1":
        normal_scenario()

    elif choice == "2":
        abnormal_scenario()

    else:
        print("Invalid choice.")