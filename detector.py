from datetime import datetime
from database import get_connection


def process_arp_event(ip_address, mac_address, operation="reply", interface="unknown"):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    connection = get_connection()
    cursor = connection.cursor()

    # Store every observed ARP event
    cursor.execute("""
        INSERT INTO arp_history
        (timestamp, ip_address, mac_address, operation, interface)
        VALUES (?, ?, ?, ?, ?)
    """, (
        timestamp,
        ip_address,
        mac_address,
        operation,
        interface
    ))

    # Check previous IP-MAC mapping
    cursor.execute("""
        SELECT mac_address
        FROM ip_mac_mapping
        WHERE ip_address = ?
    """, (ip_address,))

    previous = cursor.fetchone()

    anomaly = None

    if previous:

        old_mac = previous["mac_address"]

        if old_mac.lower() != mac_address.lower():

            anomaly = {
                "event_type": "IP-MAC Change",
                "ip_address": ip_address,
                "old_mac": old_mac,
                "new_mac": mac_address,
                "severity": "HIGH",
                "description":
                    f"IP {ip_address} changed from "
                    f"{old_mac} to {mac_address}"
            }

            cursor.execute("""
                INSERT INTO anomaly_events
                (timestamp, event_type, ip_address,
                 old_mac, new_mac, severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                anomaly["event_type"],
                anomaly["ip_address"],
                anomaly["old_mac"],
                anomaly["new_mac"],
                anomaly["severity"],
                anomaly["description"]
            ))

            # Update mapping
            cursor.execute("""
                UPDATE ip_mac_mapping
                SET mac_address = ?,
                    last_seen = ?,
                    observation_count = observation_count + 1
                WHERE ip_address = ?
            """, (
                mac_address,
                timestamp,
                ip_address
            ))

        else:

            cursor.execute("""
                UPDATE ip_mac_mapping
                SET last_seen = ?,
                    observation_count = observation_count + 1
                WHERE ip_address = ?
            """, (
                timestamp,
                ip_address
            ))

    else:

        cursor.execute("""
            INSERT INTO ip_mac_mapping
            (ip_address, mac_address, first_seen,
             last_seen, observation_count)
            VALUES (?, ?, ?, ?, 1)
        """, (
            ip_address,
            mac_address,
            timestamp,
            timestamp
        ))

    connection.commit()
    connection.close()

    return anomaly