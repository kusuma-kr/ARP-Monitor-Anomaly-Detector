from flask import Flask, render_template, jsonify
import sqlite3

app = Flask(__name__)

DATABASE = "arp_monitor.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():
    return render_template("index.html")


# --------------------------------------------------
# ARP HISTORY
# --------------------------------------------------

@app.route("/api/history")
def get_history():

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT *
        FROM arp_history
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


# --------------------------------------------------
# ANOMALIES
# --------------------------------------------------

@app.route("/api/anomalies")
def get_anomalies():

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT *
        FROM anomaly_events
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


# --------------------------------------------------
# STATISTICS
# --------------------------------------------------

@app.route("/api/statistics")
def get_statistics():

    conn = get_db_connection()

    total_events = conn.execute("""
        SELECT COUNT(*) AS count
        FROM arp_history
    """).fetchone()["count"]

    unique_ips = conn.execute("""
        SELECT COUNT(DISTINCT ip_address) AS count
        FROM arp_history
    """).fetchone()["count"]

    unique_macs = conn.execute("""
        SELECT COUNT(DISTINCT mac_address) AS count
        FROM arp_history
    """).fetchone()["count"]

    total_anomalies = conn.execute("""
        SELECT COUNT(*) AS count
        FROM anomaly_events
    """).fetchone()["count"]

    normal_events = total_events - total_anomalies

    conn.close()

    return jsonify({
        "total_events": total_events,
        "unique_ips": unique_ips,
        "unique_macs": unique_macs,
        "anomalies": total_anomalies,
        "normal_events": normal_events
    })


# --------------------------------------------------
# CHART DATA
# --------------------------------------------------

@app.route("/api/chart-data")
def get_chart_data():

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT
            strftime('%H:%M', timestamp) AS time,
            COUNT(*) AS count
        FROM arp_history
        GROUP BY strftime('%H:%M', timestamp)
        ORDER BY MIN(timestamp)
        LIMIT 30
    """).fetchall()

    conn.close()

    return jsonify({
        "labels": [row["time"] for row in rows],
        "values": [row["count"] for row in rows]
    })


# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------

if __name__ == "__main__":

    print("\n======================================")
    print("      ARP MONITOR DASHBOARD")
    print("======================================")
    print("Dashboard: http://127.0.0.1:5000")
    print("======================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )