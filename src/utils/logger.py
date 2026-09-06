import csv
from datetime import datetime


LOG_FILE = "logs/traffic_log.csv"


def log_traffic(packet):

    with open(LOG_FILE, "a", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            datetime.now(),
            packet["src_ip"],
            packet["dst_ip"],
            packet["proto"],
            packet["packet_size"]
        ])