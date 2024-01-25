import urllib.request
import time
import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Create a new directory for this run
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
os.makedirs(f"data_{timestamp}", exist_ok=True)

# Take instance IPs from command line arguments
instances = sys.argv[1:]

# RPS 
# 11 node
peer_data = [b"1", b"3", b"5", b"7", b"10", b"15", b"30"]  # Add more values as needed
# 31 node 500Kb msg
# peer_data = [b"1", b"2", b"3", b"5", b"7", b"10"]  # Add more values as needed
# 11  node 25kb msg
# peer_data = [b"10", b"20", b"50", b"100", b"200"]  # Add more values as needed

def send_to_peers(data):
    for instance in instances:
        try:
            # Make a request to each peer with the corresponding data
            with urllib.request.urlopen(f"http://{instance}:9090/setrate", data=data) as response:
                print(f"Sent data to {instance}: {value.decode('utf-8')}")
        except Exception as e:
            print(f"Error sending data to {instance}: {e}")

def scrape_metrics(instance):
    try:
        with urllib.request.urlopen(f"http://{instance}:9090/metrics") as response:
            data = response.read().decode('utf-8')
            udp_tx = ""
            udp_rx = ""
            libp2p_tx = ""
            libp2p_rx = ""
            sent_artifacts = ""
            received_artifacts = ""
            received_artifacts_bytes = ""
            message_latency = ""
            for line in data.split("\n"):
                if "#" in line:
                    continue
                elif "quic_transport_quinn_sent_bytes" in line:
                    udp_tx = line.split(" ")[-1]
                elif "quic_transport_quinn_received_bytes" in line: 
                    udp_rx = line.split(" ")[-1]
                elif "libp2p_bandwidth_bytes_total" in line and "Inbound" in line: 
                    libp2p_rx = line.split(" ")[-1]
                elif "libp2p_bandwidth_bytes_total" in line and "Outbound" in line: 
                    libp2p_tx = line.split(" ")[-1]
                elif "load_generator_sent_artifacts" in line: 
                    sent_artifacts = line.split(" ")[-1]
                elif "load_generator_received_artifacts_bytes" in line: 
                    received_artifacts_bytes = line.split(" ")[-1]
                elif "load_generator_received_artifacts" in line: 
                    received_artifacts = line.split(" ")[-1]
                elif "load_generator_message_latency_sum" in line: 
                    message_latency = line.split(" ")[-1]
            data = []
            data.append(received_artifacts_bytes if received_artifacts_bytes else "-1")
            data.append(received_artifacts if received_artifacts else "-1")
            data.append(sent_artifacts if sent_artifacts else "-1")
            data.append(udp_tx if udp_tx else "-1")
            data.append(udp_rx if udp_rx else "-1")
            data.append(libp2p_tx if libp2p_tx else "-1")
            data.append(libp2p_rx if libp2p_rx else "-1")
            data.append(message_latency if message_latency else "-1")

            current_time = datetime.now().isoformat()
            with open(f"data_{timestamp}/{instance}_metrics.csv", "a") as file:
                file.write(f"{current_time},{','.join(data)}\n")
    except Exception as e:
        print(f"Error scraping {instance}: {e}")


# Initial timestamp for the first scrape
last_scrape_time = time.time()
last_update_time = time.time()



# Index to keep track of the current value to send to peers
current_peer_data_index = 0

while True:
    # Check if 8 seconds have passed since the last scrape
    current_time = time.time()
    if current_time - last_scrape_time >= 8:
        with ThreadPoolExecutor(max_workers=len(instances)) as executor:
            executor.map(scrape_metrics, instances)
        last_scrape_time = current_time

    # Send the next value to peers every 3 minutes
    if current_time - last_update_time >= 180:
        print("UPDATING RPS TO ", peer_data[current_peer_data_index])
        send_to_peers([peer_data[current_peer_data_index]])
        
        # Update the index to the next value in the list
        current_peer_data_index = (current_peer_data_index + 1) % len(peer_data)
        
        last_update_time = current_time

    # # Sleep for a short interval before checking again
    time.sleep(1)
