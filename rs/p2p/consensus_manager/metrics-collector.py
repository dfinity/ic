import urllib.request
import time
import os
import sys
from datetime import datetime

# Create a new directory for this run
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
os.makedirs(f"data_{timestamp}", exist_ok=True)

# Take instance IPs from command line arguments
instances = sys.argv[1:]

# RPS 
peer_data = [b"1", b"3", b"5", b"7", b"10", b"15"]  # Add more values as needed

def send_to_peers(data):
    for instance in instances:
        try:
            # Make a request to each peer with the corresponding data
            with urllib.request.urlopen(f"http://{instance}:9090/setrate", data=data) as response:
                print(f"Sent data to {instance}: {value.decode('utf-8')}")
        except Exception as e:
            print(f"Error sending data to {instance}: {e}")

def scrape_metrics():
    for instance in instances:
        try:
            with urllib.request.urlopen(f"http://{instance}:9090/metrics") as response:
                data = response.read().decode('utf-8').split(',')
                print(data)
                current_time = datetime.now().isoformat()
                with open(f"data_{timestamp}/{instance}_metrics.csv", "a") as file:
                    file.write(f"{current_time}, {','.join(data)}\n")
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
        scrape_metrics()
        last_scrape_time = current_time

    # Send the next value to peers every 3 minutes
    if current_time - last_update_time >= 180:
        print("UPDATING RPS TO ", peer_data[current_peer_data_index])
        send_to_peers([peer_data[current_peer_data_index]])
        
        # Update the index to the next value in the list
        current_peer_data_index = (current_peer_data_index + 1) % len(peer_data)
        
        last_update_time = current_time

    # Sleep for a short interval before checking again
    time.sleep(1)
