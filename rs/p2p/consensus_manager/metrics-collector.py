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

def scrape_metrics():
    for instance in instances:
        try:
            with urllib.request.urlopen(f"http://{instance}:9090") as response:
                data = response.read().decode('utf-8').split(',')
                current_time = datetime.now().isoformat()
                with open(f"data_{timestamp}/{instance}_metrics.csv", "a") as file:
                    file.write(f"{current_time},{','.join(data)}\n")
        except Exception as e:
            print(f"Error scraping {instance}: {e}")

while True:
    scrape_metrics()
    time.sleep(10)

