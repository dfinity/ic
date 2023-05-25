import csv
import re
import sys

voltage_readings = sys.argv[1]

with open(voltage_readings, 'r') as in_file, open('voltage_readings.csv', 'w', newline='') as out_file:
    writer = csv.writer(out_file)
    writer.writerow(['Time', 'Instantaneous voltage reading'])

    lines = in_file.readlines()

    for line in lines:
        if line.startswith('    Instantaneous power reading:'):
            voltage_reading = re.search(r'\d+', line).group()

        elif line.startswith('    IPMI timestamp:'):
            time = re.search(r'\d{2}:\d{2}:\d{2}', line).group()

            writer.writerow([time, voltage_reading])
