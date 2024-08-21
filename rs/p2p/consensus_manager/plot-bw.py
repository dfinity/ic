import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import glob

def calculate_rate(df):
    df['Time'] = pd.to_datetime(df['Time'])
    df['Mbits'] = df['Bytes'] * 8 / 1e6  # Convert bytes to Mbits
    df['Rate_Mbit_s'] = df['Mbits'].diff() / df['Time'].diff().dt.total_seconds()
    df['libp2p_tx_Mbits'] = df['libp2p_tx'] * 8 / 1e6  # Convert bytes to Mbits
    df['rate_libp2p_tx_mbits_s'] = df['libp2p_tx_Mbits'].diff() / df['Time'].diff().dt.total_seconds()
    df['libp2p_rx_Mbits'] = df['libp2p_rx'] * 8 / 1e6  # Convert bytes to Mbits
    df['rate_libp2p_rx_mbits_s'] = df['libp2p_rx_Mbits'].diff() / df['Time'].diff().dt.total_seconds()
    df['Artifacts'] = df['Artifacts']
    return df

def plot_data(folder):
    files = glob.glob(os.path.join(folder, "*_metrics.csv"))

    plt.figure(figsize=(12, 8))

    for file in files:
        # df = pd.read_csv(file, names=['Time', 'Bytes', 'Artifacts', 'Sent', 'udp_tx', 'udp_rx', 'libp2p_tx', 'libp2p_rx'])
        df = pd.read_csv(file, names=['Time', 'Bytes', 'Artifacts', 'Sent', 'udp_tx', 'udp_rx', 'libp2p_tx', 'libp2p_rx', 'latency'])
        df = calculate_rate(df)
        plt.plot(df['Time'], df['Rate_Mbit_s'], marker='o', label=os.path.basename(file))
        # plt.plot(df['Time'], df['Artifacts'], marker='o', label=os.path.basename(file))
        # plt.plot(df['Time'], df['rate_libp2p_rx_mbits_s'], marker='o', label=os.path.basename(file))
        # plt.plot(df['Time'], df['rate_libp2p_tx_mbits_s'], marker='o', label=os.path.basename(file))
        # plt.plot(df['Time'], df['Libp2p RX'], marker='o', label=os.path.basename(file))

    plt.title('Data Rate over Time for Each Machine')
    plt.xlabel('Time')
    plt.ylabel('Rate (Mbit/s)')
    plt.legend()
    plt.grid(True)

    # Save the plot in the current directory
    plt.savefig('network_data_rate_plot.png')
    print("Plot saved as 'network_data_rate_plot.png'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 plot-bw.py <folder>")
        sys.exit(1)

    plot_data(sys.argv[1])
