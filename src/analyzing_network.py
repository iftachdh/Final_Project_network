import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os
from collections import Counter


def extract_features(pcap_file):
    print(f"Processing file: {pcap_file}")
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    # Lists to store the size of each packet and the time between packets
    packet_sizes = []
    inter_arrival_times = []
    # List to store the Time to Live (TTL) values from IP packets.
    ttls = []
    # Counters for TCP, UDP, and TLS packets.
    tcp_count = 0
    udp_count = 0
    tls_count = 0
    # Variables to track the time of the first and last packet processed.
    last_time = None
    first_time = None
    # Counters for the most frequently used ports and IP addresses.
    top_ports = Counter()
    top_ips = Counter()
    # A flag to indicate whether the loop was exited due to exceeding the time limit.
    break_help = False

    # Iterate over each packet in the capture.
    for packet in cap:
        try:
            # Initialize the first_time variable with the timestamp of the first packet.
            if first_time is None:
                first_time = float(packet.sniff_timestamp)

            # Record the timestamp of the current packet.
            current_time = float(packet.sniff_timestamp)
            # Stop processing if more than 60 seconds have passed since the first packet.
            if current_time - first_time > 60:
                break_help = True
                break

            # Store the size of the current packet.
            packet_size = int(packet.length)
            packet_sizes.append(packet_size)

            # Calculate the time difference between the current and the last packet, then store it.
            if last_time is not None:
                inter_arrival_times.append(current_time - last_time)
            last_time = current_time

            # If the packet has an IP layer, store the TTL value and update IP counters.
            if 'IP' in packet:
                ttls.append(int(packet.ip.ttl))
                top_ips.update([packet.ip.src, packet.ip.dst])
            # If the packet is TCP, increment the TCP count and update the TCP ports counter.
            if 'TCP' in packet:
                tcp_count += 1
                top_ports.update([packet.tcp.srcport, packet.tcp.dstport])
            # If the packet is UDP, increment the UDP count.
            if 'UDP' in packet:
                udp_count += 1
                top_ports.update([packet.udp.srcport, packet.udp.dstport])
            # If the packet is TLS, increment the TLS count.
            if 'TLS' in packet:
                tls_count += 1
                top_ports.update([packet.tls.srcport, packet.tls.dstport])

        except AttributeError:
            # Continue to the next packet if an expected attribute is missing in the packet.
            continue

    cap.close()

    if break_help:
        print(f"The capture {pcap_file} is more than a minute long and we take the first minute.\n")
    else:
        print(f"The capture {pcap_file} is less than a minute long and lasted {last_time - first_time} seconds.\n")

    # Calculate the total number of packets and percentages of different protocols.
    total_packets = len(packet_sizes)
    tcp_percentage = (tcp_count / total_packets * 100) if total_packets else 0
    udp_percentage = (udp_count / total_packets * 100) if total_packets else 0
    other_percentage = (100 - tcp_percentage - udp_percentage)
    tls_percentage = (tls_count / total_packets * 100) if total_packets else 0

    # Return a dictionary containing all the calculated statistics and information.
    return {
        'file': pcap_file,
        'total_packets': total_packets,
        'flow_volume': sum(packet_sizes),
        'average_packet_size': np.mean(packet_sizes) if packet_sizes else 0,
        'average_inter_arrival_time': np.mean(inter_arrival_times) if inter_arrival_times else 0,
        'average_ttl': np.mean(ttls) if ttls else 0,
        'tcp_percentage': tcp_percentage,
        'udp_percentage': udp_percentage,
        'tls_percentage': tls_percentage,
        'other_percentage': other_percentage,
        'top_ports': top_ports.most_common(1),
        'top_ips': top_ips.most_common(3)[1:],  # Excluding local IP if it's the most common
    }

def plot_basic_graph(data_of_all_records, key, title, ylabel,output_folder):
    # Extract labels from the file names within the features list.
    labels = [os.path.splitext(os.path.basename(f['file']))[0] for f in data_of_all_records]
    # Extract the values to be plotted from the features list using the specified key.
    values = [f[key] for f in data_of_all_records]
    # Define a color gradient for the bars in the graph.
    colors = plt.cm.viridis(np.linspace(0, 1, len(labels)))

    # Setup the figure and axes for the plot with specified dimensions.
    plt.figure(figsize=(10, 5))
    # Create a bar chart with the data.
    plt.bar(labels, values, color=colors)
    # Set the title of the plot.
    plt.title(title)
    # Set the label for the y-axis.
    plt.ylabel(ylabel)
    # Rotate the x-axis labels for better readability.
    plt.xticks(rotation=45)
    # Adjust layout to prevent clipping of tick-labels.
    plt.tight_layout()
    plot_path = os.path.join(output_folder, f"{title.replace(' ', '_')}.png")
    plt.savefig(plot_path)
    plt.close()
    print(f"Graph saved as {plot_path}")


def plot_protocol_usage(data_of_all_records, labels, output_folder):
    protocols = ['tcp_percentage', 'udp_percentage', 'other_percentage']
    protocol_labels = ['TCP', 'UDP', 'Other']
    colors = plt.cm.Paired(np.linspace(0, 1, len(protocols)))

    fig, ax = plt.subplots(figsize=(10, 5))
    width = 0.1
    for i, protocol in enumerate(protocols):
        values = [f[protocol] for f in data_of_all_records]
        ax.bar(np.arange(len(labels)) + i * width, values, width, label=protocol_labels[i], color=colors[i])

    ax.set_xticks(np.arange(len(labels)) + width * (len(protocols) - 1) / 2)
    ax.set_xticklabels(labels)
    ax.set_title('Protocol Usage Comparison')
    ax.set_ylabel('Percentage')
    ax.legend(title="Protocols")

    plot_path = os.path.join(output_folder, "Protocol_Usage_Comparison.png")
    plt.savefig(plot_path)
    plt.close()
    print(f"Graph saved as {plot_path}")


def plot_top_ports(data_of_all_records, output_folder):
    plt.figure(figsize=(10, 5))
    for f in data_of_all_records:
        port, count = f['top_ports'][0]
        plt.bar(f['file'], count, label=f'{port}')

    plt.title('Most Used Ports')
    plt.ylabel('Count')
    plt.legend(title="Port Number")
    plt.xticks(rotation=45)
    plt.tight_layout()

    plot_path = os.path.join(output_folder, "Most_Used_Ports.png")
    plt.savefig(plot_path)
    plt.close()
    print(f"Graph saved as {plot_path}")


def plot_top_ips(data_of_all_records, output_folder):
    plt.figure(figsize=(12, 6))
    for f in data_of_all_records:
        ips = ', '.join([ip for ip, count in f['top_ips']])
        plt.bar(f['file'], [count for ip, count in f['top_ips']], label=ips)

    plt.title('Most Used IPs')
    plt.ylabel('Count')
    plt.legend(title="IP Addresses")
    plt.xticks(rotation=45)
    plt.tight_layout()

    plot_path = os.path.join(output_folder, "Most_Used_IPs.png")
    plt.savefig(plot_path)
    plt.close()
    print(f"Graph saved as {plot_path}")


def main():
    # Specify the directory containing the pcapng files and the directory for saving graphs.
    folder_path = '../records/records_comparing'

    output_folder = '../res/Graphs'

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Gather paths for all pcapng files in the specified directory.
    file_paths = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.pcapng')]

    # Process each pcap file to extract features.
    data_of_all_records = [extract_features(fp) for fp in file_paths]

    # Extract labels for plotting from the processed data.
    labels = [os.path.splitext(os.path.basename(f['file']))[0] for f in data_of_all_records]

    # Plot various graphs based on the extracted data.
    plot_basic_graph(data_of_all_records, 'total_packets', 'Total Packets Comparison', 'Number of Packets',output_folder)
    plot_basic_graph(data_of_all_records, 'flow_volume', 'Total Data Transferred', 'Bytes',output_folder)
    plot_basic_graph(data_of_all_records, 'average_packet_size', 'Average Packet Size', 'Bytes',output_folder)
    plot_basic_graph(data_of_all_records, 'average_inter_arrival_time', 'Average Inter-Arrival Time', 'Seconds',output_folder)
    plot_basic_graph(data_of_all_records, 'average_ttl', 'Average TTL', 'TTL Value',output_folder)
    plot_basic_graph(data_of_all_records, 'tls_percentage', 'TLS Percentage', 'Percentage',output_folder)

    # Plot more complex graphs
    plot_protocol_usage(data_of_all_records, labels,output_folder)
    plot_top_ports(data_of_all_records,output_folder)
    plot_top_ips(data_of_all_records,output_folder)


if __name__ == "__main__":
    main()
