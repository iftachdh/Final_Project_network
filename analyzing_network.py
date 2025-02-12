import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os
from collections import Counter


def extract_features(pcap_file):
    print(f"Processing file: {pcap_file}")  # Print the current file being processed
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    packet_sizes = []
    inter_arrival_times = []
    ttls = []
    tcp_count = 0
    udp_count = 0
    tls_count = 0
    other_protocol_count = 0  # count non-TCP/UDP/TLS packets
    last_time = None
    top_ports = Counter()
    top_ips = Counter()

    for packet in cap:
        try:
            packet_size = int(packet.length)
            packet_sizes.append(packet_size)

            current_time = float(packet.sniff_timestamp)
            if last_time is not None:
                inter_arrival_times.append(current_time - last_time)
            last_time = current_time

            if 'IP' in packet:
                ttls.append(int(packet.ip.ttl))
                top_ips.update([packet.ip.src, packet.ip.dst])
            if 'TCP' in packet:
                tcp_count += 1
                top_ports.update([packet.tcp.srcport, packet.tcp.dstport])
            if 'UDP' in packet:
                udp_count += 1
            if 'TLS' in packet:
                tls_count += 1

        except AttributeError:
            continue

    cap.close()
    total_packets = len(packet_sizes)
    tcp_percentage = (tcp_count / total_packets * 100) if total_packets else 0
    udp_percentage = (udp_count / total_packets * 100) if total_packets else 0
    other_percentage = (100 - tcp_percentage - udp_percentage)
    tls_percentage = (tls_count / total_packets * 100) if total_packets else 0


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
        'top_ips': top_ips.most_common(3)[1:],  # excluding local IP if it's the most common
    }


def plot_basic_graph(features_list, key, title, ylabel):
    labels = [os.path.splitext(os.path.basename(f['file']))[0] for f in features_list]
    values = [f[key] for f in features_list]
    colors = plt.cm.viridis(np.linspace(0, 1, len(labels)))

    plt.figure(figsize=(10, 5))
    plt.bar(labels, values, color=colors)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


def plot_protocol_usage(features_list, labels):
    protocols = ['tcp_percentage', 'udp_percentage','other_percentage']
    protocol_labels = ['TCP', 'UDP', 'Other']
    colors = plt.cm.Paired(np.linspace(0, 1, len(protocols)))

    fig, ax = plt.subplots(figsize=(10, 5))
    width = 0.1
    for i, protocol in enumerate(protocols):
        values = [f[protocol] for f in features_list]
        ax.bar(np.arange(len(labels)) + i * width, values, width, label=protocol_labels[i], color=colors[i])

    ax.set_xticks(np.arange(len(labels)) + width * (len(protocols)-1) / 2)
    ax.set_xticklabels(labels)
    ax.set_title('Protocol Usage Comparison')
    ax.set_ylabel('Percentage')
    ax.legend(title="Protocols")
    plt.show()



def plot_top_ports(features_list):
    plt.figure(figsize=(10, 5))
    for f in features_list:
        port, count = f['top_ports'][0]
        plt.bar(f['file'], count, label=f'{port}')

    plt.title('Most Used Ports')
    plt.ylabel('Count')
    plt.legend(title="Port Number")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


def plot_top_ips(features_list):
    plt.figure(figsize=(12, 6))
    for f in features_list:
        ips = ', '.join([ip for ip, count in f['top_ips']])
        plt.bar(f['file'], [count for ip, count in f['top_ips']], label=ips)

    plt.title('Most Used IPs')
    plt.ylabel('Count')
    plt.legend(title="IP Addresses")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


def main():
    folder_path = 'records_part_c'
    file_paths = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.pcapng')]
    features_list = [extract_features(fp) for fp in file_paths]
    labels = [os.path.splitext(os.path.basename(f['file']))[0] for f in features_list]  # Create labels from features_list

    # Plot different graphs
    plot_basic_graph(features_list, 'total_packets', 'Total Packets Comparison', 'Number of Packets')
    plot_basic_graph(features_list, 'flow_volume', 'Total Data Transferred', 'Bytes')
    plot_basic_graph(features_list, 'average_packet_size', 'Average Packet Size', 'Bytes')
    plot_basic_graph(features_list, 'average_inter_arrival_time', 'Average Inter-Arrival Time', 'Seconds')
    plot_basic_graph(features_list, 'average_ttl', 'Average TTL', 'TTL Value')
    plot_basic_graph(features_list, 'tls_percentage', 'TLS Percentage', 'TLS Percentage')

    # Complex graphs
    plot_protocol_usage(features_list, labels)  # Pass labels to the function
    plot_top_ports(features_list)
    plot_top_ips(features_list)

if __name__ == "__main__":
    main()

