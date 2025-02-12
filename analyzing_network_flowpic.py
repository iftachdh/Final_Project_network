import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os
from matplotlib.colors import LinearSegmentedColormap, BoundaryNorm

def custom_cmap():
    # Create a color list with smooth transitions
    colors = [
        (1, 1, 1),    # white for count 0
        (0.8, 0.8, 1),  # light violet for small packet count
        (0.6, 0.4, 0.8),  # violet
        (0.4, 0.4, 1),  # blue
        (0.2, 0.6, 0.2),  # green
        (1, 1, 0),    # yellow
        (1, 0.6, 0),  # orange
        (1, 0, 0),    # red
        (0.5, 0, 0)   # dark red
    ]
    cmap = LinearSegmentedColormap.from_list("custom_cmap", colors, N=256)
    cmap.set_under('white')  # Set the under color to white for zero counts
    return cmap

def create_norm():
    # Normalize colors with fixed intervals, ensuring a smooth transition
    bounds = [0, 1, 200, 400, 600, 800, 1000, 1200, 1400, 1600]
    norm = BoundaryNorm(bounds, 256)
    return norm

def extract_packet_data(pcap_file):
    print(f"Loading data from {pcap_file}...")
    cap = pyshark.FileCapture(pcap_file, keep_packets=True)
    times = []
    sizes = []
    for packet in cap:
        try:
            if 'IP' in packet:
                size = int(packet.length)
                timestamp = float(packet.sniff_timestamp)
                times.append(timestamp)
                sizes.append(size)
        except AttributeError:
            continue
    cap.close()
    print(f"Finished processing {pcap_file}.")
    return times, sizes

def generate_image(times, sizes, filename, output_folder):
    print(f"Generating image for {filename}...")
    # Normalize time data
    start_time = min(times)
    times = [time - start_time for time in times]

    # Prepare data
    times = np.array(times)
    sizes = np.array(sizes)

    # Create 2D histogram
    fig, ax = plt.subplots()
    cmap = custom_cmap()
    norm = create_norm()
    h = ax.hist2d(times, sizes, bins=[60, 100], range=[[0, 60], [0, 1600]],
                  cmap=cmap, norm=norm, cmin=-0.1)
    cbar = plt.colorbar(h[3], ax=ax, ticks=np.arange(0, 1601, 200))
    cbar.set_label('Count')

    ax.set_title('Packet Timing and Size Representation')
    ax.set_xlabel('Time since start (seconds)')
    ax.set_ylabel('Packet Size (bytes)')

    ax.set_facecolor('white')

    graph_filename = os.path.join(output_folder, f"{filename}_chart.png")
    plt.savefig(graph_filename)
    plt.close()
    print(f"Image saved as {graph_filename}")

# Define and ensure the output folder exists
output_folder = 'Graphs'
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Path to the folder containing pcap files
folder_path = 'records_part_c'
file_paths = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.pcapng')]

# Process each pcap file and generate image
for file_path in file_paths:
    filename = os.path.splitext(os.path.basename(file_path))[0]
    times, sizes = extract_packet_data(file_path)
    generate_image(times, sizes, filename, output_folder)
