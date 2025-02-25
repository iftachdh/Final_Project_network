import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os
from collections import Counter
from matplotlib.colors import LinearSegmentedColormap, BoundaryNorm

def custom_cmap():
    # color list
    colors = ['white', 'lavender', 'plum', 'blue', 'green', 'yellow', 'orange', 'red', 'darkred']
    cmap = LinearSegmentedColormap.from_list("color_map", colors)  # Create the colormap from the list of colors.
    cmap.set_under('white')  # Specify a color for any data points below the lowest boundary.
    return cmap

def create_norm():
    # Define color boundaries for consistent and intuitive visual interpretation.
    bounds = [0, 1, 200, 400, 600, 800, 1000, 1200, 1400, 1600]  # Set thresholds for color changes.
    norm = BoundaryNorm(bounds, 256)  # Create a normalization that maps data points to the colormap.
    return norm

def extract_most_use_ip(pcap_file):
    print(f"Extracting most used IP addresses in {pcap_file}")
    top_ips = Counter()
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    for packet in cap:
        try:
            if 'IP' in packet:
                top_ips.update([packet.ip.src, packet.ip.dst])
        except AttributeError:
            # Continue to the next packet if an expected attribute is missing in the packet.
            continue
    cap.close()
    print(f"{top_ips.most_common(2)[1][0]}")
    return top_ips.most_common(2)[1][0]

def extract_packet_data(pcap_file, flag_most_use_ip=None):
    print(f"Processing file: {pcap_file}")
    cap = pyshark.FileCapture(pcap_file, keep_packets=True)
    times = []
    sizes = []
    first_packet_time = None
    break_help = False

    for packet in cap:
        try:
            if 'IP' in packet:
                timestamp = float(packet.sniff_timestamp)
                if first_packet_time is None:
                    first_packet_time = timestamp  # Set first_packet_time for the first IP packet seen

                if flag_most_use_ip is None or flag_most_use_ip == packet.ip.src or flag_most_use_ip == packet.ip.dst:
                    if timestamp - first_packet_time > 60:
                        break_help = True
                        break
                    size = int(packet.length)
                    times.append(timestamp - first_packet_time)  # Calculate relative time
                    sizes.append(size)
        except AttributeError:
            continue

    cap.close()

    if break_help:
        print(f"The capture {pcap_file} is more than a minute long and we take the first minute.")
    else:
        alltime = times[-1] if times else 0  # Calculate total time from first relevant packet
        print(f"The capture {pcap_file} is less than a minute long and lasted {alltime} seconds.")

    return times, sizes

def generate_image(times, sizes, filename, output_folder):
    print(f"Generating image for {filename}")
    times = np.array(times)  # Convert list to numpy array for processing.
    sizes = np.array(sizes)  # Convert list to numpy array for processing.

    fig, ax = plt.subplots()  # Create a figure and a set of subplots.
    cmap = custom_cmap()  # Get the custom colormap.
    norm = create_norm()  # Get the normalization based on defined boundaries.
    h = ax.hist2d(times, sizes, bins=[60, 100], range=[[0, 60], [0, 1600]], cmap=cmap, norm=norm, cmin=-0.1)
    cbar = plt.colorbar(h[3], ax=ax, ticks=np.arange(0, 1601, 200))  # Add a color bar to the histogram.
    cbar.set_label('Count')  # Label the color bar.

    ax.set_title(f'FlowPic: {filename}')  # Set title for the histogram.
    ax.set_xlabel('Time since start (seconds)')  # Set the x-axis label.
    ax.set_ylabel('Packet Size (bytes)')  # Set the y-axis label.
    ax.set_facecolor('white')  # Set the background color for the axes.

    graph_filename = os.path.join(output_folder, f"{filename}_graph.png")  # Construct full file path.
    plt.savefig(graph_filename)  # Save the figure.
    plt.close()  # Close the plot to free up memory.
    print(f"Image saved as {graph_filename}\n")  # Confirm the save.

def main():
    flag_most_use_ip = None
    while True:
        flag = input("Do you want to filter by most common IP in the records? 1 for yes, 0 for no:")
        if flag == '1' or flag == '0':
            break

    if flag == '1':
        output_folder = '../res/FlowPicsFilter'
    else:
        output_folder = '../res/FlowPics'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    folder_path = '../records/all_records'
    file_paths = sorted([os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith('.pcapng')])  # List all pcap files.

    for file_path in file_paths:
        filename = os.path.splitext(os.path.basename(file_path))[0]  # Extract the base name for use in titles.
        if flag == '1':
            flag_most_use_ip = extract_most_use_ip(file_path)

        times, sizes = extract_packet_data(file_path,flag_most_use_ip)  # Extract packet data.
        generate_image(times, sizes, filename, output_folder)  # Generate and save the histogram image.

if __name__ == "__main__":
    main()
