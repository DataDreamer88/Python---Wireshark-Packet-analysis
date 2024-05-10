import scapy.all as scapy
import matplotlib.pyplot as plt

# Replace 'C:\\path\\to\\your\\packetcapture.pcap' with the actual file path
pcap_file = 'packetcapture.pcap'

# Read packets from the capture file
packets = scapy.rdpcap(pcap_file)

# Define your criteria for normal packets
def is_normal(packet):
    # Replace with your criteria for normal packets
    return True

# Filter packets based on your criteria for normal packets
normal_packets = [packet for packet in packets if is_normal(packet)]

# Calculate bandwidth for normal TCP packets
normal_bandwidth_values = []  # List to store bandwidth values (in bps) for each normal packet

# Calculate bandwidth values using raw packet length and timestamps
prev_packet_time = normal_packets[0].time
for packet in normal_packets[1:]:
    time_difference = float(packet.time - prev_packet_time)  # Convert to float
    if time_difference == 0:
        # Handle division by zero by skipping this packet or setting bandwidth to zero
        bandwidth = 0
    else:
        # Calculate bandwidth in bps using raw packet length
        bandwidth = (float(len(packet)) * 8) / time_difference  # Convert to float
    normal_bandwidth_values.append(bandwidth)
    prev_packet_time = packet.time

# Create a bar graph for the bandwidth of normal TCP packets
plt.bar(range(len(normal_bandwidth_values)), normal_bandwidth_values, color='blue')
plt.xlabel('Packet Number')
plt.ylabel('Bandwidth (bps)')
plt.title('Bandwidth of Normal TCP Packets')

# Set a custom y-axis limit with a logarithmic scale to make the bars more visible
plt.yscale('log')
plt.ylim(1e3, 1e8)  # You can adjust the limits based on your data

plt.show()
