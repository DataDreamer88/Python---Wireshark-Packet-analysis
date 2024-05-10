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

# Calculate bandwidth for normal packets
bandwidth_values = []  # List to store bandwidth values (in bps)

prev_packet_time = normal_packets[0].time
for packet in normal_packets[1:]:
    time_difference = float(packet.time - prev_packet_time)  # Convert to float
    if time_difference == 0:
        # Handle division by zero by skipping this packet or setting bandwidth to zero
        bandwidth = 0
    else:
        # Calculate bandwidth in bps using raw packet length
        bandwidth = (float(len(packet)) * 8) / time_difference  # Convert to float
    bandwidth_values.append(bandwidth)

# Create a histogram for normal bandwidth measurements
plt.figure(figsize=(10, 6))  # Adjust the figure size as needed
plt.hist(bandwidth_values, bins=20, color='blue', alpha=0.7)
plt.xlabel('Bandwidth (bps)')
plt.ylabel('Frequency')
plt.title('Histogram of Bandwidth Measurements (Normal)')
plt.grid(True)

plt.show()
