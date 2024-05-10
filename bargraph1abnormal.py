import scapy.all as scapy
import matplotlib.pyplot as plt

# Replace 'C:\\path\\to\\your\\packetcapture.pcap' with the actual file path
pcap_file = 'packetcapture.pcap'

# Read packets from the capture file
packets = scapy.rdpcap(pcap_file)

# Define your criteria for abnormal packets
def is_abnormal(packet):
    # Replace with your criteria for abnormal packets
    return True

# Filter packets based on your criteria for abnormal packets
abnormal_packets = [packet for packet in packets if is_abnormal(packet)]

# Calculate bandwidth for abnormal TCP packets
abnormal_bandwidth_values = []  # List to store bandwidth values (in bps) for each abnormal packet

# Calculate bandwidth values using raw packet length and timestamps
prev_packet_time = abnormal_packets[0].time
for packet in abnormal_packets[1:]:
    time_difference = float(packet.time - prev_packet_time)  # Convert to float
    if time_difference == 0:
        # Handle division by zero by skipping this packet or setting bandwidth to zero
        bandwidth = 0
    else:
        # Calculate bandwidth in bps using raw packet length
        bandwidth = (float(len(packet)) * 8) / time_difference  # Convert to float
    abnormal_bandwidth_values.append(bandwidth)
    prev_packet_time = packet.time

# Create a bar graph for the bandwidth of abnormal TCP packets
plt.bar(range(len(abnormal_bandwidth_values)), abnormal_bandwidth_values, color='red')
plt.xlabel('Packet Number')
plt.ylabel('Bandwidth (bps)')
plt.title('Bandwidth of Abnormal TCP Packets')

# Set a custom y-axis limit with a logarithmic scale to make the bars more visible
plt.yscale('log')
plt.ylim(1e3, 1e8)  # You can adjust the limits based on your data

plt.show()
