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

# Calculate bandwidth for abnormal TCP packets and collect timestamps
abnormal_bandwidth_values = []  # List to store bandwidth values (in bps) for each abnormal packet
timestamps = []

# Calculate bandwidth values and timestamps using raw packet length and packet times
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
    timestamps.append(packet.time)
    prev_packet_time = packet.time

# Create a line graph for the bandwidth of abnormal TCP packets over time
plt.plot(timestamps, abnormal_bandwidth_values, color='red')
plt.xlabel('Time')
plt.ylabel('Bandwidth (bps)')
plt.title('Bandwidth of Abnormal TCP Packets Over Time')

plt.show()
