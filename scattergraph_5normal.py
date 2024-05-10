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

# Create lists to store bandwidth, packet count, SYN flag presence, ACK flag presence, and FIN flag presence
bandwidth_values = []
packet_count_values = []
syn_flags = []
ack_flags = []
fin_flags = []

# Calculate bandwidth and count flags for normal packets
previous_packet_time = normal_packets[0].time
for packet in normal_packets:
    if scapy.IP in packet and scapy.TCP in packet:
        packet_size = len(packet)
        packet_time = packet.time

        # Check if the time difference is greater than zero
        if packet_time - previous_packet_time > 0:
            bandwidth = packet_size / (packet_time - previous_packet_time)
            bandwidth_values.append(bandwidth)
            packet_count_values.append(packet_time - normal_packets[0].time)
            syn_flags.append(1 if packet[scapy.TCP].flags & 2 else 0)
            ack_flags.append(1 if packet[scapy.TCP].flags & 16 else 0)
            fin_flags.append(1 if packet[scapy.TCP].flags & 1 else 0)

        previous_packet_time = packet_time

# Create a scatter plot for normal traffic
plt.figure(figsize=(10, 6))  # Adjust the figure size as needed
plt.scatter(packet_count_values, bandwidth_values, c=syn_flags, cmap='coolwarm', label='SYN Flag', alpha=0.5, marker='o', s=20)
plt.scatter(packet_count_values, bandwidth_values, c=ack_flags, cmap='coolwarm', label='ACK Flag', alpha=0.5, marker='s', s=20)
plt.scatter(packet_count_values, bandwidth_values, c=fin_flags, cmap='coolwarm', label='FIN Flag', alpha=0.5, marker='^', s=20)
plt.xlabel('Packet Count (Time)')
plt.ylabel('Bandwidth (bps)')
plt.title('Scatter Plot of Bandwidth vs. Packet Count with Flag Presence (Normal)')
plt.legend()
plt.grid(True)

plt.show()
