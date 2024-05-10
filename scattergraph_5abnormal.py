import scapy.all as scapy
import matplotlib.pyplot as plt

# Replace 'C:\\path\\to\\your\\packetcapture.pcap' with the actual file path
pcap_file = 'packets.pcap'

# Read packets from the capture file
packets = scapy.rdpcap(pcap_file)

# Define your criteria for abnormal packets
def is_abnormal(packet):
    # Replace with your criteria for abnormal packets
    return True

# Filter packets based on your criteria for abnormal packets
abnormal_packets = [packet for packet in packets if is_abnormal(packet)]

# Create lists to store bandwidth, packet count, SYN flag presence, ACK flag presence, and FIN flag presence for abnormal traffic
bandwidth_values_abnormal = []
packet_count_values_abnormal = []
syn_flags_abnormal = []
ack_flags_abnormal = []
fin_flags_abnormal = []

# Calculate bandwidth and count flags for abnormal packets
previous_packet_time_abnormal = abnormal_packets[0].time
for packet in abnormal_packets:
    if scapy.IP in packet and scapy.TCP in packet:
        packet_size = len(packet)
        packet_time = packet.time

        # Check if the time difference is greater than zero
        if packet_time - previous_packet_time_abnormal > 0:
            bandwidth = packet_size / (packet_time - previous_packet_time_abnormal)
            bandwidth_values_abnormal.append(bandwidth)
            packet_count_values_abnormal.append(packet_time - abnormal_packets[0].time)
            syn_flags_abnormal.append(1 if packet[scapy.TCP].flags & 2 else 0)
            ack_flags_abnormal.append(1 if packet[scapy.TCP].flags & 16 else 0)
            fin_flags_abnormal.append(1 if packet[scapy.TCP].flags & 1 else 0)

        previous_packet_time_abnormal = packet_time

# Create a scatter plot for abnormal traffic
plt.figure(figsize=(10, 6))  # Adjust the figure size as needed
plt.scatter(packet_count_values_abnormal, bandwidth_values_abnormal, c=syn_flags_abnormal, cmap='coolwarm', label='SYN Flag', alpha=0.5, marker='o', s=20)
plt.scatter(packet_count_values_abnormal, bandwidth_values_abnormal, c=ack_flags_abnormal, cmap='coolwarm', label='ACK Flag', alpha=0.5, marker='s', s=20)
plt.scatter(packet_count_values_abnormal, bandwidth_values_abnormal, c=fin_flags_abnormal, cmap='coolwarm', label='FIN Flag', alpha=0.5, marker='^', s=20)
plt.xlabel('Packet Count (Time)')
plt.ylabel('Bandwidth (bps)')
plt.title('Scatter Plot of Bandwidth vs. Packet Count with Flag Presence (Abnormal)')
plt.legend()
plt.grid(True)

plt.show()
