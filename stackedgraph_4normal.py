import scapy.all as scapy
import matplotlib.pyplot as plt

# Replace 'C:\\path\\to\\your\\packetcapture.pcap' with the actual file path
pcap_file = 'packet.pcap'

# Read packets from the capture file
packets = scapy.rdpcap(pcap_file)

# Define your criteria for normal packets
def is_normal(packet):
    # Replace with your criteria for normal packets
    return True

# Filter packets based on your criteria for normal packets
normal_packets = [packet for packet in packets if is_normal(packet)]

# Initialize counters for SYN, ACK, and FIN flags
syn_count_normal = 0
ack_count_normal = 0
fin_count_normal = 0

# Count the number of packets with each flag for normal traffic
for packet in normal_packets:
    if scapy.TCP in packet:
        if packet[scapy.TCP].flags & 2:  # Check if SYN flag is set
            syn_count_normal += 1
        if packet[scapy.TCP].flags & 16:  # Check if ACK flag is set
            ack_count_normal += 1
        if packet[scapy.TCP].flags & 1:  # Check if FIN flag is set
            fin_count_normal += 1

# Create a stacked bar chart for normal packets
flag_labels = ['SYN', 'ACK', 'FIN']
flag_counts_normal = [syn_count_normal, ack_count_normal, fin_count_normal]

plt.figure(figsize=(10, 6))  # Adjust the figure size as needed
plt.bar(flag_labels, flag_counts_normal, color=['blue', 'green', 'red'])
plt.xlabel('Flag Type')
plt.ylabel('Packet Count')
plt.title('Stacked Bar Chart of Flag Types (Normal)')
plt.grid(True)

plt.show()
