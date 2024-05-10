from scapy.all import *

# Load the PCAP file
packets = rdpcap("packets.pcap")

# Alternatively, capture live traffic (e.g., on interface 'eth0')
# packets = sniff(iface="eth0", count=1000)  # Capture 1000 packets
# Dictionary to store packet reordering
reordering_dict = {}

for packet in packets:
    if "TCP" in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        seq_num = packet[TCP].seq

        if (src_port, dst_port) not in reordering_dict:
            reordering_dict[(src_port, dst_port)] = []

        reordering_dict[(src_port, dst_port)].append(seq_num)
import matplotlib.pyplot as plt

# Calculate packet reordering for each flow
reordering_values = []

for flow, seq_nums in reordering_dict.items():
    reordering = sum(1 for i, seq in enumerate(seq_nums) if i != seq - seq_nums[0])
    reordering_values.append(reordering)

# Create an occurrence plot (histogram)
plt.hist(reordering_values, bins=50, edgecolor='k')
plt.title('Packet Reordering Occurrence Plot')
plt.xlabel('Packet Reordering')
plt.ylabel('Frequency')
plt.grid(True)

# Show the plot
plt.show()
