from scapy.all import *
import matplotlib.pyplot as plt

# Load the PCAP file or capture live traffic as before
packets = rdpcap("packets.pcap")

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

# Calculate packet reordering for each flow
reordering_values = []

for flow, seq_nums in reordering_dict.items():
    reordering = sum(1 for i, seq in enumerate(seq_nums) if i != seq - seq_nums[0])
    reordering_values.append(reordering)

# Create a pie chart
unique_flows = list(reordering_dict.keys())
reordering_counts = [len(reordering_dict[flow]) for flow in unique_flows]

# Generate labels for the pie chart
labels = [f"Flow {flow[0]}->{flow[1]}" for flow in unique_flows]

# Create the pie chart
plt.figure(figsize=(8, 8))
plt.pie(reordering_counts, labels=labels, autopct='%1.1f%%', startangle=140)
plt.title('Packet Reordering by Flow')
plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

# Show the pie chart
plt.show()
