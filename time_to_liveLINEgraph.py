from scapy.all import *
import matplotlib.pyplot as plt

# Load the PCAP file or capture live traffic as before
packets = rdpcap("packets.pcap")

# Extract TTL values from packets
ttl_values = [packet[IP].ttl for packet in packets if IP in packet]

# Count the occurrences of each TTL value
ttl_counts = {}
for ttl in ttl_values:
    ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1

# Sort the TTL values in ascending order
sorted_ttl_values = sorted(ttl_counts.keys())

# Create lists for x (TTL values) and y (occurrence counts)
x = sorted_ttl_values
y = [ttl_counts[ttl] for ttl in x]

# Create a line graph
plt.figure(figsize=(10, 6))
plt.plot(x, y, marker='o', linestyle='-')
plt.title('TTL Occurrence Line Graph')
plt.xlabel('TTL Value')
plt.ylabel('Frequency')
plt.grid(True)

# Show the line graph
plt.show()
