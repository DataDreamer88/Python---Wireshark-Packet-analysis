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

# Prepare data for the pie chart
labels = [f"TTL {ttl}" for ttl in ttl_counts.keys()]
sizes = list(ttl_counts.values())

# Create a pie chart
plt.figure(figsize=(8, 8))
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
plt.title('TTL Occurrence Pie Chart')

# Show the pie chart
plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
plt.show()
