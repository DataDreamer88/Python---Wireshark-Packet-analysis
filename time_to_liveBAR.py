from scapy.all import *

# Load the PCAP file
packets = rdpcap("packets.pcap")

# Alternatively, capture live traffic (e.g., on interface 'eth0')
# packets = sniff(iface="eth0", count=1000)  # Capture 1000 packets
# Extract TTL values from packets
ttl_values = [packet[IP].ttl for packet in packets if IP in packet]
import matplotlib.pyplot as plt

# Create an occurrence plot (histogram)
plt.hist(ttl_values, bins=50, edgecolor='k')
plt.title('TTL Occurrence Plot')
plt.xlabel('TTL Value')
plt.ylabel('Frequency')
plt.grid(True)

# Show the plot
plt.show()
