import scapy.all as scapy
import matplotlib.pyplot as plt

# Replace 'C:\\path\\to\\your\\packetcapture.pcap' with the actual file path
pcap_file = 'packetcapture.pcap'

# Read packets from the capture file
packets = scapy.rdpcap(pcap_file)

# Define your criteria for normal and abnormal packets
def is_normal(packet):
    # Replace with your criteria for normal packets
    # For example, you can check for known characteristics of normal traffic
    return True

def is_abnormal(packet):
    # Replace with your criteria for abnormal packets
    # For example, you can check for known characteristics of abnormal traffic
    return False

# Filter packets based on your criteria for normal and abnormal packets
normal_packets = [packet for packet in packets if is_normal(packet)]
abnormal_packets = [packet for packet in packets if is_abnormal(packet)]

# Calculate the total bandwidth for normal and abnormal TCP packets
total_bandwidth_normal = sum(len(packet) * 8 for packet in normal_packets)
total_bandwidth_abnormal = sum(len(packet) * 8 for packet in abnormal_packets)

# Create a pie chart to show the proportion of bandwidth used by normal and abnormal packets
labels = ['Normal Packets', 'Abnormal Packets']
sizes = [total_bandwidth_normal, total_bandwidth_abnormal]
colors = ['blue', 'red']

plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)

plt.title('Proportion of Bandwidth Used by Normal and Abnormal Packets')
plt.axis('equal')  # Equal aspect ratio ensures that the pie is drawn as a circle

plt.show()
