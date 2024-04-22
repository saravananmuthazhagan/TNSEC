


Python
from scapy.all import sniff, wrpcap

# Define a callback function to analyze packets
def analyze_packet(packet):
  # Print basic info
  print(f"Source: {packet[IP].src} Destination: {packet[IP].dst}")
  print(f"Protocol: {packet[IP].proto}")

  # Analyze specific protocols (e.g., TCP, UDP)
  if packet.haslayer(TCP):
    print(f"TCP Source Port: {packet[TCP].sport} Destination Port: {packet[TCP].dport}")
  elif packet.haslayer(UDP):
    print(f"UDP Source Port: {packet[UDP].sport} Destination Port: {packet[UDP].dport}")

# Capture packets and call the callback function for each packet
sniff(prn=analyze_packet, filter="tcp", store=False)  # Capture only TCP packets

# Alternatively, analyze a captured PCAP file
# wrpcap("captured_traffic.pcap", sniff(count=1000))  # Capture 1000 packets and save to a file
