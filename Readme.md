 Packet Sniffer using Python & Scapy

📌 Overview

This project is a Python-based network packet sniffer that captures live network traffic, analyzes packets, and logs them for further inspection. It uses Scapy to intercept and process network packets.

🚀 Features

✅ Capture live network traffic✅ Display real-time packet details (IP, TCP, UDP, ICMP, etc.)✅ Filter packets by protocol✅ Save captured packets for later analysis (Wireshark .pcap)✅ Works on Windows, Linux, and macOS

📂 Installation

🔹 Step 1: Install Dependencies

Make sure you have Python 3 installed. Then, install scapy:

pip install scapy

🔹 Step 2: Install WinPcap/Npcap (Windows Users)

Windows users need Npcap for packet capturing:🔗 Download NpcapDuring installation, check "Install Npcap in WinPcap API-compatible mode".

For Linux/macOS, no additional setup is required.

🎯 Usage

🔹 Run the Packet Sniffer

Open a terminal and run:

python packet_sniffer.py

🔹 Capture Packets on a Specific Interface

Find your network interfaces:

python -c "from scapy.all import IFACES; print(IFACES)"

Then, capture packets from a specific interface (e.g., Wi-Fi):

python packet_sniffer.py --iface wlan0

🔹 Save Packets to a File

To save packets for Wireshark analysis:

python packet_sniffer.py --output packets.pcap

📸 Screenshots

🔹 Packet Sniffer Output



🔹 Captured Packets in Wireshark



🔬 How It Works

The script sniffs live network traffic using Scapy’s sniff() function.

It extracts details (IP addresses, ports, protocols).

The output is displayed in real time and can be saved for analysis.

Packets can be filtered by protocol (TCP, UDP, ICMP, DNS).

⚠️ Legal Disclaimer

⚠️ Use this tool only on networks you have permission to monitor. Unauthorized packet sniffing is illegal in many countries.

📝 License

This project is open-source and available under the MIT License.

🌟 Contributing

Want to improve this project? Feel free to fork the repo and submit pull requests! 🚀

