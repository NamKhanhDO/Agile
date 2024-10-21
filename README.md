

# Pyroscope PROJECT

- **ASTRUC Mathieu** - PRODUCT OWNER
- **OUVRARD Emilien** - SCRUM MASTER
- **BRUS Clément** - QUALITY ASSURANCE EXPERT
- **MERYET Benjamin** - DEVELOPER
- **DO NAM KHANH** - DEVELOPER

# Pyroscope

**Pyroscope** is a simple Intrusion Detection System (IDS) application designed to monitor network traffic and detect suspicious activities. The application utilizes **Scapy** for packet sniffing and optionally uses **Tkinter** for the graphical user interface (GUI). However, the GUI isn't mandatory for running the application itself.

## Features

- **DNS Tunneling Detection**: Identifies potential DNS tunneling activities that could signal data exfiltration or command-and-control communications.
- **SSH Tunneling Detection**: Detects potentially malicious SSH tunneling activities used for bypassing firewalls.
- **SYN Flood Monitoring**: Monitors and detects SYN flood attacks, a common type of Denial of Service (DoS) attack.
- **Keyword Detection**: Scans network traffic for specific suspicious keywords that could indicate an attack or data leak.
- **Real-time Monitoring**: Provides continuous real-time network traffic monitoring.

### GUI (Optional)

Although the primary functionality can be executed without the GUI, you can use Tkinter to launch a graphical interface that enhances user interaction with the IDS.

- **Real-time Traffic Monitoring** on the left: Displays live traffic data.
- **Suspicious Activities** on the right: Displays logs of flagged suspicious activities.

## Installation

### Pre-requisites:

- **Python 3.x**
- **Npcap**: Required for packet capturing. Install from [Npcap website](https://nmap.org/npcap/) to enable network packet analysis.
- **Scapy**: For network traffic monitoring and sniffing.
- **Tkinter**: For the optional graphical interface (optional).
  
### Steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/pyroscope.git
    cd pyroscope
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the application** (without GUI):
    ```bash
    python ids.py
    ```

4. **Run the application** (with GUI):
    ```bash
    python ids_gui.py
    ```

> **Note:** Ensure that **Npcap** is installed to properly capture packets on the system.

## Usage

1. **Select Network Interface**: Choose the network interface you want to monitor.
2. **Start Monitoring**: Initiate the real-time monitoring of traffic.
3. **Logs**: Detected suspicious activities are logged and displayed (either in the GUI or in the command line interface, depending on the mode used).

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for new features, bug fixes, or improvements.

## License

This project is licensed under the MIT License.

---

