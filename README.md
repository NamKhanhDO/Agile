Pyroscope Project
- ASTRUC Mathieu - PRODUCT OWNER
- OUVRARD Emilien - SCRUM MASTER
- BRUS Clément - QIALITY ASSURANCE EXPERT
- MERYET Benjamin - DEVELOPER
- DO NAM KHANH - DEVELOPER

# Pyroscope

Pyroscope is a simple Intrusion Detection System (IDS) application designed to monitor network traffic and detect suspicious activities. The application uses Scapy for packet sniffing and Tkinter for the graphical user interface (GUI).

## Features

- **DNS Tunneling Detection**: Identifies potential DNS tunneling activities.
- **SSH Tunneling Detection**: Detects suspicious SSH tunneling activities.
- **SYN Flood Monitoring**: Monitors and detects SYN flood attacks.
- **Keyword Detection**: Scans for suspicious keywords in network traffic.
- **Real-time Monitoring**: Provides real-time monitoring of network traffic.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/pyroscope.git
    cd pyroscope
    ```

2. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Run the application**:
    ```bash
    python ids.py
    ```

## Usage

1. **Select Network Interface**: Choose the network interface you want to monitor from the dropdown menu.
2. **Start Monitoring**: Click the "Start Monitoring" button to begin real-time traffic monitoring.
3. **View Logs**: Suspicious activities will be logged and displayed in the scrolled text area.

## Requirements

- Python 3.x
- Scapy
- Tkinter

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License.
 
