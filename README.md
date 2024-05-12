
# Network Traffic Analyzer

Network Traffic Analyzer is a Python-based application that uses Scapy and PyQt5 to monitor, analyze, and visualize network traffic in real-time. It allows users to inspect packets, apply filters, and detect potentially malicious activities.

## Features

- **Real-Time Packet Capture**: Capture and display network packets in real-time.
- **Packet Filtering**: Filter packets based on specific criteria.
- **Packet Inspection**: View detailed information about individual packets.
- **Anomaly Detection**: Detect and block suspicious IP addresses.
- **Logging**: Maintain logs of network activities and application usage.

## Requirements

- Python 3.x
- PyQt5
- Scapy
- Psutil
- Joblib
- Scikit-learn
- Pandas
- Numpy

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/network-traffic-analyzer.git
   cd network-traffic-analyzer
   ```

2. **Install the required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the application**:
   ```bash
   python NetworkTrafficAnalyzer.py
   ```

2. **Main Interface**:
   - The main interface displays the captured packets in a table format.
   - You can start and stop packet capture using the provided buttons.
   - Apply filters using the search bar to find specific packets.

3. **Packet Details**:
   - Click on a packet in the table to view detailed information about it.
   - A dialog box will appear showing the packet's details.

4. **Anomaly Detection**:
   - The application uses a pre-trained machine learning model to detect anomalies in network traffic.
   - If a suspicious packet is detected, it will block the corresponding IP address.

## File Structure

- `NetworkTrafficAnalyzer.py`: Main application file.
- `requirements.txt`: List of dependencies.

## Logging

- Logs are maintained in the `app.log` file, recording application events and errors.

## Key Functions and Classes

### `SnifferThread(QThread)`

A QThread class responsible for capturing network packets using Scapy and updating the UI.

- `run()`: Start packet capture.
- `process_packet(packet)`: Process each captured packet and make predictions.

### `SnifferApp(QMainWindow)`

The main application window class, managing the UI and user interactions.

- `initUI()`: Initialize the user interface.
- `update_packet_table(packet)`: Update the packet table with new packets.
- `apply_filter()`: Filter packets based on user input.
- `show_packet_details(item, column)`: Display detailed information about a selected packet.

### Utility Functions

- `block_ip(ip_address)`: Block a specific IP address using Windows Firewall rules.
- `unblock_ip(ip_address)`: Unblock a specific IP address using Windows Firewall rules.
- `get_row_color(packet)`: Determine the color for a table row based on the packet type.

### Logging Decorator

- `log_decorator(func)`: Decorator for logging function calls and exceptions.

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any features or bug fixes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For any questions or issues, please contact [babazadasahin@gmail.com](mailto:babazadasahin@gmail.com).
