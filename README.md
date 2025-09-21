1. Project Title
**Real-Time Network Traffic Analyzer with AI/ML**

2. Short Description
A dashboard that leverages unsupervised machine learning to detect suspicious and malicious IPs in real-time, classifies traffic (Web, Streaming, DNS, SSH, FTP, Email), generates AI-driven risk scores, and provides interactive dashboards for monitoring.

3. Features
Real-time packet sniffing with Python & Scapy
Traffic classification by protocol and port
Malicious IP detection using Isolation Forest (unsupervised ML)

Interactive Streamlit dashboard:
Scrollable IP stats table
Live line chart showing traffic trends
AI-driven alerts for suspicious connections
Risk scoring for each IP

4. How It Works
Captures network packets in real-time and extracts protocol, port, and IP details.
Classifies traffic into categories using port/protocol mapping.
Aggregates IP statistics: packet count, unique ports, protocol ratios, average packet size.
Detects anomalies using Isolation Forest.
Visualizes traffic trends and alerts in a Streamlit dashboard.

5. Tech Stack / Libraries
Python | Scapy | Pandas | Streamlit | Altair | scikit-learn | NumPy

6. Installation & Setup
# Clone the repo
git clone <https://github.com/Nirali1002/Real-Time-Network-Traffic-Analyzer-with-AI-ML.git>
# Install dependencies
pip install -r requirements.txt
# Run the dashboard
streamlit run dashboard.py

7. Future Enhancements
Integration with cloud services (AWS EC2) for scalable monitoring
Automated mitigation or firewall suggestions
Support for more traffic categories and protocols
