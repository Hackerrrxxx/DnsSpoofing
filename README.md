# DnsSpoofing
This project detects DNS spoofing (also known as DNS cache poisoning) by verifying if a domain resolves to an unexpected IP address. If spoofing is detected, the system sends an SMS alert using the Textbelt API and logs the incident.
🛠 Features
✅ Resolves a domain’s IP address and checks for anomalies.
✅ Detects possible DNS spoofing attempts.
✅ Logs suspicious activity in a text file.
✅ Sends real-time SMS alerts (via Textbelt API) when spoofing is detected.

📂 Project Structure
bash
Copy
Edit
/dns_spoof_detection
│── dns_spoof_checker.py   # Main script for DNS spoofing detection
│── dns_spoof_log.txt      # Log file to store spoofing alerts
│── README.md              # Documentation (this file)
└── requirements.txt       # Required dependencies
⚙️ How It Works
The script resolves the IP address of a domain (e.g., google.com).
If the domain fails to resolve or returns an unexpected IP, it is flagged as suspicious.
The alert is logged in dns_spoof_log.txt.
An SMS alert is sent to the configured phone number using Textbelt API.
📥 Installation
1️⃣ Clone the Repository
bash
Copy
Edit
git clone https://github.com/your-username/dns-spoof-detection.git
cd dns-spoof-detection
2️⃣ Install Dependencies
Ensure you have Python installed. Then install the required dependencies:

bash
Copy
Edit
pip install -r requirements.txt
3️⃣ Run the Script
bash
Copy
Edit
python dns_spoof_checker.py
🔧 Configuration
Modify These Settings in dns_spoof_checker.py
Change PHONE_NUMBER to your recipient number.
Use 'textbelt' as the API key for free SMS alerts.
python
Copy
Edit
PHONE_NUMBER = "+1234567890"  # Replace with your number
TEXTBELT_API_KEY = 'textbelt'  # Free key (1 SMS/day)
📌 Example Output
Case 1: No Spoofing Detected

bash
Copy
Edit
✅ DNS response: google.com resolves to 142.250.180.206
✅ No DNS spoofing detected for google.com.
Case 2: Potential Spoofing Detected

bash
Copy
Edit
❌ DNS resolution failed for google.com: Unexpected IP detected!
📱 SMS alert sent!
(An SMS is sent to the configured number)

📜 Log File (dns_spoof_log.txt)
All detected spoofing attempts are logged in this file:

rust
Copy
Edit
2025-02-17 15:45:12 - DNS Spoofing detected for google.com.
🛠 Future Enhancements
🔹 Add support for multiple DNS resolvers (Google, Cloudflare, OpenDNS).
🔹 Implement email alerts as an additional notification method.
🔹 Develop a GUI dashboard to visualize spoofing events.
