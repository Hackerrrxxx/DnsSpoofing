import dns.resolver
import time
import requests

# Textbelt API configurations (replace with your details)
TEXTBELT_API_KEY = 'textbelt'  # Free API key for Textbelt (limit of 1 free SMS per day)
PHONE_NUMBER = "+1234567890"  # Replace with the phone number you want to send SMS to

def send_sms_alert(domain):
    """Send an SMS alert using Textbelt."""
    try:
        response = requests.post(
            'https://textbelt.com/text', 
            {
                'phone': PHONE_NUMBER,
                'message': f"DNS Spoofing Alert! Potential spoofing detected for {domain}.",
                'key': TEXTBELT_API_KEY
            }
        )
        response_data = response.json()
        if response_data.get('success'):
            print("📱 SMS alert sent!")
        else:
            print(f"❌ Error sending SMS: {response_data.get('error')}")
    except Exception as e:
        print(f"❌ Error sending SMS: {e}")

def detect_dns_spoofing(domain):
    """Detect DNS spoofing and trigger alerts."""
    try:
        # Resolve domain
        answers = dns.resolver.resolve(domain, 'A')
        ip_address = answers[0].to_text()
        print(f"✅ DNS response: {domain} resolves to {ip_address}")
        return False  # No spoofing detected
    except Exception as e:
        print(f"❌ DNS resolution failed for {domain}: {e}")
        return True  # Spoofing detected

def log_message(message):
    """Log the alert message to a file."""
    try:
        with open("dns_spoof_log.txt", "a") as log_file:
            log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    except Exception as e:
        print(f"❌ Error logging message: {e}")

if __name__ == "__main__":
    domain = "google.com"  # Change this to the domain you want to check

    if detect_dns_spoofing(domain):
        alert_message = f"DNS Spoofing detected for {domain}."
        log_message(alert_message)

        # Trigger the SMS alert
        send_sms_alert(domain)
    else:
        print(f"✅ No DNS spoofing detected for {domain}.")
