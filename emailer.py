from email import message_from_string

class Emailer:
    def __init__(self, content):
        self._parsed = message_from_string(content)
        self.body      = self._parsed.get_payload()  or "No body"
        self.subject   = self._parsed['Subject']     or "No subject"
        self.timestamp = self._parsed['Date']        or "Unknown date"
        self.sender    = self._parsed['From']        or "Unknown sender"
if __name__ == "__main__":
    email1 = Emailer("""From: "John Doe" <john.doe@example.com>
                     
Subject: Test Email
Date: Mon, 1 Jan 2023 12:00:00 +0000
To: "Jane Smith" <jane.smith@example.com>
This is a test email.""")
    print(f"Subject: {email1.subject}")
    print(f"Timestamp: {email1.timestamp}")
    print(f"Sender: {email1.sender}")
    print(f"Content: {email1.body}")