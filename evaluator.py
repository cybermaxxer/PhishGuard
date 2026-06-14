import json 
import re
import socket
from collections import Counter
from urllib.parse import urlparse
from emailer import Emailer
import requests
class Evaluator: 
    def __init__(self):
        self.reports = 0
        self.all_categories = []
        self.identified_categories = []
        self.links = []
        self.score = 0
        self.thresholds = [
            {"max": 20, "level": "Low Risk", "msg": "This message appears standard, but stay alert.", "advice": "Ensure you recognize the sender. Only open links or attachments if you were expecting this communication."},
            {"max": 40, "level": "Suspicious", "msg": "This message uses language commonly found in phishing attempts.", "advice": "Do not click links or download attachments yet. Check the sender's actual email address. Navigate to official websites manually."},
            {"max": 60, "level": "High Risk", "msg": "Strong indicators of a phishing or scam attempt detected.", "advice": "Do not reply or interact. Verify the request by contacting the supposed sender directly via a trusted, separate channel."},
            {"max": 80, "level": "Critical", "msg": "This message is highly likely to be malicious.", "advice": "Do not interact. Report or delete immediately. Do not pay any demanded ransoms or provide credentials."},
            {"max": 100, "level": "Severe", "msg": "This message is almost certainly a dangerous phishing attempt.", "advice": "Do not interact. Report or delete immediately. Do not pay any demanded ransoms or provide credentials."}
        ]
    #runs all the checks and generates a report based on the score and identified categories. It also saves a detailed report to a text file and returns a dictionary with the results for CSV logging.
    def evaluate(self, email):
        self.reports = self.reports + 1
        reportData = ""
        self.evaluate_hotWords(email)
        self.check_ip_addresses(email) # Check links and append link-related info to the report
        reportData += self.check_links(email) 
        level = self.thresholds[len(self.thresholds) - 1]  # Default to the highest level if score exceeds all thresholds
        for threshold in self.thresholds:
            if self.score <= threshold["max"]: # Determine the risk level based on the score and thresholds
                level = threshold
                break
        print("Identified Categories:", self.identified_categories) # Print identified categories for debugging
        reportData += f"Identified Categories: {self.identified_categories}\n" # Append identified categories to the report
        singleCategory = max(set(self.identified_categories), key=self.identified_categories.count) if self.identified_categories else "None"
        secondMax = Counter(self.identified_categories).most_common(2)
        ratio = (secondMax[0][1] / secondMax[1][1]) if len(secondMax) > 1 and secondMax[1][1] > 0 else 1
        
        if singleCategory != "None" and ratio > 1.5:
            print(f"Strongly associated category: {singleCategory} (appears {secondMax[0][1]} times, ratio bonus applied)")
            reportData += f"Strongly associated category: {singleCategory} (appears {secondMax[0][1]} times, ratio bonus applied)\n"
            self.score = self.score + 10  # Add a bonus to the score for strong category association    
            for threshold in self.thresholds:
                if self.score <= threshold["max"]:
                    level = threshold
                    break
        csvDict = { # Prepare data for CSV logging
            "Subject": email.subject,
            "Timestamp": email.timestamp,
            "Sender": email.sender,
            "Identified Categories": self.identified_categories,
            "Most Frequent Category": singleCategory,
            "Category Ratio": ratio,
            "Score": self.score,
            "Risk Level": level['level'],
            "Message": level['msg'],
            "Advice": level['advice']
        }
        print(f"Most Frequent Category: {singleCategory}")
        reportData += f"Most Frequent Category: {singleCategory}\n"
        print(f"Category Ratio: {ratio:.2f}")
        reportData += f"Category Ratio: {ratio:.2f}\n"
        print(f"Score: {min(self.score, 100)}/100. Risk Level: {level['level']}. {level['msg']} Advice: {level['advice']}")
        reportData += f"Score: {min(self.score, 100)}/100\nRisk Level: {level['level']}\nMessage: {level['msg']}\nAdvice: {level['advice']}\n"
        with open(f'report_{self.reports}.txt', 'w') as report_file:
            report_file.write(reportData)
        return csvDict
    #runs a check for predefined high-risk words in the email's subject and body, updating the score and identified categories accordingly.
    def evaluate_hotWords(self, email):
        email = email.body + " " + email.subject
        self.all_categories = []
        self.identified_categories = []
        self.score = 0
        with open('hotWords.json', 'r') as f:
            data = json.load(f)
        for key in data["high_risk_words"].keys():
            if key:
                self.all_categories.append(key)
        for category in self.all_categories:
            for token in data["high_risk_words"][category]["tokens"]:
                reg_token = '\\b' + token + '\\b'
                if re.search(reg_token, email, re.IGNORECASE):
                    self.score += int(data["high_risk_words"][category]["tokens"][token])
                    self.identified_categories.append(category)
                    print(f"identified {token}")
    #checks for IP addresses in the email content and subject, adding to the score and identified categories for each IP address found.
    def check_ip_addresses(self, email):
        email = email.body + " " + email.subject
        ip_pattern = r'\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b' 
        ips = re.findall(ip_pattern, email)
        for ip in ips:
            self.score += 15  # Add points for each IP address found
            self.identified_categories.append("IP Address")
            print(f"identified IP address: {ip}")
    #checks for URLs in the email content and subject, evaluating the risk based on the country associated with the URL's IP address and updating the score and identified categories accordingly.
    def check_links(self, email):
        email = email.body + " " + email.subject
        url_pattern = r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?'
        self.links = re.findall(url_pattern, email)
        reportData = ""
        with open('domainCountries.json', 'r') as f:
            domainCountries = {item["country"]: item["risk_score"] for item in json.load(f)}
        for link in self.links:
            print(f"Checking link: {link}")
            reportData += f"URL: {link}\n"
            normalized_link = link if link.startswith(("http://", "https://")) else f"http://{link}"
            parsed_link = urlparse(normalized_link)
            host = parsed_link.hostname # Extract the hostname from the URL for geolocation lookup
            if not host:
                continue
            try:
                ip_address = socket.gethostbyname(host)
            except socket.gaierror:
                continue
            request = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5) # Get geolocation data for the IP address
            response = request.json()
            country = response.get("country", "") # Extract country from the geolocation response
            if country in domainCountries:
                risk_score = domainCountries[country]
                self.score += risk_score
                reportData += f"Country: {country}\nCountry Risk Score: {risk_score}\n"

            self.identified_categories.append("Link")
            print(f"identified link: {link}")
        return reportData
if __name__ == "__main__":
    evaluator = Evaluator()
    email_obj = Emailer("""From: test@example.com
Subject: Test
Date: Mon, 1 Jan 2023 12:00:00
To: user@example.com

ozon.ru""")
    evaluator.evaluate(email_obj)