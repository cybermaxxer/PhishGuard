## PhishGuard: Project Documentation

### Table of Contents

- [[#Overview]]
- [[#Architecture: How the Files Talk to Each Other]]
- [[#Module 1: emailer.py — The Parser]]
- [[#Module 2: evaluator.py — The Brain]]
- [[#Data Layer: hotWords.json]]
- [[#Data Layer: domainCountries.json]]
- [[#Module 3: main.py — The GUI]]
- [[#The Scoring Algorithm, Visualized]]
- [[#Dependency Map]]
- [[#How to Build This Yourself]]

---

## Overview

PhishGuard is a desktop phishing email analyzer. you paste raw email content into a GUI; the app tears it apart, scores it for risk, and tells you whether it looks legitimate or malicious.

it operates on three signals:

|signal|source|what it catches|
|---|---|---|
|keyword matching|`hotWords.json`|manipulative language, urgency, financial lures|
|ip address detection|`evaluator.py`|raw ips embedded in email body|
|link geolocation|`domainCountries.json` + `ip-api.com`|links resolving to high-risk countries|

all results get logged to `history.csv` for audit purposes.

---

## Architecture: How the Files Talk to Each Other

```
[User types email into GUI]
         |
         v
     main.py
    (tkinter GUI)
         |
         |---> creates Emailer(raw_text)   [emailer.py]
         |         parses subject, sender,
         |         timestamp, body from
         |         the raw string
         |
         |---> passes Emailer object to
               Evaluator.evaluate()         [evaluator.py]
                    |
                    |---> evaluate_hotWords()
                    |     reads hotWords.json
                    |     scans body+subject
                    |     adds score per token
                    |
                    |---> check_ip_addresses()
                    |     finds raw IPs in text
                    |     +15 per IP found
                    |
                    |---> check_links()
                    |     finds all URLs
                    |     resolves each to IP
                    |     geolocates via ip-api.com
                    |     reads domainCountries.json
                    |     adds country risk score
                    |
                    |---> applies threshold logic
                    |     returns dict with score,
                    |     risk level, message, advice
                    |
         main.py receives the dict
         displays result in colored label
         appends row to history.csv
```

---

## Module 1: emailer.py — The Parser

**what it does:** takes a raw string (the full email text) and uses python's built-in `email` library to extract structured fields from it.

**library used:** `email.message_from_string` from the standard library; no installation needed.

**how it works:**

```
[raw email string]
        |
        v
message_from_string(content)
        |
        |--- reads 'From:' header    --> self.sender
        |--- reads 'Subject:' header --> self.subject
        |--- reads 'Date:' header    --> self.timestamp
        |--- reads body payload      --> self.body
```

**the class:**

```python
class Emailer:
    def __init__(self, content):
        self._parsed = message_from_string(content)
        self.body      = self._parsed.get_payload() or "No body"
        self.subject   = self._parsed['Subject']    or "No subject"
        self.timestamp = self._parsed['Date']       or "Unknown date"
        self.sender    = self._parsed['From']       or "Unknown sender"
```

**what `message_from_string` expects:**

the raw string must follow the RFC 2822 email format; headers first, then a blank line, then the body:

```
From: John Doe <john@example.com>
Subject: Hello
Date: Mon, 1 Jan 2023 12:00:00 +0000

This is the body text.
```

if a field is missing, python returns `None`; the `or "fallback"` pattern handles that gracefully.

**what you get back:** an `Emailer` object with four attributes you can access like `email.body`, `email.subject`, etc.

---

## Module 2: evaluator.py — The Brain

this is the scoring engine. it runs three separate checks on the email object and accumulates a `self.score` integer.

### Constructor: what gets initialized

```python
def __init__(self):
    self.reports = 0              # counts how many emails have been evaluated
    self.all_categories = []      # all category names from hotWords.json
    self.identified_categories = [] # categories triggered by this email
    self.links = []               # all URLs found in the email
    self.score = 0                # cumulative risk score
    self.thresholds = [...]       # score ranges mapped to risk labels
```

**key insight:** `self.score` is reset every time `evaluate_hotWords()` runs; so each new email starts from zero.

---

### Check 1: evaluate_hotWords()

**what it does:** loads `hotWords.json`, iterates every category, every token inside that category, and checks if the token appears in the email text using a regex word-boundary match.

**libraries used:**

- `json` — reads the hotWords file
- `re` — regex matching with `\b` word boundaries (so "pay" doesn't accidentally match "payment")

**flow:**

```
[email body + subject concatenated into one string]
         |
         v
for each category in hotWords.json:
    for each token in that category:
        regex: \bTOKEN\b (case-insensitive)
        if match found:
            self.score += token's weight value
            self.identified_categories.append(category name)
```

**word boundary explained simply:** `\b` means "only match this word if it stands alone"; so `\bpay\b` will NOT trigger on "payment" but WILL trigger on "you must pay now".

---

### Check 2: check_ip_addresses()

**what it does:** scans email text for raw IPv4 addresses like `192.168.1.1`. legitimate emails almost never contain raw IPs; phishing emails sometimes link to them to hide the actual domain.

**library used:** `re`

**the regex pattern:**

```
\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:...)){3}\b
```

in plain english: "match exactly four octets (0-255) separated by dots."

**scoring:** every IP found adds 15 to the score.

---

### Check 3: check_links()

**what it does:** finds all URLs in the email, resolves each hostname to an IP, geolocates that IP, then checks the country against `domainCountries.json`.

**libraries used:**

|library|role|
|---|---|
|`re`|finds all URLs with a pattern|
|`urllib.parse.urlparse`|splits a URL into hostname, path, scheme|
|`socket.gethostbyname`|resolves a domain name to an IP address (DNS lookup)|
|`requests`|calls the `ip-api.com` REST API to get geolocation|
|`json`|reads `domainCountries.json`|

**flow:**

```
[find all URLs in body+subject]
         |
         v
for each URL:
    normalize it (add http:// if missing)
    parse out the hostname
    socket.gethostbyname(hostname) --> IP address
    GET http://ip-api.com/json/{ip} --> country name
    if country in domainCountries.json:
        self.score += that country's risk_score
    self.identified_categories.append("Link")
```

**important:** if `socket.gethostbyname` fails (domain doesn't resolve), it raises `socket.gaierror`; the `try/except` block catches it and skips that link silently.

---

### The Threshold System

after all three checks run, `self.score` is compared against this ladder:

|score range|risk level|
|---|---|
|0 to 20|Low Risk|
|21 to 40|Suspicious|
|41 to 60|High Risk|
|61 to 80|Critical|
|81 to 100|Severe|

**category ratio bonus:**

```
IF one category dominates (appears 1.5x more than the second most common):
    THEN add +10 to score
    THEN re-evaluate threshold
```

this catches emails that are laser-focused on one attack type; a pure credential harvesting email is more suspicious than one that casually mentions three different things.

**the evaluate() method returns a dict:**

```python
{
    "Score": 47,
    "Risk Level": "High Risk",
    "Message": "Strong indicators of a phishing attempt.",
    "Advice": "Do not reply or interact..."
}
```

it also writes a `.txt` report file per scan; `report_1.txt`, `report_2.txt`, and so on.

---

## Data Layer: hotWords.json

**what it is:** a weighted keyword dictionary; the fuel that powers `evaluate_hotWords()`.

**structure:**

```json
{
  "rule_metadata": { ... },
  "high_risk_words": {
    "CATEGORY_NAME": {
      "description": "...",
      "tokens": {
        "token_string": SCORE_VALUE
      }
    }
  }
}
```

**the 11 categories:**

|category|what it targets|example high-score token|
|---|---|---|
|urgency_indicators|panic induction|"act immediately" (15)|
|action_indicators|demand for clicks|"verify account" (15)|
|financial_lures|money hooks|"routing number" (15)|
|coercion_and_fear|threat language|"legal action" (18)|
|credential_harvesting|login theft|"recovery phrase" (15)|
|crypto_and_web3|wallet scams|"seed phrase" (20)|
|corporate_and_hr|spear phishing|"direct deposit update" (18)|
|shipping_and_delivery|smishing|"redelivery fee" (15)|
|tech_support_scams|fake renewals|"call to cancel" (18)|
|gift_card_and_advance_fee|classic scams|"buy me a gift card" (20)|
|extortion_and_blackmail|sextortion|"record you" (20)|

**scoring philosophy:** common english words score very low (1-3); aggressive, specific phishing phrases score high (15-20). this prevents false positives on legitimate business emails.

---

## Data Layer: domainCountries.json

**what it is:** a list of countries with an associated risk score. used by `check_links()` after geolocating a URL.

**structure:**

```json
[
  { "country": "Russia", "risk_score": 10 },
  { "country": "Ukraine", "risk_score": 3 }
]
```

the file gets loaded and converted into a dict like `{"Russia": 10, "China": 10, ...}` inside `check_links()` for O(1) lookup:

```python
domainCountries = {item["country"]: item["risk_score"] for item in json.load(f)}
```

**how to extend it:** just add a new json object to the array with a country name matching what `ip-api.com` returns and a risk score between 1 and 10.

---

## Module 3: main.py — The GUI

**library used:** `tkinter` — python's standard GUI library; no installation needed.

**what it builds:**

```
+------------------------------------------+
|  🐠 PhishGuard 🛡️  (header bar, ACCENT)  |
+------------------------------------------+
|  Email Details                            |
|  Subject: [___________________________]   |
|  Sender:  [___________________________]   |
|                                           |
|  Email Body:                              |
|  [                                       ]|
|  [    (multiline text input)             ]|
|                                           |
|  [Evaluate Email]  [result label]  [Clear]|
+------------------------------------------+
```

**the widget types:**

|widget|class|purpose|
|---|---|---|
|window|`Tk()`|root window container|
|header|`Label`|top banner|
|input_frame|`Frame`|groups all inputs|
|subject_input|`Entry`|single-line text field|
|sender_input|`Entry`|single-line text field|
|body_input|`Text`|multiline text area|
|resilts_label|`Label`|displays score output|
|evaluate_button|`Button`|triggers on_click()|
|clearCsv_button|`Button`|wipes history.csv|

**placeholder system:**

the three helper functions `set_placeholder`, `clear_placeholder`, `restore_placeholder` simulate placeholder text (like HTML `placeholder=""`) because tkinter does not have this built-in.

```
on widget load:
    insert placeholder text in gray color

on FocusIn event (user clicks field):
    IF current text == placeholder text:
        clear it; switch to white color

on FocusOut event (user leaves field):
    IF field is empty:
        restore placeholder text in gray
```

**the on_click() function — the orchestrator:**

```
[user clicks Evaluate]
         |
         v
1. grab body_input text
2. create Emailer(body_text)
3. override subject/sender if user filled those fields
4. call evaluator_instance.evaluate(emailer_obj)
5. receive result dict
6. normalize subject (truncate to 100 chars)
7. extract clean email address from "Name <email>" format
8. display results in resilts_label with color based on risk level
9. append row to history.csv
```

**color system:**

|risk level|color|
|---|---|
|Low Risk|`#2ecc71` (green)|
|Suspicious|`#f39c12` (amber)|
|High Risk|`#f39c12` (amber)|
|Critical|`#e63946` (red)|
|Severe|`#e63946` (red)|

**csv logging:**

```
IF history.csv doesn't exist or is empty:
    create it and write header row:
    ["Subject", "Scan_Time", "Sender", "Risk_Level", "Score"]

THEN always append the result row
```

---

## The Scoring Algorithm, Visualized

```
[raw email]
     |
     v
+--[hotWords scan]---> score += weighted token hits
     |
     v
+--[IP scan]---------> score += 15 per raw IP found
     |
     v
+--[link scan]-------> score += country risk per URL
     |
     v
+--[ratio check]-----> score += 10 if one category dominates (1.5x ratio)
     |
     v
+--[cap at 100]------> min(score, 100)
     |
     v
[threshold lookup] --> risk level + message + advice
```

---

## Dependency Map

**standard library (no install needed):**

|module|used in|purpose|
|---|---|---|
|`tkinter`|main.py|GUI rendering|
|`email`|emailer.py|RFC 2822 parsing|
|`json`|evaluator.py|reading .json data files|
|`re`|evaluator.py + main.py|regex matching|
|`socket`|evaluator.py|DNS resolution|
|`csv`|main.py|reading/writing history|
|`os`|main.py|checking if csv exists|
|`collections.Counter`|evaluator.py|counting category frequency|
|`urllib.parse.urlparse`|evaluator.py|splitting URLs|
|`datetime`|main.py|scan timestamp|

**third-party (requires install):**

```bash
pip install requests
```

|module|used in|purpose|
|---|---|---|
|`requests`|evaluator.py|HTTP call to ip-api.com|

---
