import tkinter
import emailer
import evaluator
import csv
import os

PLACEHOLDER_COLOR = "#7f8a9a"
INPUT_COLOR = "#e0e6f0"

evaluator_instance = evaluator.Evaluator()

def set_placeholder(entry, text): # Set placeholder text for an entry widget
    entry._placeholder = text # Store the placeholder text as an attribute of the entry widget
    entry.insert(0, text) # Insert the placeholder text into the entry widget
    entry.config(fg=PLACEHOLDER_COLOR) # Set the text color to the placeholder color

def clear_placeholder(event): # Clear placeholder text when the entry widget gains focus
    entry = event.widget # Get the entry widget that triggered the event
    if getattr(entry, "_placeholder", None) and entry.get() == entry._placeholder: # Check if the entry widget has a placeholder attribute and if the current text is the placeholder
        entry.delete(0, "end") # Clear the entry widget's text
        entry.config(fg=INPUT_COLOR) # Set the text color to the input color for user input

def restore_placeholder(event):
    entry = event.widget
    if getattr(entry, "_placeholder", None) and not entry.get().strip():
        entry.insert(0, entry._placeholder)
        entry.config(fg=PLACEHOLDER_COLOR)

def get_entry_value(entry): # Retrieve the value from an entry widget, returning an empty string if it's the placeholder or empty
    value = entry.get().strip() # Get the current text from the entry widget and remove leading/trailing whitespace
    if getattr(entry, "_placeholder", None) and value == entry._placeholder: # Check if the entry widget has a placeholder attribute and if the current text is the placeholder
        return "" # Return an empty string if the current text is the placeholder
    return value

def extract_email(sender_str): # Extract email address from 'Name <email@domain.com>' format
    """Extract email address from 'Name <email@domain.com>' format."""
    if not sender_str:
        return "Unknown Sender"
    import re # Use regular expression to find an email address in the sender string
    match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', sender_str)
    if match:
        return match.group(0).lower()
    return sender_str.lower() if sender_str else "Unknown Sender"

def normalize_subject(subject_str): 
    """Truncate subject to 100 chars and use fallback if empty."""
    if not subject_str or subject_str == "No subject":
        return "[No Subject]"
    return subject_str[:100]

def on_click(text=None):
    if text: # If text is provided, use it as the email content (for testing purposes)
        email_content = text
    else:
        email_content = body_input.get("1.0", "end-1c")
    
    if not email_content.strip():
        print("No email content provided.")
        return
    
    from datetime import datetime
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    userInput = emailer.Emailer(email_content)
    subject_value = get_entry_value(subject_input)
    sender_value = get_entry_value(sender_input)

    if subject_value:
        userInput.subject = subject_value
    if sender_value:
        userInput.sender = sender_value

    result = evaluator_instance.evaluate(userInput)
    
    cleaned_subject = normalize_subject(userInput.subject)
    cleaned_sender = extract_email(userInput.sender)
    
    results_text = f"Subject: {cleaned_subject}\nScan Time: {scan_time}\nSender: {cleaned_sender}\nScore: {min(result['Score'], 100)}/100\nRisk Level: {result['Risk Level']}\nMessage: {result['Message']}\nAdvice: {result['Advice']}"
    level_colors = {
    "Low Risk": SAFE,
    "Suspicious": WARNING,
    "High Risk": WARNING,
    "Critical": DANGER,
    "Severe": DANGER
    }
    color = level_colors.get(result["Risk Level"], TEXT)
    resilts_label.config(text=results_text, fg=color)
    if not os.path.exists('history.csv') or os.path.getsize('history.csv') == 0:
        with open('history.csv', 'w', newline='') as csvfile: # Create the history.csv file and write the header if it doesn't exist or is empty
            writer = csv.writer(csvfile) 
            writer.writerow(["Subject", "Scan_Time", "Sender", "Risk_Level", "Score"])
    with open('history.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([cleaned_subject, scan_time, cleaned_sender, result['Risk Level'], evaluator_instance.score])

BG         = "#0a0e1a"
SECONDARY  = "#131929"
ACCENT     = "#0078d4"
SAFE       = "#2ecc71"
WARNING    = "#f39c12"
DANGER     = "#e63946"
TEXT       = "#e0e6f0"

window = tkinter.Tk()
window.title("PhishGuard")
window.configure(bg=BG)
window.geometry("600x700")

header = tkinter.Label(
    window,
    text="🐠PhishGuard🛡️",
    bg=ACCENT,
    fg=TEXT,
    font=("Consolas", 20, "bold"),
    pady=15
)
header.pack(fill="x")

input_frame = tkinter.Frame(window, bg=SECONDARY, padx=20, pady=20)
input_frame.pack(fill="both", expand=True, padx=20, pady=20)

input_label = tkinter.Label(input_frame, text="Email Details", bg=SECONDARY, fg=TEXT, font=("Consolas", 14, "bold"))
input_label.place(relx=0.5, rely=0.03, anchor="center")

subject_label = tkinter.Label(input_frame, text='Subject:', bg=SECONDARY, fg=TEXT, font=("Consolas", 11))
subject_label.place(relx=0.04, rely=0.13, anchor="nw")
subject_input = tkinter.Entry(input_frame, bg=BG, fg=TEXT, font=("Consolas", 12), insertbackground=TEXT)
subject_input.place(relx=0.22, rely=0.13, anchor="nw", relwidth=0.74)
set_placeholder(subject_input, "Example: Password reset notice")
subject_input.bind("<FocusIn>", clear_placeholder)
subject_input.bind("<FocusOut>", restore_placeholder)

sender_label = tkinter.Label(input_frame, text='Sender:', bg=SECONDARY, fg=TEXT, font=("Consolas", 11))
sender_label.place(relx=0.04, rely=0.22, anchor="nw")
sender_input = tkinter.Entry(input_frame, bg=BG, fg=TEXT, font=("Consolas", 12), insertbackground=TEXT)
sender_input.place(relx=0.22, rely=0.22, anchor="nw", relwidth=0.74)
set_placeholder(sender_input, "Example: Security Team <security@example.com>")
sender_input.bind("<FocusIn>", clear_placeholder)
sender_input.bind("<FocusOut>", restore_placeholder)

body_label = tkinter.Label(input_frame, text='Email Body:', bg=SECONDARY, fg=TEXT, font=("Consolas", 11))
body_label.place(relx=0.04, rely=0.40, anchor="nw")

body_input = tkinter.Text(input_frame, height=15, bg=BG, fg=TEXT, font=("Consolas", 12), insertbackground=TEXT)
body_input.place(relx=0.04, rely=0.45, anchor="nw", relwidth=0.92, relheight=0.34)

resilts_label = tkinter.Label(input_frame, text='', bg=SECONDARY, fg=TEXT, font=("Consolas", 12))
resilts_label.place(relx=0.52, rely=0.90, anchor="center")

evaluate_button = tkinter.Button(input_frame, text="Evaluate Email", bg=ACCENT, fg=TEXT, font=("Consolas", 12, "bold"), padx=10, pady=5, command=lambda: on_click())
evaluate_button.place(relx=0.26, rely=0.90, anchor="center")

clearCsv_button = tkinter.Button(input_frame, text="Clear History", bg=DANGER, fg=TEXT, font=("Consolas", 12, "bold"), padx=10, pady=5, command=lambda: open('history.csv', 'w').close())
clearCsv_button.place(relx=0.74, rely=0.90, anchor="center")
window.mainloop()