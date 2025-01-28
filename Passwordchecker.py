import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from passlib.hash import pbkdf2_sha256
import fpdf
import re
import requests


class PasswordPolicyChecker:
    def __init__(self, min_length=8, max_length=64, require_upper=True, require_lower=True,
                 require_digit=True, require_special=True, avoid_common=True):
        self.min_length = min_length
        self.max_length = max_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.require_special = require_special
        self.avoid_common = avoid_common
        self.common_passwords = set(["password", "123456", "qwerty", "admin", "welcome"])

    def validate_password(self, password):
        """Validates the password based on the defined policy."""
        errors = []
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long.")
        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters.")
        if self.require_upper and not re.search(r"[A-Z]", password):
            errors.append("Password must include at least one uppercase letter.")
        if self.require_lower and not re.search(r"[a-z]", password):
            errors.append("Password must include at least one lowercase letter.")
        if self.require_digit and not re.search(r"\d", password):
            errors.append("Password must include at least one digit.")
        if self.require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must include at least one special character.")
        if self.avoid_common and password.lower() in self.common_passwords:
            errors.append("Password is too common and easily guessable.")
        return errors

    def password_strength(self, password):
        """Evaluates the strength of a password."""
        score = 0
        if len(password) >= self.min_length:
            score += 1
        if re.search(r"[A-Z]", password):
            score += 1
        if re.search(r"[a-z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        if score <= 2:
            return "Weak"
        elif score == 3:
            return "Moderate"
        else:
            return "Strong"

    def check_breach(self, password):
        """Checks if the password exists in known breaches using Have I Been Pwned API."""
        try:
            sha1_hash = pbkdf2_sha256.hash(password).upper()
            prefix = sha1_hash[:5]
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                hashes = response.text.splitlines()
                return any(sha1_hash[5:] in h for h in hashes)
            return False
        except Exception:
            return None  # Handle network errors gracefully

    def compliance_check(self, password):
        """Checks if the password complies with NIST and ISO/IEC 27001 standards."""
        nist_compliant = len(password) >= 8 and not self.avoid_common
        iso_compliant = len(password) >= 12 and bool(re.search(r"[A-Z]", password)) and bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
        return nist_compliant, iso_compliant


class ReportGenerator:
    def __init__(self, file_name="PasswordReport.pdf"):
        """Initializes a PDF report generator."""
        self.pdf = fpdf.FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.file_name = file_name

    def add_section(self, title, content):
        """Adds a section to the PDF report."""
        self.pdf.add_page()
        self.pdf.set_font("Arial", size=12)
        self.pdf.cell(200, 10, txt=title, ln=True, align='C')
        self.pdf.ln(10)
        for line in content:
            self.pdf.multi_cell(0, 10, txt=line)

    def save(self):
        """Saves the PDF to the specified file."""
        self.pdf.output(self.file_name)


class PasswordCheckerApp:
    def __init__(self, root):
        """Initializes the main GUI application."""
        self.root = root
        self.root.title("Password Policy Checker")
        self.root.geometry("800x600")  # Set initial window size
        self.root.minsize(600, 400)  # Minimum window size
        self.policy_checker = PasswordPolicyChecker()

        # Apply a modern theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Arial", 12), padding=5)
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TEntry", font=("Arial", 12))
        style.configure("TText", font=("Arial", 12))

        # Set up the GUI
        self.setup_gui()

    def setup_gui(self):
        # Frames for layout
        input_frame = ttk.Frame(self.root, padding="10")
        input_frame.pack(fill="x", pady=10)

        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(fill="x", pady=10)

        output_frame = ttk.Frame(self.root, padding="10")
        output_frame.pack(fill="both", expand=True)

        # Input section
        ttk.Label(input_frame, text="Enter Password:").pack(side="left", padx=5)
        self.password_entry = ttk.Entry(input_frame, show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, padx=5)

        # Buttons
        ttk.Button(button_frame, text="Validate", command=self.validate_password).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report).pack(side="left", padx=5)

        # Output section
        self.output_text = tk.Text(output_frame, wrap="word", font=("Arial", 12))
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.output_text.config(state="disabled")  # Disable editing

    def validate_password(self):
        """Validates the entered password and displays results."""
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password field cannot be empty!")
            return

        errors = self.policy_checker.validate_password(password)
        strength = self.policy_checker.password_strength(password)
        breach_status = self.policy_checker.check_breach(password)
        nist, iso = self.policy_checker.compliance_check(password)

        result = f"Password: {password}\n"
        result += f"Strength: {strength}\n"
        result += f"Breached: {'Yes' if breach_status else 'No'}\n"
        result += f"NIST Compliant: {'Yes' if nist else 'No'}\n"
        result += f"ISO/IEC 27001 Compliant: {'Yes' if iso else 'No'}\n"
        result += "Validation Errors:\n" + "\n".join(errors) if errors else "No Errors"

        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, result)
        self.output_text.config(state="disabled")

    def generate_report(self):
        """Generates a PDF report based on the validation results."""
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                                 filetypes=[("PDF Files", "*.pdf")])
        if not file_path:
            return

        report = ReportGenerator(file_name=file_path)
        content = self.output_text.get(1.0, tk.END).strip().split("\n")
        report.add_section("Password Validation Report", content)
        report.save()
        messagebox.showinfo("Success", f"Report saved at {file_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
