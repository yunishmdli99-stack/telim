import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
import socket
import requests
from urllib.parse import urlparse
import dns.resolver
import dns.exception

class SubdomainTakeoverChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Subdomain Takeover Checker")
        self.root.geometry("1000x750")

        # Known vulnerable fingerprints (service → error message patterns)
        self.fingerprints = {
            "AWS S3": ["NoSuchBucket", "The specified bucket does not exist", "bucket does not exist"],
            "GitHub Pages": ["There isn't a GitHub Pages site here", "repository not found"],
            "Heroku": ["No such app", "herokuapp.com", "application not found"],
            "Azure": ["App not found", "azurewebsites.net", "The resource you are looking for has been removed"],
            "Netlify": ["Page not found", "netlify.app", "Not found - Request ID"],
            "Vercel": ["The page could not be found", "vercel.app", "DEPLOYMENT_NOT_FOUND"],
            "Shopify": ["Sorry, this shop is currently unavailable", "shopify.com"],
            "Tumblr": ["There's nothing here", "tumblr.com"],
            "Fastly": ["Fastly error: unknown domain"],
            "Pantheon": ["The gods are wise, but the fates are wiser"],
            "Surge.sh": ["project not found"],
        }

        self.create_widgets()

    def create_widgets(self):
        # === Target / Input Frame ===
        input_frame = ttk.LabelFrame(self.root, text="Subdomains", padding=10)
        input_frame.pack(fill="x", padx=10, pady=8)

        ttk.Label(input_frame, text="Target Domain (optional):").grid(row=0, column=0, sticky="w")
        self.target_domain = ttk.Entry(input_frame, width=50)
        self.target_domain.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(input_frame, text="Load Subdomains from File", command=self.load_file).grid(row=1, column=0, pady=5, padx=5)
        ttk.Button(input_frame, text="Add Single Subdomain", command=self.add_single).grid(row=1, column=1, pady=5, sticky="w")

        # Subdomain list
        list_frame = ttk.Frame(input_frame)
        list_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)

        self.sub_list = tk.Listbox(list_frame, height=8, selectmode="multiple")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.sub_list.yview)
        self.sub_list.configure(yscrollcommand=scrollbar.set)

        self.sub_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # === Controls ===
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=8)

        ttk.Button(control_frame, text="Start Scanning", command=self.start_scan, style="Accent.TButton").pack(side="left", padx=5)
        ttk.Button(control_frame, text="Stop", command=self.stop_scan).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear List", command=self.clear_list).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)

        # === Results Log ===
        log_frame = ttk.LabelFrame(self.root, text="Scan Log & Results", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=28, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True)

        # Style
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Arial", 10, "bold"))

    def log(self, message, color="black"):
        self.log_text.configure(state='normal')
        tag = f"tag_{time.time()}"
        self.log_text.tag_configure(tag, foreground=color)
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')
        self.root.update_idletasks()

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain and not subdomain.startswith("#"):
                            if subdomain not in self.sub_list.get(0, tk.END):
                                self.sub_list.insert(tk.END, subdomain)
                self.log(f"Loaded subdomains from {file_path}", "blue")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def add_single(self):
        subdomain = tk.simpledialog.askstring("Add Subdomain", "Enter subdomain (e.g. dev.example.com):")
        if subdomain:
            subdomain = subdomain.strip()
            if subdomain and subdomain not in self.sub_list.get(0, tk.END):
                self.sub_list.insert(tk.END, subdomain)
                self.log(f"Added: {subdomain}", "green")

    def clear_list(self):
        self.sub_list.delete(0, tk.END)

    def clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')

    def get_cname(self, subdomain):
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except (dns.exception.DNSException, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None
        except Exception:
            return None

    def check_takeover(self, subdomain):
        self.log(f"Checking → {subdomain}")

        # Try to resolve CNAME first
        cname = self.get_cname(subdomain)
        if cname:
            self.log(f"   CNAME: {cname}", "blue")

        # Fetch HTTP response
        try:
            url = f"http://{subdomain}" if not subdomain.startswith("http") else subdomain
            headers = {"User-Agent": "Subdomain-Takeover-Checker"}
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            content = response.text.lower()
            status = response.status_code

            self.log(f"   Status: {status} | Length: {len(content)}", "black")

            # Check fingerprints
            for service, patterns in self.fingerprints.items():
                for pattern in patterns:
                    if pattern.lower() in content:
                        self.log(f"   *** POTENTIAL TAKEOVER DETECTED ***", "red")
                        self.log(f"   Service: {service} | Pattern matched: {pattern}", "red")
                        self.log(f"   → Vulnerable! Attacker may claim {cname or subdomain}", "red")
                        return True

            if status in [404, 410, 503] and cname:
                self.log(f"   Possible dangling record (status {status}) – manual verification recommended", "orange")

        except requests.exceptions.RequestException as e:
            self.log(f"   Connection error: {str(e)[:100]}", "gray")
        except Exception as e:
            self.log(f"   Error: {e}", "gray")

        return False

    def scan_worker(self):
        subdomains = list(self.sub_list.get(0, tk.END))
        if not subdomains:
            messagebox.showwarning("Warning", "No subdomains to check!")
            return

        self.log("=== Subdomain Takeover Scan Started ===", "green")
        self.log(f"Total subdomains: {len(subdomains)}\n")

        vulnerable_count = 0

        for i, sub in enumerate(subdomains, 1):
            try:
                self.log(f"[{i}/{len(subdomains)}] Scanning {sub}")
                if self.check_takeover(sub):
                    vulnerable_count += 1
                time.sleep(0.8)  # Be respectful to targets
            except Exception as e:
                self.log(f"Unexpected error on {sub}: {e}", "red")

        self.log("\n=== Scan Completed ===", "green")
        self.log(f"Total checked: {len(subdomains)} | Potential takeovers: {vulnerable_count}", 
                 "red" if vulnerable_count > 0 else "green")

    def start_scan(self):
        threading.Thread(target=self.scan_worker, daemon=True).start()

    def stop_scan(self):
        self.log("Stop requested (current check will finish)...", "orange")


if __name__ == "__main__":
    root = tk.Tk()
    app = SubdomainTakeoverChecker(root)
    root.mainloop()
