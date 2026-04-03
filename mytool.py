import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import Counter
import csv
from datetime import datetime

class TopAttackerIPFinder:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Top Attacker IP Finder")
        self.root.geometry("1000x720")
        self.root.configure(bg="#0f172a")
        
        # Variables
        self.file_path = None
        self.ip_counts = Counter()
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title = tk.Label(self.root, text="Top Attacker IP Finder", 
                        font=("Inter", 24, "bold"), fg="#22d3ee", bg="#0f172a")
        title.pack(pady=20)
        
        subtitle = tk.Label(self.root, text="Analyze failed login attempts • Identify the most aggressive attacker IP",
                           font=("Inter", 12), fg="#94a3b8", bg="#0f172a")
        subtitle.pack(pady=(0, 30))
        
        # Main Frame
        main_frame = tk.Frame(self.root, bg="#1e2937", relief="flat", bd=0)
        main_frame.pack(fill="both", expand=True, padx=40, pady=10)
        
        # Upload Section
        upload_frame = tk.Frame(main_frame, bg="#1e2937")
        upload_frame.pack(fill="x", pady=20)
        
        self.upload_btn = tk.Button(upload_frame, text="📤 Select Log File", 
                                   font=("Inter", 14, "bold"), bg="#22d3ee", fg="#0f172a",
                                   height=2, command=self.select_file)
        self.upload_btn.pack(fill="x", pady=10)
        
        self.file_label = tk.Label(upload_frame, text="No file selected", 
                                  font=("Consolas", 11), fg="#64748b", bg="#1e2937", wraplength=800)
        self.file_label.pack(pady=8)
        
        # Analyze Button
        self.analyze_btn = tk.Button(main_frame, text="🚀 Analyze Failed Login Attempts", 
                                    font=("Inter", 14, "bold"), bg="#06b67f", fg="white",
                                    height=2, state="disabled", command=self.analyze_log)
        self.analyze_btn.pack(fill="x", pady=15)
        
        # Status
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(main_frame, textvariable=self.status_var, 
                                    font=("Inter", 11), fg="#94a3b8", bg="#1e2937")
        self.status_label.pack(pady=5)
        
        # Results Area
        self.results_frame = tk.Frame(main_frame, bg="#1e2937")
        self.results_frame.pack(fill="both", expand=True, pady=20)
        
        # Top Attacker Card
        self.top_frame = tk.Frame(self.results_frame, bg="#1e2937", relief="solid", bd=2, highlightbackground="#ef4444", highlightthickness=2)
        self.top_frame.pack(fill="x", pady=(0, 20))
        
        tk.Label(self.top_frame, text="🚨 TOP ATTACKER IP", font=("Inter", 14, "bold"), 
                fg="#ef4444", bg="#1e2937").pack(pady=(15, 5))
        
        self.top_ip_label = tk.Label(self.top_frame, text="—", font=("Consolas", 28, "bold"), 
                                    fg="#f97316", bg="#1e2937")
        self.top_ip_label.pack(pady=5)
        
        self.top_count_label = tk.Label(self.top_frame, text="0 failed attempts", 
                                       font=("Inter", 16), fg="#94a3b8", bg="#1e2937")
        self.top_count_label.pack(pady=(0, 15))
        
        # Table Frame
        table_frame = tk.Frame(self.results_frame, bg="#1e2937")
        table_frame.pack(fill="both", expand=True)
        
        tk.Label(table_frame, text="Top Attacker IPs", font=("Inter", 14, "bold"), 
                fg="#22d3ee", bg="#1e2937").pack(anchor="w", pady=(0, 10))
        
        # Treeview for results
        columns = ("Rank", "IP Address", "Failed Attempts", "Percentage")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
        
        self.tree.heading("Rank", text="Rank")
        self.tree.heading("IP Address", text="IP Address")
        self.tree.heading("Failed Attempts", text="Failed Attempts")
        self.tree.heading("Percentage", text="Percentage")
        
        self.tree.column("Rank", width=60, anchor="center")
        self.tree.column("IP Address", width=200)
        self.tree.column("Failed Attempts", width=150, anchor="center")
        self.tree.column("Percentage", width=100, anchor="center")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Action Buttons
        btn_frame = tk.Frame(self.results_frame, bg="#1e2937")
        btn_frame.pack(fill="x", pady=20)
        
        tk.Button(btn_frame, text="📤 Export to CSV", font=("Inter", 12, "bold"), 
                 bg="#64748b", fg="white", command=self.export_csv).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="📋 Copy Top IP", font=("Inter", 12, "bold"), 
                 bg="#f59e0b", fg="white", command=self.copy_top_ip).pack(side="left", padx=5)
        
        tk.Button(btn_frame, text="🔄 Analyze Another File", font=("Inter", 12, "bold"), 
                 bg="#ef4444", fg="white", command=self.reset_app).pack(side="right", padx=5)
        
        # Hide results initially
        self.results_frame.pack_forget()
        
    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("Log Files", "*.log *.txt *.csv"),
                ("All Files", "*.*")
            ]
        )
        
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=f"Selected: {file_path.split('/')[-1]}", fg="#22d3ee")
            self.analyze_btn.config(state="normal")
            self.status_var.set("File loaded. Click 'Analyze' to start.")
    
    def analyze_log(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a log file first!")
            return
        
        self.status_var.set("Analyzing log file... Please wait.")
        self.root.update()
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Regex for IPv4
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            # Common failed login keywords
            failed_keywords = [
                'failed password', 'authentication failure', 'login failed',
                'invalid user', 'permission denied', 'bad password',
                'auth failed', 'failed login', 'incorrect password'
            ]
            
            self.ip_counts.clear()
            total_failed = 0
            
            for line in content.splitlines():
                line_lower = line.lower()
                if any(keyword in line_lower for keyword in failed_keywords):
                    ips = ip_pattern.findall(line)
                    for ip in ips:
                        # Basic validation
                        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', ip):
                            self.ip_counts[ip] += 1
                            total_failed += 1
            
            if not self.ip_counts:
                messagebox.showwarning("No Results", 
                    "No failed login attempts were found in this log file.\n\n"
                    "Make sure the log contains phrases like 'Failed password' or 'authentication failure'.")
                self.status_var.set("No failed attempts found.")
                return
            
            self.display_results(total_failed)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze log:\n{str(e)}")
            self.status_var.set("Analysis failed.")
    
    def display_results(self, total_failed):
        # Sort IPs by count (descending)
        sorted_ips = self.ip_counts.most_common()
        top_ip, top_count = sorted_ips[0]
        
        # Update Top Attacker Card
        self.top_ip_label.config(text=top_ip)
        self.top_count_label.config(
            text=f"{top_count:,} failed attempts ({top_count/total_failed*100:.1f}% of total)"
        )
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Populate table
        for rank, (ip, count) in enumerate(sorted_ips[:20], 1):  # Show top 20
            percentage = (count / total_failed) * 100
            self.tree.insert("", "end", values=(
                rank,
                ip,
                f"{count:,}",
                f"{percentage:.1f}%"
            ))
        
        # Show results
        self.results_frame.pack(fill="both", expand=True, pady=20)
        self.status_var.set(f"Analysis complete • {total_failed:,} failed attempts • {len(self.ip_counts)} unique IPs")
        
    def export_csv(self):
        if not self.ip_counts:
            messagebox.showwarning("Nothing to export", "Please analyze a log file first.")
            return
        
        filename = f"attacker_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=filename,
            filetypes=[("CSV Files", "*.csv")]
        )
        
        if filepath:
            try:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Rank", "IP Address", "Failed Attempts", "Percentage"])
                    
                    sorted_ips = self.ip_counts.most_common()
                    total = sum(self.ip_counts.values())
                    
                    for rank, (ip, count) in enumerate(sorted_ips, 1):
                        percentage = (count / total) * 100
                        writer.writerow([rank, ip, count, f"{percentage:.2f}%"])
                
                messagebox.showinfo("Export Successful", f"Results saved to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Export Failed", str(e))
    
    def copy_top_ip(self):
        if not self.ip_counts:
            messagebox.showwarning("No Data", "Please analyze a log file first.")
            return
        
        top_ip = self.ip_counts.most_common(1)[0][0]
        self.root.clipboard_clear()
        self.root.clipboard_append(top_ip)
        messagebox.showinfo("Copied", f"Top attacker IP copied to clipboard:\n{top_ip}")
    
    def reset_app(self):
        self.file_path = None
        self.ip_counts.clear()
        self.file_label.config(text="No file selected", fg="#64748b")
        self.analyze_btn.config(state="disabled")
        self.results_frame.pack_forget()
        self.status_var.set("")
        self.top_ip_label.config(text="—")
        self.top_count_label.config(text="0 failed attempts")


# ====================== RUN THE APPLICATION ======================
if __name__ == "__main__":
    root = tk.Tk()
    app = TopAttackerIPFinder(root)
    root.mainloop()
