import tkinter as tk
from tkinter import scrolledtext, ttk
import os
import json
import subprocess
import threading
from collections import Counter

LOG_FILE = "log.txt"

class LogViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Decoder Log Viewer")
        self.geometry("1200x750")
        self.configure(bg="#f5f5f5")

        # Decoder process management
        self.decoder_process = None
        self.decoder_running = False
        self.decoder_ip = tk.StringVar(value="192.168.3.1")

        # Filter variables
        self.type_var = tk.StringVar(value="All")
        self.addr_var = tk.StringVar(value="All")
        self.adv_addr_var = tk.StringVar(value="All")
        self.type_options = ["All"]
        self.addr_options = ["All"]
        self.adv_addr_options = ["All"]

        # Decoder control section
        decoder_frame = tk.LabelFrame(self, text="Decoder Control", bg="#f5f5f5", font=("Arial", 11, "bold"))
        decoder_frame.pack(fill=tk.X, padx=10, pady=6)
        
        # Control buttons row
        control_row = tk.Frame(decoder_frame, bg="#f5f5f5")
        control_row.pack(fill=tk.X, pady=2)
        
        tk.Label(control_row, text="Decoder IP:", bg="#f5f5f5", font=("Arial", 10)).pack(side=tk.LEFT, padx=(8,2))
        tk.Entry(control_row, textvariable=self.decoder_ip, width=15, font=("Consolas", 11)).pack(side=tk.LEFT, padx=2)
        
        self.start_btn = tk.Button(control_row, text="Start Decoder", command=self.start_decoder, 
                                  bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.start_btn.pack(side=tk.LEFT, padx=8)
        
        self.stop_btn = tk.Button(control_row, text="Stop & Reset", command=self.stop_decoder, 
                                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        self.status_label = tk.Label(control_row, text="Status: Stopped", bg="#f5f5f5", 
                                    font=("Arial", 10), fg="#666")
        self.status_label.pack(side=tk.LEFT, padx=12)
        
        # Terminal section
        terminal_row = tk.Frame(decoder_frame, bg="#f5f5f5")
        terminal_row.pack(fill=tk.X, pady=2)
        
        tk.Label(terminal_row, text="Terminal:", bg="#f5f5f5", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(8,8))
        self.terminal_text = scrolledtext.ScrolledText(terminal_row, height=6, width=80, 
                                                      font=("Consolas", 9), bg="black", fg="white")
        self.terminal_text.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # Filter section
        filter_frame = tk.LabelFrame(self, text="Filter", bg="#f5f5f5", font=("Arial", 11, "bold"))
        filter_frame.pack(fill=tk.X, padx=10, pady=6)
        tk.Label(filter_frame, text="Type:", bg="#f5f5f5", font=("Arial", 10)).pack(side=tk.LEFT, padx=(8,2))
        self.type_combo = ttk.Combobox(filter_frame, textvariable=self.type_var, values=self.type_options, width=15, state="readonly")
        self.type_combo.pack(side=tk.LEFT, padx=2)
        tk.Label(filter_frame, text="Access address:", bg="#f5f5f5", font=("Arial", 10)).pack(side=tk.LEFT, padx=(12,2))
        self.addr_combo = ttk.Combobox(filter_frame, textvariable=self.addr_var, values=self.addr_options, width=20, state="readonly")
        self.addr_combo.pack(side=tk.LEFT, padx=2)
        tk.Label(filter_frame, text="Adv address:", bg="#f5f5f5", font=("Arial", 10)).pack(side=tk.LEFT, padx=(12,2))
        self.adv_addr_combo = ttk.Combobox(filter_frame, textvariable=self.adv_addr_var, values=self.adv_addr_options, width=22, state="readonly")
        self.adv_addr_combo.pack(side=tk.LEFT, padx=2)
        tk.Button(filter_frame, text="Apply", command=self.refresh_log, bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=12)

        # Search section
        search_frame = tk.LabelFrame(self, text="Search", bg="#f5f5f5", font=("Arial", 11, "bold"))
        search_frame.pack(fill=tk.X, padx=10, pady=2)
        tk.Label(search_frame, text="Search:", bg="#f5f5f5", font=("Arial", 10)).pack(side=tk.LEFT, padx=(8,2))
        self.search_var = tk.StringVar()
        tk.Entry(search_frame, textvariable=self.search_var, width=30, font=("Consolas", 11)).pack(side=tk.LEFT, padx=2)
        tk.Button(search_frame, text="Find", command=self.highlight_search, bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=8)

        # Main area: horizontal split
        main_pane = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#f5f5f5")
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Left: statistics
        stats_frame = tk.Frame(main_pane, bg="#f5f5f5")
        self.stats_label = tk.Label(stats_frame, text="", anchor="nw", justify="left", bg="#f5f5f5", font=("Consolas", 11), fg="#333")
        self.stats_label.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        main_pane.add(stats_frame, minsize=340)

        # Right: log content
        content_frame = tk.Frame(main_pane, bg="#fff")
        self.text_area = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, font=("Consolas", 11), bg="#fff", fg="#222", borderwidth=2, relief="groove")
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        main_pane.add(content_frame)

        self.last_size = 0
        self.after(1000, self.refresh_log)

    def which(self, program):
        """Check if program exists in PATH"""
        import shutil
        return shutil.which(program) is not None

    def start_decoder(self):
        """Start the decoder process"""
        if self.decoder_running:
            return
            
        try:
            ip = self.decoder_ip.get().strip()
            if not ip:
                self.terminal_print("Error: No IP specified")
                self.status_label.config(text="Status: Error - No IP specified", fg="#f44336")
                return
                
            # For Windows, try to find decoder executable
            possible_names = ["decoder", "decoder.exe"]
            decoder_path = None
            
            for name in possible_names:
                if os.path.exists(name):
                    decoder_path = name
                    break
                    
            if not decoder_path:
                current_dir = os.getcwd()
                files = os.listdir('.')
                decoder_files = [f for f in files if 'decoder' in f.lower()]
                error_msg = f"decoder not found in {current_dir}"
                if decoder_files:
                    error_msg += f"\nFound files: {decoder_files}"
                self.terminal_print(error_msg)
                self.status_label.config(text="Status: Error - decoder not found", fg="#f44336")
                return
                
            # Clear terminal and show command
            self.terminal_text.delete(1.0, tk.END)
            command = f"{decoder_path} ip:{ip}"
            self.terminal_print(f"Starting: {command}")
            self.terminal_print("─" * 60)
                
            # Start decoder process in background thread
            def run_decoder():
                try:
                    cmd = [decoder_path, f"ip:{ip}"]
                    
                    self.decoder_process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.STDOUT,  # Combine stderr with stdout
                        stdin=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        cwd=os.getcwd()
                    )
                    self.decoder_running = True
                    
                    # Update UI in main thread
                    self.after(0, self.update_decoder_started)
                    
                    # Read output in real time
                    while self.decoder_running and self.decoder_process.poll() is None:
                        output = self.decoder_process.stdout.readline()
                        if output:
                            self.after(0, lambda text=output.strip(): self.terminal_print(text))
                        else:
                            break
                    
                    # Get any remaining output
                    remaining_output, _ = self.decoder_process.communicate()
                    if remaining_output:
                        for line in remaining_output.strip().split('\n'):
                            if line.strip():
                                self.after(0, lambda text=line.strip(): self.terminal_print(text))
                    
                    # Update UI when process ends
                    return_code = self.decoder_process.returncode
                    if return_code != 0 and self.decoder_running:
                        self.after(0, lambda: self.terminal_print(f"Process exited with code: {return_code}"))
                    else:
                        self.after(0, lambda: self.terminal_print("Process ended normally"))
                        
                    self.after(0, self.update_decoder_stopped)
                    
                except Exception as e:
                    self.after(0, lambda: self.terminal_print(f"Error: {str(e)}"))
                    self.after(0, lambda: self.status_label.config(
                        text=f"Status: Error - {str(e)}", fg="#f44336"
                    ))
                    
            threading.Thread(target=run_decoder, daemon=True).start()
            
        except Exception as e:
            self.terminal_print(f"Failed to start: {str(e)}")
            self.status_label.config(text=f"Status: Error - {str(e)}", fg="#f44336")

    def terminal_print(self, text):
        """Print text to terminal with timestamp"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.terminal_text.insert(tk.END, f"[{timestamp}] {text}\n")
        self.terminal_text.see(tk.END)  # Auto scroll to bottom

    def filter_scum3_device(self):
        """Apply preset filter for SCUM3 device (90D7EBB19299)"""
        self.adv_addr_var.set("90D7EBB19299")
        self.refresh_log()

    def clear_all_filters(self):
        """Clear all filters and show all packets"""
        self.type_var.set("All")
        self.addr_var.set("All")
        self.adv_addr_var.set("All")
        self.refresh_log()

    def handle_decoder_crash(self, returncode, error_msg=""):
        """Handle decoder crash and attempt restart if enabled"""
        self.decoder_running = False
        self.restart_count += 1
        
        crash_msg = f"Decoder crashed (exit code: {returncode})"
        if error_msg:
            crash_msg += f" - {error_msg[:100]}"  # Limit error message length
        
        if self.auto_restart.get() and self.restart_count <= self.max_restarts:
            # Attempt restart
            self.status_label.config(
                text=f"Status: Crashed - Restarting... (attempt {self.restart_count}/{self.max_restarts})", 
                fg="#FF9800"
            )
            self.restart_info.config(text=f"Restart {self.restart_count}/{self.max_restarts}: {error_msg[:50] if error_msg else 'Unknown error'}")
            
            # Wait 2 seconds before restart
            self.after(2000, self.restart_decoder)
        else:
            # No restart or max attempts reached
            if self.restart_count > self.max_restarts:
                crash_msg += f" - Max restart attempts ({self.max_restarts}) reached"
            else:
                crash_msg += " - Auto restart disabled"
                
            self.status_label.config(text=f"Status: {crash_msg}", fg="#f44336")
            self.restart_info.config(text=f"Crashed {self.restart_count} times - Last error: {error_msg[:50] if error_msg else 'Unknown'}")
            self.update_decoder_stopped()

    def restart_decoder(self):
        """Restart the decoder after a crash"""
        if not self.decoder_running:  # Make sure we're not already running
            self.start_decoder()

    def stop_decoder(self):
        """Stop the decoder process"""
        if self.decoder_process and self.decoder_running:
            try:
                # For Windows, try multiple ways to stop the process
                if os.name == 'nt':  # Windows
                    # First try terminate
                    self.decoder_process.terminate()
                    # If it doesn't work, use kill
                    import time
                    time.sleep(0.5)  # Give it time to terminate gracefully
                    if self.decoder_process.poll() is None:  # Still running
                        self.decoder_process.kill()
                else:
                    self.decoder_process.terminate()
                
                self.decoder_process = None
                self.decoder_running = False
                self.update_decoder_stopped()
                self.status_label.config(text="Status: Stopped (Process terminated)", fg="#666")
                
            except Exception as e:
                self.status_label.config(text=f"Status: Error stopping - {str(e)}", fg="#f44336")
                # Force reset the state even if there's an error
                self.decoder_process = None
                self.decoder_running = False
                self.restart_count = 0  # Reset restart counter when manually stopped
                self.restart_info.config(text="")
                self.update_decoder_stopped()

    def update_decoder_started(self):
        """Update UI when decoder starts"""
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text=f"Status: Running (ip:{self.decoder_ip.get()})", fg="#4CAF50")

    def update_decoder_stopped(self):
        """Update UI when decoder stops"""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", fg="#666")
        self.decoder_running = False

    def is_near_bottom(self):
        return float(self.text_area.yview()[1]) > 0.98

    def refresh_log(self):
        try:
            if os.path.exists(LOG_FILE):
                yview = self.text_area.yview()
                with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                type_set = set()
                addr_set = set()
                adv_addr_set = set()
                packets = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if line.endswith(',}'):
                        line = line.replace(',}', '}')
                    try:
                        pkt = json.loads(line)
                        type_set.add(pkt.get('type', ''))
                        addr_set.add(pkt.get('access_address', ''))
                        adv_addr_set.add(pkt.get('adv_address', ''))
                        packets.append(pkt)
                    except Exception:
                        continue

                type_list = ["All"] + sorted(type_set)
                addr_list = ["All"] + sorted(addr_set)
                adv_addr_list = ["All"] + sorted(adv_addr_set)
                self.type_combo["values"] = type_list
                self.addr_combo["values"] = addr_list
                self.adv_addr_combo["values"] = adv_addr_list

                if self.type_var.get() not in type_list:
                    self.type_var.set("All")
                if self.addr_var.get() not in addr_list:
                    self.addr_var.set("All")
                if self.adv_addr_var.get() not in adv_addr_list:
                    self.adv_addr_var.set("All")

                filtered_packets = []
                type_counter = Counter()
                adv_addr_counter = Counter()
                payload_counter = Counter()
                for pkt in packets:
                    if self.type_var.get() != "All" and pkt.get('type', '') != self.type_var.get():
                        continue
                    if self.addr_var.get() != "All" and pkt.get('access_address', '') != self.addr_var.get():
                        continue
                    if self.adv_addr_var.get() != "All" and pkt.get('adv_address', '') != self.adv_addr_var.get():
                        continue
                    filtered_packets.append(self.format_packet(pkt))
                    type_counter[pkt.get('type', '')] += 1
                    adv_addr_counter[pkt.get('adv_address', '')] += 1
                    payload_counter[pkt.get('payload', '')] += 1

                # Statistics (left)
                stats = "Type count:\n"
                for k, v in type_counter.most_common():
                    stats += f"  {k:<15}: {v}\n"
                stats += "\nAdv address count:\n"
                for k, v in adv_addr_counter.most_common():
                    stats += f"  {k:<20}: {v}\n"
                if self.adv_addr_var.get() != "All":
                    stats += "\nPayload count (filtered):\n"
                    for k, v in payload_counter.most_common():
                        stats += f"  {k}: {v}\n"
                self.stats_label.config(text=stats)

                self.text_area.delete(1.0, tk.END)
                for pkt_str in filtered_packets:
                    # Insert each line and highlight field names before colon (only right panel)
                    for line in pkt_str.splitlines():
                        start_idx = self.text_area.index(tk.END)
                        self.text_area.insert(tk.END, line + "\n")
                        colon = line.find(":")
                        if colon > 0:
                            # Only highlight the first word (field name)
                            field_end = line.find(" ")
                            if field_end == -1 or field_end > colon:
                                field_end = colon
                            line_start = f"{start_idx}"
                            line_end = f"{start_idx}+{field_end}c"
                            self.text_area.tag_add("field", line_start, line_end)
                    # Add separator and empty line
                    self.text_area.insert(tk.END, "─" * 80 + "\n\n", "sep")
                self.text_area.tag_config("sep", foreground="#bbb")
                self.text_area.tag_config("field", foreground="#1565C0", font=("Consolas", 11, "bold"))
                self.text_area.yview_moveto(yview[0])
                self.last_size = len(lines)
        except Exception as e:
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, f"Error reading log: {e}")
        self.after(1000, self.refresh_log)

    def format_packet(self, pkt):
        payload = pkt.get("payload", "")
        lines = [
            f"{'Type':<15}: {pkt.get('type','')}",
            f"{'Access address':<15}: {pkt.get('access_address','')}",
            f"{'Adv address':<15}: {pkt.get('adv_address','')}",
            f"{'PayLoad_Length':<15}: {pkt.get('payload_len','')}",
            f"{'Payload':<15}: {payload}"
        ]
        return "\n".join(lines)

    def highlight_search(self):
        self.text_area.tag_remove('search', '1.0', tk.END)
        search = self.search_var.get()
        if not search:
            return
        idx = '1.0'
        while True:
            idx = self.text_area.search(search, idx, nocase=1, stopindex=tk.END)
            if not idx:
                break
            lastidx = f"{idx}+{len(search)}c"
            self.text_area.tag_add('search', idx, lastidx)
            idx = lastidx
        self.text_area.tag_config('search', background='#FFF59D', foreground='#000')

    def on_closing(self):
        """Handle window closing"""
        if self.decoder_running:
            self.stop_decoder()
        self.destroy()

if __name__ == "__main__":
    app = LogViewer()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)  # Handle window close properly
    app.mainloop()