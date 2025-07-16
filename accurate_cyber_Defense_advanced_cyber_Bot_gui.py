import sys
import socket
import threading
import time
import datetime
import json
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
from collections import defaultdict
import psutil
import platform
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Menu, filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import logging
from logging.handlers import RotatingFileHandler

# Constants
CONFIG_FILE = "cyber_monitor_config.json"
LOG_FILE = "cyber_monitor.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
MAX_LOG_BACKUPS = 5

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=MAX_LOG_BACKUPS),
        logging.StreamHandler()
    ]
)

class CyberMonitor:
    def __init__(self):
        self.monitoring = False
        self.target_ip = None
        self.telegram_enabled = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.thresholds = {
            'port_scan': 10,  # Ports scanned within 10 seconds
            'dos_attack': 100,  # Packets per second
            'http_flood': 50,  # HTTP requests per second
            'unusual_traffic': 1000  # Packets per second from single IP
        }
        self.stats = {
            'total_packets': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'threats_detected': 0,
            'port_scans': 0,
            'dos_attacks': 0,
            'http_floods': 0,
            'unusual_traffic': 0
        }
        self.packet_counts = defaultdict(int)
        self.port_access_counts = defaultdict(lambda: defaultdict(int))
        self.http_request_counts = defaultdict(int)
        self.last_reset_time = time.time()
        self.sniffer_thread = None
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.telegram_enabled = config.get('telegram_enabled', False)
                self.telegram_token = config.get('telegram_token')
                self.telegram_chat_id = config.get('telegram_chat_id')
                self.thresholds = config.get('thresholds', self.thresholds)
        except FileNotFoundError:
            logging.warning("Configuration file not found, using defaults")
        except json.JSONDecodeError:
            logging.error("Invalid configuration file, using defaults")

    def save_config(self):
        """Save configuration to file"""
        config = {
            'telegram_enabled': self.telegram_enabled,
            'telegram_token': self.telegram_token,
            'telegram_chat_id': self.telegram_chat_id,
            'thresholds': self.thresholds
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)

    def start_monitoring(self, ip):
        """Start monitoring a specific IP address"""
        if self.monitoring:
            self.stop_monitoring()
        
        self.target_ip = ip
        self.monitoring = True
        self.stats = {k: 0 for k in self.stats}  # Reset stats
        self.packet_counts.clear()
        self.port_access_counts.clear()
        self.http_request_counts.clear()
        self.last_reset_time = time.time()
        
        self.sniffer_thread = threading.Thread(target=self._packet_sniffer, daemon=True)
        self.sniffer_thread.start()
        
        logging.info(f"Started monitoring IP: {ip}")
        self.send_telegram_alert(f"🚨 Started monitoring IP: {ip}")
        
        # Start periodic stats reset
        threading.Thread(target=self._periodic_stats_reset, daemon=True).start()

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2)
        
        logging.info("Stopped monitoring")
        self.send_telegram_alert("🛑 Stopped monitoring")

    def _periodic_stats_reset(self):
        """Periodically reset counters to detect bursts"""
        while self.monitoring:
            time.sleep(10)  # Reset every 10 seconds
            self.packet_counts.clear()
            self.http_request_counts.clear()
            self.last_reset_time = time.time()

    def _packet_sniffer(self):
        """Packet sniffer using scapy"""
        filter_str = f"host {self.target_ip}" if self.target_ip else ""
        
        while self.monitoring:
            try:
                sniff(prn=self._analyze_packet, filter=filter_str, store=0, count=100, timeout=5)
            except Exception as e:
                logging.error(f"Packet sniffing error: {str(e)}")
                time.sleep(1)

    def _analyze_packet(self, packet):
        """Analyze individual packets for threats"""
        if not self.monitoring:
            return
        
        self.stats['total_packets'] += 1
        
        # Record packet counts by source IP
        if IP in packet:
            src_ip = packet[IP].src
            self.packet_counts[src_ip] += 1
            
            # Check for unusual traffic (potential DoS)
            if self.packet_counts[src_ip] > self.thresholds['unusual_traffic']:
                self.stats['unusual_traffic'] += 1
                self.stats['threats_detected'] += 1
                alert_msg = f"⚠️ Unusual traffic detected from {src_ip} ({self.packet_counts[src_ip]} packets)"
                logging.warning(alert_msg)
                self.send_telegram_alert(alert_msg)
            
            # Check for port scanning
            if TCP in packet:
                self.stats['tcp'] += 1
                dst_port = packet[TCP].dport
                self.port_access_counts[src_ip][dst_port] += 1
                
                # Detect port scan (many unique ports from single IP)
                if len(self.port_access_counts[src_ip]) > self.thresholds['port_scan']:
                    self.stats['port_scans'] += 1
                    self.stats['threats_detected'] += 1
                    alert_msg = f"🔍 Port scan detected from {src_ip} ({len(self.port_access_counts[src_ip])} ports)"
                    logging.warning(alert_msg)
                    self.send_telegram_alert(alert_msg)
                
                # Check for HTTP flood
                if dst_port == 80 or dst_port == 443:
                    self.http_request_counts[src_ip] += 1
                    if self.http_request_counts[src_ip] > self.thresholds['http_flood']:
                        self.stats['http_floods'] += 1
                        self.stats['threats_detected'] += 1
                        protocol = "HTTP" if dst_port == 80 else "HTTPS"
                        alert_msg = f"🌊 {protocol} flood detected from {src_ip} ({self.http_request_counts[src_ip]} requests)"
                        logging.warning(alert_msg)
                        self.send_telegram_alert(alert_msg)
            
            elif UDP in packet:
                self.stats['udp'] += 1
                # UDP flood detection could be added here
            
            elif ICMP in packet:
                self.stats['icmp'] += 1
                # ICMP flood (ping flood) detection could be added here

    def send_telegram_alert(self, message):
        """Send alert to Telegram"""
        if not self.telegram_enabled or not self.telegram_token or not self.telegram_chat_id:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            response = requests.post(url, data=payload, timeout=5)
            if response.status_code != 200:
                logging.error(f"Telegram API error: {response.text}")
        except Exception as e:
            logging.error(f"Failed to send Telegram alert: {str(e)}")

    def get_network_info(self):
        """Get network interface information"""
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_io_counters(pernic=True)
        info = []
        
        for name, addrs in interfaces.items():
            interface_info = {
                'name': name,
                'addresses': [],
                'stats': stats.get(name, {})
            }
            for addr in addrs:
                interface_info['addresses'].append({
                    'family': addr.family.name,
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
            info.append(interface_info)
        
        return info

    def ping(self, ip):
        """Ping an IP address"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True, output
        except subprocess.CalledProcessError as e:
            return False, e.output

    def traceroute(self, ip):
        """Perform traceroute to an IP address"""
        param = '-d' if platform.system().lower() == 'windows' else ''
        command = ['tracert', param, ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True, output
        except subprocess.CalledProcessError as e:
            return False, e.output

class CyberMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.monitor = CyberMonitor()
        self.setup_ui()
        self.setup_menu()
        self.setup_themes()
        self.current_theme = "orange"
        self.apply_theme(self.current_theme)

    def setup_ui(self):
        """Set up the main user interface"""
        self.root.title("Accurate Cyber Defense Advanced Threat Monitoring Tool Bot")
        self.root.geometry("1200x800")
        
        # Create paned window for resizable panels
        main_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # Left panel - Controls and terminal
        left_panel = ttk.Frame(main_pane, width=300)
        main_pane.add(left_panel)
        
        # Right panel - Dashboard and visualizations
        right_panel = ttk.Frame(main_pane)
        main_pane.add(right_panel)
        
        # Setup left panel components
        self.setup_control_panel(left_panel)
        self.setup_terminal_panel(left_panel)
        
        # Setup right panel components
        self.setup_dashboard_panel(right_panel)
        self.setup_visualization_panel(right_panel)
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def setup_menu(self):
        """Set up the menu bar"""
        menubar = Menu(self.root)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Log", command=self.save_log)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dark Theme", command=lambda: self.apply_theme("black_green"))
        view_menu.add_command(label="Orange Theme", command=lambda: self.apply_theme("orange"))
        view_menu.add_command(label="Red Theme", command=lambda: self.apply_theme("red"))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Network Info", command=self.show_network_info)
        tools_menu.add_command(label="Ping Tool", command=self.show_ping_tool)
        tools_menu.add_command(label="Traceroute", command=self.show_traceroute_tool)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Telegram Settings", command=self.show_telegram_settings)
        settings_menu.add_command(label="Threshold Settings", command=self.show_threshold_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)

    def setup_themes(self):
        """Define color themes"""
        self.themes = {
            "orange": {
                "bg": "#f5f5f5",
                "fg": "#333333",
                "button_bg": "#ff8c00",
                "button_fg": "white",
                "terminal_bg": "black",
                "terminal_fg": "white",
                "highlight": "#ff8c00"
            },
            "black_green": {
                "bg": "#121212",
                "fg": "#00ff00",
                "button_bg": "#003300",
                "button_fg": "#00ff00",
                "terminal_bg": "black",
                "terminal_fg": "#00ff00",
                "highlight": "#00ff00"
            },
            "red": {
                "bg": "#121212",
                "fg": "#ff3333",
                "button_bg": "#330000",
                "button_fg": "#ff3333",
                "terminal_bg": "black",
                "terminal_fg": "#ff3333",
                "highlight": "#ff3333"
            }
        }

    def apply_theme(self, theme_name):
        """Apply the selected theme"""
        theme = self.themes.get(theme_name, self.themes["orange"])
        self.current_theme = theme_name
        
        # Apply to root and all widgets
        self.root.config(bg=theme["bg"])
        
        # Apply to all ttk widgets
        style = ttk.Style()
        style.configure(".", background=theme["bg"], foreground=theme["fg"])
        style.configure("TFrame", background=theme["bg"])
        style.configure("TLabel", background=theme["bg"], foreground=theme["fg"])
        style.configure("TButton", background=theme["button_bg"], foreground=theme["button_fg"])
        style.configure("TEntry", fieldbackground=theme["terminal_bg"], foreground=theme["terminal_fg"])
        style.configure("TCombobox", fieldbackground=theme["terminal_bg"], foreground=theme["terminal_fg"])
        
        # Apply to terminal
        self.terminal.config(
            bg=theme["terminal_bg"],
            fg=theme["terminal_fg"],
            insertbackground=theme["terminal_fg"]
        )
        
        # Update status bar
        self.status_bar.config(background=theme["highlight"], foreground="white")

    def setup_control_panel(self, parent):
        """Set up the control panel with monitoring controls"""
        control_frame = ttk.LabelFrame(parent, text="Monitoring Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP Address Entry
        ttk.Label(control_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(control_frame)
        self.ip_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Start/Stop Buttons
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=1, column=0, columnspan=2, pady=5, sticky=tk.EW)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=0, columnspan=2, pady=5, sticky=tk.EW)
        
        # Telegram Alert Toggle
        self.telegram_var = tk.BooleanVar(value=self.monitor.telegram_enabled)
        telegram_check = ttk.Checkbutton(
            control_frame, 
            text="Enable Telegram Alerts", 
            variable=self.telegram_var,
            command=self.toggle_telegram_alerts
        )
        telegram_check.grid(row=3, column=0, columnspan=2, pady=5, sticky=tk.W)
        
        # Configure grid weights
        control_frame.columnconfigure(1, weight=1)

    def setup_terminal_panel(self, parent):
        """Set up the terminal/command panel"""
        terminal_frame = ttk.LabelFrame(parent, text="Terminal", padding=10)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Terminal output
        self.terminal = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            state='disabled',
            height=10
        )
        self.terminal.pack(fill=tk.BOTH, expand=True)
        
        # Command input
        cmd_frame = ttk.Frame(terminal_frame)
        cmd_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.cmd_entry = ttk.Entry(cmd_frame)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        ttk.Button(cmd_frame, text="Send", command=self.execute_command).pack(side=tk.RIGHT)

    def setup_dashboard_panel(self, parent):
        """Set up the dashboard panel with statistics"""
        dashboard_frame = ttk.LabelFrame(parent, text="Dashboard", padding=10)
        dashboard_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Stats display
        self.stats_text = scrolledtext.ScrolledText(
            dashboard_frame,
            wrap=tk.WORD,
            state='disabled',
            height=10
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Update stats periodically
        self.update_stats()

    def setup_visualization_panel(self, parent):
        """Set up the visualization panel with charts"""
        viz_frame = ttk.LabelFrame(parent, text="Threat Visualization", padding=10)
        viz_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create a figure for matplotlib
        self.figure = plt.Figure(figsize=(6, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=viz_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Update charts periodically
        self.update_charts()

    def update_stats(self):
        """Update the statistics display"""
        if self.monitor.monitoring:
            stats = self.monitor.stats
            text = f"""
            Monitoring Target: {self.monitor.target_ip}
            Status: {'Active' if self.monitor.monitoring else 'Inactive'}
            
            Packet Statistics:
            - Total Packets: {stats['total_packets']}
            - TCP Packets: {stats['tcp']}
            - UDP Packets: {stats['udp']}
            - ICMP Packets: {stats['icmp']}
            
            Threats Detected:
            - Total Threats: {stats['threats_detected']}
            - Port Scans: {stats['port_scans']}
            - DoS Attacks: {stats['dos_attacks']}
            - HTTP/HTTPS Floods: {stats['http_floods']}
            - Unusual Traffic: {stats['unusual_traffic']}
            """
            
            self.stats_text.config(state='normal')
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, text)
            self.stats_text.config(state='disabled')
        
        # Schedule next update
        self.root.after(1000, self.update_stats)

    def update_charts(self):
        """Update the threat visualization charts"""
        if self.monitor.monitoring:
            stats = self.monitor.stats
            
            # Clear previous figure
            self.figure.clear()
            
            # Create pie chart for packet types
            ax1 = self.figure.add_subplot(121)
            packet_types = ['TCP', 'UDP', 'ICMP']
            packet_counts = [stats['tcp'], stats['udp'], stats['icmp']]
            ax1.pie(packet_counts, labels=packet_types, autopct='%1.1f%%')
            ax1.set_title('Packet Types')
            
            # Create bar chart for threats
            ax2 = self.figure.add_subplot(122)
            threat_types = ['Port Scans', 'DoS', 'HTTP Flood', 'Unusual']
            threat_counts = [
                stats['port_scans'],
                stats['dos_attacks'],
                stats['http_floods'],
                stats['unusual_traffic']
            ]
            ax2.bar(threat_types, threat_counts)
            ax2.set_title('Detected Threats')
            
            # Adjust layout and draw
            self.figure.tight_layout()
            self.canvas.draw()
        
        # Schedule next update
        self.root.after(5000, self.update_charts)

    def start_monitoring(self):
        """Start monitoring the specified IP"""
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        try:
            socket.inet_aton(ip)  # Validate IP address
        except socket.error:
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        self.monitor.start_monitoring(ip)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.append_to_terminal(f"Started monitoring {ip}")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitor.stop_monitoring()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.append_to_terminal("Stopped monitoring")

    def toggle_telegram_alerts(self):
        """Toggle Telegram alerts"""
        self.monitor.telegram_enabled = self.telegram_var.get()
        self.monitor.save_config()
        status = "enabled" if self.monitor.telegram_enabled else "disabled"
        self.append_to_terminal(f"Telegram alerts {status}")

    def execute_command(self, event=None):
        """Execute terminal command"""
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        
        if not cmd:
            return
        
        self.append_to_terminal(f"> {cmd}")
        
        # Process commands
        if cmd.lower() == "help":
            self.show_help()
        elif cmd.lower() == "exit":
            self.root.quit()
        elif cmd.lower().startswith("ping "):
            ip = cmd[5:].strip()
            self.execute_ping(ip)
        elif cmd.lower().startswith("start monitoring "):
            ip = cmd[17:].strip()
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, ip)
            self.start_monitoring()
        elif cmd.lower() == "stop":
            self.stop_monitoring()
        elif cmd.lower() in ["ifconfig", "ifconfig /all"]:
            self.show_network_info()
        elif cmd.lower() == "netstat":
            self.show_network_stats()
        elif cmd.lower().startswith("tracert "):
            ip = cmd[8:].strip()
            self.execute_traceroute(ip)
        else:
            self.append_to_terminal(f"Unknown command: {cmd}")

    def append_to_terminal(self, text):
        """Append text to the terminal"""
        self.terminal.config(state='normal')
        self.terminal.insert(tk.END, f"{text}\n")
        self.terminal.config(state='disabled')
        self.terminal.see(tk.END)

    def execute_ping(self, ip):
        """Execute ping command"""
        success, output = self.monitor.ping(ip)
        self.append_to_terminal(output)

    def execute_traceroute(self, ip):
        """Execute traceroute command"""
        success, output = self.monitor.traceroute(ip)
        self.append_to_terminal(output)

    def show_network_info(self):
        """Display network interface information"""
        info = self.monitor.get_network_info()
        text = "Network Interfaces:\n\n"
        
        for interface in info:
            text += f"Interface: {interface['name']}\n"
            for addr in interface['addresses']:
                text += f"  {addr['family']}: {addr['address']}\n"
            text += "\n"
        
        self.append_to_terminal(text)

    def show_network_stats(self):
        """Display network statistics"""
        stats = psutil.net_io_counters()
        text = f"""
        Network Statistics:
        - Bytes Sent: {stats.bytes_sent}
        - Bytes Received: {stats.bytes_recv}
        - Packets Sent: {stats.packets_sent}
        - Packets Received: {stats.packets_recv}
        - Errors In: {stats.errin}
        - Errors Out: {stats.errout}
        - Drops In: {stats.dropin}
        - Drops Out: {stats.dropout}
        """
        self.append_to_terminal(text)

    def show_telegram_settings(self):
        """Show Telegram settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Telegram Settings")
        dialog.geometry("400x250")
        
        ttk.Label(dialog, text="Telegram Bot Token:").pack(pady=(10, 0))
        token_entry = ttk.Entry(dialog, width=40)
        token_entry.pack(pady=5)
        token_entry.insert(0, self.monitor.telegram_token or "")
        
        ttk.Label(dialog, text="Chat ID:").pack(pady=(10, 0))
        chat_id_entry = ttk.Entry(dialog, width=40)
        chat_id_entry.pack(pady=5)
        chat_id_entry.insert(0, self.monitor.telegram_chat_id or "")
        
        def save_settings():
            self.monitor.telegram_token = token_entry.get().strip()
            self.monitor.telegram_chat_id = chat_id_entry.get().strip()
            self.monitor.save_config()
            dialog.destroy()
            messagebox.showinfo("Success", "Telegram settings saved")
        
        ttk.Button(dialog, text="Save", command=save_settings).pack(pady=10)

    def show_threshold_settings(self):
        """Show threshold settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Threshold Settings")
        dialog.geometry("400x300")
        
        thresholds = self.monitor.thresholds
        
        ttk.Label(dialog, text="Port Scan Threshold (ports/10s):").pack(pady=(10, 0))
        port_scan_entry = ttk.Entry(dialog, width=10)
        port_scan_entry.pack(pady=5)
        port_scan_entry.insert(0, str(thresholds['port_scan']))
        
        ttk.Label(dialog, text="DoS Attack Threshold (packets/s):").pack(pady=(10, 0))
        dos_entry = ttk.Entry(dialog, width=10)
        dos_entry.pack(pady=5)
        dos_entry.insert(0, str(thresholds['dos_attack']))
        
        ttk.Label(dialog, text="HTTP Flood Threshold (requests/s):").pack(pady=(10, 0))
        http_entry = ttk.Entry(dialog, width=10)
        http_entry.pack(pady=5)
        http_entry.insert(0, str(thresholds['http_flood']))
        
        ttk.Label(dialog, text="Unusual Traffic Threshold (packets/s):").pack(pady=(10, 0))
        unusual_entry = ttk.Entry(dialog, width=10)
        unusual_entry.pack(pady=5)
        unusual_entry.insert(0, str(thresholds['unusual_traffic']))
        
        def save_settings():
            try:
                self.monitor.thresholds = {
                    'port_scan': int(port_scan_entry.get()),
                    'dos_attack': int(dos_entry.get()),
                    'http_flood': int(http_entry.get()),
                    'unusual_traffic': int(unusual_entry.get())
                }
                self.monitor.save_config()
                dialog.destroy()
                messagebox.showinfo("Success", "Threshold settings saved")
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers")
        
        ttk.Button(dialog, text="Save", command=save_settings).pack(pady=10)

    def show_ping_tool(self):
        """Show ping tool dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping Tool")
        dialog.geometry("500x400")
        
        ttk.Label(dialog, text="IP Address or Hostname:").pack(pady=(10, 0))
        ip_entry = ttk.Entry(dialog, width=30)
        ip_entry.pack(pady=5)
        
        output_text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, height=15)
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def execute_ping():
            ip = ip_entry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address or hostname")
                return
            
            output_text.config(state='normal')
            output_text.insert(tk.END, f"Pinging {ip}...\n")
            output_text.config(state='disabled')
            
            success, result = self.monitor.ping(ip)
            
            output_text.config(state='normal')
            output_text.insert(tk.END, result + "\n")
            output_text.config(state='disabled')
            output_text.see(tk.END)
        
        ttk.Button(dialog, text="Ping", command=execute_ping).pack(pady=5)

    def show_traceroute_tool(self):
        """Show traceroute tool dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Traceroute Tool")
        dialog.geometry("500x400")
        
        ttk.Label(dialog, text="IP Address or Hostname:").pack(pady=(10, 0))
        ip_entry = ttk.Entry(dialog, width=30)
        ip_entry.pack(pady=5)
        
        output_text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, height=15)
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def execute_traceroute():
            ip = ip_entry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address or hostname")
                return
            
            output_text.config(state='normal')
            output_text.insert(tk.END, f"Tracing route to {ip}...\n")
            output_text.config(state='disabled')
            
            success, result = self.monitor.traceroute(ip)
            
            output_text.config(state='normal')
            output_text.insert(tk.END, result + "\n")
            output_text.config(state='disabled')
            output_text.see(tk.END)
        
        ttk.Button(dialog, text="Trace", command=execute_traceroute).pack(pady=5)

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About",
            "Accurate Cyber Defnse Bot Monitoring Tool\n\n"
            "Version 1.0\n"
            "A comprehensive network monitoring solution for detecting "
            "various cyber threats including port scans, DoS attacks, "
            "and unusual network traffic patterns."
        )

    def show_help(self):
        """Show help information"""
        help_text = """
        Available Commands:
        - help: Show this help message
        - ping <IP>: Ping an IP address
        - start monitoring <IP>: Start monitoring an IP address
        - stop: Stop monitoring
        - ifconfig: Show network interface information
        - ifconfig /all: Show detailed network info
        - netstat: Show network statistics
        - tracert <IP>: Trace route to an IP
        - exit: Exit the application
        
        Dashboard Features:
        - Real-time packet statistics
        - Threat detection alerts
        - Visualizations of network activity
        - Telegram integration for alerts
        """
        self.append_to_terminal(help_text)

    def save_log(self):
        """Save terminal log to file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.terminal.get(1.0, tk.END))
                messagebox.showinfo("Success", "Log saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def export_report(self):
        """Export monitoring report"""
        if not self.monitor.monitoring:
            messagebox.showerror("Error", "No active monitoring session to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                stats = self.monitor.stats
                report = f"""
                Accurate Cyber Defense Bot Monitoring Report
                ==============================
                
                Monitoring Target: {self.monitor.target_ip}
                Monitoring Duration: {datetime.datetime.now() - datetime.datetime.fromtimestamp(self.monitor.last_reset_time)}
                
                Packet Statistics:
                - Total Packets: {stats['total_packets']}
                - TCP Packets: {stats['tcp']}
                - UDP Packets: {stats['udp']}
                - ICMP Packets: {stats['icmp']}
                
                Threats Detected:
                - Total Threats: {stats['threats_detected']}
                - Port Scans: {stats['port_scans']}
                - DoS Attacks: {stats['dos_attacks']}
                - HTTP/HTTPS Floods: {stats['http_floods']}
                - Unusual Traffic: {stats['unusual_traffic']}
                
                Report Generated: {datetime.datetime.now()}
                """
                
                with open(file_path, 'w') as f:
                    f.write(report)
                messagebox.showinfo("Success", "Report exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = CyberMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()