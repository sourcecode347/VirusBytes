# VirusBytes.py
# Author : sourcecode347
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import tarfile
import gzip
import io
import tempfile
import threading
import concurrent.futures
import queue
import webbrowser
import logging
import time
import pickle
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
if os.name == 'nt':
    import winreg
    import GPUtil  # For GPU monitoring, install with pip install gputil    
import json
import urllib.parse
import requests
import platform
from PIL import Image, ImageTk  # For image resizing
import sys
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sqlite3
import gc
import signal

# Get script directory for absolute paths
script_dir = os.path.dirname(os.path.abspath(__file__))

# Configure logging to terminal
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

global logoascii
logoascii = '''
░██    ░█░██                        ░████████             ░██                     
░██    ░██                          ░██    ░██            ░██                     
░██    ░█░█░██░███░██    ░██░███████░██    ░██░██    ░█░███████░███████ ░███████  
░██    ░█░█░███   ░██    ░█░██      ░████████ ░██    ░██  ░██ ░██    ░█░██        
 ░██  ░██░█░██    ░██    ░██░███████░██     ░█░██    ░██  ░██ ░█████████░███████  
  ░██░██ ░█░██    ░██   ░███      ░█░██     ░█░██   ░███  ░██ ░██             ░██ 
   ░███  ░█░██     ░█████░██░███████░█████████ ░█████░██   ░███░███████ ░███████  
                                                     ░██                          
                                               ░███████                           
'''
class VirusBytes(FileSystemEventHandler):
    __slots__ = ['root', 'image_path', 'base_image', 'threats_blocked', 'scanning', 'importing', 'updating_urls', 
                 'detected_queue', 'use_all_hashes', 'web_protection_enabled', 'observer_running', 'auto_start_enabled', 
                 'pending_alerts', 'alert_timer', 'sent_history', 'recv_history', 'max_history', 'previous_net', 
                 'paused', 'cancelled', 'pause_event', 'pkl_file', 'db_hashes', 'malicious_pkl', 'db_urls', 
                 'quarantine_dir', 'quarantine_metadata_pkl', 'quarantine_metadata', 'monitored_folders_pkl', 
                 'monitored_folders', 'reports_file', 'reports', 'blocklist_urls', 'style', 'notebook', 
                 'dashboard_frame', 'scan_frame', 'quarantine_frame', 'monitoring_frame', 'settings_frame', 
                 'threats_label', 'scan_history_label', 'logo_image', 'db_count_label', 'urls_count_label', 
                 'import_btn', 'scan_btn', 'pause_btn', 'cancel_btn', 'progress', 'current_label', 'size_label', 
                 'scanned_files_label', 'results_list', 'quarantine_list', 'system_info_label', 'cpu_canvas', 
                 'cpu_label', 'ram_canvas', 'ram_label', 'disk_canvas', 'disk_label', 'gpu_canvas', 'gpu_label', 
                 'fig_sent', 'ax_sent', 'sent_canvas', 'sent_label', 'fig_recv', 'ax_recv', 'recv_canvas', 
                 'recv_label', 'battery_canvas', 'battery_label', 'real_time_var', 'web_protection_var', 
                 'auto_start_var', 'monitored_folders_list', 'observer', 'prev_cpu', 'prev_ram', 
                 'prev_disk', 'prev_gpu', 'prev_battery', 'prev_sent', 'prev_recv', 'hashes_lock', 'urls_lock',
                 'running', 'monitor_thread', 'hashes_lock2', 'settings_pkl']

    def __init__(self, root):
        self.root = root
        self.root.title("VirusBytes - Open Source AntiVirus")
        self.root.geometry("1000x800")
        self.root.configure(bg='#1e1e1e')
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # Handle close properly

        # Load image once for icon, dashboard, and tray using absolute path
        self.image_path = os.path.join(script_dir, 'img', 'VirusBytes.png')
        if os.path.exists(self.image_path):
            self.base_image = Image.open(self.image_path)
            self.root.iconphoto(True, ImageTk.PhotoImage(self.base_image))
        else:
            logging.warning(f"Image file not found: {self.image_path}")
            self.base_image = Image.new('RGB', (64, 64), color=(255, 0, 0))  # Red square if icon not found

        # Initialize state variables
        self.threats_blocked = 0
        self.scanning = False
        self.importing = False
        self.updating_urls = False
        self.detected_queue = queue.Queue()
        self.use_all_hashes = True
        self.web_protection_enabled = True
        self.observer_running = False
        self.auto_start_enabled = self.check_auto_start()
        self.pending_alerts = []
        self.alert_timer = None
        self.sent_history = []
        self.recv_history = []
        self.max_history = 60
        self.previous_net = psutil.net_io_counters()
        self.paused = False
        self.cancelled = False
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.prev_cpu = 0
        self.prev_ram = 0
        self.prev_disk = 0
        self.prev_gpu = 0
        self.prev_battery = 0
        self.prev_sent = 0
        self.prev_recv = 0
        self.running = True
        self.monitor_thread = None

        # Initialize locks for thread-safe DB access
        self.hashes_lock = threading.Lock()
        self.hashes_lock2 = threading.Lock()
        self.urls_lock = threading.Lock()

        # Initialize database paths
        self.pkl_file = os.path.join(script_dir, "virus_hashes.pkl")
        self.db_hashes = os.path.join(script_dir, "virus_hashes.db")
        self.malicious_pkl = os.path.join(script_dir, "malicious_urls.pkl")
        self.db_urls = os.path.join(script_dir, "malicious_urls.db")

        # Initialize databases
        with self.get_hashes_connection() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA synchronous = 0")
            cur.execute("PRAGMA journal_mode = MEMORY")
            cur.execute("CREATE TABLE IF NOT EXISTS hashes (hash TEXT PRIMARY KEY)")
            conn.commit()

        with self.get_urls_connection() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA synchronous = 0")
            cur.execute("PRAGMA journal_mode = MEMORY")
            cur.execute("CREATE TABLE IF NOT EXISTS urls (url TEXT PRIMARY KEY)")
            conn.commit()

        self.load_db()
        self.load_malicious_urls()

        self.quarantine_dir = os.path.join(script_dir, "quarantine")
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

        self.quarantine_metadata_pkl = os.path.join(script_dir, "quarantine_metadata.pkl")
        self.quarantine_metadata = self.load_quarantine_metadata()

        self.monitored_folders_pkl = os.path.join(script_dir, "monitored_folders.pkl")
        self.monitored_folders = set()
        self.load_monitored_folders()
        if not self.monitored_folders:
            self.monitored_folders = set([os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")])
            self.save_monitored_folders()

        self.reports_file = os.path.join(script_dir, "reports.json")
        self.reports = self.load_reports()

        self.blocklist_urls = {"malicious.example.com", "phishing-site.net"}

        # Configure dark theme styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', background='#333333', foreground='white', borderwidth=0)
        self.style.configure('TLabel', background='#1e1e1e', foreground='white')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TProgressbar', troughcolor='#2e2e2e', background='#4CAF50')
        self.style.map('TButton', background=[('active', '#444444')])

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard()

        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="Scan")
        self.setup_scan_tab()

        self.quarantine_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.quarantine_frame, text="Quarantine")
        self.setup_quarantine_tab()

        self.monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitoring_frame, text="Monitoring")
        self.setup_monitoring_tab()

        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_tab()

        self.settings_pkl = os.path.join(script_dir, "settings.pkl")
        self.load_settings()

        self.web_protection_enabled = self.web_protection_var.get()
        if self.real_time_var.get():
            self.start_real_time_monitoring()

        # Start real-time monitoring and other threads
        self.start_system_monitoring()

    def load_settings(self):
        if os.path.exists(self.settings_pkl):
            try:
                with open(self.settings_pkl, 'rb') as f:
                    settings = pickle.load(f)
                self.real_time_var.set(settings.get('real_time', True))
                self.web_protection_var.set(settings.get('web_protection', True))
                logging.debug(f"Loaded settings from {self.settings_pkl}")
            except Exception as e:
                logging.error(f"Failed to load settings: {str(e)}")
                self.real_time_var.set(True)
                self.web_protection_var.set(True)
        else:
            self.real_time_var.set(True)
            self.web_protection_var.set(True)

    def save_settings(self):
        try:
            settings = {
                'real_time': self.real_time_var.get(),
                'web_protection': self.web_protection_var.get()
            }
            with open(self.settings_pkl, 'wb') as f:
                pickle.dump(settings, f)
            logging.debug(f"Saved settings to {self.settings_pkl}")
        except Exception as e:
            logging.error(f"Failed to save settings: {str(e)}")

    def on_close(self):
        self.save_settings()
        try:
            self.running = False
            logging.debug(f"Set Running To False...")
        except:
            pass
        if os.name != 'nt':
            try:
                if hasattr(self, 'observer') and self.observer_running:
                    self.observer.stop()
                    logging.debug(f"OBServer Thread Stop...")
                    self.observer.join()
                    logging.debug(f"OBServer Thread Join...")
            except:
                pass
            try:
                if self.monitor_thread and self.monitor_thread.is_alive():
                    self.monitor_thread.join()
                    logging.debug(f"Monitor Thread Join...")
            except:
                pass
        try:
            self.root.destroy()
            logging.debug(f"Root Destroy...")
        except:
            pass
        if os.name == 'nt':
            try:
                logging.debug(f"My PID is : {os.getpid()}")
                time.sleep(1) 
                logging.debug(f"Sending SIGINT to self...")
                os.kill(os.getpid(), signal.SIGINT)
            except:
                pass
        else:
            try:
                logging.debug(f"My PID is : {os.getpid()}")
                time.sleep(1) 
                logging.debug(f"Trying to Kill {os.getpid()}")
                os.system("kill "+str(os.getpid()))
            except:
                pass

    def get_hashes_connection(self):
        """Create a new SQLite connection for the hashes database."""
        conn = sqlite3.connect(self.db_hashes)
        return conn

    def get_urls_connection(self):
        """Create a new SQLite connection for the URLs database."""
        conn = sqlite3.connect(self.db_urls)
        return conn

    def load_quarantine_metadata(self):
        if os.path.exists(self.quarantine_metadata_pkl):
            try:
                with open(self.quarantine_metadata_pkl, 'rb') as f:
                    data = pickle.load(f)
                # Normalize paths in metadata
                normalized_data = {k: os.path.normpath(v) for k, v in data.items()}
                return normalized_data
            except Exception as e:
                logging.error(f"Failed to load quarantine metadata: {str(e)}")
        return {}

    def save_quarantine_metadata(self):
        try:
            with open(self.quarantine_metadata_pkl, 'wb') as f:
                pickle.dump(self.quarantine_metadata, f)
        except Exception as e:
            logging.error(f"Failed to save quarantine metadata: {str(e)}")

    def add_donate_link(self, parent_frame):
        donate_link = ttk.Label(parent_frame, text="Donate", font=('Arial', 8), foreground='#1E90FF', cursor="hand2")
        donate_link.pack(side=tk.RIGHT, pady=5)
        donate_link.bind("<Button-1>", lambda e: webbrowser.open("https://buy.stripe.com/fZu28keQj5Um1Yk6P01gs00"))
        return donate_link

    def setup_dashboard(self):
        top_frame = ttk.Frame(self.dashboard_frame)
        top_frame.pack(fill=tk.X, pady=5)
        self.add_donate_link(top_frame)

        dashboard_label = ttk.Label(self.dashboard_frame, text="VirusBytes Dashboard", font=('Arial', 14))
        dashboard_label.pack(pady=10)

        self.threats_label = ttk.Label(self.dashboard_frame, text=f"Threats Blocked: {self.threats_blocked}", font=('Arial', 10))
        self.threats_label.pack(pady=5)

        self.scan_history_label = ttk.Label(self.dashboard_frame, text="Last Scan: None", font=('Arial', 10))
        self.scan_history_label.pack(pady=5)

        view_reports_btn = ttk.Button(self.dashboard_frame, text="View Reports", command=self.view_reports)
        view_reports_btn.pack(pady=5)

        clear_reports_btn = ttk.Button(self.dashboard_frame, text="Clear Reports", command=self.clear_reports)
        clear_reports_btn.pack(pady=5)

        # Use resized base_image for dashboard logo
        if hasattr(self, 'base_image'):
            img = self.base_image.resize((256, 256), Image.Resampling.LANCZOS)
            self.logo_image = ImageTk.PhotoImage(img)
            logo_label = ttk.Label(self.dashboard_frame, image=self.logo_image, background='#1e1e1e')
            logo_label.pack(pady=10)

    def setup_scan_tab(self):
        top_frame = ttk.Frame(self.scan_frame)
        top_frame.pack(fill=tk.X, pady=5)

        links_frame = ttk.Frame(top_frame)
        links_frame.pack(side=tk.LEFT, padx=5)

        virusbytes_link = ttk.Label(links_frame, text="Update Virus Database via VirusBytes", font=('Arial', 8), foreground='#1E90FF', cursor="hand2")
        virusbytes_link.pack(anchor=tk.W)
        virusbytes_link.bind("<Button-1>", lambda e: webbrowser.open("https://virusbytes.com/VirusBytesDatabase.cvd"))

        clamav_link = ttk.Label(links_frame, text="Update Virus Database via Clamav", font=('Arial', 8), foreground='#1E90FF', cursor="hand2")
        clamav_link.pack(anchor=tk.W)
        clamav_link.bind("<Button-1>", lambda e: webbrowser.open("https://clamwin.com/content/view/58/27/"))

        self.add_donate_link(top_frame)

        self.db_count_label = ttk.Label(self.scan_frame, text=f"Loaded hashes: {self.get_hash_count()}", font=('Arial', 10))
        self.db_count_label.pack(pady=5)

        self.urls_count_label = ttk.Label(self.scan_frame, text=f"Loaded malicious URLs: {self.get_url_count()}", font=('Arial', 10))
        self.urls_count_label.pack(pady=5)

        db_buttons_frame = ttk.Frame(self.scan_frame)
        db_buttons_frame.pack(pady=5)

        self.import_btn = ttk.Button(db_buttons_frame, text="Import Database File (CVD/TXT/PKL)", command=self.start_import_db)
        self.import_btn.pack(side=tk.LEFT, padx=5)

        export_cvd_btn = ttk.Button(db_buttons_frame, text="Export DB CVD", command=self.start_export_cvd)
        export_cvd_btn.pack(side=tk.LEFT, padx=5)

        export_pkl_btn = ttk.Button(db_buttons_frame, text="Export DB PKL", command=self.start_export_pkl)
        export_pkl_btn.pack(side=tk.LEFT, padx=5)

        scan_buttons_frame = ttk.Frame(self.scan_frame)
        scan_buttons_frame.pack(pady=5)

        self.scan_btn = ttk.Button(scan_buttons_frame, text="Scan Folder", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.pause_btn = ttk.Button(scan_buttons_frame, text="Pause Scan", command=self.pause_scan, state='disabled')
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(scan_buttons_frame, text="Cancel Scan", command=self.cancel_scan, state='disabled')
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(self.scan_frame, orient='horizontal', length=300, mode='determinate')
        self.progress.pack(pady=10)

        self.current_label = ttk.Label(self.scan_frame, text="", font=('Arial', 8))
        self.current_label.pack(pady=2)

        self.size_label = ttk.Label(self.scan_frame, text="", font=('Arial', 8))
        self.size_label.pack(pady=2)

        self.scanned_files_label = ttk.Label(self.scan_frame, text="Files Scanned: 0", font=('Arial', 8))
        self.scanned_files_label.pack(pady=2)

        self.results_list = tk.Listbox(self.scan_frame, bg='#2e2e2e', fg='white', font=('Arial', 10), height=9)
        self.results_list.pack(fill=tk.BOTH, expand=True, pady=10)

        button_frame = ttk.Frame(self.scan_frame)
        button_frame.pack(fill=tk.X, pady=5)

        delete_btn = ttk.Button(button_frame, text="Delete Selected", command=self.delete_selected_scan)
        delete_btn.pack(side=tk.LEFT, padx=5)

        extract_btn = ttk.Button(button_frame, text="Extract Detections", command=self.extract_detections)
        extract_btn.pack(side=tk.LEFT, padx=5)

        delete_all_btn = ttk.Button(button_frame, text="Delete All Detections", command=self.delete_all_detections)
        delete_all_btn.pack(side=tk.LEFT, padx=5)

        remove_hash_btn = ttk.Button(button_frame, text="Remove Selected Hash From Database", command=self.remove_selected_hash)
        remove_hash_btn.pack(side=tk.LEFT, padx=5)

        check_vt_btn = ttk.Button(button_frame, text="Check Selected On VirusTotal", command=self.check_selected_on_virustotal)
        check_vt_btn.pack(side=tk.LEFT, padx=5)

    def setup_quarantine_tab(self):
        top_frame = ttk.Frame(self.quarantine_frame)
        top_frame.pack(fill=tk.X, pady=5)
        self.add_donate_link(top_frame)

        quarantine_label = ttk.Label(self.quarantine_frame, text="Quarantine", font=('Arial', 14))
        quarantine_label.pack(pady=10)

        self.quarantine_list = tk.Listbox(self.quarantine_frame, bg='#2e2e2e', fg='white', font=('Arial', 10))
        self.quarantine_list.pack(fill=tk.BOTH, expand=True, pady=10)

        button_frame = ttk.Frame(self.quarantine_frame)
        button_frame.pack(fill=tk.X, pady=5)

        restore_btn = ttk.Button(button_frame, text="Restore Selected", command=self.restore_selected)
        restore_btn.pack(side=tk.LEFT, padx=5)

        delete_btn = ttk.Button(button_frame, text="Delete Selected", command=self.delete_selected_quarantine)
        delete_btn.pack(side=tk.LEFT, padx=5)

        self.update_quarantine_list()

    def setup_monitoring_tab(self):
        top_frame = ttk.Frame(self.monitoring_frame)
        top_frame.pack(fill=tk.X, pady=5)
        self.add_donate_link(top_frame)

        monitoring_label = ttk.Label(self.monitoring_frame, text="System Monitoring", font=('Arial', 14))
        monitoring_label.pack(pady=10)

        self.system_info_label = ttk.Label(self.monitoring_frame, text="", font=('Arial', 10))
        self.system_info_label.pack(pady=5)

        # Horizontal frame for CPU, RAM, Disk, GPU
        progress_frame = ttk.Frame(self.monitoring_frame)
        progress_frame.pack(fill=tk.X, pady=5)

        # CPU
        cpu_frame = ttk.Frame(progress_frame)
        cpu_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        ttk.Label(cpu_frame, text="CPU Usage", font=('Arial', 10)).pack()
        self.cpu_canvas = tk.Canvas(cpu_frame, width=100, height=100, bg='#1e1e1e', highlightthickness=0)
        self.cpu_canvas.pack()
        self.cpu_label = ttk.Label(cpu_frame, text="0%", font=('Arial', 10))
        self.cpu_label.pack()

        # RAM
        ram_frame = ttk.Frame(progress_frame)
        ram_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        ttk.Label(ram_frame, text="RAM Usage", font=('Arial', 10)).pack()
        self.ram_canvas = tk.Canvas(ram_frame, width=100, height=100, bg='#1e1e1e', highlightthickness=0)
        self.ram_canvas.pack()
        self.ram_label = ttk.Label(ram_frame, text="0%", font=('Arial', 10))
        self.ram_label.pack()

        # Disk
        disk_frame = ttk.Frame(progress_frame)
        disk_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        ttk.Label(disk_frame, text="Disk Usage", font=('Arial', 10)).pack()
        self.disk_canvas = tk.Canvas(disk_frame, width=100, height=100, bg='#1e1e1e', highlightthickness=0)
        self.disk_canvas.pack()
        self.disk_label = ttk.Label(disk_frame, text="0%", font=('Arial', 10))
        self.disk_label.pack()

        # GPU
        if os.name == 'nt':
            gpu_frame = ttk.Frame(progress_frame)
            gpu_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
            ttk.Label(gpu_frame, text="GPU Usage", font=('Arial', 10)).pack()
            self.gpu_canvas = tk.Canvas(gpu_frame, width=100, height=100, bg='#1e1e1e', highlightthickness=0)
            self.gpu_canvas.pack()
            self.gpu_label = ttk.Label(gpu_frame, text="N/A", font=('Arial', 10))
            self.gpu_label.pack()

        # Network
        net_frame = ttk.Frame(self.monitoring_frame)
        net_frame.pack(fill=tk.X, pady=5)

        sent_frame = ttk.Frame(net_frame)
        sent_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        ttk.Label(sent_frame, text="Sent (MB/s)", font=('Arial', 10)).pack()
        self.fig_sent, self.ax_sent = plt.subplots(figsize=(3, 2))
        self.sent_canvas = FigureCanvasTkAgg(self.fig_sent, master=sent_frame)
        self.sent_canvas.get_tk_widget().pack()
        self.sent_label = ttk.Label(sent_frame, text="0.00 MB/s", font=('Arial', 10))
        self.sent_label.pack()

        recv_frame = ttk.Frame(net_frame)
        recv_frame.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        ttk.Label(recv_frame, text="Received (MB/s)", font=('Arial', 10)).pack()
        self.fig_recv, self.ax_recv = plt.subplots(figsize=(3, 2))
        self.recv_canvas = FigureCanvasTkAgg(self.fig_recv, master=recv_frame)
        self.recv_canvas.get_tk_widget().pack()
        self.recv_label = ttk.Label(recv_frame, text="0.00 MB/s", font=('Arial', 10))
        self.recv_label.pack()

        # Battery
        battery_frame = ttk.Frame(self.monitoring_frame)
        battery_frame.pack(pady=5)
        ttk.Label(battery_frame, text="Battery", font=('Arial', 10)).pack()
        self.battery_canvas = tk.Canvas(battery_frame, width=100, height=100, bg='#1e1e1e', highlightthickness=0)
        self.battery_canvas.pack()
        self.battery_label = ttk.Label(battery_frame, text="N/A", font=('Arial', 10))
        self.battery_label.pack()

    def draw_progress_circle(self, canvas, percent):
        canvas.delete("all")
        # Background circle
        canvas.create_oval(10, 10, 90, 90, outline='gray', width=8)
        # Progress arc
        angle = 360 * (percent / 100)
        color = 'green' if percent < 80 else 'red'
        canvas.create_arc(10, 10, 90, 90, start=90, extent=-angle, outline=color, width=8, style='arc')
        # Text
        canvas.create_text(50, 50, text=f"{percent:.1f}%", fill='white', font=('Arial', 12))

    def draw_na(self, canvas):
        canvas.delete("all")
        canvas.create_text(50, 50, text="N/A", fill='white', font=('Arial', 12))

    def update_graph(self, ax, history, canvas):
        ax.clear()
        ax.plot(history, color='blue')
        ax.set_ylim(0, max(history + [1]))
        canvas.draw()

    def setup_settings_tab(self):
        top_frame = ttk.Frame(self.settings_frame)
        top_frame.pack(fill=tk.X, pady=5)
        self.add_donate_link(top_frame)

        settings_label = ttk.Label(self.settings_frame, text="Settings", font=('Arial', 14))
        settings_label.pack(pady=10)

        self.real_time_var = tk.BooleanVar(value=True)
        real_time_check = ttk.Checkbutton(self.settings_frame, text="Enable Real-time Protection", variable=self.real_time_var, command=self.toggle_real_time)
        real_time_check.pack(pady=5)

        self.web_protection_var = tk.BooleanVar(value=True)
        web_protection_check = ttk.Checkbutton(self.settings_frame, text="Enable Web Protection", variable=self.web_protection_var, command=self.toggle_web_protection)
        web_protection_check.pack(pady=5)

        if os.name == 'nt':
            self.auto_start_var = tk.BooleanVar(value=self.auto_start_enabled)
            auto_start_check = ttk.Checkbutton(self.settings_frame, text="Start with Windows (Registry)", variable=self.auto_start_var, command=self.toggle_auto_start)
            auto_start_check.pack(pady=5)

        update_urls_btn = ttk.Button(self.settings_frame, text="Update Malicious URLs", command=self.start_update_malicious_urls)
        update_urls_btn.pack(pady=5)

        monitored_frame = ttk.Frame(self.settings_frame)
        monitored_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        monitored_label = ttk.Label(monitored_frame, text="Monitored Folders for Real-time Protection", font=('Arial', 10))
        monitored_label.pack(pady=5)

        self.monitored_folders_list = tk.Listbox(monitored_frame, bg='#2e2e2e', fg='white', font=('Arial', 10), height=5)
        self.monitored_folders_list.pack(fill=tk.BOTH, expand=True, pady=5)

        buttons_frame = ttk.Frame(monitored_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        add_folder_btn = ttk.Button(buttons_frame, text="Add Folder", command=self.add_monitored_folder)
        add_folder_btn.pack(side=tk.LEFT, padx=5)
        remove_folder_btn = ttk.Button(buttons_frame, text="Remove Selected Folder", command=self.remove_monitored_folder)
        remove_folder_btn.pack(side=tk.LEFT, padx=5)

        self.update_monitored_folders_list()

    def load_monitored_folders(self):
        if os.path.exists(self.monitored_folders_pkl):
            try:
                with open(self.monitored_folders_pkl, 'rb') as f:
                    saved_folders = pickle.load(f)
                self.monitored_folders = set(saved_folders)
                logging.debug(f"Loaded {len(self.monitored_folders)} monitored folders from {self.monitored_folders_pkl}")
            except Exception as e:
                logging.error(f"Failed to load {self.monitored_folders_pkl}: {str(e)}")
        else:
            logging.debug(f"No {self.monitored_folders_pkl} found, using default folders")

    def save_monitored_folders(self):
        try:
            with open(self.monitored_folders_pkl, 'wb') as f:
                pickle.dump(self.monitored_folders, f)
            logging.debug(f"Saved {len(self.monitored_folders)} monitored folders to {self.monitored_folders_pkl}")
        except Exception as e:
            logging.error(f"Failed to save {self.monitored_folders_pkl}: {str(e)}")

    def update_monitored_folders_list(self):
        self.monitored_folders_list.delete(0, tk.END)
        for folder in sorted(self.monitored_folders):
            self.monitored_folders_list.insert(tk.END, folder)

    def add_monitored_folder(self):
        folder = filedialog.askdirectory(title="Select Folder for Real-time Protection")
        if not folder:
            return
        if folder in self.monitored_folders:
            messagebox.showwarning("Warning", "This folder is already being monitored.")
            return
        if folder == self.quarantine_dir or folder.startswith(self.quarantine_dir + os.sep):
            messagebox.showwarning("Warning", "Cannot monitor the quarantine directory.")
            return
        self.monitored_folders.add(folder)
        self.save_monitored_folders()
        self.update_monitored_folders_list()
        if self.real_time_var.get():
            self.stop_observer_async(self.start_real_time_monitoring)
        logging.debug(f"Added folder to monitor: {folder}")

    def stop_observer_async(self, callback=None):
        def stop_observer():
            try:
                if hasattr(self, 'observer') and self.observer_running:
                    self.observer.stop()
                    self.observer.join()
                    self.observer_running = False
                    logging.debug("Observer stopped successfully")
                if callback:
                    self.root.after(0, callback)
            except Exception as e:
                logging.error(f"Failed to stop observer: {str(e)}")
                self.root.after(0, lambda err=str(e): messagebox.showerror("Error", f"Failed to stop monitoring: {err}"))
        threading.Thread(target=stop_observer, daemon=True).start()

    def remove_monitored_folder(self):
        selected = self.monitored_folders_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select a folder to remove.")
            return
        folder = self.monitored_folders_list.get(selected[0])
        confirm = messagebox.askyesno("Confirmation", f"Are you sure you want to stop monitoring {folder}?")
        if not confirm:
            return
        self.monitored_folders.remove(folder)
        self.save_monitored_folders()
        self.update_monitored_folders_list()
        if self.real_time_var.get():
            self.stop_observer_async(self.start_real_time_monitoring)
        logging.debug(f"Removed folder from monitoring: {folder}")

    def start_system_monitoring(self):
        self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=False)
        self.monitor_thread.start()

    def monitor_system(self):
        while self.running:
            try:
                system_info = f"Computer Name: {platform.node()}\nOS: {platform.system()} {platform.release()}\nCPU Cores: {os.cpu_count()}\nProcessor: {platform.processor()}"
                self.root.after(0, lambda: self.system_info_label.config(text=system_info))

                cpu_percent = psutil.cpu_percent(interval=1)
                if abs(cpu_percent - self.prev_cpu) > 1:
                    self.root.after(0, lambda: self.draw_progress_circle(self.cpu_canvas, cpu_percent))
                    self.root.after(0, lambda: self.cpu_label.config(text=f"{cpu_percent}%"))
                    self.prev_cpu = cpu_percent

                ram = psutil.virtual_memory()
                if abs(ram.percent - self.prev_ram) > 1:
                    self.root.after(0, lambda: self.draw_progress_circle(self.ram_canvas, ram.percent))
                    self.root.after(0, lambda: self.ram_label.config(text=f"{ram.percent}% ({ram.used / (1024**3):.2f} GB used / {ram.total / (1024**3):.2f} GB total)"))
                    self.prev_ram = ram.percent

                disk = psutil.disk_usage('/')
                if abs(disk.percent - self.prev_disk) > 1:
                    self.root.after(0, lambda: self.draw_progress_circle(self.disk_canvas, disk.percent))
                    self.root.after(0, lambda: self.disk_label.config(text=f"{disk.percent}% ({disk.used / (1024**3):.2f} GB used / {disk.total / (1024**3):.2f} GB total)"))
                    self.prev_disk = disk.percent

                if os.name == 'nt':
                    gpus = GPUtil.getGPUs()
                    if gpus:
                        gpu = gpus[0]
                        gpu_load = gpu.load * 100
                        if abs(gpu_load - self.prev_gpu) > 1:
                            self.root.after(0, lambda: self.draw_progress_circle(self.gpu_canvas, gpu_load))
                            self.root.after(0, lambda: self.gpu_label.config(text=f"{gpu.name}, Usage: {gpu_load:.1f}%"))
                            self.prev_gpu = gpu_load
                    else:
                        self.root.after(0, lambda: self.draw_na(self.gpu_canvas))
                        self.root.after(0, lambda: self.gpu_label.config(text="N/A"))

                net_io = psutil.net_io_counters()
                delta_sent = (net_io.bytes_sent - self.previous_net.bytes_sent) / (1024 ** 2)  # MB/s
                delta_recv = (net_io.bytes_recv - self.previous_net.bytes_recv) / (1024 ** 2)  # MB/s
                self.sent_history.append(delta_sent)
                self.recv_history.append(delta_recv)
                if len(self.sent_history) > self.max_history:
                    self.sent_history.pop(0)
                if len(self.recv_history) > self.max_history:
                    self.recv_history.pop(0)
                if abs(delta_sent - self.prev_sent) > 0.01:  # Assuming small change threshold for MB/s
                    self.root.after(0, lambda: self.update_graph(self.ax_sent, self.sent_history, self.sent_canvas))
                    self.root.after(0, lambda: self.sent_label.config(text=f"{delta_sent:.2f} MB/s"))
                    self.prev_sent = delta_sent
                if abs(delta_recv - self.prev_recv) > 0.01:
                    self.root.after(0, lambda: self.update_graph(self.ax_recv, self.recv_history, self.recv_canvas))
                    self.root.after(0, lambda: self.recv_label.config(text=f"{delta_recv:.2f} MB/s"))
                    self.prev_recv = delta_recv
                self.previous_net = net_io

                battery = psutil.sensors_battery()
                if battery:
                    if abs(battery.percent - self.prev_battery) > 1:
                        self.root.after(0, lambda: self.draw_progress_circle(self.battery_canvas, battery.percent))
                        self.root.after(0, lambda: self.battery_label.config(text=f"{battery.percent}% ({'Plugged' if battery.power_plugged else 'Not Plugged'})"))
                        self.prev_battery = battery.percent
                else:
                    self.root.after(0, lambda: self.draw_na(self.battery_canvas))
                    self.root.after(0, lambda: self.battery_label.config(text="N/A"))

                for _ in range(30):  # Approximate 3 seconds, interruptable
                    if not self.running:
                        return
                    time.sleep(0.1)
            except Exception as e:
                logging.error(f"System monitoring error: {str(e)}")
                for _ in range(30):
                    if not self.running:
                        return
                    time.sleep(0.1)

    def get_hash_count(self):
        with self.hashes_lock:
            with self.get_hashes_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM hashes")
                return cur.fetchone()[0]

    def get_url_count(self):
        with self.urls_lock:
            with self.get_urls_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM urls")
                return cur.fetchone()[0]

    def load_db(self):
        if os.path.exists(self.pkl_file):
            try:
                with open(self.pkl_file, 'rb') as f:
                    hashes = pickle.load(f)
                self.insert_hashes_to_db(hashes)
                os.remove(self.pkl_file)  # Migrate
                logging.debug(f"Migrated {len(hashes)} hashes from pickle to DB")
            except Exception as e:
                logging.error(f"Failed to migrate {self.pkl_file}: {str(e)}")

    def load_malicious_urls(self):
        if os.path.exists(self.malicious_pkl):
            try:
                with open(self.malicious_pkl, 'rb') as f:
                    urls = pickle.load(f)
                self.insert_urls_to_db(urls)
                os.remove(self.malicious_pkl)  # Migrate
                logging.debug(f"Migrated {len(urls)} URLs from pickle to DB")
            except Exception as e:
                logging.error(f"Failed to migrate {self.malicious_pkl}: {str(e)}")

    def insert_hashes_to_db(self, hashes):
        with self.hashes_lock2:
            with self.get_hashes_connection() as conn:
                cur = conn.cursor()
                batch_size = 100000
                batch = []
                cur.execute("BEGIN")
                executedHashes = 0
                for h in hashes:
                    batch.append((h,))
                    if len(batch) == batch_size:
                        executedHashes += batch_size
                        logging.debug(f"{executedHashes} Of {len(hashes)} Hashes Processed to DB")
                        cur.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", batch)
                        self.root.after(0, lambda val=(executedHashes) / len(hashes) * 100: self.progress.config(value=val))
                        batch = []
                        gc.collect()
                if batch:
                    executedHashes += len(batch)
                    logging.debug(f"{executedHashes} Of {len(hashes)} Hashes Processed to DB")
                    cur.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", batch)
                    self.root.after(0, lambda val=(executedHashes) / len(hashes) * 100: self.progress.config(value=val))
                cur.execute("COMMIT")
                gc.collect()

    def insert_urls_to_db(self, urls):
        with self.urls_lock:
            with self.get_urls_connection() as conn:
                cur = conn.cursor()
                batch_size = 100000
                batch = []
                cur.execute("BEGIN")
                for u in urls:
                    batch.append((u,))
                    if len(batch) == batch_size:
                        cur.executemany("INSERT OR IGNORE INTO urls VALUES (?)", batch)
                        batch = []
                        gc.collect()
                if batch:
                    cur.executemany("INSERT OR IGNORE INTO urls VALUES (?)", batch)
                cur.execute("COMMIT")
                gc.collect()

    def load_reports(self):
        if os.path.exists(self.reports_file):
            try:
                with open(self.reports_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Failed to load {self.reports_file}: {str(e)}")
        return []

    def save_reports(self):
        try:
            with open(self.reports_file, 'w') as f:
                json.dump(self.reports, f, indent=4)
            logging.debug(f"Saved reports to {self.reports_file}")
        except Exception as e:
            logging.error(f"Failed to save {self.reports_file}: {str(e)}")

    def clear_reports(self):
        self.reports = []
        self.save_reports()
        messagebox.showinfo("Success", "Reports cleared.")
        logging.debug("Reports cleared")

    def start_real_time_monitoring(self):
        if self.observer_running:
            logging.debug("Real-time monitoring already running, skipping start")
            return
        if hasattr(self, 'observer'):
            self.stop_observer_async()
        self.observer = Observer()
        for path in self.monitored_folders:
            if os.path.exists(path):
                self.observer.schedule(self, path, recursive=True)
                logging.debug(f"Monitoring folder: {path}")
        if self.real_time_var.get():
            self.observer.start()
            self.observer_running = True
            logging.debug("Started real-time monitoring")
        else:
            logging.debug("Real-time monitoring not started (disabled in settings)")

    def toggle_real_time(self):
        if self.real_time_var.get():
            if not self.observer_running:
                threading.Thread(target=self.start_real_time_monitoring, daemon=True).start()
        else:
            self.stop_observer_async()
            logging.debug("Stopped real-time monitoring")
        self.save_settings()

    def on_modified(self, event):
        if not self.real_time_var.get() or event.is_directory:
            return
        file_path = event.src_path
        if self.is_safe_extension(file_path):
            logging.debug(f"Skipped safe extension file: {file_path}")
            return
        logging.debug(f"Detected file modification: {file_path}")
        self.scan_file(file_path)

    def on_created(self, event):
        if not self.real_time_var.get() or event.is_directory:
            return
        file_path = event.src_path
        if self.is_safe_extension(file_path):
            logging.debug(f"Skipped safe extension file: {file_path}")
            return
        logging.debug(f"Detected file creation: {file_path}")
        self.scan_file(file_path)

    def is_safe_extension(self, file_path):
        safe_extensions = ('.txt', '.log', '.json', '.csv', '.ini', '.cfg', '.pkl')
        return file_path.lower().endswith(safe_extensions)

    def scan_file(self, file_path):
        if any(file_path.lower().endswith(ext) for ext in ('.part', '.crdownload', '.download', '.tmp')):
            logging.debug(f"Skipped partial download: {file_path}")
            return
        if file_path.endswith('.quarantine'):
            logging.debug(f"Skipped quarantined file: {file_path}")
            return
        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logging.debug(f"Skipped empty file: {file_path}")
                return
        except:
            return
        hashes = self.compute_hash(file_path)
        if hashes:
            with self.hashes_lock:
                with self.get_hashes_connection() as conn:
                    cur = conn.cursor()
                    for hash_type, hash_val in hashes.items():
                        cur.execute("SELECT 1 FROM hashes WHERE hash = ?", (hash_val,))
                        if cur.fetchone():
                            self.threats_blocked += 1
                            self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                            alert_msg = f"Virus detected in {file_path} ({hash_type.upper()}={hash_val}). Moving to quarantine."
                            self.pending_alerts.append(alert_msg)
                            if self.alert_timer is None:
                                self.alert_timer = self.root.after(2000, self.show_pending_alerts)
                            self.quarantine_file(file_path, hash_val)
                            self.add_report(file_path, hash_val, "Hash-based detection")
                            break

    def show_pending_alerts(self):
        if self.pending_alerts:
            msg = "Threats Detected:\n" + "\n".join(self.pending_alerts)
            messagebox.showwarning("Threats Detected", msg)
            self.pending_alerts = []
        self.alert_timer = None

    def toggle_web_protection(self):
        self.web_protection_enabled = self.web_protection_var.get()
        logging.debug(f"Web protection {'enabled' if self.web_protection_enabled else 'disabled'}")
        self.save_settings()

    def check_url(self, url):
        if not self.web_protection_enabled:
            return True
        try:
            parsed_url = urllib.parse.urlparse(url)
            netloc = parsed_url.netloc.lower()
            full_url = url.lower()
            if netloc in self.blocklist_urls:
                logging.warning(f"Blocked malicious URL: {url}")
                self.threats_blocked += 1
                self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                self.root.after(0, lambda: messagebox.showwarning("Malicious URL", f"Blocked malicious URL: {url}"))
                self.add_report(url, "N/A", "Malicious URL blocked")
                return False
            with self.urls_lock:
                with self.get_urls_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT 1 FROM urls WHERE url = ?", (full_url,))
                    if cur.fetchone():
                        logging.warning(f"Blocked malicious URL: {url}")
                        self.threats_blocked += 1
                        self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                        self.root.after(0, lambda: messagebox.showwarning("Malicious URL", f"Blocked malicious URL: {url}"))
                        self.add_report(url, "N/A", "Malicious URL blocked")
                        return False
                    cur.execute("SELECT 1 FROM urls WHERE url = ?", (netloc,))
                    if cur.fetchone():
                        logging.warning(f"Blocked malicious URL: {url}")
                        self.threats_blocked += 1
                        self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                        self.root.after(0, lambda: messagebox.showwarning("Malicious URL", f"Blocked malicious URL: {url}"))
                        self.add_report(url, "N/A", "Malicious URL blocked")
                        return False

            # Check for valid SSL certificate
            if parsed_url.scheme == 'https':
                try:
                    requests.head(url, verify=True, timeout=5)
                except requests.exceptions.SSLError:
                    logging.warning(f"Blocked URL with invalid SSL: {url}")
                    self.threats_blocked += 1
                    self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                    self.root.after(0, lambda: messagebox.showwarning("Invalid SSL", f"Blocked URL with invalid SSL certificate: {url}"))
                    self.add_report(url, "N/A", "Invalid SSL certificate")
                    return False
            elif parsed_url.scheme == 'http':
                logging.warning(f"Blocked non-HTTPS URL: {url}")
                self.threats_blocked += 1
                self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                self.root.after(0, lambda: messagebox.showwarning("Non-Secure URL", f"Blocked non-HTTPS URL: {url}"))
                self.add_report(url, "N/A", "Non-secure HTTP URL")
                return False

            return True
        except Exception as e:
            logging.error(f"Failed to check URL {url}: {str(e)}")
            return True

    def start_update_malicious_urls(self):
        if self.updating_urls:
            messagebox.showwarning("Warning", "Malicious URLs update already in progress.")
            return
        self.updating_urls = True
        self.notebook.select(self.scan_frame)
        self.progress['value'] = 0
        self.current_label.config(text="Updating malicious URLs...")
        self.root.update_idletasks()
        threading.Thread(target=self.update_malicious_urls, daemon=True).start()

    def update_malicious_urls(self):
        url_source = "https://phish.co.za/latest/phishing-links-ACTIVE.txt"
        try:
            response = requests.get(url_source, timeout=10)
            response.raise_for_status()
            lines = response.text.splitlines()
            total = len(lines)
            with self.urls_lock:
                with self.get_urls_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM urls")
                    conn.commit()
            chunk_size = max(1, total // os.cpu_count())
            chunks = [lines[i:i + chunk_size] for i in range(0, total, chunk_size)]

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(self.process_url_chunk, chunk) for chunk in chunks]
                processed_count = 0
                for future in concurrent.futures.as_completed(futures):
                    urls = future.result()
                    self.insert_urls_to_db(urls)
                    processed_count += len(urls)
                    self.root.after(0, lambda val=processed_count / total * 100: self.progress.config(value=val))

            self.root.after(0, lambda: self.urls_count_label.config(text=f"Loaded malicious URLs: {self.get_url_count()}"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Updated {self.get_url_count()} malicious URLs."))
            logging.debug(f"Updated {self.get_url_count()} malicious URLs from {url_source}")
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to update malicious URLs: {str(e)}"))
            logging.error(f"Failed to update malicious URLs from {url_source}: {str(e)}")
        finally:
            self.updating_urls = False
            self.root.after(0, lambda: self.progress.config(value=100))
            self.root.after(0, lambda: self.current_label.config(text=""))
            gc.collect()

    def process_url_chunk(self, chunk):
        urls = set()
        for line in chunk:
            line = line.strip()
            if not line:
                continue
            try:
                parsed = urllib.parse.urlparse(line)
                if parsed.scheme in ('http', 'https') and parsed.netloc:
                    urls.add(line.lower())
                    urls.add(parsed.netloc.lower())
            except:
                logging.warning(f"Invalid URL skipped: {line}")
        return urls

    def quarantine_file(self, file_path, file_hash):
        try:
            if file_path.endswith('.quarantine'):
                logging.warning(f"Skipped already quarantined file: {file_path}")
                return
            quarantine_filename = os.path.basename(file_path) + f".{file_hash}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            if os.path.exists(quarantine_path):
                os.remove(file_path)
                logging.info(f"Duplicate threat detected, deleted {file_path}")
                self.add_report(file_path, file_hash, "Duplicate threat deleted")
                return
            try:
                os.rename(file_path, quarantine_path)
                self.quarantine_metadata[quarantine_filename] = os.path.normpath(file_path)
                self.save_quarantine_metadata()
                logging.info(f"Quarantined file: {file_path} to {quarantine_path}")
                self.update_quarantine_list()
                self.add_report(file_path, file_hash, "Moved to quarantine")
            except Exception as e:
                logging.error(f"Failed to move to quarantine {file_path}: {str(e)}")
                try:
                    os.remove(file_path)
                    logging.info(f"Deleted {file_path} due to quarantine failure")
                    self.add_report(file_path, file_hash, "Deleted due to quarantine failure")
                except Exception as de:
                    logging.error(f"Failed to delete {file_path}: {str(de)}")
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to quarantine or delete {file_path}: {str(e)} / {str(de)}"))
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {str(e)}")
            self.root.after(0, lambda err=str(e): messagebox.showerror("Error", f"Failed to quarantine {file_path}: {err}"))

    def update_quarantine_list(self):
        self.quarantine_list.delete(0, tk.END)
        for file in os.listdir(self.quarantine_dir):
            if file.endswith(".quarantine"):
                self.quarantine_list.insert(tk.END, file)

    def restore_selected(self):
        selected = self.quarantine_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select files from the quarantine list.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to restore the selected files?")
        if not confirm:
            return

        for idx in sorted(selected, reverse=True):
            file = self.quarantine_list.get(idx)
            quarantine_path = os.path.join(self.quarantine_dir, file)
            original_path = self.quarantine_metadata.get(file, os.path.normpath(os.path.join(os.path.dirname(quarantine_path), file.rsplit(".", 2)[0])))
            try:
                os.rename(quarantine_path, original_path)
                self.quarantine_list.delete(idx)
                if file in self.quarantine_metadata:
                    del self.quarantine_metadata[file]
                    self.save_quarantine_metadata()
                logging.info(f"Restored file: {quarantine_path} to {original_path}")
                self.add_report(original_path, "N/A", "Restored from quarantine")
                self.update_scan_results_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore {file}: {str(e)}")
                logging.error(f"Failed to restore {file}: {str(e)}")

    def delete_selected_quarantine(self):
        selected = self.quarantine_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select files from the quarantine list.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected files?")
        if not confirm:
            return

        for idx in sorted(selected, reverse=True):
            file = self.quarantine_list.get(idx)
            quarantine_path = os.path.join(self.quarantine_dir, file)
            try:
                os.remove(quarantine_path)
                self.quarantine_list.delete(idx)
                if file in self.quarantine_metadata:
                    del self.quarantine_metadata[file]
                    self.save_quarantine_metadata()
                logging.info(f"Deleted quarantined file: {quarantine_path}")
                self.add_report(quarantine_path, "N/A", "Deleted from quarantine")
                self.update_scan_results_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {file}: {str(e)}")
                logging.error(f"Failed to delete {file}: {str(e)}")

    def add_report(self, file_path, file_hash, action):
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": file_path,
            "hash": file_hash,
            "action": action
        }
        self.reports.append(report)
        self.save_reports()

    def view_reports(self):
        reports_window = tk.Toplevel(self.root)
        reports_window.title("VirusBytes Reports")
        reports_window.geometry("600x400")
        reports_list = tk.Listbox(reports_window, bg='#2e2e2e', fg='white', font=('Arial', 10))
        reports_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for report in self.reports:
            reports_list.insert(tk.END, f"{report['timestamp']} - {report['action']}: {report['file_path']} (Hash: {report['hash']})")

    def start_import_db(self):
        if self.importing:
            messagebox.showwarning("Warning", "Import already in progress.")
            return
        file_path = filedialog.askopenfilename(title="Select Database File", filetypes=[("Database Files", "*.cvd *.txt *.pkl")])
        if not file_path:
            return

        self.importing = True
        self.progress['value'] = 0
        self.current_label.config(text="Importing database...")
        self.size_label.config(text="")
        self.scanned_files_label.config(text="Files Scanned: 0")
        self.root.update_idletasks()

        threading.Thread(target=self.import_db, args=(file_path,), daemon=True).start()

    def import_db(self, file_path):
        try:
            with self.hashes_lock:
                with self.get_hashes_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("BEGIN")
                    if file_path.lower().endswith('.txt'):
                        self.import_txt(file_path, conn)
                    elif file_path.lower().endswith('.cvd'):
                        self.import_cvd(file_path, conn)
                    elif file_path.lower().endswith('.pkl'):
                        self.import_pkl(file_path, conn)
                    else:
                        self.root.after(0, lambda: messagebox.showerror("Error", "Unsupported file type. Use .cvd, .txt, or .pkl."))
                        return
                    cur.execute("COMMIT")

            self.root.after(0, lambda: self.db_count_label.config(text=f"Loaded hashes: {self.get_hash_count()}"))
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Database updated! Now has {self.get_hash_count()} hashes."))
            gc.collect()
        except Exception as e:
            with self.hashes_lock:
                with self.get_hashes_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("ROLLBACK")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to import: {str(e)}"))
            logging.error(f"Import failed: {str(e)}")
        finally:
            self.importing = False
            self.root.after(0, lambda: self.progress.config(value=100))
            self.root.after(0, lambda: self.current_label.config(text=""))
            self.root.after(0, lambda: self.size_label.config(text=""))
            self.root.after(0, lambda: self.scanned_files_label.config(text="Files Scanned: 0"))
            gc.collect()

    def import_txt(self, file_path, conn):
        try:
            total = sum(1 for _ in open(file_path, 'r'))  # For progress, optional
            invalid_count = 0
            invalid_samples = []
            md5_count = sha1_count = sha256_count = 0
            empty_hashes = {'d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
            batch = []
            batch_size = 100000
            processed = 0
            cur = conn.cursor()
            with open(file_path, 'r') as f:
                #logging.debug(f"Opened file : {file_path} ")
                for line in f:
                    hash_val = line.strip().lower()
                    #logging.debug(f"Try to import : {hash_val} ")
                    processed += 1
                    if hash_val in empty_hashes:
                        continue  # Skip empty file hashes
                    if len(hash_val) in (32, 40, 64) and all(c in '0123456789abcdef' for c in hash_val):
                        batch.append((hash_val,))
                        #logging.debug(f"Appended to Batch : {hash_val} ")
                        if len(hash_val) == 32:
                            md5_count += 1
                        elif len(hash_val) == 40:
                            sha1_count += 1
                        elif len(hash_val) == 64:
                            sha256_count += 1
                        if len(batch) == batch_size:
                            with self.hashes_lock2:
                                cur.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", batch)
                                #logging.debug(f"Imported {processed} Hashes to Database (!)")
                            batch = []
                            gc.collect()
                    else:
                        invalid_count += 1
                        if len(invalid_samples) < 5:
                            invalid_samples.append(hash_val)
                    self.root.after(0, lambda val=processed / total * 100 if total else 0: self.progress.config(value=val))
                if batch:
                    with self.hashes_lock2:
                        cur.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", batch)
                if invalid_count > 0:
                    logging.warning(f"Skipped {invalid_count} invalid hashes in {file_path}. Sample invalid entries: {invalid_samples[:5]}")
                logging.debug(f"Imported from {file_path}: {md5_count} MD5, {sha1_count} SHA1, {sha256_count} SHA256 hashes")
                gc.collect()
        except Exception as e:
            logging.error(f"Failed to import {file_path}: {str(e)}")

    def import_cvd(self, file_path, conn):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
                if len(header) < 512:
                    raise ValueError("File too small to be a valid CVD.")
                header_str = header.decode('utf-8', errors='ignore').strip()
                if not header_str.startswith('ClamAV-VDB') and not header_str.startswith("VirusBytes-DB"):
                    raise ValueError("Invalid CVD file header.")
                data = f.read()

            try:
                gz_data = gzip.decompress(data)
            except OSError as e:
                raise ValueError(f"Failed to decompress: {e}")

            with tempfile.TemporaryDirectory() as tmp_dir:
                try:
                    tar_io = io.BytesIO(gz_data)
                    with tarfile.open(fileobj=tar_io) as tar:
                        tar.extractall(path=tmp_dir, filter='data')
                except tarfile.TarError as e:
                    raise ValueError(f"Failed to extract tar: {e}")

                hash_files = [f for f in os.listdir(tmp_dir) if f.endswith(('.hdb', '.hsb', '.msb'))]
                total_files = len(hash_files)
                if total_files == 0:
                    raise ValueError("No hash database files (.hdb, .hsb, .msb) found in CVD.")

                added_count = 0
                invalid_count = 0
                invalid_samples = []
                md5_count = sha1_count = sha256_count = 0
                empty_hashes = {'d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                batch = []
                batch_size = 100000
                cur = conn.cursor()
                processedHashes = 0
                totalLines=0
                for i, hf in enumerate(hash_files):
                    hf_path = os.path.join(tmp_dir, hf)
                    with open(hf_path, 'r', encoding='latin1', errors='ignore') as f:
                        totalLines+=len(f.readlines())
                for i, hf in enumerate(hash_files):
                    hf_path = os.path.join(tmp_dir, hf)
                    with open(hf_path, 'r', encoding='latin1', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            parts = line.split(':', 1)
                            hash_val = parts[0].lower()
                            if hash_val in empty_hashes:
                                continue  # Skip empty file hashes
                            if len(hash_val) in (32, 40, 64) and all(c in '0123456789abcdef' for c in hash_val):
                                batch.append((hash_val,))
                                added_count += 1
                                if len(hash_val) == 32:
                                    md5_count += 1
                                elif len(hash_val) == 40:
                                    sha1_count += 1
                                elif len(hash_val) == 64:
                                    sha256_count += 1
                                if len(batch) == batch_size:
                                    processedHashes+=batch_size
                                    logging.debug(f"{processedHashes} Of {totalLines} Hashes Processed To DB ")
                                    with self.hashes_lock2:
                                        cur.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", batch)
                                        self.root.after(0, lambda val=(processedHashes) / totalLines * 100: self.progress.config(value=val))
                                    batch = []
                                    gc.collect()
                            else:
                                invalid_count += 1
                                if len(invalid_samples) < 5:
                                    invalid_samples.append(hash_val)
                    self.root.after(0, lambda val=(i + 1) / total_files * 100: self.progress.config(value=val))
                if batch:
                    processedHashes+=len(batch)
                    logging.debug(f"{processedHashes} Of {totalLines} Hashes Processed To DB ")
                    with self.hashes_lock2:
                        cur.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", batch)
                        self.root.after(0, lambda val=(processedHashes) / totalLines * 100: self.progress.config(value=val))
                if invalid_count > 0:
                    logging.warning(f"Skipped {invalid_count} invalid hashes in {file_path}. Sample invalid entries: {invalid_samples[:5]}")
                logging.debug(f"Imported from {file_path}: {md5_count} MD5, {sha1_count} SHA1, {sha256_count} SHA256 hashes, total added: {added_count}")
                gc.collect()
        except Exception as e:
            logging.error(f"Failed to import {file_path}: {str(e)}")

    def import_pkl(self, file_path, conn):
        try:
            with open(file_path, 'rb') as f:
                loaded_hashes = pickle.load(f)
            if not isinstance(loaded_hashes, set):
                raise ValueError("Invalid pickle content: expected a set of hashes.")
            cur = conn.cursor()
            added_count = len(loaded_hashes)
            self.insert_hashes_to_db(loaded_hashes)
            logging.debug(f"Imported {len(loaded_hashes)} hashes from {file_path}, {added_count} new hashes added.")
            self.root.after(0, lambda val=100: self.progress.config(value=val))
            gc.collect()
        except Exception as e:
            logging.error(f"Failed to import {file_path}: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to import pickle file: {str(e)}"))

    def compute_hash(self, file_path):
        if self.use_all_hashes:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        md5_hash.update(chunk)
                        sha1_hash.update(chunk)
                        sha256_hash.update(chunk)
                hashes = {
                    'md5': md5_hash.hexdigest().lower(),
                    'sha1': sha1_hash.hexdigest().lower(),
                    'sha256': sha256_hash.hexdigest().lower()
                }
                logging.debug(f"Computed hashes for {file_path}: MD5={hashes['md5']}, SHA1={hashes['sha1']}, SHA256={hashes['sha256']}")
                return hashes
            except Exception as e:
                logging.error(f"Failed to compute hashes for {file_path}: {str(e)}")
                return None
        else:
            md5_hash = hashlib.md5()
            try:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(4096):
                        md5_hash.update(chunk)
                hash_val = md5_hash.hexdigest().lower()
                logging.debug(f"Computed MD5 hash for {file_path}: {hash_val}")
                return {'md5': hash_val}
            except Exception as e:
                logging.error(f"Failed to compute MD5 hash for {file_path}: {str(e)}")
                return None

    def pause_scan(self):
        if self.paused:
            self.paused = False
            self.pause_btn.config(text="Pause Scan")
            self.pause_event.set()
            logging.debug("Scan resumed")
        else:
            self.paused = True
            self.pause_btn.config(text="Resume Scan")
            self.pause_event.clear()
            logging.debug("Scan paused")

    def cancel_scan(self):
        self.cancelled = True
        self.pause_event.set()  # To unblock paused threads
        logging.debug("Scan cancellation requested")

    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("Warning", "Scan already in progress.")
            return
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return

        logging.debug(f"Starting scan with {self.get_hash_count()} hashes in DB")
        self.scanning = True
        self.paused = False
        self.cancelled = False
        self.pause_event.set()
        self.results_list.delete(0, tk.END)
        self.progress['value'] = 0
        self.current_label.config(text="")
        self.size_label.config(text="")
        self.scanned_files_label.config(text="Files Scanned: 0")
        self.root.after(0, lambda: self.scan_btn.config(state='disabled'))
        self.root.after(0, lambda: self.pause_btn.config(state='normal'))
        self.root.after(0, lambda: self.cancel_btn.config(state='normal'))
        self.root.update_idletasks()

        threading.Thread(target=self.scan_folder, args=(folder,), daemon=True).start()

    def get_files(self, folder):
        for root_dir, _, files in os.walk(folder):
            for file in files:
                fp = os.path.join(root_dir, file)
                if not fp.endswith('.quarantine'):
                    yield fp

    def scan_folder(self, folder):
        start_time = time.time()
        try:
            file_list = list(self.get_files(folder))  # List for total count
            total_files = len(file_list)
            if total_files == 0:
                self.root.after(0, lambda: messagebox.showinfo("Results", "No files found!"))
                return

            logging.debug(f"Scanning {total_files} files in {folder}")
            detected = []
            processed = 0
            lock = threading.Lock()

            def process_file(file_path):
                nonlocal processed
                try:
                    file_size = os.path.getsize(file_path)
                    size_str = f"Size: {file_size:,} bytes"
                    if file_size == 0:
                        logging.debug(f"Skipped empty file: {file_path}")
                        with lock:
                            processed += 1
                            self.root.after(0, lambda: self.progress.config(value=processed / total_files * 100))
                            self.root.after(0, lambda: self.scanned_files_label.config(text=f"Files Scanned: {processed}"))
                        return
                except:
                    size_str = "Size: Unknown"
                self.root.after(0, lambda p=file_path, s=size_str: (self.current_label.config(text=f"Scanning: {p}"), self.size_label.config(text=s)))
                # Pause handling
                while not self.cancelled:
                    if self.pause_event.wait(timeout=1):
                        break
                if self.cancelled:
                    return
                hashes = self.compute_hash(file_path)
                if hashes:
                    with self.hashes_lock:
                        with self.get_hashes_connection() as conn:
                            cur = conn.cursor()
                            for hash_type, hash_val in hashes.items():
                                cur.execute("SELECT 1 FROM hashes WHERE hash = ?", (hash_val,))
                                if cur.fetchone():
                                    logging.info(f"Detected virus in {file_path}: {hash_type.upper()}={hash_val}")
                                    self.detected_queue.put((file_path, hash_val, file_size))
                                    self.threats_blocked += 1
                                    self.root.after(0, lambda: self.threats_label.config(text=f"Threats Blocked: {self.threats_blocked}"))
                with lock:
                    processed += 1
                    self.root.after(0, lambda: self.progress.config(value=processed / total_files * 100))
                    self.root.after(0, lambda: self.scanned_files_label.config(text=f"Files Scanned: {processed}"))

            max_workers = max(1, os.cpu_count() // 2)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(process_file, fp) for fp in file_list]
                while any(not f.done() for f in futures):
                    if self.cancelled:
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break
                    time.sleep(0.1)
                executor.shutdown(wait=True)

            if self.cancelled:
                self.root.after(0, lambda: messagebox.showinfo("Scan Cancelled", "Scan was cancelled."))
                return

            while not self.detected_queue.empty():
                file_path, file_hash, file_size = self.detected_queue.get()
                detected.append(file_path)
                self.root.after(0, lambda fp=file_path, fh=file_hash: self.results_list.insert(tk.END, f"Detected: {fp} (Hash: {fh})"))
                self.quarantine_file(file_path, file_hash)

            self.root.after(0, lambda: self.scan_history_label.config(text=f"Last Scan: {time.strftime('%Y-%m-%d %H:%M:%S')}"))
            self.add_report(folder, "N/A", f"Scanned {total_files} files, found {len(detected)} threats")

            if detected:
                self.root.after(0, lambda: messagebox.showwarning("Results", f"Found {len(detected)} suspicious files. Moved to quarantine."))
            else:
                self.root.after(0, lambda: messagebox.showinfo("Results", "No viruses found!"))

            self.root.after(0, lambda: self.current_label.config(text=""))
            self.root.after(0, lambda: self.size_label.config(text=""))
            self.root.after(0, lambda: self.scanned_files_label.config(text=f"Files Scanned: {processed}"))
            end_time = time.time()
            logging.debug(f"Scan completed: {len(detected)} viruses found in {end_time - start_time:.2f} seconds")
            gc.collect()
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_btn.config(state='normal'))
            self.root.after(0, lambda: self.pause_btn.config(state='disabled', text="Pause Scan"))
            self.root.after(0, lambda: self.cancel_btn.config(state='disabled'))
            self.paused = False
            self.cancelled = False
            self.pause_event.set()
            gc.collect()

    def update_scan_results_list(self):
        for i in range(self.results_list.size() - 1, -1, -1):
            entry = self.results_list.get(i)
            file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
            norm_path = os.path.normpath(file_path)
            if norm_path not in self.quarantine_metadata.values():
                self.results_list.delete(i)

    def delete_selected_scan(self):
        selected = self.results_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select files from the list.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected files?")
        if not confirm:
            return

        for idx in sorted(selected, reverse=True):
            entry = self.results_list.get(idx)
            file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
            file_hash = entry.split(" (Hash:")[1].rstrip(")").strip()
            quarantine_filename = os.path.basename(file_path) + f".{file_hash}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            try:
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                    if quarantine_filename in self.quarantine_metadata:
                        del self.quarantine_metadata[quarantine_filename]
                        self.save_quarantine_metadata()
                    logging.info(f"Deleted quarantined file: {quarantine_path}")
                    self.add_report(file_path, file_hash, "Deleted from quarantine")
                else:
                    logging.warning(f"Quarantined file not found: {quarantine_path}")
                self.results_list.delete(idx)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {file_path}: {str(e)}")
                logging.error(f"Failed to delete {file_path}: {str(e)}")
        self.update_quarantine_list()

    def delete_all_detections(self):
        if not self.results_list.size():
            messagebox.showwarning("Warning", "No detections to delete.")
            return

        confirm = messagebox.askyesno("Confirmation", f"Are you sure you want to delete all {self.results_list.size()} detected files?")
        if not confirm:
            return

        for i in range(self.results_list.size() - 1, -1, -1):
            entry = self.results_list.get(i)
            file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
            file_hash = entry.split(" (Hash:")[1].rstrip(")").strip()
            quarantine_filename = os.path.basename(file_path) + f".{file_hash}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            try:
                if os.path.exists(quarantine_path):
                    os.remove(quarantine_path)
                    if quarantine_filename in self.quarantine_metadata:
                        del self.quarantine_metadata[quarantine_filename]
                        self.save_quarantine_metadata()
                    logging.info(f"Deleted quarantined file: {quarantine_path}")
                    self.add_report(file_path, file_hash, "Deleted from quarantine")
                else:
                    logging.warning(f"Quarantined file not found: {quarantine_path}")
                self.results_list.delete(i)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete {file_path}: {str(e)}")
                logging.error(f"Failed to delete {file_path}: {str(e)}")
        self.update_quarantine_list()

    def extract_detections(self):
        if not self.results_list.size():
            messagebox.showwarning("Warning", "No detections to export.")
            return

        detections_file = os.path.join(os.path.dirname(self.pkl_file), "detections.txt")
        try:
            with open(detections_file, 'w', encoding='utf-8') as f:
                for i in range(self.results_list.size()):
                    entry = self.results_list.get(i)
                    file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
                    file_hash = entry.split(" (Hash:")[1].rstrip(")").strip()
                    quarantine_filename = os.path.basename(file_path) + f".{file_hash}.quarantine"
                    quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
                    try:
                        file_size = os.path.getsize(quarantine_path) if os.path.exists(quarantine_path) else "Unknown"
                        size_str = f"{file_size:,} bytes" if isinstance(file_size, int) else file_size
                    except:
                        size_str = "Unknown"
                    f.write(f"File: {file_path}\nHash: {file_hash}\nSize: {size_str}\n\n")
            messagebox.showinfo("Success", f"Detections exported to {detections_file}")
            logging.info(f"Exported {self.results_list.size()} detections to {detections_file}")
            self.add_report(detections_file, "N/A", "Exported detections")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export detections: {str(e)}")
            logging.error(f"Failed to export detections to {detections_file}: {str(e)}")

    def remove_selected_hash(self):
        selected = self.results_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select a detection to remove its hash.")
            return

        confirm = messagebox.askyesno("Confirmation", "Are you sure you want to remove the selected hash(es) from the database? This will prevent future detections of this hash.")
        if not confirm:
            return

        removed_hashes = set()
        for idx in sorted(selected, reverse=True):
            entry = self.results_list.get(idx)
            try:
                file_hash = entry.split(" (Hash:")[1].rstrip(")").strip()
                with self.hashes_lock:
                     with self.get_hashes_connection() as conn2:
                        cur2 = conn2.cursor()
                        cur2.execute("DELETE FROM hashes WHERE hash = ?", (file_hash,))
                        conn2.commit()
                removed_hashes.add(file_hash)
                logging.info(f"Removed hash from database: {file_hash}")
                self.results_list.delete(idx)
            except Exception as e:
                logging.error(f"Failed to parse or remove hash from entry: {entry} - {str(e)}")

        if removed_hashes:
            self.root.after(0, lambda: self.db_count_label.config(text=f"Loaded hashes: {self.get_hash_count()}"))
            messagebox.showinfo("Success", f"Removed {len(removed_hashes)} hash(es) from database.")
            self.add_report("Database", "N/A", f"Removed {len(removed_hashes)} hash(es)")

    def check_selected_on_virustotal(self):
        selected = self.results_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select a detection to check on VirusTotal.")
            return

        for idx in selected:
            entry = self.results_list.get(idx)
            file_path = entry.split(" (Hash:")[0].replace("Detected: ", "")
            file_hash = entry.split(" (Hash:")[1].rstrip(")").strip()
            quarantine_filename = os.path.basename(file_path) + f".{file_hash}.quarantine"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            if os.path.exists(quarantine_path):
                hashes = self.compute_hash(quarantine_path)
                if hashes:
                    sha256 = hashes.get('sha256', None)
                    if sha256:
                        url = f"https://www.virustotal.com/gui/file/{sha256}"
                        webbrowser.open(url)
                        logging.debug(f"Opened VirusTotal for {sha256}")
                    else:
                        messagebox.showerror("Error", "Could not compute SHA256 hash.")
                else:
                    messagebox.showerror("Error", "Could not compute hashes.")
            else:
                if os.path.exists(file_path):
                    hashes = self.compute_hash(file_path)
                    if hashes:
                        sha256 = hashes.get('sha256', None)
                        if sha256:
                            url = f"https://www.virustotal.com/gui/file/{sha256}"
                            webbrowser.open(url)
                            logging.debug(f"Opened VirusTotal for {sha256}")
                        else:
                            messagebox.showerror("Error", "Could not compute SHA256 hash.")
                    else:
                        messagebox.showerror("Error", "Could not compute hashes.")
                else:
                    messagebox.showwarning("Warning", f"Quarantined file not found: {quarantine_path} \n Original Path of file not found: {file_path}")

    def check_auto_start(self):
        try:
            if os.name == 'nt':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, "VirusBytes")
                winreg.CloseKey(key)
                return os.path.abspath(sys.argv[0]) in value  # Check if script path is part of the value
        except:
            return False

    def toggle_auto_start(self):
        try:
            if os.name == 'nt':
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_ALL_ACCESS)
                script_path = os.path.abspath(sys.argv[0])
                python_path = os.path.join(os.path.dirname(sys.executable), 'python.exe')
                if os.path.exists(python_path):
                    full_command = f'"{python_path}" "{script_path}"'  # Use pythonw.exe for no console
                else:
                    logging.warning("pythonw.exe not found, falling back to python.exe")
                    full_command = f'"{sys.executable}" "{script_path}"'
                if self.auto_start_var.get():
                    winreg.SetValueEx(key, "VirusBytes", 0, winreg.REG_SZ, full_command)
                    logging.debug(f"Added VirusBytes to auto-start with command: {full_command}")
                else:
                    winreg.DeleteValue(key, "VirusBytes")
                    logging.debug("Removed VirusBytes from auto-start")
                winreg.CloseKey(key)
        except Exception as e:
            logging.error(f"Failed to toggle auto-start (registry): {str(e)}")
            messagebox.showerror("Error", f"Failed to toggle auto-start (registry): {str(e)}. Try running as Administrator.")

    def start_export_cvd(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".cvd", filetypes=[("CVD Files", "*.cvd")])
        if not file_path:
            return
        self.progress['value'] = 0
        self.current_label.config(text="Exporting to CVD...")
        self.root.update_idletasks()
        threading.Thread(target=self.export_to_cvd, args=(file_path,), daemon=True).start()

    def export_to_cvd(self, file_path):
        try:
            with self.hashes_lock:
                with self.get_hashes_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT hash FROM hashes")
                    hashes = [row[0] for row in cur.fetchall()]
            count = len(hashes)
            if count == 0:
                raise ValueError("No hashes to export.")

            with tempfile.TemporaryDirectory() as tmp_dir:
                hdb_path = os.path.join(tmp_dir, "main.hdb")
                with open(hdb_path, 'w') as f:
                    for h in hashes:
                        f.write(f"{h}:1:VirusBytes\n")

                tar_io = io.BytesIO()
                with tarfile.open(fileobj=tar_io, mode="w") as tar:
                    tar.add(hdb_path, arcname="main.hdb")
                tar_data = tar_io.getvalue()

                gz_io = io.BytesIO()
                with gzip.GzipFile(fileobj=gz_io, mode='wb') as gz:
                    gz.write(tar_data)
                gz_data = gz_io.getvalue()

                md5 = hashlib.md5(gz_data).hexdigest()

                date_str = time.strftime("%d %b %Y %H-%M-%S")
                builder = "sourcecode347"
                flevel = 1
                dsig = ""
                header_str = f"VirusBytes-DB:{date_str}:{count}:{flevel}:{builder}:{md5}:{dsig}:0"
                header = header_str.encode('utf-8').ljust(512, b'\0')

                with open(file_path, 'wb') as f:
                    f.write(header)
                    f.write(gz_data)

            self.root.after(0, lambda: messagebox.showinfo("Success", f"Exported {count} hashes to {file_path}"))
            logging.debug(f"Exported {count} hashes to CVD: {file_path}")
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to export CVD: {str(e)}"))
            logging.error(f"Failed to export CVD to {file_path}: {str(e)}")
        finally:
            self.root.after(0, lambda: self.progress.config(value=100))
            self.root.after(0, lambda: self.current_label.config(text=""))
            gc.collect()

    def start_export_pkl(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pkl", filetypes=[("PKL Files", "*.pkl")])
        if not file_path:
            return
        self.progress['value'] = 0
        self.current_label.config(text="Exporting to PKL...")
        self.root.update_idletasks()
        threading.Thread(target=self.export_to_pkl, args=(file_path,), daemon=True).start()

    def export_to_pkl(self, file_path):
        try:
            with self.hashes_lock:
                with self.get_hashes_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT hash FROM hashes")
                    hashes = set(row[0] for row in cur.fetchall())
            with open(file_path, 'wb') as f:
                pickle.dump(hashes, f)
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Exported {len(hashes)} hashes to {file_path}"))
            logging.debug(f"Exported {len(hashes)} hashes to PKL: {file_path}")
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to export PKL: {str(e)}"))
            logging.error(f"Failed to export PKL to {file_path}: {str(e)}")
        finally:
            self.root.after(0, lambda: self.progress.config(value=100))
            self.root.after(0, lambda: self.current_label.config(text=""))
            gc.collect()

if __name__ == "__main__":
    print(logoascii)
    logging.debug("Starting VirusBytes application")
    try:
        root = tk.Tk()
        app = VirusBytes(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"Application failed to start: {str(e)}")
        raise