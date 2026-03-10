import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import threading
import time
from scapy.all import sniff

# Import our fuzzy logic module
from fuzzy_logic import evaluate_risk, traffic_var, logins_var, risk_var

class CybersecurityRiskApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Fuzzy Logic Cybersecurity Risk Detection")
        self.root.geometry("1000x800")
        
        # Configure layout
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=2)
        self.root.rowconfigure(0, weight=1)

        # Left Panel for Controls
        control_frame = ttk.LabelFrame(self.root, text="Network Parameters", padding=10)
        control_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Traffic input
        ttk.Label(control_frame, text="Network Traffic (packets/sec):", font=("Helvetica", 10, "bold")).pack(pady=(10, 0), anchor="w")
        self.traffic_val = tk.IntVar(value=500)
        self.traffic_label = ttk.Label(control_frame, text="500", font=("Helvetica", 10))
        self.traffic_label.pack(anchor="w")
        self.traffic_scale = ttk.Scale(
            control_frame, from_=0, to=1000, orient="horizontal", 
            variable=self.traffic_val, command=self.update_traffic_label
        )
        self.traffic_scale.pack(fill="x", pady=5)
        
        # Live Capture toggle
        self.live_capture_var = tk.BooleanVar(value=False)
        self.live_capture_cb = ttk.Checkbutton(
            control_frame, text="Live Packet Capture (Wireshark mode)", 
            variable=self.live_capture_var, command=self.toggle_live_capture
        )
        self.live_capture_cb.pack(fill="x", pady=(0, 10))
        
        # Packet counter for sniffing
        self.packet_count = 0
        self.sniffing_thread = None
        self.stop_sniffing = threading.Event()
        
        # Logins input
        ttk.Label(control_frame, text="Failed Logins (attempts/min):", font=("Helvetica", 10, "bold")).pack(pady=(20, 0), anchor="w")
        self.logins_val = tk.IntVar(value=25)
        self.logins_label = ttk.Label(control_frame, text="25", font=("Helvetica", 10))
        self.logins_label.pack(anchor="w")
        self.logins_scale = ttk.Scale(
            control_frame, from_=0, to=50, orient="horizontal", 
            variable=self.logins_val, command=self.update_logins_label
        )
        self.logins_scale.pack(fill="x", pady=5)
        
        # Analyze Button
        self.analyze_btn = ttk.Button(control_frame, text="Analyze Risk", command=self.analyze)
        self.analyze_btn.pack(pady=30, fill="x")
        
        # Result Display
        self.result_frame = ttk.LabelFrame(control_frame, text="Risk Analysis Result", padding=10)
        self.result_frame.pack(fill="x", pady=10)
        
        self.risk_level_label = ttk.Label(self.result_frame, text="Risk Level: N/A", font=("Helvetica", 16, "bold"))
        self.risk_level_label.pack(pady=10)
        self.risk_pct_label = ttk.Label(self.result_frame, text="0.00%", font=("Helvetica", 14))
        self.risk_pct_label.pack(pady=5)

        # Right Panel for Graphs
        self.graph_frame = ttk.Frame(self.root, padding=10)
        self.graph_frame.grid(row=0, column=1, sticky="nsew")
        
        # Initialize empty figure
        self.fig = plt.Figure(figsize=(7, 8), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Initial plot
        self.plot_membership_functions()

    def update_traffic_label(self, val):
        self.traffic_label.config(text=str(int(float(val))))

    def update_logins_label(self, val):
        self.logins_label.config(text=str(int(float(val))))
        
    def toggle_live_capture(self):
        if self.live_capture_var.get():
            self.traffic_scale.state(["disabled"])
            self.stop_sniffing.clear()
            self.packet_count = 0
            self.sniffing_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            self.sniffing_thread.start()
            self.update_traffic_loop()
        else:
            self.traffic_scale.state(["!disabled"])
            self.stop_sniffing.set()
            
    def packet_callback(self, packet):
        if not self.stop_sniffing.is_set():
            self.packet_count += 1

    def start_sniffing(self):
        try:
            sniff(prn=self.packet_callback, store=False, stop_filter=lambda p: self.stop_sniffing.is_set())
        except Exception as e:
            print(f"Error sniffing: {e}")

    def update_traffic_loop(self):
        if self.live_capture_var.get():
            current_count = self.packet_count
            self.packet_count = 0  # reset count for next second
            
            # Since scapy capture might be fast but not extremely high without load, 
            # let's map the raw packet count directly or apply a multiplier if desired.
            # Using raw count for now, capped at 1000.
            display_count = min(1000, current_count)
            self.traffic_val.set(display_count)
            self.update_traffic_label(display_count)
            
            # Trigger analysis with new live values
            self.analyze()
            
            self.root.after(1000, self.update_traffic_loop)
        
    def analyze(self):
        traffic = self.traffic_val.get()
        logins = self.logins_val.get()
        
        risk = evaluate_risk(traffic, logins)
        
        # Determine risk category
        if risk < 40.0:
            category = "LOW"
            color = "green"
        elif risk < 70.0:
            category = "MEDIUM"
            color = "orange"
        else:
            category = "HIGH"
            color = "red"
            
        self.risk_level_label.config(text=f"Risk Level: {category}", foreground=color)
        self.risk_pct_label.config(text=f"{risk:.2f}%")
        
        self.plot_risk_result(traffic, logins, risk)

    def plot_membership_functions(self):
        self.fig.clear()
        
        ax1 = self.fig.add_subplot(311)
        ax2 = self.fig.add_subplot(312)
        ax3 = self.fig.add_subplot(313)
        
        # Plot Traffic
        for label in traffic_var.terms:
            ax1.plot(traffic_var.universe, traffic_var[label].mf, label=label)
        ax1.set_title("Network Traffic")
        ax1.legend()
        
        # Plot Logins
        for label in logins_var.terms:
            ax2.plot(logins_var.universe, logins_var[label].mf, label=label)
        ax2.set_title("Failed Logins")
        ax2.legend()
        
        # Plot Risk
        for label in risk_var.terms:
            ax3.plot(risk_var.universe, risk_var[label].mf, label=label)
        ax3.set_title("Risk Level")
        ax3.legend()
        
        self.fig.tight_layout()
        self.canvas.draw()
        
    def plot_risk_result(self, traffic, logins, risk):
        self.fig.clear()
        
        ax1 = self.fig.add_subplot(311)
        ax2 = self.fig.add_subplot(312)
        ax3 = self.fig.add_subplot(313)
        
        # Plot Traffic with vertical line
        for label in traffic_var.terms:
            ax1.plot(traffic_var.universe, traffic_var[label].mf, label=label)
        ax1.axvline(x=traffic, color='red', linestyle='--', linewidth=2, label=f'Input: {traffic}')
        ax1.set_title("Network Traffic")
        ax1.legend()
        
        # Plot Logins with vertical line
        for label in logins_var.terms:
            ax2.plot(logins_var.universe, logins_var[label].mf, label=label)
        ax2.axvline(x=logins, color='red', linestyle='--', linewidth=2, label=f'Input: {logins}')
        ax2.set_title("Failed Logins")
        ax2.legend()
        
        # Plot Risk Result
        for label in risk_var.terms:
            ax3.plot(risk_var.universe, risk_var[label].mf, label=label, alpha=0.5)
            
        ax3.axvline(x=risk, color='black', linestyle='-', linewidth=3, label=f'Result: {risk:.1f}%')
        
        # Optional: draw a patch to color code the background risk level area
        if risk < 40.0:
            ax3.axvspan(0, 40, color='green', alpha=0.2)
        elif risk < 70.0:
            ax3.axvspan(20, 80, color='orange', alpha=0.2)
        else:
            ax3.axvspan(60, 100, color='red', alpha=0.2)
            
        ax3.set_title("Computed Risk Level")
        ax3.legend()
        
        self.fig.tight_layout()
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    app = CybersecurityRiskApp(root)
    root.mainloop()
