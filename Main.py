import customtkinter as ctk
import serial, serial.tools.list_ports
import threading, os, platform, hashlib
from pathlib import Path
from dotenv import load_dotenv

# load password hash
load_dotenv(dotenv_path=Path(__file__).resolve().parent / '.env')


class ProximityLockApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        # retrieve the password hash
        self.stored_hash = os.getenv("ADMIN_HASH")

        # name & dimensions
        self.title("UWB Security Lock")
        self.geometry("500x700")

        # check if locked
        self.is_locked = False

        self.distance_history = []
        self.smoothing_window = 25

        self.nan_counter = 0
        self.verifying_presence = False

        # initialize variables
        self.current_distance, self.offset, self.away_count = 0, 0, 0
        self.lock_radius, self.time_to_lock = ctk.IntVar(value=150), ctk.IntVar(value=3)
        self.running, self.ser = False, None

        # initialize the tabbed interface
        self.tabview = ctk.CTkTabview(self, command=self.handle_auth)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        self.tab_dash = self.tabview.add("Dashboard")
        self.tab_admin = self.tabview.add("Admin Settings")

        # set up dashboard visuals
        self.label = ctk.CTkLabel(self.tab_dash, text="0 cm", font=("Arial", 48, "bold"))
        self.label.pack(pady=40)
        self.status_label = ctk.CTkLabel(self.tab_dash, text="STATUS: DISCONNECTED", font=("Arial", 14, "bold"),
                                         text_color="gray")
        self.status_label.pack()

        self.create_admin_controls()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)



    def create_admin_controls(self):
        ctk.CTkLabel(self.tab_admin, text="Bridge Device:", font=("Arial", 12, "bold")).pack(pady=(10, 0))
        self.port_menu = ctk.CTkOptionMenu(self.tab_admin, values=self.get_ports(), command=self.change_port)
        self.port_menu.pack(pady=5)

        self.add_setting("Security Radius (cm)", 50, 400, self.lock_radius)
        self.add_setting("Lock Delay (seconds)", 1, 100, self.time_to_lock)

        ctk.CTkButton(self.tab_admin, text="Calibrate 0cm", command=self.calibrate).pack(pady=20)

        ctk.CTkLabel(self.tab_admin, text="Hardware Terminal", font=("Arial", 12, "bold")).pack(pady=(20, 0))

        self.terminal_output = ctk.CTkTextbox(self.tab_admin, height=150, width=400)
        self.terminal_output.pack(pady=5)
        self.terminal_output.configure(state="disabled")

        self.command_entry = ctk.CTkEntry(self.tab_admin, placeholder_text="Type command (e.g. 'si')")
        self.command_entry.pack(pady=5, fill="x", padx=40)
        self.command_entry.bind("<Return>", lambda e: self.send_manual_command())

        ctk.CTkButton(self.tab_admin, text="Send Command", command=self.send_manual_command).pack(pady=5)

    def add_setting(self, label, fr, to, var):
        ctk.CTkLabel(self.tab_admin, text=label, font=("Arial", 12, "bold")).pack(pady=(10, 0))
        s = ctk.CTkSlider(self.tab_admin, from_=fr, to=to, variable=var)
        s.pack()
        l = ctk.CTkLabel(self.tab_admin, text=f"{var.get()}")
        l.pack()
        s.configure(command=lambda v: l.configure(text=f"{int(v)}"))

    def handle_auth(self):
        if self.tabview.get() == "Admin Settings":
            # Immediately switch back to Dashboard while we authenticate
            self.tabview.set("Dashboard")
            self.request_password()

    def request_password(self):
        # Create a popup window
        self.auth_win = ctk.CTkToplevel(self)
        self.auth_win.title("Admin Authentication")
        self.auth_win.geometry("300x150")
        self.auth_win.attributes("-topmost", True)
        self.auth_win.grab_set()  # Prevent clicking main window

        ctk.CTkLabel(self.auth_win, text="Enter Admin Password:", font=("Arial", 12, "bold")).pack(pady=10)

        # The 'show="*"' is what creates the mask
        self.pw_entry = ctk.CTkEntry(self.auth_win, show="*", width=200)
        self.pw_entry.pack(pady=5)
        self.pw_entry.focus_set()

        # Bind the Enter key to the submit function
        self.pw_entry.bind("<Return>", lambda e: self.verify_admin_pass())

        ctk.CTkButton(self.auth_win, text="Login", command=self.verify_admin_pass).pack(pady=10)

    def verify_admin_pass(self):
        pw = self.pw_entry.get()
        if hashlib.sha256(pw.encode()).hexdigest() == self.stored_hash:
            self.auth_win.destroy()
            # If correct, stay on Admin tab
            self.tabview.set("Admin Settings")
        else:
            self.auth_win.destroy()
            self.tabview.set("Dashboard")
            print("Access Denied: Incorrect Password")

    def get_ports(self):
        keys = ["SEGGER", "J-LINK", "USBMODEM"]
        ports = [p.device for p in serial.tools.list_ports.comports()
                 if any(k in (p.description + p.device).upper() for k in keys)]
        return ports or ["No Bridge Located"]

    def calibrate(self):
        self.offset += self.current_distance

    def change_port(self, port):
        if port == "No Device Found": return
        self.running = False
        if self.ser: self.ser.close()
        self.running = True
        threading.Thread(target=self.serial_reader, args=(port,), daemon=True).start()

    def serial_reader(self, port):
        try:
            with serial.Serial(port, 115200, timeout=2) as self.ser:
                self.ser.write(b'\r\r lec\r\r')
                while self.running:
                    line = self.ser.readline().decode(errors='ignore')


                    if line.strip():
                        self.after(0, lambda l=line: self.log_to_terminal(l))


                    # Debug line
                    if line.strip(): print(f"[DEBUG RAW]: {line.strip()}")


                    if "nan" in line.lower() and "0A92" in line:
                        self.nan_counter += 1
                        if self.nan_counter >= 10 and not self.verifying_presence and not self.is_locked:
                            self.after(0, self.trigger_presence_check)
                        continue

                    if "POS" in line and "0A92" in line:
                        self.nan_counter = 0
                        if self.verifying_presence:
                            self.after(0, self.cancel_presence_check)
                        # Extracting 3D coordinates and converting to Euclidean distance
                        try:
                            parts = line.split(',')
                            x_t = float(parts[3])  # X Axis
                            y_t = float(parts[4])  # Y Axis
                            z_t = float(parts[5])  # Z Axis

                            # 3D Euclidean Calculation (Reference origin is 0,0,0)
                            d_raw = (x_t ** 2 + y_t ** 2 + z_t ** 2) ** 0.5

                            # Convert meters to cm and apply calibration offset
                            self.current_distance = int(abs(d_raw * 100)) - self.offset
                            self.after(0, lambda: self.label.configure(text=f"{self.current_distance} cm"))

                        except (ValueError, IndexError):
                            # Log the error and skip the cycle to maintain system uptime
                            continue
        except Exception as e:
            self.after(0, lambda err=e: self.status_label.configure(text=f"ERR: {err}"))

    def trigger_presence_check(self):
        """Minimalist timed popup"""
        if self.verifying_presence: return

        self.verifying_presence, self.countdown_val = True, 10
        self.presence_popup = ctk.CTkToplevel(self)
        self.presence_popup.title("Signal Lost")
        self.presence_popup.geometry("300x180")
        self.presence_popup.attributes("-topmost", True)
        self.presence_popup.grab_set()

        self.presence_label = ctk.CTkLabel(self.presence_popup, text=f"Locking in {self.countdown_val}s...",
                                           font=("Arial", 14, "bold"))
        self.presence_label.pack(pady=20)

        ctk.CTkButton(self.presence_popup, text="I'm here", command=self.cancel_presence_check).pack()
        self.run_countdown()

    def run_countdown(self):
        if not self.verifying_presence: return

        if self.countdown_val > 0:
            self.countdown_val -= 1
            self.presence_label.configure(text=f"Locking in {self.countdown_val}s...")
            self.after(1000, self.run_countdown)
        else:
            self.execute_lock()

    def cancel_presence_check(self):
        self.verifying_presence = False
        if hasattr(self, 'presence_popup') and self.presence_popup is not None:
            try:
                if self.presence_popup.winfo_exists():
                    self.presence_popup.destroy()
                self.presence_popup = None
            except:
                pass

    def execute_lock(self):
        self.cancel_presence_check()
        self.is_locked = True
        self.away_count = 0
        cmd = "rundll32.exe user32.dll,LockWorkStation" if platform.system() == "Windows" else "pmset displaysleepnow"
        os.system(cmd)

    # --- SIMPLIFIED RECOVERY LOGIC ---
    def trigger_recovery_dialog(self):
        """Just opens the window. Main loop handles the checking."""
        if hasattr(self, 'recovery_win') and self.recovery_win.winfo_exists():
            self.recovery_win.lift()
            return

        self.recovery_win = ctk.CTkToplevel(self)
        self.recovery_win.title("Security Recovery")
        self.recovery_win.geometry("400x200")
        self.recovery_win.attributes("-topmost", True)
        self.recovery_win.grab_set()

        ctk.CTkLabel(self.recovery_win, text="UWB Signal Missing!\nRestore LOS or use Manual Override.",
                     font=("Arial", 14, "bold")).pack(pady=20)
        ctk.CTkButton(self.recovery_win, text="Manual Override", fg_color="orange", command=self.manual_override).pack(
            pady=10)

    def manual_override(self):
        self.is_locked = False
        self.away_count = 0
        if hasattr(self, 'recovery_win'): self.recovery_win.destroy()

    def check_security(self):
        """Robust non-blocking security loop"""

        # 1. Recovery Mode: If locked, check for signal or show dialog
        if self.is_locked:
            if 0 < self.current_distance < self.lock_radius.get():
                # Signal found: Unlock and remove dialog
                self.is_locked = False
                self.away_count = 0
                self.status_label.configure(text="STATUS: SECURE", text_color="green")
                if hasattr(self, 'recovery_win'): self.recovery_win.destroy()
            else:
                # No signal: Ensure dialog is open
                self.status_label.configure(text="STATUS: RECOVERY MODE", text_color="orange")
                self.trigger_recovery_dialog()

            # CRITICAL: Keep loop alive, but skip the locking logic below
            self.after(100, self.check_security)
            return

        # 2. Monitoring Mode: Only runs if NOT locked
        is_away = self.current_distance > self.lock_radius.get()
        self.away_count = self.away_count + 1 if is_away else 0

        if self.away_count >= (self.time_to_lock.get() * 10):
            self.execute_lock()
            # Loop continues next cycle (which will hit the 'if self.is_locked' block)
            self.after(100, self.check_security)
            return

        status = ("LOCKING...", "red") if is_away and self.away_count > 0 else ("SECURE", "green")
        self.status_label.configure(text=f"STATUS: {status[0]}", text_color=status[1])

        self.after(100, self.check_security)

    def on_closing(self):
        self.running = False
        self.destroy()

    def send_manual_command(self):
        cmd = self.command_entry.get().strip()
        if self.ser and self.ser.is_open:
            # Hardware expects carriage returns to execute
            full_cmd = f"\r{cmd}\r".encode()
            self.ser.write(full_cmd)

            # UI Feedback
            self.log_to_terminal(f">>> {cmd}\n")
            self.command_entry.delete(0, 'end')
        else:
            self.log_to_terminal("ERR: Serial not connected.\n")

    def log_to_terminal(self, text):
        ## Updates terminal box ##
        self.terminal_output.configure(state="normal")
        self.terminal_output.insert("end", text)
        self.terminal_output.see("end")  # Scroll to bottom
        self.terminal_output.configure(state="disabled")


if __name__ == "__main__":
    app = ProximityLockApp()
    app.check_security()
    app.mainloop()