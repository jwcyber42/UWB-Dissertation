import customtkinter as ctk
import serial, serial.tools.list_ports
import threading, os, platform, hashlib, sys
from pathlib import Path
from dotenv import load_dotenv

# When running as a PyInstaller bundle, bundled files land in sys._MEIPASS (a temp folder).
# When running normally as a .py script, they're just next to this file.
# This helper makes sure we always find the .env regardless of how the app was launched.
def resource_path(filename):
    base = getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)
    return Path(base) / filename

# Pull the admin password hash from the .env file.
# Storing a hash instead of the plaintext means the password isn't exposed if someone opens the file.
load_dotenv(dotenv_path=resource_path('.env'))


class ProximityLockApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Grab the stored hash — we'll compare against this when the admin logs in
        self.stored_hash = os.getenv("ADMIN_HASH")

        self.title("UWB Security Lock")
        self.geometry("500x700")

        # is_locked tracks whether the workstation has been locked by the system.
        # Once True, the security loop shifts into recovery mode instead of monitoring.
        self.is_locked = False

        # nan_counter tracks how many consecutive NaN readings we've received.
        self.nan_counter = 0
        self.verifying_presence = False

        # current_distance: latest computed distance from the tag to the anchor origin (cm)
        # offset: calibration value — subtracted from raw distance to zero the reading
        # away_count: how many consecutive 100ms ticks the user has been outside the radius
        self.current_distance, self.offset, self.away_count = 0, 0, 0

        # lock_radius: the security bubble size in cm (user-adjustable)
        # time_to_lock: how many seconds outside the radius before the system locks
        self.lock_radius, self.time_to_lock = ctk.IntVar(value=150), ctk.IntVar(value=3)

        # running controls the serial reader thread loop. ser holds the open serial port.
        self.running, self.ser = False, None

        # Build the tabbed layout. handle_auth fires whenever the active tab changes,
        # so we can intercept clicks on Admin Settings and ask for a password.
        self.tabview = ctk.CTkTabview(self, command=self.handle_auth)
        self.tabview.pack(padx=10, pady=10, fill="both", expand=True)
        self.tab_dash = self.tabview.add("Dashboard")
        self.tab_admin = self.tabview.add("Admin Settings")

        # Large distance readout on the dashboard
        self.label = ctk.CTkLabel(self.tab_dash, text="0 cm", font=("Arial", 48, "bold"))
        self.label.pack(pady=40)

        # Status line below the distance — updates to SECURE / LOCKING... / RECOVERY MODE
        self.status_label = ctk.CTkLabel(self.tab_dash, text="STATUS: DISCONNECTED", font=("Arial", 14, "bold"),
                                         text_color="gray")
        self.status_label.pack()

        self.create_admin_controls()

        # Make sure the serial thread stops cleanly if the window is closed
        self.protocol("WM_DELETE_WINDOW", self.on_closing)



    def create_admin_controls(self):
        # Port selector — only shows devices matching known bridge identifiers
        ctk.CTkLabel(self.tab_admin, text="Bridge Device:", font=("Arial", 12, "bold")).pack(pady=(10, 0))
        self.port_menu = ctk.CTkOptionMenu(self.tab_admin, values=self.get_ports(), command=self.change_port)
        self.port_menu.pack(pady=5)

        # Sliders for the two main security parameters
        self.add_setting("Security Radius (cm)", 50, 400, self.lock_radius)
        self.add_setting("Lock Delay (seconds)", 1, 100, self.time_to_lock)

        # Calibrate sets the current distance as the new zero point.
        # Useful for correcting the hardware's anchor origin if it drifts.
        ctk.CTkButton(self.tab_admin, text="Calibrate 0cm", command=self.calibrate).pack(pady=20)

        # Raw terminal for sending commands directly to the DWM1001 over serial
        ctk.CTkLabel(self.tab_admin, text="Hardware Terminal", font=("Arial", 12, "bold")).pack(pady=(20, 0))

        self.terminal_output = ctk.CTkTextbox(self.tab_admin, height=150, width=400)
        self.terminal_output.pack(pady=5)
        self.terminal_output.configure(state="disabled")  # read-only until we write to it programmatically

        self.command_entry = ctk.CTkEntry(self.tab_admin, placeholder_text="Type command (e.g. 'si')")
        self.command_entry.pack(pady=5, fill="x", padx=40)
        self.command_entry.bind("<Return>", lambda e: self.send_manual_command())

        ctk.CTkButton(self.tab_admin, text="Send Command", command=self.send_manual_command).pack(pady=5)

    def add_setting(self, label, fr, to, var):
        # Reusable helper that draws a labelled slider and keeps the value label in sync
        ctk.CTkLabel(self.tab_admin, text=label, font=("Arial", 12, "bold")).pack(pady=(10, 0))
        s = ctk.CTkSlider(self.tab_admin, from_=fr, to=to, variable=var)
        s.pack()
        l = ctk.CTkLabel(self.tab_admin, text=f"{var.get()}")
        l.pack()
        s.configure(command=lambda v: l.configure(text=f"{int(v)}"))

    def handle_auth(self):
        if self.tabview.get() == "Admin Settings":
            # Switch back to Dashboard first, then prompt — prevents flashing the admin tab
            # before the password has been verified
            self.tabview.set("Dashboard")
            self.request_password()

    def request_password(self):
        # Modal popup so the user can't interact with the main window until they authenticate
        self.auth_win = ctk.CTkToplevel(self)
        self.auth_win.title("Admin Authentication")
        self.auth_win.geometry("300x150")
        self.auth_win.attributes("-topmost", True)
        self.auth_win.grab_set()

        ctk.CTkLabel(self.auth_win, text="Enter Admin Password:", font=("Arial", 12, "bold")).pack(pady=10)

        self.pw_entry = ctk.CTkEntry(self.auth_win, show="*", width=200)  # show="*" masks input as dots
        self.pw_entry.pack(pady=5)
        self.pw_entry.focus_set()

        self.pw_entry.bind("<Return>", lambda e: self.verify_admin_pass())
        ctk.CTkButton(self.auth_win, text="Login", command=self.verify_admin_pass).pack(pady=10)

    def verify_admin_pass(self):
        pw = self.pw_entry.get()
        # Hash the entered password and compare against the stored hash.
        # We never store or compare the plaintext password directly.
        if hashlib.sha256(pw.encode()).hexdigest() == self.stored_hash:
            self.auth_win.destroy()
            self.tabview.set("Admin Settings")  # correct password — let them in
        else:
            self.auth_win.destroy()
            self.tabview.set("Dashboard")  # wrong password — stay on dashboard
            print("Access Denied: Incorrect Password")

    def get_ports(self):
        # Filter connected serial ports to only show ones that look like a DWM1001 bridge.
        keys = ["USBMODEM"]
        ports = [p.device for p in serial.tools.list_ports.comports()
                 if any(k in (p.description + p.device).upper() for k in keys)]
        return ports or ["No Bridge Located"]

    def calibrate(self):
        # Add the current distance to the offset so it reads as 0cm from here.
        self.offset += self.current_distance

    def change_port(self, port):
        if port == "No Bridge Located": return

        # Stop any existing reader thread before starting a new one
        self.running = False
        if self.ser: self.ser.close()

        self.running = True
        # Daemon=True means the thread dies automatically when the main window closes
        threading.Thread(target=self.serial_reader, args=(port,), daemon=True).start()

    def serial_reader(self, port):
        # This runs on a background thread so it doesn't block the GUI.
        # It reads lines from the DWM1001 over UART and updates shared state.
        try:
            with serial.Serial(port, 115200, timeout=2) as self.ser:
                # 'lec' is the PANS shell command that starts streaming position data
                self.ser.write(b'\r\r lec\r\r')

                while self.running:
                    line = self.ser.readline().decode(errors='ignore')

                    # Mirror every line to the hardware terminal in the GUI
                    if line.strip():
                        self.after(0, lambda l=line: self.log_to_terminal(l))

                    if line.strip(): print(f"[DEBUG RAW]: {line.strip()}")

                    # After 10 consecutive NaNs we assume the user has left and start the countdown.
                    if "nan" in line.lower() and "0A92" in line:
                        self.nan_counter += 1
                        if self.nan_counter >= 10 and not self.verifying_presence and not self.is_locked:
                            self.after(0, self.trigger_presence_check)
                        continue

                    # A valid POS line means the tag is visible again — reset the NaN counter
                    # and cancel any in-progress presence check
                    if "POS" in line and "0A92" in line:
                        self.nan_counter = 0
                        if self.verifying_presence:
                            self.after(0, self.cancel_presence_check)

                        # Parse X, Y, Z from the PANS position packet and compute Euclidean distance.
                        # The anchors are arranged so that (0,0,0) is the reference origin at the workstation.
                        try:
                            parts = line.split(',')
                            x_t = float(parts[3])
                            y_t = float(parts[4])
                            z_t = float(parts[5])

                            # 3D Euclidean distance from the origin
                            d_raw = (x_t ** 2 + y_t ** 2 + z_t ** 2) ** 0.5

                            # Convert metres to cm, then subtract the calibration offset
                            self.current_distance = int(abs(d_raw * 100)) - self.offset
                            self.after(0, lambda: self.label.configure(text=f"{self.current_distance} cm"))

                        except (ValueError, IndexError):
                            # Malformed packet — skip and wait for the next one
                            continue

        except Exception as e:
            # If the serial connection drops, surface the error in the status label
            self.after(0, lambda err=e: self.status_label.configure(text=f"ERR: {err}"))

    def trigger_presence_check(self):
        # Popup that counts down before locking. Gives the user a chance to cancel. #
        if self.verifying_presence: return  # already showing — don't open a second one

        self.verifying_presence, self.countdown_val = True, 10
        self.presence_popup = ctk.CTkToplevel(self)
        self.presence_popup.title("Signal Lost")
        self.presence_popup.geometry("300x180")
        self.presence_popup.attributes("-topmost", True)
        self.presence_popup.grab_set()  # blocks interaction with the main window

        self.presence_label = ctk.CTkLabel(self.presence_popup, text=f"Locking in {self.countdown_val}s...",
                                           font=("Arial", 14, "bold"))
        self.presence_label.pack(pady=20)

        ctk.CTkButton(self.presence_popup, text="I'm here", command=self.cancel_presence_check).pack()
        self.run_countdown()

    def run_countdown(self):
        # Recursive 1-second tick. Each call schedules the next one via self.after()
        # so we're not blocking the main thread with a sleep.
        if not self.verifying_presence: return

        if self.countdown_val > 0:
            self.countdown_val -= 1
            self.presence_label.configure(text=f"Locking in {self.countdown_val}s...")
            self.after(1000, self.run_countdown)
        else:
            self.execute_lock()

    def cancel_presence_check(self):
        # Called when the tag reappears (signal recovered) or the user clicks "I'm here"
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

        # Different OS lock commands — Windows uses rundll32, macOS puts the display to sleep
        cmd = "rundll32.exe user32.dll,LockWorkStation" if platform.system() == "Windows" else "pmset displaysleepnow"
        os.system(cmd)

    def trigger_recovery_dialog(self):
        # Opens the recovery dialog. The security loop handles unlock detection. #

        # If the dialog is already open, just bring it to the front rather than opening another
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
        # Lets the user unlock manually if the UWB signal can't be restored (e.g. hardware fault)
        self.is_locked = False
        self.away_count = 0
        if hasattr(self, 'recovery_win'): self.recovery_win.destroy()

    def check_security(self):
        # Security state machine, polls every 100ms via self.after().

        # --- Locked state ---
        # Once locked, we just wait for a valid in-range reading before unlocking.
        if self.is_locked:
            if 0 < self.current_distance < self.lock_radius.get():
                # Tag is back in range — unlock and clear the recovery dialog
                self.is_locked = False
                self.away_count = 0
                self.status_label.configure(text="STATUS: SECURE", text_color="green")
                if hasattr(self, 'recovery_win'): self.recovery_win.destroy()
            else:
                # Still no signal — keep showing the recovery dialog
                self.status_label.configure(text="STATUS: RECOVERY MODE", text_color="orange")
                self.trigger_recovery_dialog()

            self.after(100, self.check_security)
            return

        # --- Normal monitoring ---
        # away_count increments every 100ms tick that the tag is outside the radius.
        # When it hits the threshold (time_to_lock * 10 ticks = time_to_lock seconds), we lock.
        is_away = self.current_distance > self.lock_radius.get()
        self.away_count = self.away_count + 1 if is_away else 0

        if self.away_count >= (self.time_to_lock.get() * 10):
            self.execute_lock()
            self.after(100, self.check_security)
            return

        # Update the status label — show LOCKING... in red if the countdown has started
        status = ("LOCKING...", "red") if is_away and self.away_count > 0 else ("SECURE", "green")
        self.status_label.configure(text=f"STATUS: {status[0]}", text_color=status[1])

        self.after(100, self.check_security)

    def on_closing(self):
        # Set running=False so the serial reader thread exits its while loop cleanly
        self.running = False
        self.destroy()

    def send_manual_command(self):
        cmd = self.command_entry.get().strip()
        if self.ser and self.ser.is_open:
            # The DWM1001 shell needs carriage returns as line terminators
            full_cmd = f"\r{cmd}\r".encode()
            self.ser.write(full_cmd)
            self.log_to_terminal(f">>> {cmd}\n")
            self.command_entry.delete(0, 'end')
        else:
            self.log_to_terminal("ERR: Serial not connected.\n")

    def log_to_terminal(self, text):
        # The textbox has to be temporarily enabled to insert text, then locked again
        self.terminal_output.configure(state="normal")
        self.terminal_output.insert("end", text)
        self.terminal_output.see("end")  # scroll to the latest line
        self.terminal_output.configure(state="disabled")


if __name__ == "__main__":
    app = ProximityLockApp()
    app.check_security()  # kick off the security polling loop before entering the GUI event loop
    app.mainloop()
