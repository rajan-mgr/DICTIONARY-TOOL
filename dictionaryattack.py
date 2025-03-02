import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import threading
import bcrypt
from hashlib import new as hash_new
import zipfile

class EnhancedHashCracker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash & ZIP Cracker Pro")
        self.geometry("800x600")
        self.configure(bg="#2e2e2e")
        self.wordlists = {
            "rockyou.txt": "/usr/share/wordlists/rockyou.txt",
            "SecLists": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        }
        self.running = False
        self.style = ttk.Style(self)
        self.configure_styles()
        self.create_widgets()
        
    def configure_styles(self):
        self.style.theme_use("clam")
        self.style.configure(".", background="#2e2e2e", foreground="white")
        self.style.configure("TFrame", background="#2e2e2e")
        self.style.configure("TLabel", background="#2e2e2e", foreground="white", font=("Helvetica", 10))
        self.style.configure("TButton", background="#404040", foreground="white", borderwidth=1,
                           font=("Helvetica", 10, "bold"))
        self.style.configure("TEntry", fieldbackground="#404040", foreground="white")
        self.style.configure("TCombobox", fieldbackground="#404040", foreground="white")
        self.style.map("TButton",
                      background=[("active", "#505050"), ("disabled", "#303030")],
                      foreground=[("active", "white")])

    def create_widgets(self):
        # Header Frame
        header_frame = ttk.Frame(self, padding=(20, 10))
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="🔒 Hash & ZIP Cracker Pro", font=("Helvetica", 16, "bold"), 
                 foreground="#00ff00").pack()

        # Main Container
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(expand=True, fill="both")

        # Attack Type
        attack_frame = ttk.Frame(main_frame)
        attack_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Label(attack_frame, text="Attack Type:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.attack_type = ttk.Combobox(attack_frame, values=["Hash Attack", "ZIP Attack"], width=15)
        self.attack_type.set("Hash Attack")
        self.attack_type.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        self.attack_type.bind("<<ComboboxSelected>>", self.toggle_attack_type)

        # Hash Input Frame
        self.hash_frame = ttk.Frame(main_frame)
        ttk.Label(self.hash_frame, text="Target Hash:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.hash_entry = ttk.Entry(self.hash_frame, width=70)
        self.hash_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)
        ttk.Label(self.hash_frame, text="Hash Type:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.hash_type = ttk.Combobox(self.hash_frame, values=["md5", "sha1", "sha256", "bcrypt", "ntlm"], width=15)
        self.hash_type.set("sha256")
        self.hash_type.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.hash_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # ZIP Input Frame
        self.zip_frame = ttk.Frame(main_frame)
        ttk.Label(self.zip_frame, text="ZIP File:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.zip_entry = ttk.Entry(self.zip_frame, width=70)
        self.zip_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.zip_frame, text="Browse", command=self.browse_zip).grid(row=0, column=2, padx=5)
        self.zip_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))
        self.zip_frame.grid_forget()

        # Wordlist Section
        wordlist_frame = ttk.Frame(main_frame)
        ttk.Label(wordlist_frame, text="Wordlist Path:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.wordlist_entry = ttk.Entry(wordlist_frame, width=60)
        self.wordlist_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(wordlist_frame, text="Browse", command=self.browse_wordlist).grid(row=0, column=2, padx=5)
        wordlist_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # Preset Buttons
        preset_frame = ttk.Frame(main_frame)
        ttk.Button(preset_frame, text="Use rockyou", 
                  command=lambda: self.load_preset("rockyou.txt")).grid(row=0, column=0, padx=5)
        ttk.Button(preset_frame, text="Use SecLists", 
                  command=lambda: self.load_preset("SecLists")).grid(row=0, column=1, padx=5)
        preset_frame.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode="indeterminate", style="TProgressbar")
        self.progress.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        # Results Display
        result_frame = ttk.Frame(main_frame)
        ttk.Label(result_frame, text="Cracking Progress:").grid(row=0, column=0, sticky="w")
        self.result_text = tk.Text(result_frame, height=10, width=80, bg="#404040", fg="white",
                                 insertbackground="white", font=("Consolas", 9))
        self.result_text.grid(row=1, column=0, sticky="nsew")
        result_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=(0, 10))

        # Control Button
        self.control_button = ttk.Button(main_frame, text="Start Attack", command=self.toggle_attack)
        self.control_button.grid(row=6, column=0, columnspan=2, pady=(10, 0))

    def toggle_attack_type(self, event=None):
        if self.attack_type.get() == "Hash Attack":
            self.zip_frame.grid_forget()
            self.hash_frame.grid()
        else:
            self.hash_frame.grid_forget()
            self.zip_frame.grid()

    def browse_wordlist(self):
        path = filedialog.askopenfilename()
        self.wordlist_entry.delete(0, tk.END)
        self.wordlist_entry.insert(0, path)

    def browse_zip(self):
        path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        self.zip_entry.delete(0, tk.END)
        self.zip_entry.insert(0, path)

    def load_preset(self, preset_name):
        if preset_name in self.wordlists:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, self.wordlists[preset_name])
        else:
            messagebox.showwarning("Preset Error", "Selected preset not available")

    def toggle_attack(self):
        if not self.running:
            self.start_attack()
            self.control_button.config(text="Stop Attack")
        else:
            self.stop_attack()
            self.control_button.config(text="Start Attack")

    def start_attack(self):
        wordlist_path = self.wordlist_entry.get()
        attack_type = self.attack_type.get()

        if not wordlist_path:
            messagebox.showerror("Error", "Wordlist is required!")
            return

        if attack_type == "Hash Attack":
            target_hash = self.hash_entry.get().strip()
            hash_type = self.hash_type.get().lower()
            if not all([target_hash, hash_type]):
                messagebox.showerror("Error", "Hash fields are required!")
                return
            args = (target_hash, hash_type, wordlist_path)
        else:
            zip_path = self.zip_entry.get()
            if not zip_path:
                messagebox.showerror("Error", "ZIP file is required!")
                return
            args = (zip_path, wordlist_path)

        self.running = True
        self.result_text.delete(1.0, tk.END)
        self.progress.start()
        
        attack_thread = threading.Thread(
            target=self.run_cracking,
            args=args
        )
        attack_thread.start()

    def stop_attack(self):
        self.running = False
        self.progress.stop()
        self.result_text.insert(tk.END, "\n[!] Attack stopped by user")

    def run_cracking(self, *args):
        try:
            if self.attack_type.get() == "Hash Attack":
                self.crack_hash(*args)
            else:
                self.crack_zip(*args)
        except Exception as e:
            self.after(10, self.show_result, f"[!] Error: {str(e)}")
        finally:
            self.running = False
            self.after(10, self.progress.stop)
            self.after(10, lambda: self.control_button.config(text="Start Attack"))

    def crack_hash(self, target_hash, hash_type, wordlist_path):
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    if not self.running:
                        break
                    password = line.strip()
                    self.after(10, self.update_display, f"Testing: {password}")
                    
                    if self.verify_hash(password, target_hash, hash_type):
                        self.after(10, self.show_result, f"[+] Cracked! Password: {password}")
                        return
                
                self.after(10, self.show_result, "[-] Password not found in wordlist")
        except Exception as e:
            self.after(10, self.show_result, f"[!] Error: {str(e)}")

    def crack_zip(self, zip_path, wordlist_path):
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    if not self.running:
                        break
                    password = line.strip()
                    self.after(10, self.update_display, f"Testing: {password}")
                    
                    if self.test_zip_password(zip_path, password):
                        self.after(10, self.show_result, f"[+] Cracked! ZIP Password: {password}")
                        return
                
                self.after(10, self.show_result, "[-] Password not found in wordlist")
        except Exception as e:
            self.after(10, self.show_result, f"[!] Error: {str(e)}")

    def verify_hash(self, password, target_hash, hash_type):
        try:
            if hash_type == "bcrypt":
                return bcrypt.checkpw(password.encode(), target_hash.encode())
            elif hash_type == "ntlm":
                hash_ntlm = hash_new('md4', password.encode('utf-16le')).hexdigest()
                return hash_ntlm == target_hash.lower()
            else:
                hasher = hashlib.new(hash_type, password.encode())
                return hasher.hexdigest() == target_hash.lower()
        except Exception as e:
            self.after(10, self.show_result, f"[!] Hash Error: {str(e)}")
            return False

    def test_zip_password(self, zip_path, password):
        try:
            with zipfile.ZipFile(zip_path) as zf:
                zf.setpassword(password.encode())
                with zf.open(zf.infolist()[0]) as f:
                    f.read(1)
                return True
        except:
            return False

    def update_display(self, message):
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)

    def show_result(self, message):
        self.result_text.insert(tk.END, message)
        self.result_text.see(tk.END)

if __name__ == "__main__":
    app = EnhancedHashCracker()
    app.mainloop()
