import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import threading
import queue

class FileScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Scope")
        self.root.geometry("600x400")

        # Create queue for thread-safe GUI updates
        self.update_queue = queue.Queue()

        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)

        # Select directory button
        self.select_btn = ttk.Button(self.main_frame, text="Select Directory", command=self.select_directory)
        self.select_btn.grid(row=0, column=0, pady=5, sticky=tk.W)

        # Directory path label
        self.dir_path = tk.StringVar()
        self.dir_label = ttk.Label(self.main_frame, textvariable=self.dir_path, wraplength=500)
        self.dir_label.grid(row=1, column=0, columnspan=2, pady=5, sticky=tk.W)

        # Scan button
        self.scan_btn = ttk.Button(self.main_frame, text="Start Scan", command=self.start_scan)
        self.scan_btn.grid(row=2, column=0, pady=5, sticky=tk.W)

        # Progress bar
        self.progress = ttk.Progressbar(self.main_frame, length=400, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))

        # Results text area with scrollbar
        self.results_frame = ttk.Frame(self.main_frame)
        self.results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.results_frame.columnconfigure(0, weight=1)
        self.results_frame.rowconfigure(0, weight=1)

        self.results_text = tk.Text(self.results_frame, height=15, width=70)
        self.scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_text.yview)

        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.results_text['yscrollcommand'] = self.scrollbar.set

        self.scanning = False
        self.selected_dir = ""

        # Start checking for updates
        self.check_queue()

    def check_queue(self):
        """Check for updates from the scanning thread"""
        try:
            while True:
                update = self.update_queue.get_nowait()
                update_type = update.get('type')
                if update_type == 'progress':
                    self.progress['value'] = update['value']
                elif update_type == 'text':
                    self.results_text.insert(tk.END, update['text'])
                    self.results_text.see(tk.END)
                elif update_type == 'scan_complete':
                    self.scanning = False
                    self.progress['value'] = 100
                    self.scan_btn['text'] = "Start Scan"
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_queue)

    def select_directory(self):
        self.selected_dir = filedialog.askdirectory()
        if self.selected_dir:
            self.dir_path.set(self.selected_dir)

    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"

    def scan_directory(self):
        if not self.selected_dir:
            messagebox.showerror("Error", "Please select a directory first")
            return

        self.update_queue.put({'type': 'text', 'text': f"Starting scan of {self.selected_dir}\n" + "=" * 50 + "\n"})

        try:
            total_files = sum([len(files) for _, _, files in os.walk(self.selected_dir)])
            processed_files = 0

            for root, _, files in os.walk(self.selected_dir):
                if not self.scanning:
                    break

                for file in files:
                    if not self.scanning:
                        break

                    filepath = os.path.join(root, file)
                    try:
                        file_hash = self.calculate_file_hash(filepath)
                        file_size = os.path.getsize(filepath)

                        result = (f"File: {filepath}\n"
                                f"Size: {file_size} bytes\n"
                                f"SHA-256: {file_hash}\n"
                                + "-" * 50 + "\n")

                        self.update_queue.put({'type': 'text', 'text': result})

                    except Exception as e:
                        self.update_queue.put({'type': 'text',
                                             'text': f"Error scanning {filepath}: {str(e)}\n"})

                    processed_files += 1
                    progress = (processed_files / total_files) * 100
                    self.update_queue.put({'type': 'progress', 'value': progress})

        except Exception as e:
            self.update_queue.put({'type': 'text',
                                 'text': f"Error during scan: {str(e)}\n"})
        finally:
            self.update_queue.put({'type': 'text', 'text': "\nScan completed!\n"})
            self.update_queue.put({'type': 'scan_complete'})

    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.scan_btn['text'] = "Stop Scan"
            self.progress['value'] = 0
            self.results_text.delete(1.0, tk.END)
            scan_thread = threading.Thread(target=self.scan_directory)
            scan_thread.daemon = True
            scan_thread.start()
        else:
            self.scanning = False
            self.scan_btn['text'] = "Start Scan"

if __name__ == "__main__":
    root = tk.Tk()
    app = FileScannerGUI(root)
    root.mainloop()
