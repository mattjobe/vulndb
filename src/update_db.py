import os, sys, time, threading
import tkinter as tk
import configparser
import urllib3
from tkinter import filedialog
from data_proc import *
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MainApp(tk.Tk):
    def __init__(root):
        super().__init__()
        global BASE_PATH
        if getattr(sys, 'frozen', False):
            icon_path = os.path.join(sys._MEIPASS, 'favicon.ico')
            root.iconbitmap(icon_path)
            BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(sys.executable)))
        else:
            BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..'))
        root.title("Manage Vulnerability Database")
        root.create_widgets()

    @staticmethod
    def load_config(key):
        config = configparser.ConfigParser()
        config.read(os.path.join(BASE_PATH,'config.ini'))
        return config.get('CURRENT', key)

    def redmine_button_click(root):
        root.write_output("--START--\n")
        root.START_TIME = time.time()
        root.update_timer_label()
        threading.Thread(target=connect_redmine, args=(root,)).start()

    def create_widgets(root):   
        root.START_TIME = None
        root.input_filepath = None
        root.label = tk.Label(root, text="Update MySQL database with data from:")
        root.label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        root.api_button = tk.Button(root, text="Nessus API", command=lambda: root.begin_update('api'))
        root.api_button.grid(row=0, column=2, padx=10, pady=10)
        root.file_button = tk.Button(root, text="Local File (.nessus, .csv, .xml)", command=lambda: root.begin_update('local'))
        root.file_button.grid(row=0, column=3, padx=10, pady=10)
        root.output_text = tk.Text(root, wrap=tk.WORD, width=80, height=20)
        root.output_text.grid(row=1, column=0, columnspan=4, rowspan=10, padx=10, pady=10)
        root.output_text.tag_configure("error", foreground="red")
        root.exit_button = tk.Button(root, text="Exit", command=root.quit)
        root.exit_button.grid(row=11, column=2, padx=10, pady=10)
        root.timer_text = tk.StringVar()
        root.timer_text.set("00:00:00")
        root.timer_label = tk.Label(root, textvariable=root.timer_text, font=("Arial", 12))
        root.timer_label.grid(row=11, column=3, padx=10, pady=10)
        root.check_var = tk.BooleanVar() 
        root.check_button = tk.Checkbutton(root, text="Delete existing issues?", variable=root.check_var, onvalue=True, offvalue=False)
        root.check_button.grid(row=11, column=0)
        root.redmine_button = tk.Button(root, text="Update Redmine", command=lambda: root.redmine_button_click())
        root.redmine_button.grid(row=11, column=1, padx=10, pady=10)

    def write_output(root, text):
        root.output_text.insert(tk.END, f'{text}')
        root.output_text.see(tk.END)
        root.update_idletasks()

    def write_error(root, text):
        root.output_text.insert(tk.END, f'{text}', 'error')
        root.output_text.see(tk.END)
        root.update_idletasks()

    def update_timer_label(root):
        if root.START_TIME is not None:
            elapsed_time = int(time.time() - root.START_TIME)
            mins, secs = divmod(elapsed_time, 60)
            hours, mins = divmod(mins, 60)
            root.timer_text.set(f"{hours:02d}:{mins:02d}:{secs:02d}")
        root.after(250, root.update_timer_label)

    def begin_update(root, type):
        root.write_output("--START--\n")
        root.START_TIME = time.time()
        root.update_timer_label()
        
        if type == 'api':
            download_thread = threading.Thread(target=connect_nessus_api(root))
            download_thread.start()

        elif type == 'local':
            file_paths = filedialog.askopenfilenames(initialdir=os.path.join(BASE_PATH, 'data'), 
                  title="Select a file",  
                  filetypes=[("Nessus files (*.nessus;*.csv)", "*.nessus;*.csv"),
                            ("STIG XML files (*.xml)", "*.xml"),
                            ("All files", "*.xml;*.nessus;*.csv")])
            if file_paths:
                process_data_thread = threading.Thread(target=root.init_processing, args=(file_paths,))
                process_data_thread.start()

    def init_processing(root, file_paths):
        dataframe_list = []
        sorted_paths = sorted(file_paths, key=os.path.getmtime)
        for path in sorted_paths:
            root.input_filepath = path
            root.input_filename = os.path.splitext(os.path.basename(path))[0]
            database = None
            root.write_output(f'\nProcessing data from file {os.path.basename(path)}...\n')

            _, file_extension = os.path.splitext(path)
            if file_extension == '.nessus':
                data = prepare_nessus_file(root)
            elif file_extension == '.csv':
                data = prepare_csv_file(root)
            elif file_extension == '.xml':
                database = 'stig'
                data = process_stig_file(root)          
            else:
                root.write_error(f"File type {file_extension} not supported.\n")

            if root.input_filename.endswith('_SDE'):
                database = 'sde'
            elif root.input_filename.endswith('_datacenter'):
                database = 'datacenter'
            else:
                if file_extension == '.nessus ' or file_extension == '.csv':
                    root.write_error(f"Filename must be categorized with _SDE or _datacenter\n")

            if data is not None and database is not None:
                dataframe_list.append({'type': file_extension, 'db': database, 'data': data})

        root.write_output("\nUpdating MySQL database...\n")

        try:
            update_database(root, dataframe_list)
        except Exception as e:
            root.write_error(f"Error updating MySQL database: {e}\n")
            root.write_output("MySQL database update failed.\n")
            root.write_output("\n--FINISHED--\n")
            root.START_TIME = None
            return
        
        root.write_output("MySQL database updated successfully.\n")
        root.write_output("\n--FINISHED--\n")
        root.START_TIME = None

if __name__ == "__main__":
    MainApp().mainloop()