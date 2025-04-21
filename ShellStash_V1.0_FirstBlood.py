import tkinter as tk
from tkinter import filedialog, ttk
import webbrowser
import html.parser
import pyperclip
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
from collections import OrderedDict
from bs4 import BeautifulSoup
import requests
import uuid  # Add this import at the top of the file

class BookmarkManager:
    def __init__(self, root):
        self.root = root
        self.root.title("ShellStash - 1337 Bookmark Hackz")
        self.config_file = "shellstash_config.json"
        
        self.load_window_geometry()
        
        self.root.config(bg="#1E1E1E")
        self.bookmarks = []
        self.bookmark_file = "bookmarks.json.enc"
        self.salt_file = "salt.bin"
        self.drag_start_index = None
        self.dragged_item = None
        self.key = None
        self.categories = {}  # Maps category names to BooleanVar for Checkbutton
        self.category_widgets = {}  # Cache for Checkbutton and Label widgets
        self.category_list = []
        self.title_cache = {}
        self.category_lock = True  # True means locked, False means unlocked
        
        self.color_schemes = {
            "default": {
                "background": "#1E1E1E",
                "primary_text": "#66FF99",
                "secondary_text": "#E0E0E0",
                "category": "#4DD0E1",
                "selection": "#FF7043",
                "error": "#FF6666",
                "active_button": "#4CAF50",
                "active_button_text": "#4CAF50",
                "input_field": "#2D2D2D",
                "username": "#FFD700",
                "password": "#FF4500",
                "copy_button": "#4CAF50",
                "copy_button_text": "#FFFFFF"
            },
            "alternative": {
                "background": "#000000",
                "primary_text": "#00FF00",
                "secondary_text": "#FFFFFF",
                "category": "#00FFFF",
                "selection": "#00FF00",
                "error": "#FF0000",
                "active_button": "#00FF00",
                "active_button_text": "#00FF00",
                "input_field": "#23282B",
                "username": "#FFFF00",
                "password": "#FF0000",
                "copy_button": "#00FF00",
                "copy_button_text": "#000000"
            }
        }
        self.current_scheme = "default"
        
        self.password_frame = tk.Frame(self.root, bg=self.color_schemes[self.current_scheme]["background"])
        self.password_frame.pack(expand=True)
        
        ascii_art = """
 _______ __           __ __ _______ __                __    
|     __|  |--.-----.|  |  |     __|  |_.---.-.-----.|  |--.
|__     |     |  -__||  |  |__     |   _|  _  |__ --||     |
|_______|__|__|_____||__|__|_______|____|___._|_____||__|__|

HACKING THE MAIN FRAME
        """
        tk.Label(self.password_frame, text=ascii_art, 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11), justify="center").pack(pady=0)
        
        if os.path.exists(self.bookmark_file):
            tk.Label(self.password_frame, text="ENTER PASSWORD", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["primary_text"], 
                     font=("Consolas", 11)).pack(pady=5)
        else:
            tk.Label(self.password_frame, text="SET A NEW PASSWORD", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["primary_text"], 
                     font=("Consolas", 11)).pack(pady=5)
        
        self.password_entry = tk.Entry(self.password_frame, show='*', width=30, 
                                       bg=self.color_schemes[self.current_scheme]["input_field"], 
                                       fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                       insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                       borderwidth=0, font=("Consolas", 11), justify="center")
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()
        
        if not os.path.exists(self.bookmark_file):
            tk.Label(self.password_frame, text="CONFIRM PASSWORD", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["primary_text"], 
                     font=("Consolas", 11)).pack(pady=5)
            self.confirm_entry = tk.Entry(self.password_frame, show='*', width=30, 
                                          bg=self.color_schemes[self.current_scheme]["input_field"], 
                                          fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                          insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                          borderwidth=0, font=("Consolas", 11), justify="center")
            self.confirm_entry.pack(pady=5)
        
        tk.Label(self.password_frame, text="[PRESS ENTER TO SAVE]", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=10)
        
        if os.path.exists(self.bookmark_file):
            self.password_entry.bind("<Return>", self.check_password)
        else:
            self.password_entry.bind("<Return>", self.handle_initial_password)
            self.confirm_entry.bind("<Return>", self.save_initial_password)
        
        self.main_frame = None
        self.tree_window = None
        self.search_var = None
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_window_geometry(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    geometry = config.get("geometry", "800x550+100+100")
                    self.root.geometry(geometry)
            except:
                self.root.geometry("800x550+100+100")
        else:
            self.root.geometry("800x550+100+100")

    def save_window_geometry(self):
        geometry = f"{self.root.winfo_width()}x{self.root.winfo_height()}+{self.root.winfo_x()}+{self.root.winfo_y()}"
        config = {"geometry": geometry}
        with open(self.config_file, 'w') as f:
            json.dump(config, f)

    def handle_initial_password(self, event):
        password = self.password_entry.get()
        if not password:
            self.show_password_error("Error: Password cannot be empty!")
            return
        self.confirm_entry.focus_set()

    def save_initial_password(self, event):
        password = self.password_entry.get()
        confirm_password = self.confirm_entry.get()
        if not password:
            self.show_password_error("Error: Password cannot be empty!")
            self.password_entry.focus_set()
            return
        if password != confirm_password:
            self.show_password_error("Error: Passwords do not match!")
            self.confirm_entry.delete(0, tk.END)
            self.confirm_entry.focus_set()
            return
        
        salt = secrets.token_bytes(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.key = Fernet(key)
        
        self.password_frame.destroy()
        self.create_main_ui()
        self.load_bookmarks()

    def check_password(self, event):
        password = self.password_entry.get()
        if not password:
            self.show_password_error("Error: Password cannot be empty!")
            return
        
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.key = Fernet(key)
        
        try:
            with open(self.bookmark_file, 'rb') as f:
                encrypted_data = f.read()
            self.key.decrypt(encrypted_data)
            self.password_frame.destroy()
            self.create_main_ui()
            self.load_bookmarks()
        except Exception as e:
            self.show_password_error(f"Error: Incorrect password or corrupted data! ({str(e)})")

    def show_password_error(self, message, duration=2000):
        if hasattr(self, 'error_label') and self.error_label.winfo_exists():
            self.error_label.config(text=message)
        else:
            self.error_label = tk.Label(self.password_frame, text=message, 
                                       bg=self.color_schemes[self.current_scheme]["background"], 
                                       fg=self.color_schemes[self.current_scheme]["error"], 
                                       font=("Consolas", 11))
            self.error_label.pack(pady=5)
        self.password_entry.delete(0, tk.END)
        self.password_entry.focus_set()
        self.root.after(duration, lambda: self.error_label.config(text=""))

    def create_main_ui(self):
        self.main_frame = tk.Frame(self.root, bg=self.color_schemes[self.current_scheme]["background"])
        self.main_frame.pack(fill=tk.BOTH, expand=True)
    
        self.cmd_frame = tk.Frame(self.main_frame, bg=self.color_schemes[self.current_scheme]["background"])
        self.cmd_frame.pack(fill=tk.X, pady=5, padx=(5, 0))
        
        commands = [
            ("[new]", self.new_bookmark),
            ("[edit]", self.edit_bookmark),
            ("[delete]", self.delete_bookmark),
            ("[tree]", self.show_tree_window),
            ("[open]", self.open_in_browser),
            ("[copy]", self.copy_url),
            ("[import]", self.import_bookmarks),
            ("[export]", self.export_bookmarks),
            ("[passwd]", self.change_password),
            ("[help]", self.show_help),
        ]
        for cmd_text, cmd_func in commands:
            btn = tk.Button(self.cmd_frame, text=cmd_text, command=cmd_func,
                            bg=self.color_schemes[self.current_scheme]["background"], 
                            fg=self.color_schemes[self.current_scheme]["primary_text"], 
                            activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                            activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                            borderwidth=0, font=("Consolas", 11))
            btn.pack(side=tk.LEFT, padx=0)
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(self.cmd_frame, textvariable=self.search_var,
                                bg=self.color_schemes[self.current_scheme]["input_field"], 
                                fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                insertbackground=self.color_schemes[self.current_scheme]["primary_text"],
                                font=("Consolas", 11), width=20)
        search_entry.pack(side=tk.RIGHT, padx=10)
        self.search_var.trace('w', lambda *args: self.update_textbox())
        
        self.textbox = tk.Text(self.main_frame, height=20, 
                               bg=self.color_schemes[self.current_scheme]["background"], 
                               fg=self.color_schemes[self.current_scheme]["secondary_text"],
                               insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                               font=("Consolas", 11), wrap=tk.NONE)
        self.textbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.update_textbox_colors()
        
        self.textbox.bind('<Button-1>', self.handle_click)
        self.textbox.bind('<B1-Motion>', self.drag_motion)
        self.textbox.bind('<ButtonRelease-1>', self.drop)
        
        self.credential_frame = tk.Frame(self.main_frame, 
                                        bg=self.color_schemes[self.current_scheme]["background"])
        self.credential_frame.pack(fill=tk.X, pady=0)
        
        self.show_button = tk.Button(self.credential_frame, text="[show]", 
                                     command=self.toggle_credentials,
                                     bg=self.color_schemes[self.current_scheme]["background"], 
                                     fg=self.color_schemes[self.current_scheme]["copy_button"], 
                                     activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                                     activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                                     borderwidth=0, font=("Consolas", 11), state='disabled')
        self.show_button.pack(side=tk.LEFT, padx=(5, 0))
        
        self.username_label = tk.Label(self.credential_frame, text="", 
                                      bg=self.color_schemes[self.current_scheme]["background"], 
                                      fg=self.color_schemes[self.current_scheme]["username"], 
                                      font=("Consolas", 11))
        self.username_label.pack(side=tk.LEFT, padx=2)
        
        self.username_copy = tk.Label(self.credential_frame, text="", 
                                     bg=self.color_schemes[self.current_scheme]["background"], 
                                     fg=self.color_schemes[self.current_scheme]["copy_button"], 
                                     font=("Consolas", 11), cursor="hand2")
        self.username_copy.pack(side=tk.LEFT)
        
        self.password_label = tk.Label(self.credential_frame, text="", 
                                      bg=self.color_schemes[self.current_scheme]["background"], 
                                      fg=self.color_schemes[self.current_scheme]["password"], 
                                      font=("Consolas", 11))
        self.password_label.pack(side=tk.LEFT, padx=2)
        
        self.password_copy = tk.Label(self.credential_frame, text="", 
                                     bg=self.color_schemes[self.current_scheme]["background"], 
                                     fg=self.color_schemes[self.current_scheme]["copy_button"], 
                                     font=("Consolas", 11), cursor="hand2")
        self.password_copy.pack(side=tk.LEFT, padx=(0, 5))
                   
        self.down_button = tk.Button(self.credential_frame, text="[↓]", command=self.move_down,
                                    bg=self.color_schemes[self.current_scheme]["background"], 
                                    fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                    activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                                    activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                                    borderwidth=0, font=("Consolas", 11))
        self.down_button.pack(side=tk.RIGHT, padx=(0, 5))
        
        self.up_button = tk.Button(self.credential_frame, text="[↑]", command=self.move_up,
                                   bg=self.color_schemes[self.current_scheme]["background"], 
                                   fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                   activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                                   activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                                   borderwidth=0, font=("Consolas", 11))
        self.up_button.pack(side=tk.RIGHT, padx=(0, 0))
       
        self.lock_button = tk.Button(self.credential_frame, text="[🔒]", command=self.toggle_category_lock,
                                   bg=self.color_schemes[self.current_scheme]["background"], 
                                   fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                   activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                                   activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                                   borderwidth=0, font=("Consolas", 11))
        self.lock_button.pack(side=tk.RIGHT, padx=(0, 0))   
        
        self.prompt_frame = tk.Frame(self.main_frame, bg=self.color_schemes[self.current_scheme]["background"])
        self.prompt_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(self.prompt_frame, text="$ ", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(side=tk.LEFT, padx=(5, 0))
        self.entry = tk.Entry(self.prompt_frame, 
                              bg=self.color_schemes[self.current_scheme]["input_field"], 
                              fg=self.color_schemes[self.current_scheme]["primary_text"], 
                              insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                              borderwidth=0, font=("Consolas", 11),
                              disabledbackground=self.color_schemes[self.current_scheme]["input_field"], 
                              disabledforeground=self.color_schemes[self.current_scheme]["primary_text"])
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.process_command)
        
        self.swap_button = tk.Button(self.prompt_frame, text="[swap]", command=self.swap_colors,
                                     bg=self.color_schemes[self.current_scheme]["background"], 
                                     fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                     activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                                     activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                                     borderwidth=0, font=("Consolas", 11))
        self.swap_button.pack(side=tk.RIGHT, padx=(0, 5))
        
        self.root.bind('<Control-n>', lambda e: self.new_bookmark())
        self.root.bind('<Control-o>', lambda e: self.open_in_browser())
        self.root.bind('<Control-d>', lambda e: self.delete_bookmark())
        self.root.bind('<Control-e>', lambda e: self.edit_bookmark())
        self.root.bind('<Control-t>', lambda e: self.show_tree_window())
        
        self.show_credentials = False
        self.current_credentials = {'username': '', 'password': ''}
        
    def toggle_category_lock(self):
        self.category_lock = not self.category_lock
        self.lock_button.config(text="[🔒]" if self.category_lock else "[🔓]")
        self.show_prompt_message(f"Categories {'locked' if self.category_lock else 'unlocked'}")     

    def update_textbox_colors(self):
        self.textbox.tag_configure("url", foreground=self.color_schemes[self.current_scheme]["primary_text"])
        self.textbox.tag_configure("title", foreground=self.color_schemes[self.current_scheme]["secondary_text"])
        self.textbox.tag_configure("selected", background=self.color_schemes[self.current_scheme]["selection"], 
                                   foreground=self.color_schemes[self.current_scheme]["background"])
        self.textbox.tag_configure("category", foreground=self.color_schemes[self.current_scheme]["category"], 
                                   underline=True)
                                   
    def swap_colors(self):
        self.current_scheme = "alternative" if self.current_scheme == "default" else "default"
        scheme = self.color_schemes[self.current_scheme]
        
        self.root.config(bg=scheme["background"])
        self.main_frame.config(bg=scheme["background"])
        self.cmd_frame.config(bg=scheme["background"])
        self.prompt_frame.config(bg=scheme["background"])
        
        for widget in self.cmd_frame.winfo_children():
            if isinstance(widget, tk.Button):
                widget.config(bg=scheme["background"], fg=scheme["primary_text"],
                             activebackground=scheme["active_button"], 
                             activeforeground=scheme["active_button_text"])
        
        for widget in self.cmd_frame.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.config(bg=scheme["input_field"], fg=scheme["primary_text"],
                             insertbackground=scheme["primary_text"])
        
        self.textbox.config(bg=scheme["background"], fg=scheme["secondary_text"],
                           insertbackground=scheme["primary_text"])
        self.update_textbox_colors()
        self.update_textbox()
        
        for widget in self.prompt_frame.winfo_children():
            if isinstance(widget, tk.Label):
                widget.config(bg=scheme["background"], fg=scheme["primary_text"])
            elif isinstance(widget, tk.Entry):
                widget.config(bg=scheme["input_field"], fg=scheme["primary_text"],
                             insertbackground=scheme["primary_text"],
                             disabledbackground=scheme["input_field"],
                             disabledforeground=scheme["primary_text"])
            elif isinstance(widget, tk.Button):
                widget.config(bg=scheme["background"], fg=scheme["primary_text"],
                             activebackground=scheme["active_button"],
                             activeforeground=scheme["active_button_text"])
        
        for widget in self.credential_frame.winfo_children():
            if isinstance(widget, tk.Label):
                if widget == self.username_label:
                    widget.config(bg=scheme["background"], fg=scheme["username"])
                elif widget == self.password_label:
                    widget.config(bg=scheme["background"], fg=scheme["password"])
                elif widget in (self.username_copy, self.password_copy):
                    widget.config(bg=scheme["background"], fg=scheme["copy_button"])
            elif isinstance(widget, tk.Button):
                if widget == self.show_button:
                    widget.config(bg=scheme["background"], fg=scheme["copy_button"],
                                 activebackground=scheme["active_button"],
                                 activeforeground=scheme["active_button_text"])
                else:
                    widget.config(bg=scheme["background"], fg=scheme["primary_text"],
                                 activebackground=scheme["active_button"],
                                 activeforeground=scheme["active_button_text"])
        self.credential_frame.config(bg=scheme["background"])
        
        if self.tree_window and self.tree_window.winfo_exists():
            self.update_tree_window_colors()
        
        self.show_prompt_message(f"Switched to {self.current_scheme} color scheme")

    def new_bookmark(self):
        new_window = tk.Toplevel(self.root)
        new_window.title("New Bookmark - ShellStash")
        new_window.geometry("480x370")
        new_window.config(bg=self.color_schemes[self.current_scheme]["background"])
        
        tk.Label(new_window, text="- url -", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=5)
        url_entry = tk.Entry(new_window, width=50, 
                             bg=self.color_schemes[self.current_scheme]["input_field"], 
                             fg=self.color_schemes[self.current_scheme]["primary_text"], 
                             insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                             borderwidth=0, font=("Consolas", 11), justify="center")
        url_entry.pack(pady=5)
        url_entry.focus_set()
        
        tk.Label(new_window, text="- title -", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["secondary_text"], 
                 font=("Consolas", 11)).pack(pady=5)
        title_entry = tk.Entry(new_window, width=50, 
                               bg=self.color_schemes[self.current_scheme]["input_field"], 
                               fg=self.color_schemes[self.current_scheme]["secondary_text"], 
                               insertbackground=self.color_schemes[self.current_scheme]["secondary_text"], 
                               borderwidth=0, font=("Consolas", 11), justify="center")
        title_entry.pack(pady=5)
        
        tk.Label(new_window, text="- category -", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["category"], 
                 font=("Consolas", 11)).pack(pady=5)
        category_entry = tk.Entry(new_window, width=50, 
                                  bg=self.color_schemes[self.current_scheme]["input_field"], 
                                  fg=self.color_schemes[self.current_scheme]["category"], 
                                  insertbackground=self.color_schemes[self.current_scheme]["category"], 
                                  borderwidth=0, font=("Consolas", 11), justify="center")
        category_entry.pack(pady=5)
        category_entry.insert(0, "Uncategorized")
        
        tk.Label(new_window, text="- username -", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["username"], 
                 font=("Consolas", 11)).pack(pady=5)
        username_entry = tk.Entry(new_window, width=50, 
                                  bg=self.color_schemes[self.current_scheme]["input_field"], 
                                  fg=self.color_schemes[self.current_scheme]["username"], 
                                  insertbackground=self.color_schemes[self.current_scheme]["username"], 
                                  borderwidth=0, font=("Consolas", 11), justify="center")
        username_entry.pack(pady=5)
        
        tk.Label(new_window, text="- password -", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["password"], 
                 font=("Consolas", 11)).pack(pady=5)
        password_entry = tk.Entry(new_window, width=50, 
                                  bg=self.color_schemes[self.current_scheme]["input_field"], 
                                  fg=self.color_schemes[self.current_scheme]["password"], 
                                  insertbackground=self.color_schemes[self.current_scheme]["password"], 
                                  borderwidth=0, font=("Consolas", 11), justify="center")
        password_entry.pack(pady=5)
        
        context_menu = tk.Menu(new_window, tearoff=0)
        context_menu.add_command(label="Paste", command=lambda: new_window.focus_get().event_generate("<<Paste>>"))

        def show_context_menu(event):
            context_menu.post(event.x_root, event.y_root)

        for entry in [title_entry, url_entry, category_entry, username_entry, password_entry]:
            entry.bind("<Button-3>", show_context_menu)
            entry.bind("<Control-v>", lambda e: entry.insert(tk.INSERT, pyperclip.paste()))
        
        def save_new_bookmark():
            title = title_entry.get().strip()
            url = url_entry.get().strip()
            category = category_entry.get().strip() or "Uncategorized"
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not url:
                self.show_prompt_message("Warning: URL cannot be empty!")
                url_entry.focus_set()
                return
            if not title:
                title = self.fetch_title(url)
                title_entry.insert(0, title)
            
            new_bookmark = {
                'id': str(uuid.uuid4()),  # Add a unique identifier
                'title': title,
                'url': url,
                'category': category,
                'username': username,
                'password': password
            }
            
            # Append bookmark to the end of its category, respecting category_list order
            if category not in self.category_list:
                self.category_list.append(category)
            insert_index = 0
            for i, bookmark in enumerate(self.bookmarks):
                if bookmark.get('category', 'Uncategorized') == category:
                    insert_index = i + 1
                elif self.category_list.index(bookmark.get('category', 'Uncategorized')) > self.category_list.index(category):
                    insert_index = i
                    break
            else:
                insert_index = len(self.bookmarks)
            self.bookmarks.insert(insert_index, new_bookmark)
            self.save_bookmarks()
            self.update_category_buttons()
            
            self.update_textbox()
            filtered_bookmarks = self.get_filtered_bookmarks()
            if new_bookmark in filtered_bookmarks:
                new_index = filtered_bookmarks.index(new_bookmark)
                line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
                new_line = [k for k, v in line_to_bookmark.items() if v == new_bookmark['id']][0]
                self.textbox.tag_remove("selected", "1.0", tk.END)
                self.textbox.tag_add("selected", f"{new_line + 1}.0", f"{new_line + 2}.0")
                self.textbox.see(f"{new_line + 1}.0")
            self.show_prompt_message(f"Added: {title} ({url}) in {category}")
            new_window.destroy()

        url_entry.bind("<Return>", lambda e: title_entry.focus_set())
        title_entry.bind("<Return>", lambda e: category_entry.focus_set())
        category_entry.bind("<Return>", lambda e: username_entry.focus_set())
        username_entry.bind("<Return>", lambda e: password_entry.focus_set())
        password_entry.bind("<Return>", lambda e: save_new_bookmark())
        
        tk.Label(new_window, text="[PRESS ENTER TO SAVE]", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=10)

    def edit_bookmark(self):
        index = self.get_selected_index()
        filtered_bookmarks = self.get_filtered_bookmarks()
        if index is not None and 0 <= index < len(filtered_bookmarks):
            bookmark = filtered_bookmarks[index]
            actual_index = self.bookmarks.index(bookmark)
            
            edit_window = tk.Toplevel(self.root)
            edit_window.title("Edit Bookmark - ShellStash")
            edit_window.geometry("480x370")
            edit_window.config(bg=self.color_schemes[self.current_scheme]["background"])
            
            tk.Label(edit_window, text="- url -", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["primary_text"], 
                     font=("Consolas", 11)).pack(pady=5)
            url_entry = tk.Entry(edit_window, width=50, 
                                 bg=self.color_schemes[self.current_scheme]["input_field"], 
                                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                 insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                 borderwidth=0, font=("Consolas", 11), justify="center")
            url_entry.pack(pady=5)
            url_entry.insert(0, bookmark['url'])
            url_entry.focus_set()
            
            tk.Label(edit_window, text="- title -", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["secondary_text"], 
                     font=("Consolas", 11)).pack(pady=5)
            title_entry = tk.Entry(edit_window, width=50, 
                                   bg=self.color_schemes[self.current_scheme]["input_field"], 
                                   fg=self.color_schemes[self.current_scheme]["secondary_text"], 
                                   insertbackground=self.color_schemes[self.current_scheme]["secondary_text"], 
                                   borderwidth=0, font=("Consolas", 11), justify="center")
            title_entry.pack(pady=5)
            title_entry.insert(0, bookmark['title'])
            
            tk.Label(edit_window, text="- category -", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["category"], 
                     font=("Consolas", 11)).pack(pady=5)
            category_entry = tk.Entry(edit_window, width=50, 
                                      bg=self.color_schemes[self.current_scheme]["input_field"], 
                                      fg=self.color_schemes[self.current_scheme]["category"], 
                                      insertbackground=self.color_schemes[self.current_scheme]["category"], 
                                      borderwidth=0, font=("Consolas", 11), justify="center")
            category_entry.pack(pady=5)
            category_entry.insert(0, bookmark.get('category', 'Uncategorized'))
            
            tk.Label(edit_window, text="- username -", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["username"], 
                     font=("Consolas", 11)).pack(pady=5)
            username_entry = tk.Entry(edit_window, width=50, 
                                      bg=self.color_schemes[self.current_scheme]["input_field"], 
                                      fg=self.color_schemes[self.current_scheme]["username"], 
                                      insertbackground=self.color_schemes[self.current_scheme]["username"], 
                                      borderwidth=0, font=("Consolas", 11), justify="center")
            username_entry.pack(pady=5)
            username_entry.insert(0, bookmark.get('username', ''))
            
            tk.Label(edit_window, text="- password -", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["password"], 
                     font=("Consolas", 11)).pack(pady=5)
            password_entry = tk.Entry(edit_window, width=50, 
                                      bg=self.color_schemes[self.current_scheme]["input_field"], 
                                      fg=self.color_schemes[self.current_scheme]["password"], 
                                      insertbackground=self.color_schemes[self.current_scheme]["password"], 
                                      borderwidth=0, font=("Consolas", 11), justify="center")
            password_entry.pack(pady=5)
            password_entry.insert(0, bookmark.get('password', ''))
            
            context_menu = tk.Menu(edit_window, tearoff=0)
            context_menu.add_command(label="Paste", command=lambda: edit_window.focus_get().event_generate("<<Paste>>"))

            def show_context_menu(event):
                context_menu.post(event.x_root, event.y_root)

            for entry in [title_entry, url_entry, category_entry, username_entry, password_entry]:
                entry.bind("<Button-3>", show_context_menu)
                entry.bind("<Control-v>", lambda e: entry.insert(tk.INSERT, pyperclip.paste()))
            
            def save_changes():
                new_category = category_entry.get().strip() or 'Uncategorized'
                updated_bookmark = {
                    'id': bookmark['id'],  # Preserve the unique identifier
                    'title': title_entry.get(),
                    'url': url_entry.get(),
                    'category': new_category,
                    'username': username_entry.get(),
                    'password': password_entry.get()
                }
                if not updated_bookmark['url']:
                    self.show_prompt_message("Warning: URL cannot be empty!")
                    url_entry.focus_set()
                    return

                # Get the old category before removing the bookmark
                old_category = self.bookmarks[actual_index].get('category', 'Uncategorized')

                # Remove old bookmark
                self.bookmarks.pop(actual_index)

                # Update category_list if new_category is not present
                if new_category not in self.category_list:
                    # Insert new_category in alphabetical order or at the end
                    insert_pos = 0
                    for i, cat in enumerate(self.category_list):
                        if cat > new_category:
                            break
                        insert_pos = i + 1
                    self.category_list.insert(insert_pos, new_category)

                # Check if old_category is still in use
                if old_category not in [b.get('category', 'Uncategorized') for b in self.bookmarks]:
                    if old_category in self.category_list:
                        self.category_list.remove(old_category)
                    if old_category in self.categories:
                        del self.categories[old_category]
                    if old_category in self.category_widgets:
                        frame, _, _ = self.category_widgets.pop(old_category)
                        frame.destroy()

                # Insert updated bookmark in the correct position based on category_list
                insert_index = 0
                for i, bookmark in enumerate(self.bookmarks):
                    bookmark_cat = bookmark.get('category', 'Uncategorized')
                    if self.category_list.index(bookmark_cat) > self.category_list.index(new_category):
                        break
                    if bookmark_cat == new_category:
                        insert_index = i + 1
                    else:
                        insert_index = i
                self.bookmarks.insert(insert_index, updated_bookmark)

                # Ensure new_category is in categories
                if new_category not in self.categories:
                    self.categories[new_category] = tk.BooleanVar(value=True)

                # Save and update UI
                self.save_bookmarks()
                self.update_category_buttons()
                self.update_textbox()

                # Update selection in the text field
                filtered_bookmarks = self.get_filtered_bookmarks()
                line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
                
                if updated_bookmark in filtered_bookmarks:
                    new_index = filtered_bookmarks.index(updated_bookmark)
                    new_line = [k for k, v in line_to_bookmark.items() if v == updated_bookmark['id']][0]
                    self.textbox.tag_remove("selected", "1.0", tk.END)
                    self.textbox.tag_add("selected", f"{new_line + 1}.0", f"{new_line + 2}.0")
                    self.textbox.see(f"{new_line + 1}.0")
                    self.show_prompt_message(f"Edited: {updated_bookmark['title']} ({updated_bookmark['url']})")
                else:
                    self.textbox.tag_remove("selected", "1.0", tk.END)
                    self.show_prompt_message(f"Edited: {updated_bookmark['title']} (now hidden)")
                
                edit_window.destroy()

            url_entry.bind("<Return>", lambda e: title_entry.focus_set())
            title_entry.bind("<Return>", lambda e: category_entry.focus_set())
            category_entry.bind("<Return>", lambda e: username_entry.focus_set())
            username_entry.bind("<Return>", lambda e: password_entry.focus_set())
            password_entry.bind("<Return>", lambda e: save_changes())
            
            tk.Label(edit_window, text="[PRESS ENTER TO SAVE]", 
                     bg=self.color_schemes[self.current_scheme]["background"], 
                     fg=self.color_schemes[self.current_scheme]["primary_text"], 
                     font=("Consolas", 11)).pack(pady=10)
        else:
            self.show_prompt_message("Warning: Please select a bookmark first!")

    def show_prompt_message(self, message, duration=2000):
        if hasattr(self, 'entry') and self.entry.winfo_exists():
            self.entry.delete(0, tk.END)
            self.entry.insert(0, message)
            self.entry.config(state='disabled', fg=self.color_schemes[self.current_scheme]["error"],
                            disabledforeground=self.color_schemes[self.current_scheme]["error"])
            self.root.after(duration, lambda: [
                self.entry.config(state='normal', 
                                fg=self.color_schemes[self.current_scheme]["primary_text"],
                                disabledforeground=self.color_schemes[self.current_scheme]["primary_text"]),
                self.entry.delete(0, tk.END)
            ])
        else:
            print(message)

    def show_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("ShellStash Help")
        help_window.geometry("800x550")
        help_window.config(bg=self.color_schemes[self.current_scheme]["background"])
        
        help_text = tk.Text(help_window, 
                            bg=self.color_schemes[self.current_scheme]["background"], 
                            fg=self.color_schemes[self.current_scheme]["primary_text"], 
                            font=("Consolas", 11), wrap=tk.WORD)
        help_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        help_content = """                                                                            
    _______ __           __ __ _______ __                __    
#  |     __|  |--.-----.|  |  |     __|  |_.---.-.-----.|  |--.
#  |__     |     |  -__||  |  |__     |   _|  _  |__ --||     |
#  |_______|__|__|_____||__|__|_______|____|___._|_____||__|__|
#  Version: 1.0 - First Blood

---

## Getting Started
1. **Initialization**:  
   - **First Launch**: Set a password to encrypt your bookmarks. Enter it twice to confirm.  
   - **Subsequent Launches**: Enter your existing password to unlock your bookmarks.  
2. **Main Interface**:  
   - **Top**: Command buttons (new, edit, delete, etc.) and a search bar.  
   - **Middle**: Credential display (username/password) with show/hide toggle.  
   - **Center**: Text area displaying bookmarks, grouped by categories.  
   - **Bottom**: Command prompt ($) for manual commands.

---

## Commands
Use these commands via buttons or type them into the prompt ($):  

- **new**: Create a new bookmark (Ctrl+N).  
- **edit**: Edit the selected bookmark (Ctrl+E).  
- **delete**: Delete the selected bookmark (Ctrl+D).  
- **tree**: Open the category tree window for sorting/renaming (Ctrl+T).  
- **open**: Open the selected bookmark in your browser (Ctrl+O).  
- **copy**: Copy the selected bookmark’s URL to the clipboard.  
- **import**: Import bookmarks from an HTML file (e.g., browser export).  
- **export**: Export all bookmarks to HTML and TXT files.  
- **passwd**: Change your encryption password.  
- **help**: Show this help window.  
- **exit**: Close ShellStash, saving bookmarks and window size.  
- **swap**: Switch color scheme (default ↔ alternative).

---

## Keyboard Shortcuts
Boost your efficiency with these shortcuts:  
- **Ctrl+N**: New bookmark.  
- **Ctrl+O**: Open bookmark in browser.  
- **Ctrl+D**: Delete bookmark.  
- **Ctrl+E**: Edit bookmark.  
- **Ctrl+T**: Show category tree.

---

## Features in Detail

### Bookmark Management
- **Adding a Bookmark**:  
  - Click "new" or press Ctrl+N.  
  - Enter URL (required), title (optional, auto-fetched if blank), category (defaults to "Uncategorized"), username, and password.  
  - Press Enter after each field; final Enter saves.  
- **Editing a Bookmark**:  
  - Select a bookmark (click it), then "edit" or Ctrl+E.  
  - Modify URL, title, category, username, or password.  
- **Deleting a Bookmark**:  
  - Select a bookmark, then "delete" or Ctrl+D.  
  - Confirmation appears in the prompt.

### Credentials
- **Storing Credentials**:  
  - Add usernames and passwords when creating/editing bookmarks.  
  - View them above the bookmark list (starred by default).  
  - Click "[show]" to reveal or "[hide]" to mask credentials.  
  - Use "[copy]" buttons to copy username or password to the clipboard.  

### Categories
- **Organization**:  
  - Bookmarks are grouped by categories (e.g., "Uncategorized", "Work", "Fun").  
  - New bookmarks are added to the end of their category.  
- **Tree Window**:  
  - Open with "tree" or Ctrl+T.  
  - View all categories with bookmark counts.  
  - **Sort**: Select a category, use ↑/↓ to reorder.  
  - **Rename**: Select a category, edit its name in the text field, press Enter (affects all bookmarks in that category).  
  - **Filter**: Check/uncheck categories to show/hide them in the main view.

### Navigation & Sorting
- **Drag-and-Drop**:  
  - Click and hold a bookmark, drag it to reorder.  
  - When **[🔒]** (locked), movement is restricted within the same category.  
  - When **[🔓]** (unlocked), drag across categories to change a bookmark's category.  
- **Move Up/Down**:  
  - Select a bookmark, use the ↑/↓ buttons on the right to shift it.  
  - When **[🔒]**, movement stops at category boundaries.  
  - When **[🔓]**, bookmarks can move across categories, adopting the new category.  
- **Lock/Unlock**:  
  - Click [🔒]/[🔓] to toggle category movement restrictions.  
  - Locked: Prevents moving bookmarks between categories.  
  - Unlocked: Allows moving bookmarks to different categories via drag-and-drop or ↑/↓ buttons.

### Search
- Type in the search bar (top-right) to filter bookmarks by title or URL.  
- Updates in real-time as you type.  
- Shows only bookmarks from enabled categories (see Tree Window).

### Security
- **Encryption**: Bookmarks are stored encrypted in `bookmarks.json.enc` using your password.  
- **Password Change**: Use "passwd", enter current and new password (with confirmation).

### Import/Export
- **Import**: Load bookmarks from an HTML file (e.g., Chrome/Firefox export). Supports nested categories.  
- **Export**:  
  - Saves bookmarks as an HTML file, compatible with most browsers.  
  - Creates a TXT file with URLs, usernames, and passwords (unencrypted—use cautiously).  

### Color Scheme
- **Switching**: Click "swap" or use the prompt to toggle between "default" (dark green) and "alternative" (black-green).  

---

## Tips & Tricks
- **Auto-Title**: Leave the title blank; ShellStash fetches it from the webpage.  
- **Right-Click**: In input fields (new/edit), right-click to paste (or use Ctrl+V).  
- **Category Movement**: Unlock categories with [🔓] to reorganize bookmarks across categories.  
- **Feedback**: Watch the prompt ($) for success/warning messages.  
- **Window Size**: ShellStash remembers size and position between sessions.  

---

## Troubleshooting
- **Wrong Password**: If decryption fails, double-check your password. No recovery option exists for forgotten passwords.  
- **Corrupted File**: If `bookmarks.json.enc` is damaged, delete it (after backup!) and start fresh.  
- **Import Issues**: Ensure your HTML file follows the Netscape bookmark format.  
- **Credential Display**: If credentials don’t show, reselect the bookmark.  
- **Category Movement**: If ↑/↓ or drag-and-drop stops at category boundaries, toggle to [🔓].

---

## Support the Project
If you find ShellStash useful,
you should support its development and throw a few Satoshis!
Copy the BTC address below to say thanks :-)

Happy hacking!
"""
        help_text.insert(tk.END, help_content)
        
        btc_frame = tk.Frame(help_window, bg=self.color_schemes[self.current_scheme]["background"])
        btc_frame.pack(fill=tk.X, padx=10, pady=2)
        
        tk.Label(btc_frame, text="BTC address:", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(side=tk.LEFT)
        btc_address = "bc1qs8g0eju0gkwtzjhh43sxdwm8yf4anmk29spq2l"
        tk.Label(btc_frame, text=btc_address, 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["secondary_text"], 
                 font=("Consolas", 11)).pack(side=tk.LEFT, padx=5)
        tk.Button(btc_frame, text="[copy]", 
                  command=lambda: [pyperclip.copy(btc_address), self.show_prompt_message("Copied BTC address")],
                  bg=self.color_schemes[self.current_scheme]["background"], 
                  fg=self.color_schemes[self.current_scheme]["primary_text"], 
                  activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                  activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                  borderwidth=0, font=("Consolas", 11)).pack(side=tk.LEFT)
        
        help_text.config(state='disabled')

    def show_tree_window(self):
        if self.tree_window and self.tree_window.winfo_exists():
            self.tree_window.lift()
            return
        
        self.tree_window = tk.Toplevel(self.root)
        self.tree_window.title("Tree - Sort Categories")
        self.tree_window.geometry("290x550")
        self.tree_window.config(bg=self.color_schemes[self.current_scheme]["background"])
        self.tree_window.protocol("WM_DELETE_WINDOW", self.on_tree_close)
        
        tree_frame = tk.Frame(self.tree_window, bg=self.color_schemes[self.current_scheme]["background"])
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        sort_frame = tk.Frame(tree_frame, bg=self.color_schemes[self.current_scheme]["background"])
        sort_frame.pack(fill=tk.X, pady=0)
        
        tk.Button(sort_frame, text="[↑]", command=lambda: self.move_category(-1),
                  bg=self.color_schemes[self.current_scheme]["background"], 
                  fg=self.color_schemes[self.current_scheme]["primary_text"], 
                  activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                  activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                  borderwidth=0, font=("Consolas", 11)).pack(side=tk.LEFT, padx=0)
        
        tk.Button(sort_frame, text="[↓]", command=lambda: self.move_category(1),
                  bg=self.color_schemes[self.current_scheme]["background"], 
                  fg=self.color_schemes[self.current_scheme]["primary_text"], 
                  activebackground=self.color_schemes[self.current_scheme]["active_button"], 
                  activeforeground=self.color_schemes[self.current_scheme]["active_button_text"], 
                  borderwidth=0, font=("Consolas", 11)).pack(side=tk.LEFT, padx=0)
        
        self.rename_entry = tk.Entry(sort_frame, width=20, 
                                     bg=self.color_schemes[self.current_scheme]["input_field"], 
                                     fg=self.color_schemes[self.current_scheme]["primary_text"],
                                     insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                     borderwidth=0, font=("Consolas", 11))
        self.rename_entry.pack(side=tk.LEFT, padx=5)
        self.rename_entry.insert(0, "Select a category")
        self.rename_entry.bind("<Return>", self.rename_category_from_entry)
        
        # Create scrollable canvas
        self.canvas = tk.Canvas(tree_frame, bg=self.color_schemes[self.current_scheme]["background"],
                                highlightthickness=0)
        self.scrollbar = tk.Scrollbar(tree_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.color_schemes[self.current_scheme]["background"])
        
        # Configure canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack canvas and scrollbar
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Enable mouse wheel scrolling for the entire tree window
        def _on_mousewheel(event):
            if self.canvas.winfo_exists():
                self.canvas.yview_scroll(-1 * (event.delta // 120), "units")
        
        def _on_button4(event):
            if self.canvas.winfo_exists():
                self.canvas.yview_scroll(-1, "units")
        
        def _on_button5(event):
            if self.canvas.winfo_exists():
                self.canvas.yview_scroll(1, "units")
        
        self.tree_window.bind("<MouseWheel>", _on_mousewheel)
        self.tree_window.bind("<Button-4>", _on_button4)
        self.tree_window.bind("<Button-5>", _on_button5)
        
        self.update_category_tree()

    def update_category_tree(self):
        if not self.tree_window or not self.tree_window.winfo_exists():
            return
        
        # Get all categories with counts
        all_categories = OrderedDict()
        for bookmark in self.bookmarks:
            cat = bookmark.get('category', 'Uncategorized')
            if cat not in all_categories:
                all_categories[cat] = 0
            all_categories[cat] += 1
        
        # Use self.category_list, update with new categories
        for cat in all_categories:
            if cat not in self.category_list:
                self.category_list.append(cat)
        # Remove categories that no longer exist
        self.category_list = [cat for cat in self.category_list if cat in all_categories]
        
        # Remove widgets for categories that no longer exist
        for cat in list(self.category_widgets.keys()):
            if cat not in all_categories:
                frame, _, _ = self.category_widgets.pop(cat)
                frame.destroy()
        
        # Update or create widgets for each category
        for index, cat in enumerate(self.category_list):
            count = all_categories.get(cat, 0)
            if cat not in self.categories:
                self.categories[cat] = tk.BooleanVar(value=True)
            
            # Check if widget exists; update or create
            if cat in self.category_widgets:
                frame, check, label = self.category_widgets[cat]
                # Update label text and color
                fg_color = (self.color_schemes[self.current_scheme]["secondary_text"]
                            if hasattr(self, 'selected_category') and self.selected_category == cat
                            else self.color_schemes[self.current_scheme]["category"])
                label.config(text=f"{cat} ({count})", fg=fg_color)
            else:
                # Create new frame and widgets
                frame = tk.Frame(self.scrollable_frame, bg=self.color_schemes[self.current_scheme]["background"])
                frame.pack(fill=tk.X, pady=2)
                
                check = tk.Checkbutton(frame, variable=self.categories[cat],
                                      command=self.update_textbox,
                                      bg=self.color_schemes[self.current_scheme]["background"],
                                      fg=self.color_schemes[self.current_scheme]["category"],
                                      selectcolor=self.color_schemes[self.current_scheme]["background"],
                                      activebackground=self.color_schemes[self.current_scheme]["background"],
                                      activeforeground=self.color_schemes[self.current_scheme]["category"],
                                      highlightthickness=0,
                                      font=("Consolas", 11))
                check.pack(side=tk.LEFT, padx=(5, 0))
                
                fg_color = (self.color_schemes[self.current_scheme]["secondary_text"]
                            if hasattr(self, 'selected_category') and self.selected_category == cat
                            else self.color_schemes[self.current_scheme]["category"])
                label = tk.Label(frame, text=f"{cat} ({count})",
                                 bg=self.color_schemes[self.current_scheme]["background"],
                                 fg=fg_color,
                                 font=("Consolas", 11))
                label.pack(side=tk.LEFT)
                label.bind('<Button-1>', lambda e, c=cat: self.select_category(c))
                
                self.category_widgets[cat] = (frame, check, label)
        
        # Reorder frames to match category_list
        for cat in self.category_list:
            if cat in self.category_widgets:
                frame, _, _ = self.category_widgets[cat]
                frame.pack_forget()
                frame.pack(fill=tk.X, pady=2)

    def select_category(self, category):
        self.selected_category = category
        self.rename_entry.delete(0, tk.END)
        self.rename_entry.insert(0, category)
        # Update only the affected labels' colors
        for cat, (frame, check, label) in self.category_widgets.items():
            fg_color = (self.color_schemes[self.current_scheme]["secondary_text"]
                        if cat == category
                        else self.color_schemes[self.current_scheme]["category"])
            label.config(fg=fg_color)
        self.show_prompt_message(f"Selected: {category}")

    def update_tree_window_colors(self):
        scheme = self.color_schemes[self.current_scheme]
        if self.tree_window and self.tree_window.winfo_exists():
            self.tree_window.config(bg=scheme["background"])
            for widget in self.tree_window.winfo_children():
                widget.config(bg=scheme["background"])
                for child in widget.winfo_children():
                    if isinstance(child, tk.Button):
                        child.config(bg=scheme["background"], fg=scheme["primary_text"],
                                     activebackground=scheme["active_button"],
                                     activeforeground=scheme["active_button_text"])
                    elif isinstance(child, tk.Entry):
                        child.config(bg=scheme["input_field"], fg=scheme["primary_text"],
                                     insertbackground=scheme["primary_text"])
                    elif isinstance(child, tk.Canvas):
                        child.config(bg=scheme["background"])
                    elif isinstance(child, tk.Scrollbar):
                        child.config(bg=scheme["background"], activebackground=scheme["active_button"])
                    elif isinstance(child, tk.Frame):
                        child.config(bg=scheme["background"])
                        for subchild in child.winfo_children():
                            subchild.config(bg=scheme["background"])
                            if isinstance(subchild, tk.Checkbutton):
                                subchild.config(bg=scheme["background"],
                                                fg=scheme["category"],
                                                selectcolor=scheme["background"],
                                                activebackground=scheme["background"],
                                                activeforeground=scheme["category"],
                                                highlightthickness=0)
                            elif isinstance(subchild, tk.Label):
                                subchild.config(bg=scheme["background"],
                                                fg=(scheme["secondary_text"]
                                                    if hasattr(self, 'selected_category') and subchild.cget("text").startswith(self.selected_category)
                                                    else scheme["category"]))
            # Update cached widgets' colors
            for cat, (frame, check, label) in self.category_widgets.items():
                frame.config(bg=scheme["background"])
                check.config(bg=scheme["background"],
                             fg=scheme["category"],
                             selectcolor=scheme["background"],
                             activebackground=scheme["background"],
                             activeforeground=scheme["category"])
                fg_color = (scheme["secondary_text"]
                            if hasattr(self, 'selected_category') and cat == self.selected_category
                            else scheme["category"])
                label.config(bg=scheme["background"], fg=fg_color)

    def move_category(self, direction):
        if not hasattr(self, 'selected_category') or not self.selected_category:
            self.show_prompt_message("Warning: Please select a category first!")
            return
        
        current_index = self.category_list.index(self.selected_category)
        new_index = current_index + direction
        
        if 0 <= new_index < len(self.category_list):
            # Swap categories in category_list
            self.category_list[current_index], self.category_list[new_index] = \
                self.category_list[new_index], self.category_list[current_index]
            
            # Rebuild bookmarks to match new category order
            grouped = OrderedDict()
            for bookmark in self.bookmarks:
                cat = bookmark.get('category', 'Uncategorized')
                if cat not in grouped:
                    grouped[cat] = []
                grouped[cat].append(bookmark)
            new_bookmarks = []
            for cat in self.category_list:
                if cat in grouped:
                    new_bookmarks.extend(grouped[cat])
            
            self.bookmarks = new_bookmarks
            self.save_bookmarks()
            self.update_category_tree()
            self.update_textbox()
            self.show_prompt_message(f"Moved {self.selected_category} {'up' if direction < 0 else 'down'}")
        else:
            self.show_prompt_message(f"Cannot move {'up' if direction < 0 else 'down'}: Already at {'top' if direction < 0 else 'bottom'}")

    def rename_category_from_entry(self, event):
        old_name = getattr(self, 'selected_category', None)
        if not old_name:
            self.show_prompt_message("Warning: Please select a category first!")
            return
        
        new_name = self.rename_entry.get().strip()
        if not new_name:
            self.show_prompt_message("Warning: Category name cannot be empty!")
            return
        if new_name != old_name:
            # Update category name in bookmarks
            for bookmark in self.bookmarks:
                if bookmark.get('category', 'Uncategorized') == old_name:
                    bookmark['category'] = new_name
            # Update categories dictionary
            if old_name in self.categories:
                self.categories[new_name] = self.categories.pop(old_name)
            # Update category_widgets dictionary
            if old_name in self.category_widgets:
                frame, check, label = self.category_widgets.pop(old_name)
                self.category_widgets[new_name] = (frame, check, label)
            # Update selected category
            self.selected_category = new_name
            # Update category_list to reflect new name, preserving order
            self.category_list = [new_name if cat == old_name else cat 
                                 for cat in self.category_list]
            # Save bookmarks without sorting
            self.save_bookmarks()
            # Update UI
            self.update_category_tree()
            self.update_textbox()
            self.show_prompt_message(f"Renamed category: {old_name} -> {new_name}")

    def on_tree_close(self):
        # Unbind mouse wheel events from tree_window
        if self.tree_window and self.tree_window.winfo_exists():
            self.tree_window.unbind("<MouseWheel>")
            self.tree_window.unbind("<Button-4>")
            self.tree_window.unbind("<Button-5>")
        self.tree_window.destroy()
        self.tree_window = None
        self.category_widgets.clear()  # Clear cache when closing window

    def update_category_buttons(self):
        self.update_category_tree()
        self.update_textbox()

    def process_command(self, event):
        command = self.entry.get().strip().lower()
        self.entry.delete(0, tk.END)
        
        if command == "new":
            self.new_bookmark()
        elif command == "edit":
            self.edit_bookmark()
        elif command == "delete":
            self.delete_bookmark()
        elif command == "tree":
            self.show_tree_window()
        elif command == "open":
            self.open_in_browser()
        elif command == "copy":
            self.copy_url()
        elif command == "import":
            self.import_bookmarks()
        elif command == "export":
            self.export_bookmarks()
        elif command == "passwd":
            self.change_password()
        elif command == "help":
            self.show_help()
        elif command == "exit":
            self.on_closing()
        elif command == "swap":
            self.swap_colors()
        else:
            self.show_prompt_message(f"Warning: Unknown command: {command}")

    def change_password(self):
        change_window = tk.Toplevel(self.root)
        change_window.title("Change Password - ShellStash")
        change_window.geometry("400x300")
        change_window.config(bg=self.color_schemes[self.current_scheme]["background"])
        
        feedback_label = tk.Label(change_window, text="", 
                                 bg=self.color_schemes[self.current_scheme]["background"], 
                                 fg=self.color_schemes[self.current_scheme]["error"], 
                                 font=("Consolas", 11))
        feedback_label.pack(pady=5)
        
        tk.Label(change_window, text="ENTER PASSWORD", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=5)
        old_password_entry = tk.Entry(change_window, show='*', width=30, 
                                      bg=self.color_schemes[self.current_scheme]["input_field"], 
                                      fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                      insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                      borderwidth=0, font=("Consolas", 11), justify="center")
        old_password_entry.pack(pady=5)
        old_password_entry.focus_set()
        
        tk.Label(change_window, text="ENTER NEW PASSWORD", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=5)
        new_password_entry = tk.Entry(change_window, show='*', width=30, 
                                      bg=self.color_schemes[self.current_scheme]["input_field"], 
                                      fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                      insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                      borderwidth=0, font=("Consolas", 11), justify="center")
        new_password_entry.pack(pady=5)
        
        tk.Label(change_window, text="CONFIRM NEW PASSWORD", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=5)
        confirm_entry = tk.Entry(change_window, show='*', width=30, 
                                 bg=self.color_schemes[self.current_scheme]["input_field"], 
                                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                                 insertbackground=self.color_schemes[self.current_scheme]["primary_text"], 
                                 borderwidth=0, font=("Consolas", 11), justify="center")
        confirm_entry.pack(pady=5)
        
        def show_feedback(message, duration=2000):
            feedback_label.config(text=message)
            change_window.after(duration, lambda: feedback_label.config(text=""))
        
        def save_new_password():
            old_password = old_password_entry.get()
            new_password = new_password_entry.get()
            confirm_password = confirm_entry.get()
            
            if not old_password or not new_password or not confirm_password:
                show_feedback("Error: All fields must be filled!")
                return
            
            try:
                with open(self.salt_file, 'rb') as f:
                    salt = f.read()
                
                kdf_old = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                old_key = base64.urlsafe_b64encode(kdf_old.derive(old_password.encode()))
                old_fernet = Fernet(old_key)
                
                with open(self.bookmark_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = old_fernet.decrypt(encrypted_data)
            except Exception as e:
                show_feedback(f"Error: Incorrect current password or file corrupted! ({str(e)})")
                old_password_entry.delete(0, tk.END)
                old_password_entry.focus_set()
                return
            
            if new_password != confirm_password:
                show_feedback("Error: New passwords do not match!")
                confirm_entry.delete(0, tk.END)
                confirm_entry.focus_set()
                return
            
            try:
                kdf_new = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                new_key = base64.urlsafe_b64encode(kdf_new.derive(new_password.encode()))
                new_fernet = Fernet(new_key)
                encrypted_data = new_fernet.encrypt(decrypted_data)
                with open(self.bookmark_file, 'wb') as f:
                    f.write(encrypted_data)
                
                self.key = new_fernet
                show_feedback("Success: Password changed successfully!", 1000)
                change_window.after(1000, change_window.destroy)
            except Exception as e:
                show_feedback(f"Error: Failed to save new password: {str(e)}")
        
        old_password_entry.bind("<Return>", lambda e: new_password_entry.focus_set())
        new_password_entry.bind("<Return>", lambda e: confirm_entry.focus_set())
        confirm_entry.bind("<Return>", lambda e: save_new_password())
        
        tk.Label(change_window, text="[PRESS ENTER TO SAVE]", 
                 bg=self.color_schemes[self.current_scheme]["background"], 
                 fg=self.color_schemes[self.current_scheme]["primary_text"], 
                 font=("Consolas", 11)).pack(pady=10)

    def toggle_credentials(self):
        self.show_credentials = not self.show_credentials
        self.show_button.config(text="[hide]" if self.show_credentials else "[show]")
        
        username = self.current_credentials['username']
        password = self.current_credentials['password']
        
        if self.show_credentials:
            self.username_label.config(text=f"Username: {username}" if username else "")
            self.password_label.config(text=f"Password: {password}" if password else "")
        else:
            self.username_label.config(text=f"Username: {'*' * len(username)}" if username else "")
            self.password_label.config(text=f"Password: {'*' * len(password)}" if password else "")
        
        self.show_prompt_message(f"Credentials {'shown' if self.show_credentials else 'hidden'}")

    def handle_click(self, event):
        try:
            line_index = int(self.textbox.index(f"@{event.x},{event.y}").split('.')[0]) - 1
            if line_index < 0:
                raise ValueError("Negative line index")
        except (tk.TclError, ValueError):
            self.show_prompt_message("Clicked outside valid text area")
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.clear_credential_display()
            return "break"

        filtered_bookmarks = self.get_filtered_bookmarks()
        line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
        
        if line_index not in line_to_bookmark:
            self.show_prompt_message("Clicked on category or empty space")
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.clear_credential_display()
            return "break"

        bookmark_id = line_to_bookmark[line_index]
        bookmark = next((b for b in self.bookmarks if b['id'] == bookmark_id), None)
        if not bookmark:
            self.show_prompt_message("Invalid bookmark index")
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.clear_credential_display()
            return "break"

        self.textbox.tag_remove("selected", "1.0", tk.END)
        self.textbox.tag_add("selected", f"{line_index + 1}.0", f"{line_index + 2}.0")
        self.drag_start_index = self.bookmarks.index(bookmark)
        self.dragged_item = bookmark

        self.clear_credential_display()
        username = bookmark.get('username', '')
        password = bookmark.get('password', '')
        
        self.current_credentials = {'username': username, 'password': password}
        
        if username:
            self.username_label.config(text=f"Username: {'*' * len(username)}")
            self.username_copy.config(text="[copy]")
            self.username_copy.bind("<Button-1>", 
                                  lambda e: [pyperclip.copy(username), 
                                            self.show_prompt_message(f"Copied username: {username}")])
        if password:
            self.password_label.config(text=f"Password: {'*' * len(password)}")
            self.password_copy.config(text="[copy]")
            self.password_copy.bind("<Button-1>", 
                                  lambda e: [pyperclip.copy(password), 
                                            self.show_prompt_message(f"Copied password: {password}")])
        
        if username or password:
            self.show_button.config(state='normal')
        else:
            self.show_button.config(state='disabled')
        
        self.show_prompt_message(f"Selected: {bookmark['title']} ({bookmark['url']})", duration=2000)
        return "break"

    def clear_credential_display(self):
        self.username_label.config(text="")
        self.username_copy.config(text="")
        self.username_copy.unbind("<Button-1>")
        self.password_label.config(text="")
        self.password_copy.config(text="")
        self.password_copy.unbind("<Button-1>")
        self.show_button.config(text="[show]", state='disabled')
        self.show_credentials = False
        self.current_credentials = {'username': '', 'password': ''}

    def drag_motion(self, event):
        if self.drag_start_index is None or self.dragged_item is None:
            return

        try:
            current_line = int(self.textbox.index(f"@{event.x},{event.y}").split('.')[0]) - 1
            if current_line < 0:
                current_line = getattr(self, '_last_valid_line', 0)
        except tk.TclError:
            current_line = getattr(self, '_last_valid_line', 0)
            if current_line < 0:
                current_line = 0

        filtered_bookmarks = self.get_filtered_bookmarks()
        line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)

        start_category = self.dragged_item.get('category', 'Uncategorized')

        # Kategoriegrenzen in filtered_bookmarks ermitteln
        category_indices = [i for i, b in enumerate(filtered_bookmarks) 
                           if b.get('category', 'Uncategorized') == start_category]
        min_index = min(category_indices) if category_indices else 0
        max_index = max(category_indices) if category_indices else len(filtered_bookmarks) - 1

        # Standardmäßig letzte gültige Position verwenden, falls vorhanden
        drop_bookmark_index = getattr(self, '_last_valid_index', min_index)

        if current_line in line_to_bookmark:
            drop_bookmark_id = line_to_bookmark[current_line]
            drop_bookmark = next((b for b in filtered_bookmarks if b['id'] == drop_bookmark_id), None)
            drop_bookmark_index = filtered_bookmarks.index(drop_bookmark) if drop_bookmark else 0
            if drop_bookmark_index >= len(filtered_bookmarks):
                drop_bookmark_index = len(filtered_bookmarks) - 1
            drop_category = filtered_bookmarks[drop_bookmark_index].get('category', 'Uncategorized')
            
            if self.category_lock and start_category != drop_category:
                drop_bookmark_index = max_index if drop_bookmark_index > max_index else min_index
                self.show_prompt_message("Cannot move between categories (unlock to enable)", duration=1000)
        else:
            drop_bookmark_index = getattr(self, '_last_valid_index', max_index)
            if not line_to_bookmark:
                drop_bookmark_index = 0

        # Kategoriegrenze prüfen (nur wenn gesperrt)
        boundary_police = False
        if self.category_lock:
            if drop_bookmark_index <= min_index:
                drop_bookmark_index = min_index
                boundary_police = True
            elif drop_bookmark_index >= max_index:
                drop_bookmark_index = max_index
                boundary_police = True
        else:
            # Begrenze auf gültige Indizes
            if drop_bookmark_index < 0:
                drop_bookmark_index = 0
                boundary_police = True
            elif drop_bookmark_index >= len(filtered_bookmarks):
                drop_bookmark_index = len(filtered_bookmarks) - 1
                boundary_police = True

        # Letzte gültige Position speichern
        self._last_valid_index = drop_bookmark_index
        self._last_valid_line = current_line if current_line in line_to_bookmark else getattr(self, '_last_valid_line', 0)

        # Temporäre Bookmark-Liste erstellen
        temp_bookmarks = self.bookmarks.copy()
        bookmark = temp_bookmarks.pop(self.drag_start_index)
        actual_drop_index = self.bookmarks.index(filtered_bookmarks[drop_bookmark_index]) if filtered_bookmarks else 0
        if not self.category_lock and filtered_bookmarks:
            bookmark['category'] = filtered_bookmarks[drop_bookmark_index].get('category', 'Uncategorized')
        temp_bookmarks.insert(actual_drop_index, bookmark)

        # Textfeld aktualisieren
        self.update_textbox_with_temp(temp_bookmarks)

        # "selected"-Tag setzen
        self.textbox.tag_remove("selected", "1.0", tk.END)
        if filtered_bookmarks and drop_bookmark_index < len(filtered_bookmarks):
            drop_line = [k for k, v in line_to_bookmark.items() if v == filtered_bookmarks[drop_bookmark_index]['id']][0]
            self.textbox.tag_add("selected", f"{drop_line + 1}.0", f"{drop_line + 2}.0")

        # Kategoriegrenze-Meldung anzeigen
        if boundary_police:
            self.show_prompt_message("List boundary reached", duration=1000)

    def drop(self, event):
        if self.drag_start_index is None or self.dragged_item is None:
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.drag_start_index = None
            self.dragged_item = None
            return

        try:
            drop_line = int(self.textbox.index(f"@{event.x},{event.y}").split('.')[0]) - 1
            if drop_line < 0:
                drop_line = getattr(self, '_last_valid_line', 0)
        except (tk.TclError, ValueError):
            drop_line = getattr(self, '_last_valid_line', 0)

        filtered_bookmarks = self.get_filtered_bookmarks()
        line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)

        start_category = self.dragged_item.get('category', 'Uncategorized')

        # Kategoriegrenzen ermitteln
        category_indices = [i for i, b in enumerate(filtered_bookmarks) 
                           if b.get('category', 'Uncategorized') == start_category]
        min_index = min(category_indices) if category_indices else 0
        max_index = max(category_indices) if category_indices else len(filtered_bookmarks) - 1

        # Standardmäßig letzte gültige Position verwenden
        drop_bookmark_index = getattr(self, '_last_valid_index', min_index)

        if drop_line in line_to_bookmark:
            drop_bookmark_id = line_to_bookmark[drop_line]
            drop_bookmark = next((b for b in filtered_bookmarks if b['id'] == drop_bookmark_id), None)
            drop_bookmark_index = filtered_bookmarks.index(drop_bookmark) if drop_bookmark else 0
            if drop_bookmark_index >= len(filtered_bookmarks):
                drop_bookmark_index = len(filtered_bookmarks) - 1
            if self.category_lock:
                drop_category = filtered_bookmarks[drop_bookmark_index].get('category', 'Uncategorized')
                if start_category != drop_category:
                    drop_bookmark_index = max_index if drop_bookmark_index > max_index else min_index
                    self.show_prompt_message("Cannot move between categories (unlock to enable)")
        else:
            drop_bookmark_index = getattr(self, '_last_valid_index', max_index)
            self.show_prompt_message("Dropped on category or empty space")

        # Kategoriegrenze korrigieren (nur wenn gesperrt)
        boundary_police = False
        if self.category_lock:
            if drop_bookmark_index <= min_index:
                drop_bookmark_index = min_index
                boundary_police = True
            elif drop_bookmark_index >= max_index:
                drop_bookmark_index = max_index
                boundary_police = True
        else:
            if drop_bookmark_index < 0:
                drop_bookmark_index = 0
                boundary_police = True
            elif drop_bookmark_index >= len(filtered_bookmarks):
                drop_bookmark_index = len(filtered_bookmarks) - 1
                boundary_police = True

        actual_drop_index = self.bookmarks.index(filtered_bookmarks[drop_bookmark_index]) if filtered_bookmarks else 0
        bookmark = self.bookmarks.pop(self.drag_start_index)
        if not self.category_lock and filtered_bookmarks:
            new_category = filtered_bookmarks[drop_bookmark_index].get('category', 'Uncategorized')
            bookmark['category'] = new_category
            if new_category not in self.category_list:
                self.category_list.append(new_category)
        self.bookmarks.insert(actual_drop_index, bookmark)
        
        self.save_bookmarks()
        self.update_category_buttons()
        self.update_textbox()
        
        filtered_bookmarks = self.get_filtered_bookmarks()
        line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
        new_line = [k for k, v in line_to_bookmark.items() if v == bookmark['id']][0] if filtered_bookmarks else 0
        
        self.textbox.tag_remove("selected", "1.0", tk.END)
        if filtered_bookmarks:
            self.textbox.tag_add("selected", f"{new_line + 1}.0", f"{new_line + 2}.0")
            self.textbox.see(f"{new_line + 1}.0")
        
        if boundary_police:
            self.show_prompt_message("List boundary reached")
        else:
            new_category = bookmark.get('category', 'Uncategorized')
            self.show_prompt_message(f"Dropped {bookmark['title']} at position {drop_bookmark_index + 1}" +
                                    (f" to {new_category}" if not self.category_lock and new_category != start_category else ""))
        
        # Zurücksetzen der gespeicherten Positionen
        self.drag_start_index = None
        self.dragged_item = None
        if hasattr(self, '_last_valid_index'):
            del self._last_valid_index
        if hasattr(self, '_last_valid_line'):
            del self._last_valid_line
        
        self.drag_start_index = None
        self.dragged_item = None

    def update_textbox_with_temp(self, temp_bookmarks):
        scroll_pos = self.textbox.yview()
        self.textbox.delete("1.0", tk.END)
        filtered_temp = self.get_filtered_bookmarks(temp_bookmarks)
        
        grouped_bookmarks = OrderedDict()
        for bookmark in temp_bookmarks:
            cat = bookmark.get('category', 'Uncategorized')
            if cat not in grouped_bookmarks:
                grouped_bookmarks[cat] = []
            if bookmark in filtered_temp:
                grouped_bookmarks[cat].append(bookmark)
        
        for cat, bookmarks in grouped_bookmarks.items():
            if bookmarks and self.categories.get(cat, tk.BooleanVar(value=True)).get():
                self.textbox.insert(tk.END, f"--- {cat} ---\n", "category")
                for bookmark in bookmarks:
                    self.textbox.insert(tk.END, f"{bookmark['url']}", "url")
                    self.textbox.insert(tk.END, f" - {bookmark['title']}\n", "title")
        
        self.textbox.yview_moveto(scroll_pos[0])

    def get_line_to_bookmark_mapping(self, filtered_bookmarks):
        line_to_bookmark = {}
        line_count = 0
        grouped = OrderedDict()
        for bookmark in filtered_bookmarks:
            cat = bookmark.get('category', 'Uncategorized')
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(bookmark)
        index = 0
        for cat in self.category_list:
            if cat in grouped and self.categories.get(cat, tk.BooleanVar(value=True)).get():
                line_count += 1  # For category header
                for bookmark in grouped[cat]:
                    line_to_bookmark[line_count] = bookmark['id']  # Use the unique identifier
                    line_count += 1
                    index += 1
        return line_to_bookmark

    def move_up(self):
        current_index = self.get_selected_index()
        if current_index is None:
            self.show_prompt_message("Warning: No bookmark selected")
            return
        
        filtered_bookmarks = self.get_filtered_bookmarks()
        if current_index <= 0:
            self.show_prompt_message("Cannot move up: Already at top")
            return

        current_bookmark = filtered_bookmarks[current_index]
        actual_index = self.bookmarks.index(current_bookmark)
        
        if actual_index > 0:
            prev_bookmark = self.bookmarks[actual_index - 1]
            if self.category_lock and prev_bookmark.get('category', 'Uncategorized') != current_bookmark.get('category', 'Uncategorized'):
                self.show_prompt_message("Cannot move up: Category boundary (unlock to move across categories)")
                return
            
            self.bookmarks[actual_index], self.bookmarks[actual_index - 1] = \
                self.bookmarks[actual_index - 1], self.bookmarks[actual_index]
            new_category = prev_bookmark.get('category', 'Uncategorized')
            if not self.category_lock and new_category != current_bookmark.get('category', 'Uncategorized'):
                current_bookmark['category'] = new_category
                if new_category not in self.category_list:
                    self.category_list.append(new_category)
            self.save_bookmarks()
            self.update_category_buttons()
            self.update_textbox()
            
            filtered_bookmarks = self.get_filtered_bookmarks()
            line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
            new_index = filtered_bookmarks.index(current_bookmark)
            new_line = [k for k, v in line_to_bookmark.items() if v == current_bookmark['id']][0]
            
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.textbox.tag_add("selected", f"{new_line + 1}.0", f"{new_line + 2}.0")
            self.textbox.see(f"{new_line + 1}.0")
            self.show_prompt_message(f"Moved {current_bookmark['title']} up" + 
                                    (f" to {new_category}" if not self.category_lock and new_category != current_bookmark.get('category', 'Uncategorized') else ""))
        else:
            self.show_prompt_message("Cannot move up: Already at top of list")

    def move_down(self):
        current_index = self.get_selected_index()
        if current_index is None:
            self.show_prompt_message("Warning: No bookmark selected")
            return
        
        filtered_bookmarks = self.get_filtered_bookmarks()
        if current_index >= len(filtered_bookmarks) - 1:
            self.show_prompt_message("Cannot move down: Already at bottom")
            return

        current_bookmark = filtered_bookmarks[current_index]
        actual_index = self.bookmarks.index(current_bookmark)
        
        if actual_index < len(self.bookmarks) - 1:
            next_bookmark = self.bookmarks[actual_index + 1]
            if self.category_lock and next_bookmark.get('category', 'Uncategorized') != current_bookmark.get('category', 'Uncategorized'):
                self.show_prompt_message("Cannot move down: Category boundary (unlock to move across categories)")
                return
            
            self.bookmarks[actual_index], self.bookmarks[actual_index + 1] = \
                self.bookmarks[actual_index + 1], self.bookmarks[actual_index]
            new_category = next_bookmark.get('category', 'Uncategorized')
            if not self.category_lock and new_category != current_bookmark.get('category', 'Uncategorized'):
                current_bookmark['category'] = new_category
                if new_category not in self.category_list:
                    self.category_list.append(new_category)
            self.save_bookmarks()
            self.update_category_buttons()
            self.update_textbox()
            
            filtered_bookmarks = self.get_filtered_bookmarks()
            line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
            new_index = filtered_bookmarks.index(current_bookmark)
            new_line = [k for k, v in line_to_bookmark.items() if v == current_bookmark['id']][0]
            
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.textbox.tag_add("selected", f"{new_line + 1}.0", f"{new_line + 2}.0")
            self.textbox.see(f"{new_line + 1}.0")
            self.show_prompt_message(f"Moved {current_bookmark['title']} down" + 
                                    (f" to {new_category}" if not self.category_lock and new_category != current_bookmark.get('category', 'Uncategorized') else ""))
        else:
            self.show_prompt_message("Cannot move down: Already at bottom of list")

    def get_selected_index(self):
        try:
            sel_start = self.textbox.index("selected.first")
            if not sel_start:
                return None
            line = int(sel_start.split('.')[0]) - 1
            filtered_bookmarks = self.get_filtered_bookmarks()
            line_to_bookmark = self.get_line_to_bookmark_mapping(filtered_bookmarks)
            bookmark_id = line_to_bookmark.get(line, None)
            return next((i for i, b in enumerate(filtered_bookmarks) if b['id'] == bookmark_id), None)
        except tk.TclError:
            return None

    def get_filtered_bookmarks(self, bookmarks=None):
        if bookmarks is None:
            bookmarks = self.bookmarks
        search_term = self.search_var.get().lower() if self.search_var else ''
        filtered = [
            b for b in bookmarks 
            if self.categories.get(b.get('category', 'Uncategorized'), 
                                  tk.BooleanVar(value=True)).get()
            and (search_term in b['title'].lower() or search_term in b['url'].lower())
        ]
        # Ensure filtered bookmarks follow category_list order
        grouped = OrderedDict()
        for bookmark in filtered:
            cat = bookmark.get('category', 'Uncategorized')
            if cat not in grouped:
                grouped[cat] = []
            grouped[cat].append(bookmark)
        filtered = []
        for cat in self.category_list:
            if cat in grouped:
                filtered.extend(grouped[cat])
        return filtered

    def load_bookmarks(self):
        if os.path.exists(self.bookmark_file):
            try:
                with open(self.bookmark_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.key.decrypt(encrypted_data)
                self.bookmarks = json.loads(decrypted_data.decode('utf-8'))
                all_categories = OrderedDict()
                for bookmark in self.bookmarks:
                    cat = bookmark.get('category', 'Uncategorized')
                    if cat not in all_categories:
                        all_categories[cat] = 0
                    all_categories[cat] += 1
                self.category_list = list(all_categories.keys())
                self.update_category_buttons()
            except Exception as e:
                self.bookmarks = []
                self.show_prompt_message(f"Error: Could not decrypt bookmarks. Wrong password or corrupted file. ({str(e)})")
        else:
            self.bookmarks = []

    def save_bookmarks(self):
        json_data = json.dumps(self.bookmarks, ensure_ascii=False, indent=2).encode('utf-8')
        encrypted_data = self.key.encrypt(json_data)
        with open(self.bookmark_file, 'wb') as f:
            f.write(encrypted_data)

    def on_closing(self):
        if self.key:
            self.save_bookmarks()
        self.save_window_geometry()
        if self.tree_window and self.tree_window.winfo_exists():
            self.tree_window.destroy()
        self.root.destroy()

    def import_bookmarks(self):
        file_path = filedialog.askopenfilename(filetypes=[("HTML files", "*.html")])
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.parse_html_bookmarks(content)
                # Initialize category_list based on HTML order
                grouped = OrderedDict()
                for bookmark in self.bookmarks:
                    cat = bookmark.get('category', 'Uncategorized')
                    if cat not in grouped:
                        grouped[cat] = []
                    grouped[cat].append(bookmark)
                self.category_list = list(grouped.keys())
                # Rebuild bookmarks to match category_list order
                self.bookmarks = []
                for cat in self.category_list:
                    self.bookmarks.extend(grouped[cat])
                self.save_bookmarks()
                self.update_category_buttons()
                self.show_prompt_message("Success: Bookmarks imported successfully!")
            except Exception as e:
                self.show_prompt_message(f"Error: Failed to import bookmarks: {str(e)}")

    def parse_html_bookmarks(self, html_content):
        class HTMLBookmarkParser(html.parser.HTMLParser):
            def __init__(self):
                super().__init__()
                self.current_url = ""
                self.current_title = ""
                self.current_category = "Uncategorized"
                self.bookmarks_list = []

            def handle_starttag(self, tag, attrs):
                if tag == 'a':
                    for attr, value in attrs:
                        if attr == 'href':
                            self.current_url = value
                elif tag == 'h3':
                    self.current_category = None

            def handle_endtag(self, tag):
                if tag == 'dl':
                    self.current_category = "Uncategorized"

            def handle_data(self, data):
                data = data.strip()
                if data:
                    if self.current_url:
                        self.current_title = data
                        self.bookmarks_list.append({
                            'id': str(uuid.uuid4()),  # Add a unique identifier
                            'title': data,
                            'url': self.current_url,
                            'category': self.current_category,
                            'username': '',
                            'password': ''
                        })
                        self.current_url = ""
                    elif self.current_category is None:
                        self.current_category = data

        parser = HTMLBookmarkParser()
        parser.feed(html_content)
        self.bookmarks = parser.bookmarks_list

    def export_bookmarks(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".html",
                                                filetypes=[("HTML files", "*.html")],
                                                title="Export Bookmarks - ShellStash")
        if file_path:
            try:
                # Export to HTML
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('<!DOCTYPE NETSCAPE-Bookmark-file-1>\n')
                    f.write('<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">\n')
                    f.write('<TITLE>Bookmarks</TITLE>\n')
                    f.write('<H1>Bookmarks</H1>\n')
                    f.write('<DL><p>\n')
                    
                    grouped_bookmarks = OrderedDict()
                    for bookmark in self.bookmarks:
                        cat = bookmark.get('category', 'Uncategorized')
                        if cat not in grouped_bookmarks:
                            grouped_bookmarks[cat] = []
                        grouped_bookmarks[cat].append(bookmark)
                    
                    for cat, bookmarks in grouped_bookmarks.items():
                        f.write(f'    <DT><H3>{cat}</H3>\n')
                        f.write('    <DL><p>\n')
                        for bookmark in bookmarks:
                            f.write(f'        <DT><A HREF="{bookmark["url"]}">{bookmark["title"]}</A>\n')
                        f.write('    </DL><p>\n')
                    f.write('</DL><p>\n')
                
                # Export to TXT with URL, username, and password
                txt_file_path = os.path.splitext(file_path)[0] + ".txt"
                with open(txt_file_path, 'w', encoding='utf-8') as f:
                    for bookmark in self.bookmarks:
                        url = bookmark.get("url", "")
                        username = bookmark.get("username", "")
                        password = bookmark.get("password", "")
                        f.write(f"URL: {url}\n")
                        f.write(f"Username: {username}\n")
                        f.write(f"Password: {password}\n")
                        f.write("-" * 50 + "\n")
                
                # Show success message first
                self.show_prompt_message("Success: Bookmarks exported successfully!", duration=2000)
                # Schedule warning message to appear after success message
                self.root.after(2500, lambda: self.show_prompt_message(
                    "Warning: Passwords in the TXT file are not encrypted!", duration=3000))
            except Exception as e:
                self.show_prompt_message(f"Error: Failed to export bookmarks: {str(e)}")

    def fetch_title(self, url):
        if url in self.title_cache:
            return self.title_cache[url]
        
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Referer': 'https://www.google.com/'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.string if soup.title else "Untitled"
            title = title.strip() if title else "Untitled"
            
            self.title_cache[url] = title
            return title
            
        except requests.exceptions.RequestException as e:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc or "Untitled"
            self.show_prompt_message(f"Warning: Could not fetch title for {url}: {str(e)}")
            self.title_cache[url] = domain
            return domain
        except Exception as e:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc or "Untitled"
            self.show_prompt_message(f"Warning: Unexpected error for {url}: {str(e)}")
            self.title_cache[url] = domain
            return domain

    def update_textbox(self):
        scroll_pos = self.textbox.yview()
        self.textbox.delete("1.0", tk.END)
        filtered_bookmarks = self.get_filtered_bookmarks()
        
        # Group bookmarks by category, maintaining order from filtered_bookmarks
        grouped_bookmarks = OrderedDict()
        for bookmark in filtered_bookmarks:
            cat = bookmark.get('category', 'Uncategorized')
            if cat not in grouped_bookmarks:
                grouped_bookmarks[cat] = []
            grouped_bookmarks[cat].append(bookmark)
        
        # Display categories in category_list order
        for cat in self.category_list:
            if cat in grouped_bookmarks and self.categories.get(cat, tk.BooleanVar(value=True)).get():
                self.textbox.insert(tk.END, f"--- {cat} ---\n", "category")
                for bookmark in grouped_bookmarks[cat]:
                    self.textbox.insert(tk.END, f"{bookmark['url']}", "url")
                    self.textbox.insert(tk.END, f" - {bookmark['title']}\n", "title")
        
        self.textbox.yview_moveto(scroll_pos[0])

    def update_textbox_with_temp(self, temp_bookmarks):
        scroll_pos = self.textbox.yview()
        self.textbox.delete("1.0", tk.END)
        filtered_temp = self.get_filtered_bookmarks(temp_bookmarks)
        
        grouped_bookmarks = OrderedDict()
        for bookmark in temp_bookmarks:
            cat = bookmark.get('category', 'Uncategorized')
            if cat not in grouped_bookmarks:
                grouped_bookmarks[cat] = []
            if bookmark in filtered_temp:
                grouped_bookmarks[cat].append(bookmark)
        
        for cat, bookmarks in grouped_bookmarks.items():
            if bookmarks and self.categories.get(cat, tk.BooleanVar(value=True)).get():
                self.textbox.insert(tk.END, f"--- {cat} ---\n", "category")
                for bookmark in bookmarks:
                    self.textbox.insert(tk.END, f"{bookmark['url']}", "url")
                    self.textbox.insert(tk.END, f" - {bookmark['title']}\n", "title")
        
        self.textbox.yview_moveto(scroll_pos[0])

    def copy_url(self):
        index = self.get_selected_index()
        filtered_bookmarks = self.get_filtered_bookmarks()
        if index is not None and 0 <= index < len(filtered_bookmarks):
            url = filtered_bookmarks[index]['url']
            pyperclip.copy(url)
            self.show_prompt_message(f"Copied URL: {url}")
        else:
            self.show_prompt_message("Warning: Please select a bookmark first!")

    def open_in_browser(self):
        index = self.get_selected_index()
        filtered_bookmarks = self.get_filtered_bookmarks()
        if index is not None and 0 <= index < len(filtered_bookmarks):
            url = filtered_bookmarks[index]['url']
            webbrowser.open(url)
            self.show_prompt_message(f"Opened in browser: {url}")
        else:
            self.show_prompt_message("Warning: Please select a bookmark first!")

    def delete_bookmark(self):
        index = self.get_selected_index()
        filtered_bookmarks = self.get_filtered_bookmarks()
        if index is not None and 0 <= index < len(filtered_bookmarks):
            bookmark = filtered_bookmarks[index]
            actual_index = self.bookmarks.index(bookmark)
            del self.bookmarks[actual_index]
            self.save_bookmarks()
            self.update_category_buttons()
            self.textbox.tag_remove("selected", "1.0", tk.END)
            self.show_prompt_message(f"Deleted: {bookmark['title']} ({bookmark['url']})")
        else:
            self.show_prompt_message("Warning: Please select a bookmark first!")

if __name__ == "__main__":
    root = tk.Tk()
    app = BookmarkManager(root)
    root.mainloop()