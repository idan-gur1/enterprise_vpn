import os
import time
import tkinter
import tkinter.messagebox as messagebox
import customtkinter
import re
from PIL import Image, ImageTk
from tkinter import filedialog

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

email_re = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}')


class App(customtkinter.CTk):
    APP_NAME = "GurNet secure VPN"
    WIDTH = 1000
    HEIGHT = 600

    def __init__(self, client, *args, **kwargs):
        """
        setting up client graphical user interface
        :param args: customtkinter CTk args
        :param kwargs: customtkinter CTk kwargs
        """

        super().__init__(*args, **kwargs)
        self.title(App.APP_NAME)
        self.geometry(f"{App.WIDTH}x{App.HEIGHT}")
        self.minsize(App.WIDTH, App.HEIGHT)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.client = client

        self.client.connect()

        self.logged_in = False
        self.admin = False
        self.__email = None

        self.pictures = tuple()

        self.home()

    def home(self):
        """
        screen with customtkinter for home screen
        :return: None
        """

        main_frame = self.layout()

        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        main_frame.columnconfigure(0, weight=1)

        image = Image.open("client_images/Logo.jpg").resize((200, 200))
        image = ImageTk.PhotoImage(image)

        label_logo = tkinter.Label(master=main_frame, image=image)
        label_logo.image = image
        label_logo.grid(column=0, row=0)

        if self.logged_in:
            label_home = customtkinter.CTkLabel(master=main_frame,
                                                text=f"Welcome to GurNet secure VPN",
                                                fg_color=("white", "gray40"),
                                                height=100,
                                                font=customtkinter.CTkFont(size=20),
                                                corner_radius=7,
                                                justify=tkinter.CENTER)
        else:
            label_home = customtkinter.CTkLabel(master=main_frame,
                                                text=f"Welcome to GurNet secure VPN\nplease login to connect the vpn",
                                                fg_color=("white", "gray40"),
                                                height=100,
                                                font=customtkinter.CTkFont(size=20),
                                                corner_radius=7,
                                                justify=tkinter.CENTER)
        label_home.grid(column=0, row=1, sticky="nwe", padx=15, pady=15)

    def login(self):
        """
        screen with customtkinter for login screen
        :return: None
        """

        main_frame = self.layout()

        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.rowconfigure(4, weight=1)
        main_frame.rowconfigure(1, weight=0)
        main_frame.columnconfigure(0, weight=1)

        label_login = customtkinter.CTkLabel(master=main_frame,
                                             text=f"Log in to your account",
                                             fg_color=("white", "gray40"),
                                             height=100,
                                             font=customtkinter.CTkFont(size=22),
                                             corner_radius=7,
                                             justify=tkinter.CENTER)
        label_login.grid(column=0, row=0, sticky="nwe", padx=15, pady=15)

        label_errors = customtkinter.CTkLabel(master=main_frame,
                                              text=f"",
                                              fg_color="gray10",
                                              font=customtkinter.CTkFont(size=22),
                                              justify=tkinter.CENTER)
        label_errors.grid(column=0, row=2, sticky="nwe", padx=15)
        label_errors.grid_forget()

        form_frame = customtkinter.CTkFrame(master=main_frame, width=500)
        form_frame.grid(column=0, row=4, sticky=tkinter.NSEW, padx=100, pady=15)

        email_entry = customtkinter.CTkEntry(master=form_frame, corner_radius=20, width=200, height=35,
                                             placeholder_text="email")
        email_entry.place(relx=0.5, rely=0.15, anchor=tkinter.CENTER)

        password_entry = customtkinter.CTkEntry(master=form_frame, corner_radius=20, width=200, height=35,
                                                placeholder_text="password")
        password_entry.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

        login_btn = customtkinter.CTkButton(master=form_frame, text="Login",  # text_font=("Arial", -18),
                                            corner_radius=6,
                                            command=lambda: self.handle_login(email_entry.get(), password_entry.get(),
                                                                              label_errors),
                                            width=200)
        login_btn.place(relx=0.5, rely=0.9, anchor=tkinter.CENTER)

    def handle_login(self, email: str, password: str, errors_label: customtkinter.CTkLabel):
        """
        validating user input and sending it to the sever with the client network interface
        :param errors_label:
        :param email: str
        :param password: str
        :return: None
        """

        if email == "" or email.isspace():
            # messagebox.showerror("Login", "please fill the email field")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="please fill the email field")
            return
        if not email_re.fullmatch(email):
            # messagebox.showerror("Login", "please enter a valid email address")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="please enter a valid email address")
            return
        if password == "" or password.isspace():
            # messagebox.showerror("Login", "please fill the password field")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="please fill the password field")
            return
        if len(password) < 6:
            # messagebox.showerror("Login", "password must be at least 6 characters")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="password must be at least 6 characters")
            return

        # self.dual_auth()

        login_status = self.client.attempt_login(email, password)

        if login_status == 1:
            messagebox.showerror("Login", "Error has accord while communicating with the server")
            return

        if login_status == 3:
            # messagebox.showinfo("Login", "You have successfully logged in!")
            # self.logged_in = True
            self.__email = email
            self.dual_auth()
        else:
            # messagebox.showerror("Login", "Email or password are wrong")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="Email or password are wrong")

    def dual_auth(self):
        """
        screen with customtkinter for login screen
        :return: None
        """

        main_frame = self.layout()

        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.rowconfigure(4, weight=1)
        main_frame.rowconfigure(1, weight=0)
        main_frame.columnconfigure(0, weight=1)

        label_login = customtkinter.CTkLabel(master=main_frame,
                                             text=f"Log in to your account",
                                             fg_color=("white", "gray40"),
                                             height=100,
                                             font=customtkinter.CTkFont(size=22),
                                             corner_radius=7,
                                             justify=tkinter.CENTER)
        label_login.grid(column=0, row=0, sticky="nwe", padx=15, pady=15)

        label_errors = customtkinter.CTkLabel(master=main_frame,
                                              text=f"",
                                              fg_color="gray10",
                                              font=customtkinter.CTkFont(size=22),
                                              justify=tkinter.CENTER)
        label_errors.grid(column=0, row=2, sticky="nwe", padx=15)
        label_errors.grid_forget()

        form_frame = customtkinter.CTkFrame(master=main_frame, width=500)
        form_frame.grid(column=0, row=4, sticky=tkinter.NSEW, padx=100, pady=15)

        email_entry = customtkinter.CTkEntry(master=form_frame, corner_radius=20, width=200, height=35,
                                             placeholder_text="otp...")
        email_entry.place(relx=0.5, rely=0.15, anchor=tkinter.CENTER)

        # password_entry = customtkinter.CTkEntry(master=form_frame, corner_radius=20, width=200, height=35,
        #                                         placeholder_text="password")
        # password_entry.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

        login_btn = customtkinter.CTkButton(master=form_frame, text="connect to VPN",  # text_font=("Arial", -18),
                                            corner_radius=6,
                                            command=lambda: self.handle_dual_auth(email_entry.get(), label_errors),
                                            width=200)
        login_btn.place(relx=0.5, rely=0.9, anchor=tkinter.CENTER)

    def handle_dual_auth(self, otp: str, errors_label: customtkinter.CTkLabel):
        """
        validating user input and sending it to the sever with the client network interface
        :param errors_label:
        :param otp: str
        :return: None
        """

        if otp == "" or otp.isspace():
            # messagebox.showerror("Login", "please fill the email field")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="please fill the email field")
            return
        if not otp.isdigit():
            # messagebox.showerror("Login", "please enter a valid email address")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="please enter a valid number")
            return

        # self.logged_in = True
        # self.home()

        login_status = self.client.attempt_dual_auth(self.__email, otp)

        if login_status == 1:
            messagebox.showerror("Login", "Error has accord while communicating with the server")
            return

        if login_status == 3:
            # messagebox.showinfo("Login", "You have successfully logged in!")
            self.logged_in = True
            self.admin = self.client.admin
            self.client.start_client_services()
            self.home()
        else:
            # messagebox.showerror("Login", "Email or password are wrong")
            errors_label.grid(column=0, row=2, sticky="nwe", padx=15)
            errors_label.configure(text="Email or password are wrong")

    def file_server(self):
        main_frame = self.layout()

        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        # main_frame.rowconfigure((0, 10), weight=1)
        main_frame.rowconfigure(4, weight=2)
        main_frame.rowconfigure(6, weight=2)
        main_frame.rowconfigure(2, weight=4)

        label_offer = customtkinter.CTkLabel(master=main_frame,
                                             text=f"File server options",
                                             fg_color=("white", "gray40"),
                                             height=100,
                                             font=customtkinter.CTkFont(size=24),
                                             justify=tkinter.CENTER)
        label_offer.grid(column=0, row=1, sticky="nwe", padx=15, pady=15)

        date_btn = customtkinter.CTkButton(master=main_frame,
                                           text="donwload file",
                                           command=self.handle_download_file,
                                           width=200, height=50,
                                           font=customtkinter.CTkFont(size=18),
                                           border_width=0,
                                           corner_radius=8)
        date_btn.grid(pady=10, padx=20, row=3, column=0)

        all_rooms_btn = customtkinter.CTkButton(master=main_frame,
                                                text="upload file",
                                                command=self.handle_upload_file,
                                                width=200, height=50,
                                                font=customtkinter.CTkFont(size=18),
                                                border_width=0,
                                                corner_radius=8)
        all_rooms_btn.grid(pady=10, padx=20, row=5, column=0)

    def handle_download_file(self):
        for filename in os.listdir("ftp"):
            file_path = os.path.join("ftp", filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))

        files = self.client.get_ftp_files()

        for file in files:
            ftp_file_path = os.path.join("ftp", file)
            with open(ftp_file_path, "w") as f:
                f.write("")

        filename = os.path.basename(filedialog.askopenfilename(
            title='select file',
            initialdir='ftp'))

        if filename == "" or filename.isspace():
            return

        file_bytes = self.client.get_ftp_file(filename)

        with open(os.path.join("downloaded_files", filename), "wb") as downloaded_file:
            downloaded_file.write(file_bytes)

    def handle_upload_file(self):
        filename = filedialog.askopenfilename(
            title='upload file',
            initialdir='/')

        if filename == "" or filename.isspace():
            return

        self.client.upload_ftp_file(filename)

    def admin_panel(self):
        main_frame = self.layout()

        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        # main_frame.rowconfigure((0, 10), weight=1)
        main_frame.rowconfigure(4, weight=2)
        main_frame.rowconfigure(6, weight=2)
        main_frame.rowconfigure(2, weight=4)

        label_offer = customtkinter.CTkLabel(master=main_frame,
                                             text=f"Admin panel",
                                             fg_color=("white", "gray40"),
                                             height=100,
                                             font=customtkinter.CTkFont(size=24),
                                             corner_radius=7,
                                             justify=tkinter.CENTER)
        label_offer.grid(column=0, row=1, sticky="nwe", padx=15, pady=15)

        date_btn = customtkinter.CTkButton(master=main_frame,
                                           text="website rules",
                                           command=self.website_rules,
                                           width=200, height=50,
                                           font=customtkinter.CTkFont(size=18),
                                           border_width=0,
                                           corner_radius=8)
        date_btn.grid(pady=10, padx=20, row=3, column=0)

        all_rooms_btn = customtkinter.CTkButton(master=main_frame,
                                                text="users",
                                                command=self.users,
                                                width=200, height=50,
                                                font=customtkinter.CTkFont(size=18),
                                                border_width=0,
                                                corner_radius=8)
        all_rooms_btn.grid(pady=10, padx=20, row=5, column=0)

    def users(self):
        main_frame = self.layout()

        main_frame.grid_columnconfigure(0, weight=1)
        # main_frame.grid_rowconfigure(0, weight=1)

        label_offer = customtkinter.CTkLabel(master=main_frame,
                                             text=f"Users",
                                             fg_color=("white", "gray40"),
                                             height=80,
                                             font=customtkinter.CTkFont(size=24),
                                             corner_radius=7,
                                             justify=tkinter.CENTER)
        label_offer.grid(column=0, row=0, sticky="nwe", padx=15, pady=15)

        login_btn = customtkinter.CTkButton(master=main_frame, text="add user",
                                            font=customtkinter.CTkFont(size=18, weight="bold"),
                                            corner_radius=6,
                                            # command=lambda: self.handle_dual_auth(email_entry.get(), label_errors),
                                            width=200)
        login_btn.grid(column=0, row=1, padx=4, pady=4)

        table_frame = customtkinter.CTkFrame(master=main_frame)
        table_frame.grid(column=0, row=2, pady=25)

        label_start_date = customtkinter.CTkLabel(master=table_frame,
                                                  text=f"email",
                                                  fg_color=("white", "gray60"),
                                                  font=customtkinter.CTkFont(size=18, weight="bold"),
                                                  justify=tkinter.CENTER,
                                                  corner_radius=6,
                                                  pady=3, padx=3)
        label_start_date.grid(column=0, row=0, padx=4, pady=4, sticky=tkinter.EW)
        label_end_date = customtkinter.CTkLabel(master=table_frame,
                                                text=f"status",
                                                fg_color=("white", "gray60"),
                                                font=customtkinter.CTkFont(size=18, weight="bold"),
                                                justify=tkinter.CENTER,
                                                corner_radius=6,
                                                pady=3, padx=3)
        label_end_date.grid(column=1, row=0, padx=4, pady=4, sticky=tkinter.EW)
        label_dispute = customtkinter.CTkLabel(master=table_frame,
                                               text=f"ip",
                                               fg_color=("white", "gray60"),
                                               font=customtkinter.CTkFont(size=18, weight="bold"),
                                               justify=tkinter.CENTER,
                                               corner_radius=6,
                                               pady=3, padx=3)
        label_dispute.grid(column=2, row=0, padx=4, pady=4, sticky=tkinter.EW)
        label_remove = customtkinter.CTkLabel(master=table_frame,
                                              text=f"admin",
                                              fg_color=("white", "gray60"),
                                              font=customtkinter.CTkFont(size=18, weight="bold"),
                                              justify=tkinter.CENTER,
                                              corner_radius=6,
                                              pady=3, padx=3)
        label_remove.grid(column=3, row=0, padx=4, pady=4, sticky=tkinter.EW)
        label_remove = customtkinter.CTkLabel(master=table_frame,
                                              text=f"FTP",
                                              fg_color=("white", "gray60"),
                                              font=customtkinter.CTkFont(size=18, weight="bold"),
                                              justify=tkinter.CENTER,
                                              corner_radius=6,
                                              pady=3, padx=3)
        label_remove.grid(column=4, row=0, padx=4, pady=4, sticky=tkinter.EW)
        label_remove = customtkinter.CTkLabel(master=table_frame,
                                              text=f"proxy",
                                              fg_color=("white", "gray60"),
                                              font=customtkinter.CTkFont(size=18, weight="bold"),
                                              justify=tkinter.CENTER,
                                              corner_radius=6,
                                              pady=3, padx=3)
        label_remove.grid(column=5, row=0, padx=4, pady=4, sticky=tkinter.EW)

        # users = [{'email': "test@test.com", 'connected': "True", 'ip': "192.168.1.105", 'admin': "True", 'FTP': "True", 'proxy': "True"},
        #          {'email': "test23@test.com", 'connected': "True", 'ip': "192.168.1.103", 'admin': "False", 'FTP': "False", 'proxy': "True"}]

        users = self.client.get_users()

        for row, user in enumerate(users):
            customtkinter.CTkLabel(master=table_frame,
                                   text=f"{user['email']}",
                                   fg_color=("white", "gray40"),
                                   font=customtkinter.CTkFont(size=18),
                                   justify=tkinter.CENTER,
                                   corner_radius=8,
                                   pady=3, padx=3).grid(column=0, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)
            customtkinter.CTkLabel(master=table_frame,
                                   text=f"{user['status']}",
                                   fg_color=("white", "gray40"),
                                   font=customtkinter.CTkFont(size=18),
                                   justify=tkinter.CENTER,
                                   corner_radius=6,
                                   pady=3, padx=3).grid(column=1, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)
            customtkinter.CTkLabel(master=table_frame,
                                   text=f"{user['ip']}",
                                   fg_color=("white", "gray40"),
                                   font=customtkinter.CTkFont(size=18),
                                   justify=tkinter.CENTER,
                                   corner_radius=6,
                                   pady=3, padx=3).grid(column=2, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)
            admin_var = tkinter.IntVar(value=1 if user['admin'] == "yes" else 0)
            a = customtkinter.CTkCheckBox(master=table_frame, text="", width=0, variable=admin_var,
                                          state=tkinter.DISABLED if user['email'] == self.__email else tkinter.NORMAL,
                                          command=lambda var=admin_var,
                                                         email=user['email']: self.handle_admin_status(var, email))
            a.grid(column=3, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)
            b = customtkinter.CTkCheckBox(master=table_frame, text="", width=24,
                                          state=tkinter.DISABLED if user['email'] == self.__email else tkinter.NORMAL,
                                          variable=tkinter.IntVar(value=1 if user['FTP'] == "True" else 0),
                                          command= lambda email=user['email']: self.handle_proxy_change(email))
            b.grid(column=4, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)
            c = customtkinter.CTkCheckBox(master=table_frame, text="", width=24,
                                          state=tkinter.DISABLED if user['email'] == self.__email else tkinter.NORMAL,
                                          variable=tkinter.IntVar(value=1 if user['proxy'] == "True" else 0))
            c.grid(column=5, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)

    def handle_admin_status(self, var, email):
        self.client.set_admin_state(var, email)
        self.users()

    def handle_proxy_change(self, email):
        self.client.set_proxy_state(email)
        self.users()

    def website_rules(self):
        main_frame = self.layout()

        main_frame.grid_columnconfigure(0, weight=1)

        label_offer = customtkinter.CTkLabel(master=main_frame,
                                             text=f"Website rules",
                                             fg_color=("white", "gray40"),
                                             height=80,
                                             font=customtkinter.CTkFont(size=24),
                                             corner_radius=7,
                                             justify=tkinter.CENTER)
        label_offer.grid(column=0, row=0, sticky="nwe", padx=15, pady=15)

        form_frame = customtkinter.CTkFrame(master=main_frame, width=500)
        form_frame.grid(column=0, row=1, padx=100, pady=25)

        email_entry = customtkinter.CTkEntry(master=form_frame, corner_radius=20, width=200, height=35,
                                             placeholder_text="domain/ip...")
        email_entry.grid(column=0, row=0, padx=4, pady=4, columnspan=2)

        login_btn = customtkinter.CTkButton(master=form_frame, text="-",
                                            font=customtkinter.CTkFont(size=16, weight="bold"),
                                            corner_radius=6,
                                            command=lambda: self.handle_remove_rule(email_entry.get()),
                                            width=80)
        login_btn.grid(column=0, row=1, padx=4, pady=4)

        login_btn = customtkinter.CTkButton(master=form_frame, text="+",
                                            font=customtkinter.CTkFont(size=16, weight="bold"),
                                            corner_radius=6,
                                            command=lambda: self.handle_add_rule(email_entry.get()),
                                            width=80)
        login_btn.grid(column=1, row=1, padx=4, pady=4)

        table_frame = customtkinter.CTkFrame(master=main_frame)
        table_frame.grid(column=0, row=3, pady=30)

        label_start_date = customtkinter.CTkLabel(master=table_frame,
                                                  text=f"domain",
                                                  fg_color=("white", "gray60"),
                                                  font=customtkinter.CTkFont(size=18, weight="bold"),
                                                  justify=tkinter.CENTER,
                                                  corner_radius=6,
                                                  pady=3, padx=4)
        label_start_date.grid(column=0, row=0, padx=4, pady=4, sticky=tkinter.EW)
        label_end_date = customtkinter.CTkLabel(master=table_frame,
                                                text=f"ip",
                                                fg_color=("white", "gray60"),
                                                font=customtkinter.CTkFont(size=18, weight="bold"),
                                                justify=tkinter.CENTER,
                                                corner_radius=6,
                                                pady=3, padx=4)
        label_end_date.grid(column=1, row=0, padx=4, pady=4, sticky=tkinter.EW)

        # users = [{'domain': "example.com", 'ip': "220.17.81.99"},
        #          {'domain': "example23.com", 'ip': "116.172.54.19"}]

        users = self.client.get_proxy_rules()

        if users == 1:
            print("an error while communicating with the server")

        print(users)

        for row, user in enumerate(users):
            customtkinter.CTkLabel(master=table_frame,
                                   text=f"{user['domain']}",
                                   fg_color=("white", "gray40"),
                                   font=customtkinter.CTkFont(size=18),
                                   justify=tkinter.CENTER,
                                   corner_radius=8,
                                   pady=3, padx=4).grid(column=0, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)
            customtkinter.CTkLabel(master=table_frame,
                                   text=f"{user['ip']}",
                                   fg_color=("white", "gray40"),
                                   font=customtkinter.CTkFont(size=18),
                                   justify=tkinter.CENTER,
                                   corner_radius=6,
                                   pady=3, padx=4).grid(column=1, row=row + 1, padx=4, pady=4, sticky=tkinter.EW)

    def handle_add_rule(self, domain):
        self.client.add_proxy_rule(domain)
        self.website_rules()

    def handle_remove_rule(self, domain):
        self.client.remove_proxy_rule(domain)
        self.website_rules()

    def layout(self, function_use=None):
        """
        sets up the side menu and main frame and return the main frame
        :param function_use: function to execute -> optional
        :return: CTkFrame
        """

        self.clear()

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        frame_left = customtkinter.CTkFrame(master=self,
                                            width=150)
        frame_left.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

        frame_right = customtkinter.CTkFrame(master=self,
                                             corner_radius=10)
        frame_right.grid(row=0, column=1, rowspan=1, pady=20, padx=20, sticky="nsew")

        # side_bar_layout

        frame_left.grid_rowconfigure(0, minsize=10)

        image = Image.open("client_images/Logo.jpg").resize((120, 120))
        image = ImageTk.PhotoImage(image)

        label_logo = tkinter.Label(master=frame_left, image=image)
        label_logo.image = image
        label_logo.grid(column=0, row=0, pady=10, padx=20)

        name_disabled_btn = customtkinter.CTkButton(master=frame_left,
                                                    text=f"Hello, user",
                                                    # text_font=("Arial", "11", "bold"),
                                                    width=120, height=30,
                                                    border_width=0,
                                                    corner_radius=8)
        name_disabled_btn.grid(pady=10, padx=20, row=1, column=0)

        home_btn = customtkinter.CTkButton(master=frame_left,
                                           text="Home",
                                           command=self.home,
                                           width=120, height=30,
                                           border_width=0,
                                           corner_radius=8)
        home_btn.grid(pady=10, padx=20, row=2, column=0, sticky=tkinter.EW)

        if not self.logged_in:
            login_btn = customtkinter.CTkButton(master=frame_left,
                                                text="Log in",
                                                command=self.login,
                                                width=120, height=30,
                                                border_width=0,
                                                corner_radius=8)
            login_btn.grid(pady=10, padx=20, row=3, column=0, sticky=tkinter.EW)

            # signup_btn = customtkinter.CTkButton(master=frame_left,
            #                                      text="Sign up",
            #                                      command=self.sign_up,
            #                                      width=120, height=30,
            #                                      border_width=0,
            #                                      corner_radius=8)
            # signup_btn.grid(pady=10, padx=20, row=4, column=0, sticky=tkinter.EW)

        else:
            offers_btn = customtkinter.CTkButton(master=frame_left,
                                                 text="file server",
                                                 command=self.file_server,
                                                 width=120, height=30,
                                                 border_width=0,
                                                 corner_radius=8)
            offers_btn.grid(pady=10, padx=20, row=3, column=0, sticky=tkinter.EW)

            if self.admin:
                admin_btn = customtkinter.CTkButton(master=frame_left,
                                                    text="admin panel",
                                                    command=self.admin_panel,
                                                    width=120, height=30,
                                                    border_width=0,
                                                    corner_radius=8)
                admin_btn.grid(pady=10, padx=20, row=5, column=0, sticky=tkinter.EW)

            logout_btn = customtkinter.CTkButton(master=frame_left,
                                                 text="disconnect",
                                                 fg_color="red",
                                                 command=self.logout,
                                                 width=120, height=30,
                                                 border_width=0,
                                                 corner_radius=8)
            logout_btn.grid(pady=10, padx=20, row=7, column=0, sticky=tkinter.EW)

            if function_use is not None:
                function_use(frame_left)

        return frame_right

    def logout(self):
        """
        changing logged in to false and going to home screen
        :return: None
        """

        self.logged_in = False
        self.client.close()
        time.sleep(3)
        self.destroy()
        self.quit()

    def clear(self):
        """
        clears all the widgets on the screen
        :return: None
        """

        for w in self.winfo_children():
            w.destroy()

    def on_closing(self):
        self.destroy()

    def start(self):
        self.mainloop()
