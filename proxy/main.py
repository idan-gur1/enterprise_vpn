from tkinter import *
from PIL import Image, ImageTk
import winreg

proxy_addr = "172.16.15.254:8080"
proxy = False

INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                                   0, winreg.KEY_ALL_ACCESS)


def set_key(name, value):
    _, reg_type = winreg.QueryValueEx(INTERNET_SETTINGS, name)
    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, reg_type, value)


def handle_btn():
    global proxy

    if not proxy:
        set_key("ProxyEnable", 1)
        set_key("ProxyOverride", u"*.local;<local>")
        set_key("ProxyServer", f"{proxy_addr}")

        proxy = True
    else:
        set_key('ProxyEnable', 0)


root = Tk()
root.geometry("500x500")
button = Button(root, command=handle_btn, relief=FLAT)
resized_image = Image.open("btn.png").resize((300, 300))
new_image = ImageTk.PhotoImage(resized_image)
button.config(image=new_image)
button.place(relx=0.5, rely=0.5, anchor=CENTER)  # Displaying the button

root.mainloop()
