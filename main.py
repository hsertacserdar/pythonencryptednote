import tkinter
from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64

#user interface
window = Tk()
window.title("Secret Notes")
window.config(padx=50,pady=40)
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def encrypted_button_clicked():
    title_input = title_entry.get()
    message_input = secret_text.get("1.0",tkinter.END)
    master_key_input = key_entry.get()
    if len(title_input) == 0 or len(message_input) == 0 or len(master_key_input) == 0:
        messagebox.showinfo(title="WARNING", message="Please enter all info!!!")
    else:
        message_enc = encode(master_key_input,message_input)
        try:
            with open("secret.txt", "a") as f:
                f.write(f"\n{title_input}\n{message_enc}")
        except FileNotFoundError:
            with open("secret.txt","a") as f:
                f.write(f"\n{title_input}\n{message_enc}")
        finally:
            title_entry.delete(0,END)
            key_entry.delete(0,END)
            secret_text.delete("1.0",tkinter.END)

def decrypted_button_clicked():
    encmessage = secret_text.get("1.0",tkinter.END)
    key_entry_input2 = key_entry.get()

    if len(encmessage)==0 or len(key_entry_input2)==0:
        messagebox.showinfo(title="WARNING", message="Please enter all info!!!")
    else:
        try:
            decmessage = decode(key_entry_input2,encmessage)
            secret_text.delete("1.0",END)
            secret_text.insert("1.0",decmessage)
        except:
            messagebox.showinfo(title="WARNING", message="Please enter encrypted text!!!")

my_img = Image.open("topsecret.png")
resized = my_img.resize((100,100))
new_img = ImageTk.PhotoImage(resized)
my_label = Label(window,image=new_img)
my_label.pack()

title_label = Label(text="Enter Your Title",pady=10,anchor="center")
title_label.pack()
title_entry = Entry(width=30)
title_entry.pack()
secret_label = Label(text="Enter Your Secret Note",pady=10)
secret_label.pack()
secret_text = Text(height=14,width=30,pady=10)
secret_text.pack()
key_label = Label(text="Enter Master Key",pady=10)
key_label.pack()
key_entry = Entry(width=30)
key_entry.pack()
encrypt_button = Button(text="Save & Encrypt",width=16,command=encrypted_button_clicked)
encrypt_button.pack(pady=5)
decrypt_button = Button(text="Decrypt",width=16,command=decrypted_button_clicked)
decrypt_button.pack(pady=5)


window.mainloop()