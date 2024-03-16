from tkinter import *
from tkinter import ttk
import random
import string


class SecurePassPro:
    def __init__(self, master):
        self.master = master
        self.master.geometry("700x550")
        self.master.title("SecurePass Pro")
        self.master.configure(bg="#1f1f1f")
        self.master.resizable(False, False)

        self.saved_passwords = []

        self.create_widgets()

    def create_widgets(self):
        # Title
        self.title_label = Label(self.master, text="SSP Password Generator", font=("Arial", 24, "bold"), pady=10,
                                 fg="white", bg="#1f1f1f")
        self.title_label.pack()

        # Strength Selection
        self.strength_frame = Frame(self.master, bg="#1f1f1f")
        self.strength_frame.pack(pady=5, anchor="center")
        self.strength_label = Label(self.strength_frame, text="Select Password Strength:", font=("Arial", 14),
                                    fg="white", bg="#1f1f1f")
        self.strength_label.grid(row=0, column=0, padx=5)
        self.choice = IntVar()
        options = [("WEAK", 1), ("AVERAGE", 2), ("STRONG", 3)]
        for text, value in options:
            Radiobutton(self.strength_frame, text=text, variable=self.choice, value=value, font=("Arial", 12),
                        bg="#1f1f1f", fg="white", selectcolor="#1f1f1f").grid(row=0, column=value, padx=5)

        # Length Selection
        self.length_frame = Frame(self.master, bg="#1f1f1f")
        self.length_frame.pack(pady=5, anchor="center")
        self.length_label = Label(self.length_frame, text="Select Password Length:", font=("Arial", 14),
                                  fg="white", bg="#1f1f1f")
        self.length_label.grid(row=0, column=0, padx=5)
        self.val = StringVar()
        self.val.set("4")  # Default length
        self.length_combo = ttk.Combobox(self.length_frame, textvariable=self.val, font=("Arial", 12), width=5,
                                         state="readonly")
        self.length_combo['values'] = tuple(range(4, 25))  # Range of values for password length
        self.length_combo.grid(row=0, column=1, padx=5)

        # Generate Button
        self.generate_button = Button(self.master, text="Generate Password", bd=5, command=self.generate_password,
                                      font=("Arial", 14), bg="#202020", fg="white")
        self.generate_button.pack(pady=10, anchor="center")

        # Buttons Frame
        self.buttons_frame = Frame(self.master, bg="#1f1f1f")
        self.buttons_frame.pack(pady=5, anchor="center")

        # Copy Button
        self.copy_button = Button(self.buttons_frame, text="Copy to Clipboard", command=self.copy_selected_password,
                                  font=("Arial", 12), bg="#202020", fg="white")
        self.copy_button.grid(row=0, column=0, padx=5)

        # Save Button
        self.save_button = Button(self.buttons_frame, text="Save Password", command=self.save_password,
                                  font=("Arial", 12), bg="#202020", fg="white")
        self.save_button.grid(row=0, column=1, padx=5)

        # Delete Button
        self.delete_button = Button(self.buttons_frame, text="Delete Password", command=self.delete_password,
                                    font=("Arial", 12), bg="#202020", fg="white")
        self.delete_button.grid(row=0, column=2, padx=5)

        # Password Label
        self.password_var = StringVar()
        self.password_label = Label(self.master, textvariable=self.password_var, font=("Arial", 18),
                                    fg="white", bg="#1f1f1f")
        self.password_label.pack(anchor="center")

        # Saved Passwords ListBox
        self.saved_passwords_frame = Frame(self.master, bg="#1f1f1f")
        self.saved_passwords_frame.pack(pady=5, anchor="center")
        self.saved_passwords_label = Label(self.saved_passwords_frame, text="Saved Passwords:", font=("Arial", 14),
                                           fg="white", bg="#1f1f1f")
        self.saved_passwords_label.grid(row=0, column=0, padx=5)
        self.saved_passwords_listbox = Listbox(self.saved_passwords_frame, font=("Arial", 12), width=30, height=5)
        self.saved_passwords_listbox.grid(row=1, column=0, padx=5, pady=5)
        self.saved_passwords_listbox.bind("<<ListboxSelect>>", self.select_password_from_list)
        scrollbar = Scrollbar(self.saved_passwords_frame, orient="vertical")
        scrollbar.config(command=self.saved_passwords_listbox.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        self.saved_passwords_listbox.config(yscrollcommand=scrollbar.set)

    def generate_password(self):
        # Password generation
        strength = self.choice.get()
        if strength == 0:
            print("INVALID: Invalid password strength")
            return
        length = int(self.val.get())
        if strength == 1:
            # Using only letters
            chars = string.ascii_letters
        elif strength == 2:
            # Using letters and digits
            chars = string.ascii_letters + string.digits
        else:
            # Using letters, digits, and punctuation symbols
            chars = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choices(chars, k=length))
        self.password_var.set(password)

    def copy_to_clipboard(self, password):
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        print("Password saved to clipboard!")

    def save_password(self):
        password = self.password_var.get()
        if not password:
            print("INVALID: No password generated.")
            return
        self.saved_passwords.append(password)
        self.saved_passwords_listbox.insert(END, password)
        print("Saved: Password saved successfully!")

    def delete_password(self):
        selected_index = self.saved_passwords_listbox.curselection()
        if selected_index:
            password = self.saved_passwords_listbox.get(selected_index)
            del self.saved_passwords[selected_index[0]]
            self.saved_passwords_listbox.delete(selected_index)
            print("Deleted: Password deleted successfully!")
        else:
            print("INVALID: Please select a password to delete.")

    def select_password_from_list(self, event):
        selected_index = self.saved_passwords_listbox.curselection()
        if selected_index:
            password = self.saved_passwords_listbox.get(selected_index)
            self.password_var.set(password)

    def copy_selected_password(self):
        selected_index = self.saved_passwords_listbox.curselection()
        if selected_index:
            password = self.saved_passwords_listbox.get(selected_index)
            self.copy_to_clipboard(password)
        else:
            print("INVALID: Please select a password to copy.")


def main():
    root = Tk()
    app = SecurePassPro(root)
    root.mainloop()


if __name__ == "__main__":
    main()
