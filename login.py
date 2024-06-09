import customtkinter as ctk
from PIL import Image, ImageTk
from event.event_handlers import open_webpage
from pain import open_box
from helper.call import auth_call
import tkinter.messagebox


def on_enter(event):
    link_button.configure(text_color='Indigo')


def on_leave(event):
    link_button.configure(text_color='black')


def create():
    email = email_entry.get()
    password = pass_entry.get()
    token = auth_call(email, password)
    if token is not None:
        print("testing")
        app.destroy()
        open_box(token)
        app.quit()
    else:
        tkinter.messagebox.showerror("Login Error", "Authentication failed, Try again please")


ctk.set_appearance_mode('dark')

app = ctk.CTk()
app.geometry('1000x800')
app.title("Safenet IDS")

outfit_large = ctk.CTkFont(family='Outfit', size=34, weight='bold')
outfit_small = ctk.CTkFont(family='Outfit', size=18, weight='normal')
outfit_smallest = ctk.CTkFont(family='Outfit', size=16, weight='normal')

left_frame = ctk.CTkFrame(app, width=400, height=800)
left_frame.grid(row=0, column=0, sticky="nsew")

background_image = Image.open("assets/dragon.jpg")
# background_image = background_image.resize((400, 800))
# bg_image = ImageTk.PhotoImage(background_image)

prc_image = ctk.CTkImage(background_image, background_image, (400, 800))
bg_label = ctk.CTkLabel(left_frame,
                        text="",
                        image=prc_image)

bg_label.place(x=0, y=0,
               relwidth=1,
               relheight=1)

right_frame = ctk.CTkFrame(app,
                           width=600,
                           height=800,
                           fg_color='white')
right_frame.grid(row=0, column=1, sticky="nsew")
app.grid_columnconfigure(1, weight=1)

greetings_label = ctk.CTkLabel(right_frame,
                               text='Welcome Back!',
                               text_color='Indigo',
                               font=outfit_large)
greetings_label.pack(anchor='w', padx=60, pady=(90, 0))

sign_in_label = ctk.CTkLabel(right_frame,
                             text="Sign in into your account ",
                             text_color='black',
                             font=outfit_small)
sign_in_label.pack(anchor='w', padx=60)

email_label = ctk.CTkLabel(right_frame,
                           text="Email:",
                           text_color='Indigo',
                           font=outfit_small)
email_label.pack(anchor='w', padx=(60, 0), pady=(60, 0))

email_entry = ctk.CTkEntry(right_frame,
                           width=350,
                           height=45,
                           fg_color='white',
                           font=outfit_small)
email_entry.pack(anchor='w', padx=(60, 0))

pass_label = ctk.CTkLabel(right_frame,
                          text="Password:",
                          text_color='Indigo',
                          font=outfit_small)
pass_label.pack(anchor='w', padx=(60, 0), pady=(20, 0))

pass_entry = ctk.CTkEntry(right_frame,
                          width=350,
                          height=45,
                          fg_color='white',
                          font=outfit_small,
                          show="*")
pass_entry.pack(anchor='w', padx=(60, 0))

login_button = ctk.CTkButton(right_frame,
                             text="Login",
                             width=350,
                             height=45,
                             corner_radius=10,
                             fg_color='Indigo',
                             font=outfit_small,
                             command=create,  # Pass the function reference without parentheses
                             hover=False)
login_button.pack(anchor='w', padx=(60, 0), pady=(40, 0))

link_button = ctk.CTkButton(right_frame,
                            text='Dont have an account? click here',
                            command=open_webpage,
                            text_color='black',
                            font=outfit_smallest,
                            fg_color='transparent',
                            )
link_button.pack(anchor='w', padx=(100, 0), pady=(0, 0))

link_button.bind("<Enter>", on_enter)
link_button.bind("<Leave>", on_leave)

app.mainloop()
