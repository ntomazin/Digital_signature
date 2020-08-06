from tkinter import *
from tkinter import ttk
import tkinter as tk
from tkinter import filedialog

from generators import *

HEIGHT = 900
WIDTH = 750
root = None


def main_window():
    global root
    root = Tk()
    root.title("NOS Nikola Tomažin")
    root.geometry(f"{str(HEIGHT)}x{str(WIDTH)}")

    Label(root, text='Odaberite zeljenu operaciju', font="helvetica 15").grid(row=0, padx=10, pady=40)

    # ENVELOPE BUTTON
    generate_envelope_button = Button(root, text="Generate envelope", command=generate_envelope, height=5, width=100)
    generate_envelope_button.grid(row=1, padx=30)

    open_envelope_button = Button(root, text="Open envelope", command=open_envelope, height=5, width=100)
    open_envelope_button.grid(row=2)

    # SIGNATURE BUTTONS
    generate_signature_button = Button(root, text="Generate signature", command=generate_signature, height=5,
                                       width=100)
    generate_signature_button.grid(row=3)

    verify_signature_button = Button(root, text="Verify signature", command=verify_signature, height=5, width=100)
    verify_signature_button.grid(row=4)

    # SEAL BUTTONS
    generate_seal_button = Button(root, text="Generate seal", command=generate_seal, height=5, width=100)
    generate_seal_button.grid(row=5)

    open_seal_button = Button(root, text="Open seal", command=open_seal, height=5, width=100)
    open_seal_button.grid(row=6)

    # KEY BUTTON
    generate_keys_button = Button(root, text="Generate keys", command=generate_keys, height=5, width=100)
    generate_keys_button.grid(row=7)

    root.mainloop()


def generate_envelope():
    window = Toplevel(root)
    window.title("Generate envelope")
    window.geometry(f"{str(700)}x{str(600)}")

    Label(window, text='Generate envelope', font="helvetica 15").grid(row=0, padx=10, pady=40)

    Label(window, text='Shared key:', font="helvetica 15").grid(row=1, column=0, padx=15, pady=15)
    shared_key = StringVar()
    shared_key.set('keys/shared_key.json')
    Entry(window, textvariable=shared_key, width=30, font="helvetica 15").grid(row=1, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: shared_key.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=1,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Reciever public key:', font="helvetica 15").grid(row=2, column=0, padx=15, pady=15)
    public_key = StringVar()
    public_key.set('keys/reciever_public_key.json')
    Entry(window, textvariable=public_key, width=30, font="helvetica 15").grid(row=2, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: public_key.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=2,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Input file:', font="helvetica 15").grid(row=3, column=0, padx=15, pady=15)
    input_path = StringVar()
    input_path.set('input/input.txt')
    Entry(window, textvariable=input_path, width=30, font="helvetica 15").grid(row=3, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: input_path.set(filedialog.askopenfilename(initialdir='input'))).grid(row=3,
                                                                                                column=2,
                                                                                                padx=15,
                                                                                                pady=15)

    Label(window, text='Crypt mode', font="helvetica 15").grid(row=4, column=1, padx=15, pady=15)
    crypt_mode = StringVar()
    crypt_mode.set("CFB")
    OptionMenu(window, crypt_mode, "OFB", "CFB").grid(row=4, column=2, padx=15, pady=15)

    Label(window, text='Output file:', font="helvetica 15").grid(row=5, column=0, padx=15, pady=15)
    output_path = StringVar()
    output_path.set('output/envelope.json')
    Entry(window, textvariable=output_path, font="helvetica 15", width=30).grid(row=5, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: output_path.set(filedialog.askopenfilename(initialdir='output'))).grid(row=5,
                                                                                                  column=2,
                                                                                                  padx=15,
                                                                                                  pady=15)

    Button(window, text='Generate', font="helvetica 15",
           command=lambda: evelope_generator(
               shared_key.get(),
               public_key.get(),
               input_path.get(),
               crypt_mode.get(),
               output_path.get(),
           )).grid(row=7,
                   column=1,
                   padx=15,
                   pady=15)


def open_envelope():
    window = Toplevel(root)
    window.title("Open envelope")
    window.geometry(f"{str(700)}x{str(600)}")

    Label(window, text='Open envelope', font="helvetica 15").grid(row=0, padx=10, pady=40)

    Label(window, text='Reciever private key:', font="helvetica 15").grid(row=2, column=0, padx=15, pady=15)
    private_key_path = StringVar()
    private_key_path.set('keys/reciever_private_key.json')
    Entry(window, textvariable=private_key_path, width=30, font="helvetica 15").grid(row=2, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: private_key_path.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=2,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Envelope:', font="helvetica 15").grid(row=3, column=0, padx=15, pady=15)
    envelope_path = StringVar()
    envelope_path.set('output/envelope.json')
    Entry(window, textvariable=envelope_path, width=30, font="helvetica 15").grid(row=3, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: envelope_path.set(filedialog.askopenfilename(initialdir='output'))).grid(row=3,
                                                                                                    column=2,
                                                                                                    padx=15,
                                                                                                    pady=15)

    Button(window, text='Open', font="helvetica 15",
           command=lambda: envelope_open(
               envelope_path.get(),
               private_key_path.get()
           )).grid(row=7,
                   column=1,
                   padx=15,
                   pady=15)


def generate_signature():
    window = Toplevel(root)
    window.title("Generate signature")
    window.geometry(f"{str(700)}x{str(600)}")

    Label(window, text='Generate signature', font="helvetica 15").grid(row=0, padx=10, pady=40)

    Label(window, text='Chose hash method', font="helvetica 15").grid(row=1, column=1, padx=15, pady=15)
    hash_method = StringVar()
    hash_method.set("sha3_224")
    OptionMenu(window, hash_method, "sha3_224", "sha3_256", "sha3_384", "sha3_512",
               "sha224", "sha256", "sha384", "sha512").grid(row=1, column=2, padx=15, pady=15)

    Label(window, text='Sender private key:', font="helvetica 15").grid(row=2, column=0, padx=15, pady=15)
    private_key_path = StringVar()
    private_key_path.set('keys/sender_private_key.json')
    Entry(window, textvariable=private_key_path, width=30, font="helvetica 15").grid(row=2, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: private_key_path.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=2,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Input file:', font="helvetica 15").grid(row=3, column=0, padx=15, pady=15)
    input_path = StringVar()
    input_path.set('input/input.txt')
    Entry(window, textvariable=input_path, width=30, font="helvetica 15").grid(row=3, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: input_path.set(filedialog.askopenfilename(initialdir='input'))).grid(row=3,
                                                                                                column=2,
                                                                                                padx=15,
                                                                                                pady=15)

    Label(window, text='Output file:', font="helvetica 15").grid(row=4, column=0, padx=15, pady=15)
    output_path = StringVar()
    output_path.set('output/signature.json')
    Entry(window, textvariable=output_path, font="helvetica 15", width=30).grid(row=4, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: output_path.set(filedialog.askopenfilename(initialdir='output'))).grid(row=4,
                                                                                                  column=2,
                                                                                                  padx=15,
                                                                                                  pady=15)

    Button(window, text='Generate', font="helvetica 15",
           command=lambda: signature_generator(
               private_key_path.get(),
               input_path.get(),
               output_path.get(),
               hash_method.get(),
           )).grid(row=5,
                   column=1,
                   padx=15,
                   pady=15)


def verify_signature():
    window = Toplevel(root)
    window.title("Verify signature")
    window.geometry(f"{str(700)}x{str(600)}")

    Label(window, text='Verify signature', font="helvetica 15").grid(row=0, padx=10, pady=40)

    Label(window, text='Sender public key:', font="helvetica 15").grid(row=2, column=0, padx=15, pady=15)
    public_key_path = StringVar()
    public_key_path.set('keys/sender_public_key.json')
    Entry(window, textvariable=public_key_path, width=30, font="helvetica 15").grid(row=2, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: public_key_path.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=2,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Input file:', font="helvetica 15").grid(row=3, column=0, padx=15, pady=15)
    input_path = StringVar()
    input_path.set('input/input.txt')
    Entry(window, textvariable=input_path, width=30, font="helvetica 15").grid(row=3, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: input_path.set(filedialog.askopenfilename(initialdir='input'))).grid(row=3,
                                                                                                column=2,
                                                                                                padx=15,
                                                                                                pady=15)

    Label(window, text='Signature:', font="helvetica 15").grid(row=4, column=0, padx=15, pady=15)
    signature = StringVar()
    signature.set('output/signature.json')
    Entry(window, textvariable=signature, width=30, font="helvetica 15").grid(row=4, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: signature.set(filedialog.askopenfilename(initialdir='output'))).grid(row=4,
                                                                                                column=2,
                                                                                                padx=15,
                                                                                                pady=15)

    Button(window, text='Verify', font="helvetica 15",
           command=lambda: signature_verify(
               input_path.get(),
               public_key_path.get(),
               signature.get(),
           )).grid(row=5,
                   column=1,
                   padx=15,
                   pady=15)


def generate_seal():
    window = Toplevel(root)
    window.title("Generate seal")
    window.geometry(f"{str(700)}x{str(600)}")

    Label(window, text='Generate seal', font="helvetica 15").grid(row=0, padx=10, pady=40)

    Label(window, text='Shared key:', font="helvetica 15").grid(row=1, column=0, padx=15, pady=15)
    shared_key = StringVar()
    shared_key.set('keys/shared_key.json')
    Entry(window, textvariable=shared_key, width=30, font="helvetica 15").grid(row=1, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: shared_key.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=1,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Reciever public key:', font="helvetica 15").grid(row=2, column=0, padx=15, pady=15)
    public_key = StringVar()
    public_key.set('keys/reciever_public_key.json')
    Entry(window, textvariable=public_key, width=30, font="helvetica 15").grid(row=2, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: public_key.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=2,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Input file:', font="helvetica 15").grid(row=3, column=0, padx=15, pady=15)
    input_path = StringVar()
    input_path.set('input/input.txt')
    Entry(window, textvariable=input_path, width=30, font="helvetica 15").grid(row=3, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: input_path.set(filedialog.askopenfilename(initialdir='input'))).grid(row=3,
                                                                                                column=2,
                                                                                                padx=15,
                                                                                                pady=15)

    Label(window, text='Crypt mode', font="helvetica 15").grid(row=4, column=1, padx=15, pady=15)
    crypt_mode = StringVar()
    crypt_mode.set("CFB")
    OptionMenu(window, crypt_mode, "OFB", "CFB").grid(row=4, column=2, padx=15, pady=15)

    Label(window, text='Chose hash method', font="helvetica 15").grid(row=5, column=1, padx=15, pady=15)
    hash_method = StringVar()
    hash_method.set("sha3_224")
    OptionMenu(window, hash_method, "sha3_224", "sha3_256", "sha3_384", "sha3_512",
               "sha224", "sha256", "sha384", "sha512").grid(row=5, column=2, padx=15, pady=15)

    Label(window, text='Sender private key:', font="helvetica 15").grid(row=6, column=0, padx=15, pady=15)
    private_key_path = StringVar()
    private_key_path.set('keys/sender_private_key.json')
    Entry(window, textvariable=private_key_path, width=30, font="helvetica 15").grid(row=6, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: private_key_path.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=6,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Output file:', font="helvetica 15").grid(row=7, column=0, padx=15, pady=15)
    output_path = StringVar()
    output_path.set('output/seal.json')
    Entry(window, textvariable=output_path, font="helvetica 15", width=30).grid(row=7, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: output_path.set(filedialog.askopenfilename(initialdir='output'))).grid(row=7,
                                                                                                  column=2,
                                                                                                  padx=15,
                                                                                                  pady=15)

    Button(window, text='Generate', font="helvetica 15",
           command=lambda: seal_generator(
               shared_key.get(),
               public_key.get(),
               input_path.get(),
               crypt_mode.get(),
               hash_method.get(),
               private_key_path.get(),
               output_path.get(),
           )).grid(row=9,
                   column=1,
                   padx=15,
                   pady=15)


def open_seal():
    window = Toplevel(root)
    window.title("Open seal")
    window.geometry(f"{str(700)}x{str(600)}")

    Label(window, text='Open seal', font="helvetica 15").grid(row=0, padx=10, pady=40)

    Label(window, text='Reciever private key:', font="helvetica 15").grid(row=2, column=0, padx=15, pady=15)
    private_key_path = StringVar()
    private_key_path.set('keys/reciever_private_key.json')
    Entry(window, textvariable=private_key_path, width=30, font="helvetica 15").grid(row=2, column=1, padx=15, pady=15)
    Button(window, text='Chose', font="helvetica 15",
           command=lambda: private_key_path.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=2,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Sender public key:', font="helvetica 15").grid(row=3, column=0, padx=15, pady=15)
    sender_public_key = StringVar()
    sender_public_key.set('keys/sender_public_key.json')
    Entry(window, textvariable=sender_public_key, width=30, font="helvetica 15").grid(row=3, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: sender_public_key.set(filedialog.askopenfilename(initialdir='keys'))).grid(
        row=3,
        column=2,
        padx=15,
        pady=15)

    Label(window, text='Seal:', font="helvetica 15").grid(row=4, column=0, padx=15, pady=15)
    seal = StringVar()
    seal.set('output/seal.json')
    Entry(window, textvariable=seal, width=30, font="helvetica 15").grid(row=4, column=1, padx=15, pady=15)
    Button(window, text='Choose', font="helvetica 15",
           command=lambda: seal.set(filedialog.askopenfilename(initialdir='output'))).grid(row=4,
                                                                                           column=2,
                                                                                           padx=15,
                                                                                           pady=15)

    Button(window, text='Open', font="helvetica 15",
           command=lambda: seal_open(
               seal.get(),
               private_key_path.get(),
               sender_public_key.get()
           )).grid(row=7,
                   column=1,
                   padx=15,
                   pady=15)


def generate_keys():
    window = Toplevel(root)
    window.title("Generate keys")
    window.geometry(f"{str(450)}x{str(550)}")

    asim = """Generate asym key"""
    Label(window, text=asim, font="helvetica 15").grid(row=1, column=2, padx=15, pady=15)

    Label(window, text='Key length:', font="helvetica 15").grid(row=3, column=2, padx=15, pady=15,
                                                                sticky=E)
    key_size_asim = StringVar()
    key_size_asim.set("2048")
    OptionMenu(window, key_size_asim, "1024", "2048", "3072").grid(row=3, column=3, padx=15, pady=15)

    Button(window, text='Generate', font="helvetica 15",
           command=lambda: RSA_generator(int(key_size_asim.get()))).grid(row=4, column=2, padx=15,
                                                                         pady=30)

    sim = """Generate shared key"""
    Label(window, text=sim, font="helvetica 15").grid(row=5, column=2, padx=15, pady=15)

    Label(window, text='Odabir metode:', font="helvetica 15").grid(row=8, column=2, padx=15, pady=15,
                                                                   sticky=E)
    sym_method = StringVar()
    sym_method.set("AES-128")
    OptionMenu(window, sym_method, "AES-128", "AES-192", "AES-256",
               "3DES-168").grid(row=8, column=3, padx=15, pady=15)

    Button(window, text='Generate', font="helvetica 15",
           command=lambda: sym_key_generator(sym_method.get())).grid(row=9, column=2, padx=15,
                                                                     pady=30)

    Button(window, text='Generate all needed keys', font="helvetica 15",
           command=lambda: all_keys_generator(int(key_size_asim.get()), sym_method.get())).grid(row=12,
                                                                                                column=2,
                                                                                                padx=15,
                                                                                                pady=30)
