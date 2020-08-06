from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os
import base64
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from writers import *
from utils import *
from tkinter import messagebox

keys_folder = "keys/"

#Ovisno je li des ili aes porekce generiranje kljuca
def sym_key_generator(method: str):
    method = method.split("-")
    if method[0] in "3DES":
        print(f"Generating 3DES key with length {method[1]}")
        DES_generator(key_length=int(method[1]))
    else:
        print(f"Generating AES key with length {method[1]}")
        AES_generator(key_length=int(method[1]))


#Generira kljuce za AES
def AES_generator(key_length, path="keys/shared_key.json"):
    secret_key = os.urandom(key_length // 8)
    encoded_secret_key = base64.b64encode(secret_key)
    simple_writer(data={"Description": "Secret Key",
                        "Method": "AES" + str(key_length),
                        "Key length": key_length,
                        "Key": encoded_secret_key.decode("ascii")
                        },
                  path=path)
    messagebox.showinfo(f"AES{key_length}", f"Generated shared key to {path}")

#Generira kljuce za DES
def DES_generator(key_length, path="keys/shared_key.json"):
    secret_key = DES3.adjust_key_parity(get_random_bytes(24))
    encoded_secret_key = base64.b64encode(secret_key)
    simple_writer(data={"Description": "Secret Key",
                        "Method": "DES3",
                        "Key length": key_length // 8,
                        "Key": encoded_secret_key.decode("ascii")
                        },
                  path=path)
    messagebox.showinfo(f"DES{key_length}", f"Generated shared key to {path}")


#metoda za generiranje svih potrebnih kljuceva odjednom
def all_keys_generator(key_length, method):
    RSA_generator(key_length, path_priv="keys/sender_private_key.json", path_pub="keys/sender_public_key.json")
    RSA_generator(key_length, path_priv="keys/reciever_private_key.json", path_pub="keys/reciever_public_key.json")
    sym_key_generator(method)


def RSA_generator(key_length, path_priv="keys/private_key.json", path_pub="keys/public_key.json"):
    random_generator = Random.new().read
    key = RSA.generate(key_length, random_generator)
    encoded_priv_key = base64.b64encode(key.export_key())
    encoded_pub_key = base64.b64encode(key.publickey().export_key())

    simple_writer(data={"Description": "Private key",
                        "Method": "RSA",
                        "Key length": key_length,
                        "Key": encoded_priv_key.decode("ascii")
                        },
                  path=path_priv)

    simple_writer(data={"Description": "Public key",
                        "Method": "RSA",
                        "Key length": key_length,
                        "Key": encoded_pub_key.decode("ascii")
                        },
                  path=path_pub)

    messagebox.showinfo("RSA", f"Generated public and private key to {path_priv} and {path_pub}")


def signature_generator(private_key_path, input_path, output_path, hash_method_name):
    hash_object = get_hash_object(hash_method_name)
    key = base64.b64decode(simple_reader(private_key_path, "Key").encode("ascii"))
    private_key = RSA.import_key(key)

    method = simple_reader(private_key_path, "Method")
    key_length = int(simple_reader(private_key_path, "Key length"))

    input = read_from_file(input_path)
    hash = hash_object.new(input.encode("ascii")) #generiranje hasha od inputa

    signature = pkcs1_15.new(private_key).sign(hash)
    encoded_signature = base64.b64encode(signature)
    simple_writer(data={"Description": "Signature",
                        "Input": input,
                        "Hash method": hash_method_name,
                        "Method": method,
                        "Key length": key_length,
                        "Signature": encoded_signature.decode("ascii")
                        },
                  path=output_path)
    messagebox.showinfo("Digital Signature", f"Digital signature saved to {output_path}")


def signature_verify(input_path, public_key_path, signature_path):
    hash_object = get_hash_object(simple_reader(signature_path, "Hash method"))
    key = base64.b64decode(simple_reader(public_key_path, "Key").encode("ascii"))
    public_key = RSA.import_key(key)

    input = read_from_file(input_path)
    hash = hash_object.new(input.encode("ascii")) #generiranje hasha od inputa

    signature = base64.b64decode(simple_reader(signature_path, "Signature").encode("ascii"))

    try:
        pkcs1_15.new(public_key).verify(hash, signature) #provjera je li potpis validan ili ne
        messagebox.showinfo("Digital signature", f"Valid signature")
    except (ValueError, TypeError) as e:
        messagebox.showinfo("Digital signature", f"Invalid signature")


def evelope_generator(sim_key_path, rec_pub_key, input_path, crypt_mode_name, output_path):
    sim_key = base64.b64decode(simple_reader(sim_key_path, "Key"))
    sym_method_name = simple_reader(sim_key_path, "Method")
    crypt_mode = get_crypt_mode(sym_method_name, crypt_mode_name)
    sym_method = get_sym_method(sym_method_name)
    sym_key_len = simple_reader(sim_key_path, "Key length")

    input = read_from_file(input_path)
    iv = Random.new().read(sym_method.block_size) #stvaranje inicijalizacijskog vektora
    cipher = sym_method.new(sim_key, crypt_mode, iv)
    envelope_data = base64.b64encode(cipher.encrypt(input.encode("ascii"))) #stvaranje kriptiranog bloka simetricnim kljucem

    public_key = RSA.import_key(base64.b64decode(simple_reader(rec_pub_key, "Key").encode("ascii")))
    asym_method = simple_reader(rec_pub_key, "Method")
    pub_key_len = simple_reader(rec_pub_key, "Key length")
    cipher = PKCS1_OAEP.new(public_key)
    envelope_key = base64.b64encode(cipher.encrypt(sim_key))#kripritranje simetricnog kljuca asimetricnim

    simple_writer(data={"Description": "Envelope",
                        "Input": input,
                        "Output": output_path,
                        "Symmetric method": sym_method_name,
                        "Asymmetric method": asym_method,
                        "Crypt mode": crypt_mode_name,
                        "Initialization vector": base64.b64encode(iv).decode("ascii"),
                        "Sym key length": sym_key_len,
                        "Asym key length": pub_key_len,
                        "Envelope data": envelope_data.decode("ascii"),
                        "Envelope key": envelope_key.decode("ascii")
                        },
                  path=output_path)
    messagebox.showinfo("Digital Envelope", f"Digital envelope saved to {output_path}")


def envelope_open(envelope_path, rec_priv_key):
    try:
        private_key = RSA.import_key(base64.b64decode(simple_reader(rec_priv_key, "Key").encode("ascii")))
        sym_method_name = simple_reader(envelope_path, "Symmetric method")
        sym_method = get_sym_method(sym_method_name)

        crypt_key = base64.b64decode(simple_reader(envelope_path, "Envelope key").encode("ascii"))
        crypt_data = base64.b64decode(simple_reader(envelope_path, "Envelope data").encode("ascii"))

        iv = base64.b64decode(simple_reader(envelope_path, "Initialization vector").encode("ascii"))
        crypt_mode = get_crypt_mode(sym_method_name, simple_reader(envelope_path, "Crypt mode"))

        cipher = PKCS1_OAEP.new(private_key) #asimetricna dekripcija
        sym_key = cipher.decrypt(crypt_key) # dohvacanje simetricnog kljuca

        cipher = sym_method.new(sym_key, crypt_mode, iv)
        message = cipher.decrypt(crypt_data) #dobivanje poruke iz envelope data preko simetricnog kljuca

        messagebox.showinfo("Digital Envelope", f"Message is: {message.decode('ascii')}")
    except:
        messagebox.showerror("Digital Envelope", f"Wrong inputs")
        return


def seal_generator(sim_key_path, rec_pub_key, input_path, crypt_mode_name, hash_method_name,
                   sender_priv_key_path, output_path):
    #dio iz omotnice
    sim_key = base64.b64decode(simple_reader(sim_key_path, "Key"))
    sym_method_name = simple_reader(sim_key_path, "Method")
    crypt_mode = get_crypt_mode(sym_method_name, crypt_mode_name)
    sym_method = get_sym_method(sym_method_name)
    sym_key_len = simple_reader(sim_key_path, "Key length")

    input = read_from_file(input_path)
    iv = Random.new().read(sym_method.block_size)
    cipher = sym_method.new(sim_key, crypt_mode, iv)
    envelope_data = base64.b64encode(cipher.encrypt(input.encode("ascii")))

    public_key = RSA.import_key(base64.b64decode(simple_reader(rec_pub_key, "Key").encode("ascii")))
    asym_method = simple_reader(rec_pub_key, "Method")
    pub_key_len = simple_reader(rec_pub_key, "Key length")
    cipher = PKCS1_OAEP.new(public_key)
    envelope_key = base64.b64encode(cipher.encrypt(sim_key))

    #dio iz potpisa
    hash_object = get_hash_object(hash_method_name)
    key = base64.b64decode(simple_reader(sender_priv_key_path, "Key").encode("ascii"))
    sender_private_key = RSA.import_key(key)

    key_and_data = envelope_key + envelope_data # hashiram konkateniran envelope key i envelope data
    hash = hash_object.new(key_and_data)

    signature = pkcs1_15.new(sender_private_key).sign(hash)
    encoded_signature = base64.b64encode(signature)

    simple_writer(data={"Description": "Seal",
                        "Input": input,
                        "Output": output_path,
                        "Symmetric method": sym_method_name,
                        "Asymmetric method": asym_method,
                        "Crypt mode": crypt_mode_name,
                        "Initialization vector": base64.b64encode(iv).decode("ascii"),
                        "Sym key length": sym_key_len,
                        "Asym key length": pub_key_len,
                        "Envelope data": envelope_data.decode("ascii"),
                        "Envelope key": envelope_key.decode("ascii"),
                        "Hash method": hash_method_name,
                        "Signature": encoded_signature.decode("ascii")
                        },
                  path=output_path)
    messagebox.showinfo("Digital Seal", f"Digital seal saved to {output_path}")


def seal_open(seal_path, rec_priv_key_path, sen_pub_key_path):
    try:
        #dio iz omotnice
        private_key = RSA.import_key(base64.b64decode(simple_reader(rec_priv_key_path, "Key").encode("ascii")))
        sym_method_name = simple_reader(seal_path, "Symmetric method")
        sym_method = get_sym_method(sym_method_name)

        crypt_key = base64.b64decode(simple_reader(seal_path, "Envelope key").encode("ascii"))
        crypt_data = base64.b64decode(simple_reader(seal_path, "Envelope data").encode("ascii"))

        iv = base64.b64decode(simple_reader(seal_path, "Initialization vector").encode("ascii"))
        crypt_mode = get_crypt_mode(sym_method_name, simple_reader(seal_path, "Crypt mode"))

        cipher = PKCS1_OAEP.new(private_key)
        sym_key = cipher.decrypt(crypt_key)

        cipher = sym_method.new(sym_key, crypt_mode, iv)
        message = cipher.decrypt(crypt_data).decode("ascii")

        #dio iz potpisa
        hash_object = get_hash_object(simple_reader(seal_path, "Hash method"))
        key = base64.b64decode(simple_reader(sen_pub_key_path, "Key").encode("ascii"))
        public_key = RSA.import_key(key)

        key_and_data = base64.b64encode(crypt_key) + base64.b64encode(crypt_data)
        hash = hash_object.new(key_and_data)

        signature = base64.b64decode(simple_reader(seal_path, "Signature").encode("ascii"))
    except:
        messagebox.showerror("Digital Seal", f"Wrong inputs")
        return

    try:
        pkcs1_15.new(public_key).verify(hash, signature)
        messagebox.showinfo("Digital Seal", f"Valid message: {message}")
    except (ValueError, TypeError) as e:
        messagebox.showinfo("Digital Seal", f"Invalid message: {message}")
