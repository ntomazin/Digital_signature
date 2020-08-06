import os
from Crypto.Hash import SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA224, SHA256, SHA384, SHA512
from Crypto.Cipher import AES, DES3


def initialize():
    if not os.path.isdir("keys"):
        print("Creating directory")
        os.mkdir("keys")

    if not os.path.isdir("input"):
        print("Creating directory")
        os.mkdir("input")

    if not os.path.isdir("output"):
        print("Creating directory")
        os.mkdir("output")


def get_hash_object(hash_method_name):
    hashes = {"sha3_224": SHA3_224,
              "sha3_256": SHA3_256,
              "sha3_384": SHA3_384,
              "sha3_512": SHA3_512,
              "sha224": SHA224,
              "sha256": SHA256,
              "sha384": SHA384,
              "sha512": SHA512}
    return hashes[hash_method_name]


def get_crypt_mode(sym_method_name, crypt_mode):
    if "ofb" in crypt_mode.lower():
        return get_sym_method(sym_method_name).MODE_OFB
    return get_sym_method(sym_method_name).MODE_CFB


def get_sym_method(sym_method_name):
    if "aes" in sym_method_name.lower():
        return AES
    else:
        return DES3

def format_output(text, separator=60):
    formated = ""
    for i, char in enumerate(text):
        if i % separator == 0:
            formated += '\n'
        formated += char
    return formated


