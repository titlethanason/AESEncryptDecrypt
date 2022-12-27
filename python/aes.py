import hashlib
import sys
import Random
from Cipher import AES


def _read_file(filename):
    f = open(filename, "r")
    return f.read()


def _pad(unpadded_text):
    number_of_bytes_to_pad = AES.block_size - len(unpadded_text) % AES.block_size
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_text = unpadded_text + padding_str
    return padded_text


def _unpad(padded_text):
    padding_length = padded_text[len(padded_text) - 1:]
    return padded_text[:-ord(padding_length)]


def _get_sha256_encrypt(secret):
    return hashlib.sha256(secret.encode()).digest()


def encrypt(secret, raw_text):
    key = _get_sha256_encrypt(secret)
    padded_text = _pad(raw_text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_text.encode())
    print((iv + ciphertext).hex())


def decrypt(secret, encrypted_text):
    key = _get_sha256_encrypt(secret)
    encrypted_text = bytes.fromhex(encrypted_text)
    iv = encrypted_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = cipher.decrypt(encrypted_text[AES.block_size:]).decode("utf-8")
    print(_unpad(plain_text))


def main(argv):
    secret = _read_file('secret.txt')
    input_text = _read_file('input.txt')
    if len(argv) == 2 and argv[1] == "encrypt":
        encrypt(secret, input_text)
    elif len(argv) == 2 and argv[1] == "decrypt":
        decrypt(secret, input_text)
    else:
        print("Encryption: put raw text in input.txt and secret in secret.txt")
        print("            then 'python aes.py encrypt'")
        print("Decryption: put encrypted text (hex) in input.txt and secret in secret.txt")
        print("            then 'python aes.py decrypt'")


if __name__ == '__main__':
    main(sys.argv)
