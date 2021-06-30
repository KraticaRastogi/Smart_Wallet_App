import base64
import os
from tkinter import Tk, CENTER, ttk

from Crypto import Random
from Crypto.Cipher import AES

path = "C:/Users/Kratica Rastogi/PycharmProjects/Cryptography/Assignment_3_Cryptography/txt_files/"

Bank_secret_key = 'F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893'
KBank = Bank_secret_key.ljust(len(Bank_secret_key) + (16 - (len(Bank_secret_key) % 16)))[:32]

WIDa = hex(5926)[2:].zfill(8)
WIDb = hex(4321)[2:].zfill(8)
amount = hex(0)[2:].zfill(8)
counter = hex(0)[2:].zfill(8)

gen_token_ab = WIDa + WIDb + amount + counter
gen_token_ba = WIDb + WIDa + amount + counter


def registering_wallet_a_to_b():
    window = Tk()
    window.option_add('*Font', 'Helvetica 10')

    window.title('Token_Gen_Xab')

    lb1 = ttk.Label(window, text="Xab token:")
    lb1.place(x=10, y=70)

    btn = ttk.Button(window, text="Token_Xab",
                     command=lambda: [generate_token_xab(raw=gen_token_ab, label=lb1, bank_key=KBank)])
    btn.place(relx=0.5, rely=0.5, anchor=CENTER)

    window.geometry("985x300")
    return window


def registering_wallet_b_to_a():
    window = Tk()
    window.option_add('*Font', 'Helvetica 10')

    window.title('Token_Gen_Xba')

    lb1 = ttk.Label(window, text="Xba token:")
    lb1.place(x=10, y=70)

    btn = ttk.Button(window, text="Token_Xba",
                     command=lambda: [generate_token_xba(raw=gen_token_ba, label=lb1, bank_key=KBank)])
    btn.place(relx=0.5, rely=0.5, anchor=CENTER)

    window.geometry("985x300")
    return window


def generate_token_xab(raw, label, bank_key):
    """
    This method will encrypt the block and generate the token using aes-256
    :param raw: amount in string format
    :param label:
    :param bank_key: wallet secret key to encrypt the amount
    :return: token generated
    """

    # getting random bits of initialization vector
    iv = Random.new().read(AES.block_size)
    # encrypting using cbc mode of aes-256
    cipher = AES.new(bytes.fromhex(bank_key), AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(raw))
    # token generated in hexadecimal format
    encrypted_token_xab = encrypted.hex()

    if label is not None and label["text"] is not None and label["text"] is not "" and encrypted_token_xab is not None:
        label.config(text="Xab token: %s" % encrypted_token_xab)
    if not os.path.exists(path + "register_WalletA_to_B_record.txt") or os.stat(
            path + "register_WalletA_to_B_record.txt").st_size == 0:
        file = open(path + "register_WalletA_to_B_record.txt", 'w')
        file.write(str(5926) + "\n" + str(1) + "\t" + str(encrypted_token_xab))
        file.close()
    else:
        with open(path + "register_WalletA_to_B_record.txt", "r") as f:
            ctr = (f.readlines()[-1:])
            ctr = int(ctr[-1].split(sep='\t')[0]) + 1
            file = open(path + "register_WalletA_to_B_record.txt", 'a')
            file.write("\n" + str(ctr) + "\t" + str(encrypted_token_xab))
            file.close()
    return encrypted_token_xab


def generate_token_xba(raw, label, bank_key):
    """
    This method will encrypt the block and generate the token using aes-256
    :param raw: amount in string format
    :param label:
    :param bank_key: wallet secret key to encrypt the amount
    :return: token generated
    """

    # getting random bits of initialization vector
    iv = Random.new().read(AES.block_size)
    # encrypting using cbc mode of aes-256
    cipher = AES.new(bytes.fromhex(bank_key), AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(raw))
    # token generated in hexadecimal format
    encrypted_token_xba = encrypted.hex()

    if label is not None and label["text"] is not None and label["text"] is not "" and encrypted_token_xba is not None:
        label.config(text="Xba token: %s" % encrypted_token_xba)
    if not os.path.exists(path + "register_WalletB_to_A_record.txt") or os.stat(
            path + "register_WalletB_to_A_record.txt").st_size == 0:
        file = open(path + "register_WalletB_to_A_record.txt", 'w')
        file.write(str(4321) + "\n" + str(1) + "\t" + str(encrypted_token_xba))
        file.close()
    else:
        with open(path + "register_WalletB_to_A_record.txt", "r") as f:
            ctr = (f.readlines()[-1:])
            ctr = int(ctr[-1].split(sep='\t')[0]) + 1
            file = open(path + "register_WalletB_to_A_record.txt", 'a')
            file.write("\n" + str(ctr) + "\t" + str(encrypted_token_xba))
            file.close()
    return encrypted_token_xba


if __name__ == '__main__':
    w1 = registering_wallet_a_to_b()
    w2 = registering_wallet_b_to_a()
    w1.mainloop()
    w2.mainloop()
