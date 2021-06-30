import base64
import hashlib
import os
from tkinter import ttk, Tk, CENTER
from Crypto import Random
from Crypto.Cipher import AES

path = "C:/Users/Kratica Rastogi/PycharmProjects/Cryptography/Assignment_3_Cryptography/txt_files/"

student_id = str(2075926)
# amount to get funds from bank

amount = hex(2000)[2:].zfill(32)

def receive_funds_from_bank():
    """
    This method is used to get the tkinter window UI to get funds from bank
    :return: window
    """
    window = Tk()
    window.option_add('*Font', 'Helvetica 13')

    window.title('Receive_funds_from_Bank')

    # create label for EMD
    lb1 = ttk.Label(window, text="EMD:")
    lb1.place(x=30, y=70)
    # create label for Updated Balance
    lb2 = ttk.Label(window, text="Updated Balance:")
    lb2.place(x=30, y=100)

    # create text box for EMD
    entry = ttk.Entry(window, width=40)
    entry.place(x=80, y=70)

    btn = ttk.Button(window, text="Submit",
                     command=lambda: [decrypt_wallet_amount(text_box=entry, label=lb2, key=generate_hash(student_id))])
    btn.place(relx=0.5, rely=0.5, anchor=CENTER)

    window.geometry("475x300")
    return window


def generate_hash(seed):
    """
    This method will generate an SHA2 hash on supplied key
    :param seed: string to generate hash
    :return: wallet secret key in string
    """
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def encrypt_wallet_amount(raw, key):
    """
    This method will encrypt (using aes-256) the receiving funds from the bank
    :param raw: amount in string format
    :param key: wallet secret key to encrypt the amount
    :return: encrypted amount or electronic money draft
    """
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(raw))
    encrypted = encrypted.hex()
    print("Electronic Money Draft:", encrypted)
    return encrypted


def decrypt_wallet_amount(text_box, label, key):
    """
    This method will decrypt (using aes-256) the amount received from the bank
    :param text_box: Electronic Money draft or amount encrypted in hexadecimal form
    :param label: updating balance value to label
    :param key: wallet secret key to decrypt the amount
    :return: Updated balance in plain text
    """
    enc = text_box.get()
    enc = base64.b64decode(bytes.fromhex(enc))
    iv = enc[:16]
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, iv)
    decrypted = int(str(cipher.decrypt(enc[16:])).replace('b', '').replace("'", ''), 16)

    # Receiving amount from bank in A's wallet

    # check if wallet A's balance file is empty
    if not os.path.exists(path + "balanceWallet_A.txt") or os.stat(
            path + "balanceWallet_A.txt").st_size == 0:
        file = open(path + "balanceWallet_A.txt", 'w')
        file.write(str(0))
        file.close()

    # read the current balance and add new amount to it in A's wallet
    balance = int(open(path + "balanceWallet_A.txt", "r").read())
    updated_balance = balance + int(decrypted)

    file = open(path + "balanceWallet_A.txt", 'w')
    file.write(str(updated_balance))
    file.close()
    if label is not None and label["text"] is not None and label["text"] is not "" and updated_balance is not None:
        label.config(text="Updated Balance: %d" % updated_balance)
    return updated_balance


if __name__ == '__main__':
    hash = generate_hash(student_id)
    encrypt_wallet_amount(amount, hash)
    w1 = receive_funds_from_bank()
    w1.mainloop()
