import base64
import os
from tkinter import Tk, ttk

from Crypto import Random
from Crypto.Cipher import AES

path = "C:/Users/Kratica Rastogi/PycharmProjects/Cryptography/Assignment_3_Cryptography/txt_files/"

# An AES 256 bit key issued by the Bank. Used to transfer funds between wallets
KBank = 'F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893'

# A unique number identifying the Wallet A's instance
WIDa = hex(5926)[2:].zfill(8)


def Wallet_A():
    """
    This method is used to get the tkinter window UI of wallet A
    :return: window
    """
    window = Tk()
    window.option_add('*Font', 'Helvetica 13')

    window.title('Sending Funds')

    # create label for Amount
    lb1 = ttk.Label(window, text="Amount:")
    lb1.place(x=10, y=70)
    # create label for Wallet-ID of B
    lb2 = ttk.Label(window, text="Receiver's Wallet ID:")
    lb2.place(x=10, y=120)
    # create label for balance of A's wallet
    lb3 = ttk.Label(window, text="Sender's Wallet Balance:")
    lb3.place(x=10, y=170)
    # create label for Token generated
    lb4 = ttk.Label(window, text="X token:")
    lb4.place(x=10, y=220)

    # create text box for Amount to transfer
    entry1 = ttk.Entry(window, width=40)
    entry1.place(x=200, y=70)
    # create text box for Wallet ID of B
    entry2 = ttk.Entry(window, width=40)
    entry2.place(x=200, y=120)

    btn = ttk.Button(window, text="Submit",
                     command=lambda: [
                         encrypted_generate_token_x(text_box1=entry1, text_box2=entry2, label1=lb3, label2=lb4,
                                                    bank_key=KBank)])
    btn.place(x=350, y=300)

    window.geometry("800x400")
    return window


def encrypted_generate_token_x(text_box1, text_box2, label1, label2, bank_key):
    """
    This method will encrypt the block and generate the token using aes-256
    :param text_box1: amount which needs to send to receiver
    :param text_box2: wallet id of receiver
    :param label1: Remaining balance of wallet A
    :param label2: Token generated Xab by wallet A
    :param bank_key: An AES 256 bit key issued by the Bank which is used to transfer funds between wallets
    :return: token generated
    """
    amount = text_box1.get()
    # insert the amount received in B's wallet
    if not os.path.exists(path + "balanceWallet_B.txt"):
        file = open(path + "balanceWallet_B.txt", 'w')
        file.write(str(amount))
    else:
        balance_B = open(path + "balanceWallet_B.txt", "r").read()
        updated_balance_B = balance_B + amount
        file = open(path + "balanceWallet_B.txt", 'w')
        file.write(str(updated_balance_B))
    file.close()

    wallet_id_b = text_box2.get()
    # convert the B's wallet id in hexadecimal form with 8 bits
    wallet_id_b = hex(int(wallet_id_b))[2:].zfill(8)

    # reading balance amount from A's wallet and writing the remaining balance left after transferring the funds
    balance = int(open(path + "balanceWallet_A.txt", "r").read())
    remaining_balance = balance - int(amount)
    file = open(path + "balanceWallet_A.txt", 'w')
    file.write(str(remaining_balance))
    file.close()
    if label1 is not None and label1["text"] is not None and label1["text"] is not "" and remaining_balance is not None:
        label1.config(text="Remaining Balance: %d" % remaining_balance)

    # getting random bits of initialization vector
    iv = Random.new().read(AES.block_size)
    # encrypting using cbc mode of aes-256
    cipher = AES.new(bytes.fromhex(bank_key), AES.MODE_CBC, iv)

    # convert the amount in hexadecimal form with 8 bits
    amount = hex(int(amount))[2:].zfill(8)

    # create wallet A's record or check the size
    # and set counter value associated with wallet id of B to zero to generate token
    with open(path + "register_WalletB_to_A_record.txt", "r") as f:
        line = (f.readlines()[-1:])
        ctr = int(line[-1].split(sep='\t')[0])
        ctr = hex(int(ctr))[2:].zfill(8)

        # structure of block
        raw = (WIDa + wallet_id_b + amount + ctr)
        encrypted = base64.b64encode(iv + cipher.encrypt(raw))

        # token generated in hexadecimal format
        encrypted_token_x = encrypted.hex()

        if label2 is not None and label2["text"] is not None and label2[
            "text"] is not "" and encrypted_token_x is not None:
            label2.config(text="X token: %s" % encrypted_token_x)

    # reading last counter value from register_WalletB_to_A_record table
    with open(path + "register_WalletB_to_A_record.txt", "r") as f:
        ctr = (f.readlines()[-1:])
        ctr = int(ctr[-1].split(sep='\t')[0]) + 1
        file = open(path + "register_WalletB_to_A_record.txt", 'a')
        file.write("\n" + str(ctr) + "\t" + str(encrypted_token_x))
        file.close()

    return encrypted_token_x


if __name__ == '__main__':
    w1 = Wallet_A()
    w1.mainloop()
