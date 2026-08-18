alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# build the tabula recta: a 26x26 matrix, row i = alphabet shifted left by i
def build_table():
    t = []
    for i in range(26):
        row = alphabet[i:] + alphabet[:i]
        t.append(row)
    return t

table = build_table()

# encode function
def enc(L, K):
    l = list(L)
    k = list(K.upper())
    a = []
    n = len(l)
    j = 0  
    for i in range(n):
        c = l[i]
        if c.isupper():
            row = ord(c) - 65
            col = ord(k[j % len(k)]) - 65
            a.append(table[row][col])
            j += 1
        elif c.islower():
            row = ord(c) - 97
            col = ord(k[j % len(k)]) - 65
            a.append(table[row][col].lower())
            j += 1
        else:
            a.append(c)
    r = "".join(a)
    return r

# decode function
def dec(L, K):
    l = list(L)
    k = list(K.upper())
    a = []
    n = len(l)
    j = 0
    for i in range(n):
        c = l[i]
        if c.isupper():
            row = ord(k[j % len(k)]) - 65
            col = table[row].index(c)
            a.append(alphabet[col])
            j += 1
        elif c.islower():
            row = ord(k[j % len(k)]) - 65
            col = table[row].index(c.upper())
            a.append(alphabet[col].lower())
            j += 1
        else:
            a.append(c)
    r = "".join(a)
    return r


#  program running
def run():
    f = input("hi this is vigenere cipher encoder/decoder \n to use : \n encode mode enter 0 \n decode mode enter 1\n")
    if f == "0":
        print("good welcome to encoder mode to exit enter (0,0)")
        e = ("1", "1")
        while e != ("0", "0"):
            e1 = input("enter word : ")
            e2 = input("enter key : ")
            e = (e1, e2)
            print(f"result : {enc(e[0], e[1])}")
    elif f == "1":
        print("good welcome to decoder mode to exit enter (0,0)")
        e = ("1", "1")
        while e != ("0", "0"):
            e1 = input("enter word : ")
            e2 = input("enter key : ")
            e = (e1, e2)
            print(f"result : {dec(e[0], e[1])}")
    else:
        run()
    return

run()
