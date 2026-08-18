# base64 alphabet (64 characters used to represent 6 bits at a time)
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# reverse lookup : character -> its index in ALPHA
REV = {}
for i in range(64):
    REV[ALPHA[i]] = i

# encode function

def enc(L):
    l = list(L)
    a = []
    n = len(l)
    i = 0
    while i < n:
        b1 = ord(l[i])
        b2 = ord(l[i+1]) if i+1 < n else 0
        b3 = ord(l[i+2]) if i+2 < n else 0

        c = (b1 << 16) | (b2 << 8) | b3

        c1 = (c >> 18) & 63
        c2 = (c >> 12) & 63
        c3 = (c >> 6) & 63
        c4 = c & 63

        a.append(ALPHA[c1])
        a.append(ALPHA[c2])
        a.append(ALPHA[c3] if i+1 < n else "=")
        a.append(ALPHA[c4] if i+2 < n else "=")

        i += 3
    r = "".join(a)
    return r

# decode function

def dec(L):
    p = L.count("=")
    l = L.rstrip("=")
    a = []
    n = len(l)
    i = 0
    while i < n:
        i1 = REV[l[i]]
        i2 = REV[l[i+1]]
        i3 = REV[l[i+2]] if i+2 < n else 0
        i4 = REV[l[i+3]] if i+3 < n else 0

        c = (i1 << 18) | (i2 << 12) | (i3 << 6) | i4

        b1 = (c >> 16) & 255
        b2 = (c >> 8) & 255
        b3 = c & 255

        a.append(chr(b1))
        a.append(chr(b2))
        a.append(chr(b3))

        i += 4
    r = "".join(a)
    if p > 0:
        r = r[:-p]
    return r

#  program running
def run():
    f = input("hi this is base64 encoder/ decoder \n to use : \n encode mode enter 0 \n decode mode enter 1\n")
    if f == "0":
        print("good welcome to encoder mode to exit enter 0")
        e = "1"
        while e != "0":
            e = input("enter word : ")
            if e != "0":
                print(f"result : {enc(e)}")
    elif f == "1":
        print("good welcome to decoder mode to exit enter 0")
        e = "1"
        while e != "0":
            e = input("enter word : ")
            if e != "0":
                print(f"result : {dec(e)}")
    else:
        run()
    return

run()
