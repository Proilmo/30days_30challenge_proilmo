# hex table used for manual conversion (no built-in hex()/format tricks)
HEXCHARS = "0123456789abcdef"

# encode function

def enc(L):
    l = list(L)
    a = []
    n = len(l)
    for i in range(n):
        c = l[i]
        v = ord(c)
        high = v // 16
        low = v % 16
        a.append(HEXCHARS[high])
        a.append(HEXCHARS[low])
    r = "".join(a)
    return r

# decode function

def dec(H):
    h = H.lower()
    a = []
    n = len(h)
    if n % 2 != 0:
        print("error : hex string must have an even length")
        return ""
    for i in range(0, n, 2):
        pair = h[i:i+2]
        try:
            high = HEXCHARS.index(pair[0])
            low = HEXCHARS.index(pair[1])
        except ValueError:
            print("error : invalid hex character in input")
            return ""
        v = high * 16 + low
        a.append(chr(v))
    r = "".join(a)
    return r

# program running

def run():
    f = input("hi this is hex encoder/decoder \n to use : \n encode mode enter 0 \n decode mode enter 1\n")
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
            e = input("enter hex : ")
            if e != "0":
                print(f"result : {dec(e)}")
    else:
        run()
    return

run()
