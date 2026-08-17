# encode function 

def enc(L ,p):
    l = list(L)
    a = []
    n = len(l)
    for i in range(n):
        c = l[i]
        if c.isupper():
            a.append(chr((ord(c)-65+int(p))%26+65))
        elif c.islower():
            a.append(chr((ord(c)-97+int(p))%26+97))
        else:
            a.append(c)
    r = "".join(a)
    return r

# decode function

def dec(L,p):
    return enc(L,-p)
# got it from a git repo 
common = set(open("C:/Users/PC/Downloads/words_alpha.txt").read().split())

def crack(L):
    best = 0
    bp = 0
    br = L
    for p in range(26):
        r = dec(L,p)
        words = r.lower().split()
        score = 0
        for w in words:
            if w in common:
                score += 1
        if score > best:
            best = score
            bp = p
            br = r
    return (br,bp)

#  program running
def run():
    f = input("hi this is cipher cipher encoder/ decoder \n to use : \n encode    mode enter 0 \n decode mode enter 1 \n crack mode enter 2\n")
    if f == "0":
        print("good welcome to encoder mode to exit enter (0,0)")
        e = ("1",1)
        while e != ("0",0):
            e1   =  input("enter word : ")
            e2 = int(input("enter shift : \n"))
            e = (e1,e2)
            print(f"result : {enc(e[0],e[1])}")
    elif f=="1":
        print("good welcome to decoder mode to exit enter (0,0)")
        e = ("1",1)
        while e != ("0",0):
            e1   =  input("enter word : ")
            e2 = int(input("enter shift : "))
            e = (e1,e2)
            print(f"result : {dec(e[0],e[1])}")
    elif f=="2":
        print("good welcome to crack mode to exit enter 0")
        e1 = input("enter word : ")
        while e1 != "0":
            br,bp = crack(e1)
            print(f"result : {br} shift : {bp}")
            e1 = input("enter word : ")
    else : 
        run()
    return

run()

