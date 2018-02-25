import string
import random

low = string.ascii_lowercase
num = string.digits
sym = string.punctuation
up = string.ascii_uppercase

catList = [low,num,sym,up]

pswList = []

ch = 0
used = 0
i = 0
y = 0
d = 0
c = 0

def main():
    while c < 4:
        y = random.randint(0,3)
        used = catList[y]
        catSel()
        
    print(pswList)
    
def catSel():
    global c
    c = c + 1
    if used == 'low':
        lowch()
    elif used == 'num':
        numch()
    elif used == 'sym':
        symch()
    else:
        upch()


def lowch():
        i = random.randint(0,26)
        lowch = low[i]
        pswList.append(lowch)
        
def numch():
        i = random.randint(0,10)
        numch = num[i]
        pswList.append(numch)
        
def symch():
        i = random.randint(0,32)
        symch = sym[i]
        pswList.append(symch)
        
def upch():
        i = random.randint(0,26)
        upch = up[i]
        pswList.append(upch)



main()
