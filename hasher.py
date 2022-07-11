from rich import *
from rich.console import Console
from time import *
from rich.tree import Tree
from rich.table import Table
from hashlib import *
from rich.prompt import Prompt
import os

# list to store txt files
res = []
# os.walk() returns subdirectories, file from current directory and 
# And follow next directory from subdirectory list recursively until last directory
for root, dirs, files in os.walk(r"wordlists"):
    for file in files:
        if file.endswith(".txt"):
            res.append(file)


console = Console()

try:
    userGive = Prompt.ask('[bold][green]Enter Hash')
    algos = ['sha256', 'blake2s', 'sha3_224', 'sha224', 'sha1', 'md5', 'sha3_256', 'shake_256', 'sha512', 'blake2b', 'shake_128', 'sha3_384', 'sha384', 'sha3_512']

    algt = Table(title="Algorithms Available")
    algt.add_column("S. No.", style="cyan", no_wrap=True)
    algt.add_column("Algorithm" , style="magenta")
    for algo in algos:
        algt.add_row(str(algos.index(algo)), algo)

    console.print(algt)
    useAlgo = Prompt.ask('[bold][green]Enter Hashing Algorithm')


    def setAlgx(code):
        if code == 0:
            return "sha256"
        elif code == 1:
            return "blake2s"
        elif code == 2:
            return "sha3_224"
        elif code == 3:
            return "sha224"
        elif code == 4:
            return "sha1"
        elif code == 5:
            return "md5"
        elif code == 6:
            return "sha3_256"
        elif code == 7:
            return "shake_256"
        elif code == 8:
            return "sha512"
        elif code == 9:
            return "blake2b"
        elif code == 10:
            return "shake_128"
        elif code == 11:
            return "sha3_384"
        elif code == 12:
            return "sha384"
        elif code == 13:
            return "sha3_512"
        else:
            return "Stopped Due To Error"

    def algo(code, pwords):
        if code == 0:
            return sha256(pwords.encode('utf-8')).hexdigest()
        elif code == 1:
            return blake2s(pwords.encode('utf-8')).hexdigest()
        elif code == 2:
            return sha3_224(pwords.encode('utf-8')).hexdigest()
        elif code == 3:
            return sha224(pwords.encode('utf-8')).hexdigest()
        elif code == 4:
            return sha1(pwords.encode('utf-8')).hexdigest()
        elif code == 5:
            return md5(pwords.encode('utf-8')).hexdigest()
        elif code == 6:
            return sha3_256(pwords.encode('utf-8')).hexdigest()
        elif code == 7:
            return shake_256(pwords.encode('utf-8')).hexdigest(64)
        elif code == 8:
            return sha512(pwords.encode('utf-8')).hexdigest()
        elif code == 9:
            return blake2b(pwords.encode('utf-8')).hexdigest()
        elif code == 10:
            return shake_128(pwords.encode('utf-8')).hexdigest(64)
        elif code == 11:
            return sha3_384(pwords.encode('utf-8')).hexdigest()
        elif code == 12:
            return sha384(pwords.encode('utf-8')).hexdigest()
        elif code == 13:
            return sha3_512(pwords.encode('utf-8')).hexdigest()
        else:
            return "WrongHashSelectedError"   

    Algx = setAlgx(int(useAlgo))

    def SpitHash(index, password, hashed, match):
        fin = "Not-Matched"
        if(match == "true"):
            fin = "Matched"
        print(f"[[cyan]{index}[/cyan]] [magenta]{password}[/magenta] : [green]{hashed}[/green]({fin})")


    tree = Tree("wordlists")
    for file in res:
        with console.status(f"[bold green]Fetching data from [blue]{file}[/blue]") as status:
            lent = str(sum(1 for line in open(f'wordlists/{file}', 'r', encoding='latin-1')))
            if len(lent)>0 and len(lent)<=5:
                lens = f"[green]{lent}[/green]"
            elif len(lent)> 5 and len(lent)<=7:
                lens = f"[yellow]{lent}[/yellow]"
            elif len(lent)> 7:
                lens = f"[red]{lent}[/red]"
            tree.add(f"{file} ([blue]Passwords[/blue] : {lens})")


    print(tree)

    chooseFiles = Prompt.ask("[bold green]Choose Wordlist (Enter Correct Name [e.g: all.txt])")
    chosen = "wordlists/"+chooseFiles

    lines = []

    with open(chosen, 'r', encoding="latin-1") as f:
        lines = f.read().splitlines()

    i = 1

    def matchF(opt, value):
        if opt == "true":
            print('[green]Match Found[/green] : [magenta]'+str(value)+'[/magenta]')
        else:
            print('[red]Match Not Found[/red]')

    mfOpt = ""
    mfVal = ""

    for pwords in lines:

        hashed = algo(int(useAlgo), pwords)
        if hashed == userGive :
            SpitHash(str(i), str(pwords), str(hashed), "true")
            mfOpt = "true"
            mfVal = str(pwords)
            break
        elif hashed == "WrongHashSelectedError":
            break
        else:
            SpitHash(str(i), str(pwords), str(hashed), "false")
            mfOpt = "false"
            mfVal = str(pwords)
        i= i+1

    matchF(mfOpt, mfVal)

except (KeyboardInterrupt, SystemExit):
    matchF(mfOpt, mfVal)
    print("[green]Process Successfully Stopped")
