import os
import time
import cupp_tg
import Metasploit_tg
os.system('@mode con cols=100 lines=40')
ayuda_comandos="""

Command  :  Tool Name

Word List Creator
cupp       :   Cupp
crunch     :   Crunch

Force Brute Attack
hydra      :   Hydra
medussa    :   Medussa

Explotation Attack
msfconsole :   Metasploit
set        :   SeToolKit
fsociety   :   Fsociety

"""
os.system('@echo off')
os.system('cls')
print('Checking resources...')
time.sleep(2)
os.system('cls')
print('All Resources Checked')
def bool():
  gg=0
  num=0
  while gg != "EXIT":
    c = 1
    limpiar=["CLEAR","CLS","CLEAN"]
    meta = ["MSF","METASPLOIT","MSFCONSOLE"]
    timern = ["DATE","DATA","TIME"]
    os.system('title '+'Comandos usados '+str(num))
    #print('Intento '+str(num))
    num = num + 1
    time.sleep(1)
    comando = input("root@root#~: ")
    comando = comando.upper()
    if comando == "NMAP":
      print("Se ejecuta nmap")
    elif comando == "HYDRA":
      print("Se ejecuta hydra")
    elif comando == "CUPP":
      #print("Se ejecuta cupp")
      cupp_tg.cupp_start()
    comando.split()
    print(comando)
    """
    elif comando =="cupp":
      print("""
#root@kali:~/cupp# python3 cupp 
# ___________ 
#   cupp!                 # Common
#      \                     # User
#       \   ,__,             # Passwords
#        \  (oo)____         # Profiler
#           (__)    )\   
#              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
#                            [ Mebus | https://github.com/Mebus/]
#
#usage: cupp [-h] [-i | -w FILENAME | -l | -a | -v] [-q]
#
#Common User Passwords Profiler
#
#optional arguments:
#  -h, --help         show this help message and exit
#  -i, --interactive  Interactive questions for user password profiling
#  -w FILENAME        Use this option to improve existing dictionary, or WyD.pl
#                     output to make some pwnsauce
#  -l                 Download huge wordlists from repository
#  -a                 Parse default usernames and passwords directly from
#                     Alecto DB. Project Alecto uses purified databases of
#                     Phenoelit and CIRT which were merged and enhanced
#  -v, --version      Show the version of this program.
#  -q, --quiet        Quiet mode (don't print banner)
##"""
##
##    elif comando == "cupp -i":
##        print("""root@kali:~/cupp# python3 cupp -i
## ___________ 
##   cupp!                 # Common
##      \                     # User
##       \   ,__,             # Passwords
##        \  (oo)____         # Profiler
##           (__)    )\   
##              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
##                            [ Mebus | https://github.com/Mebus/]
##
##
##[+] Insert the information about the victim to make a dictionary
##[+] If you don't know all the info, just hit enter when asked! ;)
##"""
#      c=input('> First Name: ')
#      c=input('> Name: ')
#      c=input('> Surname: ')
#      c=input('> Nickname: ')
#      c=input('> Birthdate (DDMMYYYY): ')
#      print("""
#
#""")
#      c=input('> Partners) name: ')
#      c=input('> Partners) nickname: ')
#      c=input('> Partners birthdate (DDMMYYYY): ')
#      print("""
#
#""")
#        c=input('> Child\'s name: ')
#        c=input('> Child\'s nickname: ')
#        c=input('> Child\'s birthdate (DDMMYYYY): ')
#        print("""
#
#
#""")
#        c=input('> Pet\'s name: ')
#        c=input('> Company name: ')
#        print("""
#
#
#""")
#        c=input('> Do you want to add some key words about the victim? Y/[N]: ')
#        c=input('> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: ')
#        c=input('> Do you want to add special chars at the end of words? Y/[N]: ')
#        c=input('> Do you want to add some random numbers at the end of words? Y/[N]: ')
#        c=input('> Leet mode? (i.e. leet = 1337) Y/[N]: ')
#        print("""
#[+] Now making a dictionary...""")
#        print("[+] Sorting list and removing duplicates...")
#        print("[+] Saving dictionary to asd.txt, counting 43846 words.")
#        print("[+] Now load your pistolero with asd.txt and shoot! Good luck!")
#    elif comando == "cupp -a":
#        print("""
#root@kali:~/cupp# python3 cupp -a
# ___________ 
#   cupp!                 # Common
#      \                     # User
#       \   ,__,             # Passwords
#        \  (oo)____         # Profiler
#           (__)    )\   
#              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
#                            [ Mebus | https://github.com/Mebus/]
#
#[+] Checking if alectodb is not present...
#[+] Downloading alectodb.csv.gz from https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz ... 
#""")
#        print("""
#[+] Exporting to alectodb-usernames.txt and alectodb-passwords.txt
#[+] Done.
#"""
#    elif comando == "cupp -l":
#        print("""
#root@kali:~/cupp# python3 cupp -l
# ___________ 
#   cupp!                 # Common
#      \                     # User
#       \   ,__,             # Passwords
#        \  (oo)____         # Profiler
#           (__)    )\   
#              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
#                            [ Mebus | https://github.com/Mebus/]
#
#  
#  Choose the section you want to download:
#
#     1   Moby            14      french          27      places
#     2   afrikaans       15      german          28      polish
#     3   american        16      hindi           29      random
#     4   aussie          17      hungarian       30      religion
#     5   chinese         18      italian         31      russian
#     6   computer        19      japanese        32      science
#     7   croatian        20      latin           33      spanish
#     8   czech           21      literature      34      swahili
#     9   danish          22      movieTV         35      swedish
#    10   databases       23      music           36      turkish
#    11   dictionaries    24      names           37      yiddish
#    12   dutch           25      net             38      exit program
#    13   finnish         26      norwegian       
#
#  
#  Files will be downloaded from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/ repository
#  
#  Tip: After downloading wordlist, you can improve it with -w option
#"""
#        f=input('> Enter number: ')
#        if f == 38:
#          print('[-] leaving.')
#        elif f in range (1,37):
#          print("[+] Exporting data ...")
#
#    elif comando == "cupp -":
#        print("""
#root@kali:~/cupp# python3 cupp -
#usage: cupp [-h] [-i | -w FILENAME | -l | -a | -v] [-q]
#cupp: error: unrecognized arguments: -
#""")
#    elif comando == "cupp -v":
#        print("""
#root@kali:~/cupp# python3 cupp -v
# ___________ 
#   cupp!                 # Common
#      \                     # User
#       \   ,__,             # Passwords
#        \  (oo)____         # Profiler
#           (__)    )\   
#              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
#                            [ Mebus | https://github.com/Mebus/]
#
#
#  [ cupp ]  3.2.5-alpha
#
#  * Hacked up by j0rgan - j0rgan@remote-exploit.org
#  * http://www.remote-exploit.org
#
#  Take a look ./README.md file for more info about the program
#"""
#elif comando == "cupp \-q":
#  print("""
#root@kali:~/cupp# python3 cupp -q
#usage: cupp [-h] [-i | -w FILENAME | -l | -a | -v] [-q]
#
#Common User Passwords Profiler
#
#optional arguments:
#  -h, --help         show this help message and exit
#  -i, --interactive  Interactive questions for user password profiling
#  -w FILENAME        Use this option to improve existing dictionary, or WyD.pl
#                     output to make some pwnsauce
#  -l                 Download huge wordlists from repository
#  -a                 Parse default usernames and passwords directly from
#                     Alecto DB. Project Alecto uses purified databases of
#                     Phenoelit and CIRT which were merged and enhanced
#  -v, --version      Show the version of this program.
#  -q, --quiet        Quiet mode (don't print banner)
#""")
    elif comando in limpiar:
          #print("Se ejecuta clean")
          os.system('cls')
        elif comando =="HELP":
          print(ayuda_comandos)
        elif comando == "EXIT":
          gg = "EXIT"
          print("Exiting...")
        elif comando in timern:
          os.system('echo %TIME% %DATE%')
        elif comando == "":
          print('hello')
        else:
          print('Comando no valido.')
          bool()

bool()
