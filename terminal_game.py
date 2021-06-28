import os
import time
import random
import cupp_tg
import Metasploit_tg
ban="""
                 ______    ___  ____   ___ ___  ____  ____    ____  _     
                |      |  /  _]|    \ |   |   ||    ||    \  /    || |    
                |      | /  [_ |  D  )| _   _ | |  | |  _  ||  o  || |    
                |_|  |_||    _]|    / |  \_/  | |  | |  |  ||     || |___ 
                  |  |  |   [_ |    \ |   |   | |  | |  |  ||  _  ||     |
                  |  |  |     ||  .  \|   |   | |  | |  |  ||  |  ||     |
                  |__|  |_____||__|\_||___|___||____||__|__||__|__||_____|
                    .__                                        __.
                    |    ___ _  _ ____    ____ ____ _  _ ____    |
                    |     |  |__| |___    | __ |__| |\/| |___    |
                    |     |  |  | |___    |__] |  | |  | |___    |
                    |__                                        __|
"""
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
help="""
clear --> Clean The Screen

cd    --> Enter on a dir
cd .. --> Get Out of a dir

cd ~  --> Go to the raw dir

rm    --> Remove files
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
  print(ban)
  while gg != "EXIT":
    limpiar=["CLEAR","CLS","CLEAN"]
    meta = ["MSF","METASPLOIT","MSFCONSOLE"]
    timern = ["DATE","DATA","TIME"]
    os.system('title '+'Comandos usados '+str(num))
    #print('Intento '+str(num))
    num = num + 1
    time.sleep(1)    
    comando = input("root@root#~: ")
    comando = comando.upper()
    comando = comando.split()
    if comando[0] == "NMAP":
      print("Se ejecuta nmap")
    elif comando[0] == "HYDRA":
      print("Se ejecuta hydra")
    #elif comando == "CUPP":
    #  print("Se ejecuta cupp")
    #  cupp_tg.cupp_start()
    elif comando[0] in meta:
      #print("Se ejecuta metasploit")
      Metasploit_tg.msfconsole()
    elif comando[0] in limpiar:
      #print("Se ejecuta clean")
      os.system('cls')
    elif comando[0] =="TOOLS":
      print(ayuda_comandos)
    elif comando[0] =="HELP":
      print(help)
    elif comando[0] == "EXIT":
      gg = "EXIT"
      #print('Confirm Exit typing \'exit\'')
      print("Exiting...")
    elif comando[0] in timern:
      os.system('echo %TIME% %DATE%')
    elif comando[0] == "":
      print('hello')
#############################################################################
    elif comando[0] =="CUPP":
      if comando[1] == "-I":
        print("""
       ___________ 
         cupp!                 # Common
            \                     # User
             \   ,__,             # Passwords
              \  (oo)____         # Profiler
                 (__)    )\   
                    ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                                  [ Mebus | https://github.com/Mebus/]
      
      
      [+] Insert the information about the victim to make a dictionary
      [+] If you don't know all the info, just hit enter when asked! ;)
      """)
        amefile = input("> File Name (i.e. name01 ): ")
        cast=input('\n> First Name: ')
        cast=input('> Name: ')
        cast=input('> Surname: ')
        cast=input('> Nickname: ')
        cast=input('> Birthdate (DDMMYYYY): ')
        print("""
      
      """)
        cast=input('> Partners) name: ')
        cast=input('> Partners) nickname: ')
        cast=input('> Partners birthdate (DDMMYYYY): ')
        print("""
      
      """)
        cast=input('> Child\'s name: ')
        cast=input('> Child\'s nickname: ')
        cast=input('> Child\'s birthdate (DDMMYYYY): ')
        print("""
      
      
      """)
        cast=input('> Pet\'s name: ')
        cast=input('> Company name: ')
        print("""
      
      
      """)
        cast=input('> Do you want to add some key words about the victim? Y/[N]: ')
        cast=input('> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed: \n')
        cast=input('> Do you want to add special chars at the end of words? Y/[N]: ')
        cast=input('> Do you want to add some random numbers at the end of words? Y/[N]: ')
        cast=input('> Leet mode? (i.e. leet = 1337) Y/[N]: ')
        randnumwords = str(random.randrange(100000, 1000000000000))
        print("""
      [+] Now making a dictionary...""")
        print("[+] Sorting list and removing duplicates...")
        print("[+] Saving dictionary to "+amefile+".txt, counting "+randnumwords+" words.")
        print("[+] Now load your pistolero with "+amefile+".txt and shoot! Good luck!")
      elif comando[1] == "-A":
        print("""
       ___________ 
         cupp!                 # Common
            \                     # User
             \   ,__,             # Passwords
              \  (oo)____         # Profiler
                 (__)    )\   
                    ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                                  [ Mebus | https://github.com/Mebus/]
      
      [+] Checking if alectodb is not present...
      [+] Downloading alectodb.csv.gz from https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz ... 
      """)
        print("""
      [+] Exporting to alectodb-usernames.txt and alectodb-passwords.txt
      [+] Done.
      """)
      elif comando[1] == "-L":
        print("""
       ___________ 
         cupp!                 # Common
            \                     # User
             \   ,__,             # Passwords
              \  (oo)____         # Profiler
                 (__)    )\   
                    ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                                  [ Mebus | https://github.com/Mebus/]
      
        
        Choose the section you want to download:
      
           1   Moby            14      french          27      places
           2   afrikaans       15      german          28      polish
           3   american        16      hindi           29      random
           4   aussie          17      hungarian       30      religion
           5   chinese         18      italian         31      russian
           6   computer        19      japanese        32      science
           7   croatian        20      latin           33      spanish
           8   czech           21      literature      34      swahili
           9   danish          22      movieTV         35      swedish
          10   databases       23      music           36      turkish
          11   dictionaries    24      names           37      yiddish
          12   dutch           25      net             38      exit program
          13   finnish         26      norwegian       
      
        
Files will be downloaded from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/ repository

      """)
        listadb = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31','32','33','34','35','36','37']
        f=input('> Enter number: ')
        if f == '38':
          print('[-] leaving.')
        elif f in listadb:
          print("[+] Exporting data ...")
      
      elif comando[1] == "-":
        print("""
      usage: cupp [-h] [-i | -l | -a | -v] [-q]
      cupp: error: unrecognized arguments: -
      """)
      elif comando[1] == "-V":
        print("""
       ___________ 
         cupp!                 # Common
            \                     # User
             \   ,__,             # Passwords
              \  (oo)____         # Profiler
                 (__)    )\   
                    ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                                  [ Mebus | https://github.com/Mebus/]
      
      
        [ cupp ]  3.2.5-alpha
      
        * Hacked up by j0rgan - j0rgan@remote-exploit.org
        * http://www.remote-exploit.org
      
        Take a look ./README.md file for more info about the program
      """)
      elif comando[1] == "-Q":
        print("""
      usage: cupp [-h] [-i | -l | -a | -v] [-q]
      
      Common User Passwords Profiler
      
      optional arguments:
        -h, --help         show this help message and exit
        -i, --interactive  Interactive questions for user password profiling
        -l                 Download huge wordlists from repository
        -a                 Parse default usernames and passwords directly from
                           Alecto DB. Project Alecto uses purified databases of
                           Phenoelit and CIRT which were merged and enhanced
        -v, --version      Show the version of this program.
        -q, --quiet        Quiet mode (don't print banner)
      """)
      else:
        print("""
       ___________ 
         cupp!                 # Common
            \                     # User
             \   ,__,             # Passwords
              \  (oo)____         # Profiler
                 (__)    )\   
                    ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                                  [ Mebus | https://github.com/Mebus/]
      
      usage: cupp [-h] [-i | -l | -a | -v] [-q]
      
      Common User Passwords Profiler
      
      optional arguments:
        -h, --help         show this help message and exit
        -i, --interactive  Interactive questions for user password profiling
        -l                 Download huge wordlists from repository
        -a                 Parse default usernames and passwords directly from
                           Alecto DB. Project Alecto uses purified databases of
                           Phenoelit and CIRT which were merged and enhanced
        -v, --version      Show the version of this program.
        -q, --quiet        Quiet mode (don't print banner)
      """)
#############################################################################
    else:
      print('Comando no valido.')
      bool()

bool()
