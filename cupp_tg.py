import os
import time
import random
os.system('@echo off')
cupp_logo="""
 ___________ 
   cupp!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\   
              ||--|| *      [ Jarry Krugston | jk@whitehat.org ]
                            [ Rugstron | https://proshub.com/Rugstron/]

usage: cupp [-h] [-i | -w FILENAME | -l | -a | -v] [-q]

Common User Passwords Profiler

optional arguments:
  -h, --help         show this help message and exit
  -i, --interactive  Interactive questions for user password profiling
  -w FILENAME        Use this option to improve existing dictionary, or WyD.pl
                     output to make some pwnsauce
  -l                 Download huge wordlists from repository
  -a                 Parse default usernames and passwords directly from
                     Alecto DB. Project Alecto uses purified databases of
                     Phenoelit and CIRT which were merged and enhanced
  -v, --version      Show the version of this program.
  -q, --quiet        Quiet mode (don't print banner)
"""
ga="""
 *************************************************
 *                   WARNING!!!                  *
 *         Using large wordlists in some         *
 *       options bellow is NOT recommended!      *
 *************************************************
"""
def cupp_start():
  randnumwords = str(random.randrange(100000, 1000000000000))
  print(cupp_logo)
  time.sleep(5)
  print(ga)
  time.sleep(5)
  namefile = input("> File Name (i.e. name01 ): ")
  f1="> Do you want to concatenate all words from wordlist? Y/[N]: y"
  f2="[-] Maximum numbr of words for concatenation is 200"
  f3="[-] Check configuration file for increasing this number."
  f4="> Do you want to concatenate all words from wordlists? Y/[N]: y"
  f5="> Do you want to add special cars at the end of words? Y/[N]: y"
  f6="> Do you want to add some random numbers at the end of words? Y/[N]: y"
  f7="> Leet Mode (i.e. leet = 1337) Y/[N]: y"
  print(f1)
  time.sleep(2.5)
  print(f2)
  time.sleep(2.5)
  print(f3)
  time.sleep(2.5)
  print(f4)
  time.sleep(2.5)
  print(f5)
  time.sleep(2.5)
  print(f6)
  time.sleep(2.5)
  print(f7)
  time.sleep(2.5)
  print("[+] Now making a dictionary...")
  time.sleep(2.5)
  time.sleep(5)
  second="""
[+] Sorting list and removing duplicates...
[+] Saving dictionary to """+namefile+".txt.cupp.txt, counting "+randnumwords+""" words.
[+] Now load your pistolero with """+namefile+""".txt.cupp.txt and shoot! Good luck!"""
  print(second)
































