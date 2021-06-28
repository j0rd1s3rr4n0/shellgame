import os
import time
import random
def msfconsole():
  banners=["""
      \            _    _            _    
       \          | |  | |          | |   
        \\\        | |__| | __ _  ___| | __
         \\\       |  __  |/ _` |/ __| |/ /
          >\/7    | |  | | (_| | (__|   < 
      _.-(6'  \   |_|  |_|\__,_|\___|_|\_\\
     (=___._/` \         _   _          
          )  \ |        | | | |         
         /   / |        | |_| |__   ___ 
        /    > /        | __| '_ \ / _ \\
       j    < _\        | |_| | | |  __/
   _.-' :      ``.       \__|_| |_|\___|
   \ r=._\        `.
  <`\\\_  \         .`-.          _____  _                  _   _ 
   \ r-7  `-. ._  ' .  `\       |  __ \| |                | | | |
    \`,      `-.`7  7)   )      | |__) | | __ _ _ __   ___| |_| |
     \/         \|  \\'  / `-._  |  ___/| |/ _` | '_ \ / _ \ __| |
                ||    .'        | |    | | (_| | | | |  __/ |_|_|
                 \\\  (          |_|    |_|\__,_|_| |_|\___|\__(_)
                  >\  >
              ,.-' >.'
             <.'_.''
               <'
""","""
 ______________________________________________________________________________
|                                                                              |
|                   METASPLOIT CYBER MISSILE COMMAND V5                        |
|______________________________________________________________________________|
      \                                  /                      /
       \     .                          /                      /            x
        \                              /                      /
         \                            /          +           /
          \            +             /                      /
           *                        /                      /
                                   /      .               /
    X                             /                      /            X
                                 /                     ###
                                /                     # % #
                               /                       ###
                      .       /
     .                       /      .            *           .
                            /
                           *
                  +                       *

                                       ^
####      __     __     __          #######         __     __     __        ####
####    /    \ /    \ /    \      ###########     /    \ /    \ /    \      ####
################################################################################
################################################################################
# WAVE 5 ######## SCORE 31337 ################################## HIGH FFFFFFFF #
################################################################################
                                                           https://metasploit.com

""",
"""
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\\
              ||--|| *

""",
"""
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

                        (`.         ,-,
                        ` `.    ,;' /
                         `.  ,'/ .'
                          `. X /.'
                .-;--''--.._` ` (
              .'            /   `
             ,           ` '   Q '
             ,         ,   `._    \\
          ,.|         '     `-.;_'
          :  . `  ;    `  ` --,.._;
           ' `    ,   )   .'
              `._ ,  '   /_
                 ; ,''-,;' ``-
                  ``-..__``--`

                             https://metasploit.com
""",
"""
     ,           ,
    /             \\
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\\
          o_o \   M S F   | \\
               \   _____  |  *
                |||   WW|||
                |||     |||
""",
"""
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com
""",
"""

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.MMMM.oOOOOoOOOOl.MMMM,OOOOOOOOo
  dOOOOOOOO.MMMMMM.cOOOOOc.MMMMMM,OOOOOOOOx
  lOOOOOOOO.MMMMMMMMM;d;MMMMMMMMM,OOOOOOOOl
  .OOOOOOOO.MMM.;MMMMMMMMMMM;MMMM,OOOOOOOO.
   cOOOOOOO.MMM.OOc.MMMMM'oOO.MMM,OOOOOOOc
    oOOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOOo
     lOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOl
      ;OOOO'MMM.OOOO.MMM:OOOO.MMM;OOOO;
       .dOOo'WM.OOOOocccxOOOO.MX'xOOd.
         ,kOl'M.OOOOOOOOOOOOO.M'dOk,
           :kk;.OOOOOOOOOOOOO.;Ok:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

""",
"""
                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \\
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/

""",
"""
Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60
ds: 0018   es: 0018  ss: 0018
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)


Stack: 90909090990909090990909090
       90909090990909090990909090
       90909090.90909090.90909090
       90909090.90909090.90909090
       90909090.90909090.09090900
       90909090.90909090.09090900
       ..........................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ccccccccc.................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       .................ccccccccc
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ..........................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffff..................
       ffffffff..................


Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N4 00 00 00 00
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing

""",
"""
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMM                MMMMMMMMMM
MMMN$                           vMMMM
MMMNl  MMMMM             MMMMM  JMMMM
MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
MMMNI  WMMMM   MMMMMMM   MMMM#  JMMMM
MMMMR  ?MMNM             MMMMM .dMMMM
MMMMNm `?MMM             MMMM` dMMMMM
MMMMMMN  ?MM             MM?  NMMMMMN
MMMMMMMMNe                 JMMMMMNMMM
MMMMMMMMMMNm,            eMMMMMNMMNMM
MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM
        https://metasploit.com
"""]
  info="""
       =[ metasploit v5.0.41-dev                          ]
+ -- --=[ 1914 exploits - 1074 auxiliary - 330 post       ]
+ -- --=[ 556 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 4 evasion                                       ]

 """
  gga=0
  random.shuffle(banners)
  print(banners[0])
  print(info)
  #120x37
  while gga != "EXIT":
    limpiar=["CLEAR","CLS","CLEAN"]
    meta = ["MSF","METASPLOIT","MSFCONSOLE"]
    timern = ["DATE","DATA","TIME"]
    msflista = ['QUIT','EXIT']
    """
Encoders
NOP Generators
Exploits
Payloads
Auxiliary
Post

msf5 > show all
"""

    msfencoder="""
Encoders
========

   #   Name                          Disclosure Date  Rank       Check  Description
   -   ----                          ---------------  ----       -----  -----------
   0   cmd/brace                                      low        No     Bash Brace Expansion Command Encoder
   1   cmd/echo                                       good       No     Echo Command Encoder
   2   cmd/generic_sh                                 manual     No     Generic Shell Variable Substitution Command Encoder
   3   cmd/ifs                                        low        No     Bourne ${IFS} Substitution Command Encoder
   4   cmd/perl                                       normal     No     Perl Command Encoder
   5   cmd/powershell_base64                          excellent  No     Powershell Base64 Command Encoder
   6   cmd/printf_php_mq                              manual     No     printf(1) via PHP magic_quotes Utility Command Encoder
   7   generic/eicar                                  manual     No     The EICAR Encoder
   8   generic/none                                   normal     No     The "none" Encoder
   9   mipsbe/byte_xori                               normal     No     Byte XORi Encoder
   10  mipsbe/longxor                                 normal     No     XOR Encoder
   11  mipsle/byte_xori                               normal     No     Byte XORi Encoder
   12  mipsle/longxor                                 normal     No     XOR Encoder
   13  php/base64                                     great      No     PHP Base64 Encoder
   14  ppc/longxor                                    normal     No     PPC LongXOR Encoder
   15  ppc/longxor_tag                                normal     No     PPC LongXOR Encoder
   16  ruby/base64                                    great      No     Ruby Base64 Encoder
   17  sparc/longxor_tag                              normal     No     SPARC DWORD XOR Encoder
   18  x64/xor                                        normal     No     XOR Encoder
   19  x64/xor_context                                normal     No     Hostname-based Context Keyed Payload Encoder
   20  x64/xor_dynamic                                normal     No     Dynamic key XOR Encoder
   21  x64/zutto_dekiru                               manual     No     Zutto Dekiru
   22  x86/add_sub                                    manual     No     Add/Sub Encoder
   23  x86/alpha_mixed                                low        No     Alpha2 Alphanumeric Mixedcase Encoder
   24  x86/alpha_upper                                low        No     Alpha2 Alphanumeric Uppercase Encoder
   25  x86/avoid_underscore_tolower                   manual     No     Avoid underscore/tolower
   26  x86/avoid_utf8_tolower                         manual     No     Avoid UTF8/tolower
   27  x86/bloxor                                     manual     No     BloXor - A Metamorphic Block Based XOR Encoder
   28  x86/bmp_polyglot                               manual     No     BMP Polyglot
   29  x86/call4_dword_xor                            normal     No     Call+4 Dword XOR Encoder
   30  x86/context_cpuid                              manual     No     CPUID-based Context Keyed Payload Encoder
   31  x86/context_stat                               manual     No     stat(2)-based Context Keyed Payload Encoder
   32  x86/context_time                               manual     No     time(2)-based Context Keyed Payload Encoder
   33  x86/countdown                                  normal     No     Single-byte XOR Countdown Encoder
   34  x86/fnstenv_mov                                normal     No     Variable-length Fnstenv/mov Dword XOR Encoder
   35  x86/jmp_call_additive                          normal     No     Jump/Call XOR Additive Feedback Encoder
   36  x86/nonalpha                                   low        No     Non-Alpha Encoder
   37  x86/nonupper                                   low        No     Non-Upper Encoder
   38  x86/opt_sub                                    manual     No     Sub Encoder (optimised)
   39  x86/service                                    manual     No     Register Service
   40  x86/shikata_ga_nai                             excellent  No     Polymorphic XOR Additive Feedback Encoder
   41  x86/single_static_bit                          manual     No     Single Static Bit
   42  x86/unicode_mixed                              manual     No     Alpha2 Alphanumeric Unicode Mixedcase Encoder
   43  x86/unicode_upper                              manual     No     Alpha2 Alphanumeric Unicode Uppercase Encoder
   44  x86/xor_dynamic                                normal     No     Dynamic key XOR Encoder
"""
    msfnopgen="""
NOP Generators
==============

   #  Name             Disclosure Date  Rank    Check  Description
   -  ----             ---------------  ----    -----  -----------
   0  aarch64/simple                    normal  No     Simple
   1  armle/simple                      normal  No     Simple
   2  mipsbe/better                     normal  No     Better
   3  php/generic                       normal  No     PHP Nop Generator
   4  ppc/simple                        normal  No     Simple
   5  sparc/random                      normal  No     SPARC NOP Generator
   6  tty/generic                       normal  No     TTY Nop Generator
   7  x64/simple                        normal  No     Simple
   8  x86/opty2                         normal  No     Opty2
   9  x86/single_byte                   normal  No     Single Byte
"""
    msfexploit="""
Exploits
========

   #     Name                                                              Disclosure Date  Rank       Check  Description
   -     ----                                                              ---------------  ----       -----  -----------
   0     aix/local/ibstat_path                                             2013-09-24       excellent  Yes    ibstat $PATH Privilege Escalation
   1     aix/rpc_cmsd_opcode21                                             2009-10-07       great      No     AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow
   2     aix/rpc_ttdbserverd_realpath                                      2009-06-17       great      No     ToolTalk rpc.ttdbserverd _tt_internal_realpath Buffer Overflow (AIX)
   3     android/adb/adb_server_exec                                       2016-01-01       excellent  Yes    Android ADB Debug Server Remote Payload Execution
   4     android/browser/samsung_knox_smdm_url                             2014-11-12       excellent  No     Samsung Galaxy KNOX Android Browser RCE
   5     android/browser/stagefright_mp4_tx3g_64bit                        2015-08-13       normal     No     Android Stagefright MP4 tx3g Integer Overflow
   6     android/browser/webview_addjavascriptinterface                    2012-12-21       excellent  No     Android Browser and WebView addJavascriptInterface Code Execution
   7     android/fileformat/adobe_reader_pdf_js_interface                  2014-04-13       good       No     Adobe Reader for Android addJavascriptInterface Exploit
   8     android/local/futex_requeue                                       2014-05-03       excellent  No     Android 'Towelroot' Futex Requeue Kernel Exploit
   9     android/local/put_user_vroot                                      2013-09-06       excellent  No     Android get_user/put_user Exploit
   10    android/local/su_exec                                             2017-08-31       manual     No     Android 'su' Privilege Escalation
   11    apple_ios/browser/safari_libtiff                                  2006-08-01       good       No     Apple iOS MobileSafari LibTIFF Buffer Overflow
   12    apple_ios/browser/webkit_createthis                               2018-03-15       manual     No     Safari Webkit Proxy Object Type Confusion
   13    apple_ios/browser/webkit_trident                                  2016-08-25       manual     No     WebKit not_number defineProperties UAF
   14    apple_ios/email/mobilemail_libtiff                                2006-08-01       good       No     Apple iOS MobileMail LibTIFF Buffer Overflow
   15    apple_ios/ssh/cydia_default_ssh                                   2007-07-02       excellent  No     Apple iOS Default SSH Password Vulnerability
   16    bsd/finger/morris_fingerd_bof                                     1988-11-02       normal     Yes    Morris Worm fingerd Stack Buffer Overflow
   17    bsdi/softcart/mercantec_softcart                                  2004-08-19       great      No     Mercantec SoftCart CGI Overflow
   18    dialup/multi/login/manyargs                                       2001-12-12       good       No     System V Derived /bin/login Extraneous Arguments Buffer Overflow
   19    firefox/local/exec_shellcode                                      2014-03-10       excellent  No     Firefox Exec Shellcode from Privileged Javascript Shell
   20    freebsd/ftp/proftp_telnet_iac                                     2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (FreeBSD)
   21    freebsd/http/watchguard_cmd_exec                                  2015-06-29       excellent  Yes    Watchguard XCS Remote Command Execution
   22    freebsd/local/intel_sysret_priv_esc                               2012-06-12       great      Yes    FreeBSD Intel SYSRET Privilege Escalation
   23    freebsd/local/mmap                                                2013-06-18       great      Yes    FreeBSD 9 Address Space Manipulation Privilege Escalation
   24    freebsd/local/rtld_execl_priv_esc                                 2009-11-30       excellent  Yes    FreeBSD rtld execl() Privilege Escalation
   25    freebsd/local/watchguard_fix_corrupt_mail                         2015-06-29       manual     Yes    Watchguard XCS FixCorruptMail Local Privilege Escalation
   26    freebsd/misc/citrix_netscaler_soap_bof                            2014-09-22       normal     Yes    Citrix NetScaler SOAP Handler Remote Code Execution
   27    freebsd/samba/trans2open                                          2003-04-07       great      No     Samba trans2open Overflow (*BSD x86)
   28    freebsd/tacacs/xtacacsd_report                                    2008-01-08       average    No     XTACACSD report() Buffer Overflow
   29    freebsd/telnet/telnet_encrypt_keyid                               2011-12-23       great      No     FreeBSD Telnet Service Encryption Key ID Buffer Overflow
   30    hpux/lpd/cleanup_exec                                             2002-08-28       excellent  No     HP-UX LPD Command Execution
   31    irix/lpd/tagprinter_exec                                          2001-09-01       excellent  Yes    Irix LPD tagprinter Command Execution
   32    linux/antivirus/escan_password_exec                               2014-04-04       excellent  Yes    eScan Web Management Console Command Injection
   33    linux/browser/adobe_flashplayer_aslaunch                          2008-12-17       good       No     Adobe Flash Player ActionScript Launch Command Execution Vulnerability
   34    linux/ftp/proftp_sreplace                                         2006-11-26       great      Yes    ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)
   35    linux/ftp/proftp_telnet_iac                                       2010-11-01       great      Yes    ProFTPD 1.3.2rc3 - 1.3.3b Telnet IAC Buffer Overflow (Linux)
   36    linux/games/ut2004_secure                                         2004-06-18       good       Yes    Unreal Tournament 2004 "secure" Overflow (Linux)
   37    linux/http/accellion_fta_getstatus_oauth                          2015-07-10       excellent  Yes    Accellion FTA getStatus verify_oauth_token Command Execution
   38    linux/http/advantech_switch_bash_env_exec                         2015-12-01       excellent  Yes    Advantech Switch Bash Environment Variable Code Injection (Shellshock)
   39    linux/http/airties_login_cgi_bof                                  2015-03-31       normal     Yes    Airties login-cgi Buffer Overflow
   40    linux/http/alcatel_omnipcx_mastercgi_exec                         2007-09-09       manual     No     Alcatel-Lucent OmniPCX Enterprise masterCGI Arbitrary Command Execution
   41    linux/http/alienvault_exec                                        2017-01-31       excellent  Yes    AlienVault OSSIM/USM Remote Code Execution
   42    linux/http/alienvault_sqli_exec                                   2014-04-24       excellent  Yes    AlienVault OSSIM SQL Injection and Remote Code Execution
   43    linux/http/apache_continuum_cmd_exec                              2016-04-06       excellent  Yes    Apache Continuum Arbitrary Command Execution
   44    linux/http/apache_couchdb_cmd_exec                                2016-04-06       excellent  Yes    Apache CouchDB Arbitrary Command Execution
   45    linux/http/astium_sqli_upload                                     2013-09-17       manual     Yes    Astium Remote Code Execution
   46    linux/http/asuswrt_lan_rce                                        2018-01-22       excellent  No     AsusWRT LAN Unauthenticated Remote Code Execution
   47    linux/http/atutor_filemanager_traversal                           2016-03-01       excellent  Yes    ATutor 2.2.1 Directory Traversal / Remote Code Execution
   48    linux/http/axis_srv_parhand_rce                                   2018-06-18       excellent  Yes    Axis Network Camera .srv to parhand RCE
   49    linux/http/belkin_login_bof                                       2014-05-09       normal     Yes    Belkin Play N750 login.cgi Buffer Overflow
   50    linux/http/centreon_sqli_exec                                     2014-10-15       excellent  Yes    Centreon SQL and Command Injection
   51    linux/http/centreon_useralias_exec                                2016-02-26       excellent  Yes    Centreon Web Useralias Command Execution
   52    linux/http/cfme_manageiq_evm_upload_exec                          2013-09-04       excellent  Yes    Red Hat CloudForms Management Engine 5.1 agent/linuxpkgs Path Traversal
   53    linux/http/cisco_firepower_useradd                                2016-10-10       excellent  Yes    Cisco Firepower Management Console 6.0 Post Authentication UserAdd Vulnerability
   54    linux/http/cisco_prime_inf_rce                                    2018-10-04       excellent  Yes    Cisco Prime Infrastructure Unauthenticated Remote Code Execution
   55    linux/http/cisco_rv130_rmi_rce                                    2019-02-27       good       No     Cisco RV130W Routers Management Interface Remote Command Execution
   56    linux/http/cisco_rv32x_rce                                        2018-09-09       normal     Yes    Cisco RV320 and RV325 Unauthenticated Remote Code Execution
   57    linux/http/cpi_tararchive_upload                                  2019-05-15       excellent  Yes    Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability
   58    linux/http/crypttech_cryptolog_login_exec                         2017-05-03       excellent  Yes    Crypttech CryptoLog Remote Code Execution
   59    linux/http/dcos_marathon                                          2017-03-03       excellent  Yes    DC/OS Marathon UI Docker Exploit
   60    linux/http/ddwrt_cgibin_exec                                      2009-07-20       excellent  No     DD-WRT HTTP Daemon Arbitrary Command Execution
   61    linux/http/denyall_waf_exec                                       2017-09-19       excellent  Yes    DenyAll Web Application Firewall Remote Code Execution
   62    linux/http/dlink_authentication_cgi_bof                           2013-02-08       normal     Yes    D-Link authentication.cgi Buffer Overflow
   63    linux/http/dlink_command_php_exec_noauth                          2013-02-04       excellent  No     D-Link Devices Unauthenticated Remote Command Execution
   64    linux/http/dlink_dcs931l_upload                                   2015-02-23       great      Yes    D-Link DCS-931L File Upload
   65    linux/http/dlink_dcs_930l_authenticated_remote_command_execution  2015-12-20       excellent  No     D-Link DCS-930L Authenticated Remote Command Execution
   66    linux/http/dlink_diagnostic_exec_noauth                           2013-03-05       excellent  No     D-Link DIR-645 / DIR-815 diagnostic.php Command Execution
   67    linux/http/dlink_dir300_exec_telnet                               2013-04-22       excellent  No     D-Link Devices Unauthenticated Remote Command Execution
   68    linux/http/dlink_dir605l_captcha_bof                              2012-10-08       manual     Yes    D-Link DIR-605L Captcha Handling Buffer Overflow
   69    linux/http/dlink_dir615_up_exec                                   2013-02-07       excellent  No     D-Link DIR615h OS Command Injection
   70    linux/http/dlink_dir850l_unauth_exec                              2017-08-09       excellent  Yes    DIR-850L (Un)authenticated OS Command Exec
   71    linux/http/dlink_dsl2750b_exec_noauth                             2016-02-05       great      Yes    D-Link DSL-2750B OS Command Injection
   72    linux/http/dlink_dspw110_cookie_noauth_exec                       2015-06-12       normal     Yes    D-Link Cookie Command Execution
   73    linux/http/dlink_dspw215_info_cgi_bof                             2014-05-22       normal     Yes    D-Link info.cgi POST Request Buffer Overflow
   74    linux/http/dlink_hedwig_cgi_bof                                   2013-02-08       normal     Yes    D-Link hedwig.cgi Buffer Overflow in Cookie Header
   75    linux/http/dlink_hnap_bof                                         2014-05-15       normal     Yes    D-Link HNAP Request Remote Buffer Overflow
   76    linux/http/dlink_hnap_header_exec_noauth                          2015-02-13       normal     Yes    D-Link Devices HNAP SOAPAction-Header Command Execution
   77    linux/http/dlink_hnap_login_bof                                   2016-11-07       excellent  Yes    Dlink DIR Routers Unauthenticated HNAP Login Stack Buffer Overflow
   78    linux/http/dlink_upnp_exec_noauth                                 2013-07-05       normal     Yes    D-Link Devices UPnP SOAP Command Execution
   79    linux/http/dnalims_admin_exec                                     2017-03-08       excellent  Yes    dnaLIMS Admin Module Command Execution
   80    linux/http/docker_daemon_tcp                                      2017-07-25       excellent  Yes    Docker Daemon - Unprotected TCP Socket Exploit
   81    linux/http/dolibarr_cmd_exec                                      2012-04-06       excellent  Yes    Dolibarr ERP/CRM Post-Auth OS Command Injection
   82    linux/http/dreambox_openpli_shell                                 2013-02-08       great      No     OpenPLI Webif Arbitrary Command Execution
   83    linux/http/efw_chpasswd_exec                                      2015-06-28       excellent  No     Endian Firewall Proxy Password Change Command Injection
   84    linux/http/empire_skywalker                                       2016-10-15       excellent  Yes    PowerShellEmpire Arbitrary File Upload (Skywalker)
   85    linux/http/esva_exec                                              2012-08-16       excellent  Yes    E-Mail Security Virtual Appliance learn-msg.cgi Command Injection
   86    linux/http/f5_icall_cmd                                           2015-09-03       excellent  Yes    F5 iControl iCall::Script Root Command Execution
   87    linux/http/f5_icontrol_exec                                       2013-09-17       excellent  Yes    F5 iControl Remote Root Command Execution
   88    linux/http/foreman_openstack_satellite_code_exec                  2013-06-06       excellent  No     Foreman (Red Hat OpenStack/Satellite) bookmarks/create Code Injection
   89    linux/http/fritzbox_echo_exec                                     2014-02-11       excellent  Yes    Fritz!Box Webcm Unauthenticated Command Injection
   90    linux/http/github_enterprise_secret                               2017-03-15       excellent  Yes    Github Enterprise Default Session Secret And Deserialization Vulnerability
   91    linux/http/gitlist_exec                                           2014-06-30       excellent  Yes    Gitlist Unauthenticated Remote Command Execution
   92    linux/http/goahead_ldpreload                                      2017-12-18       excellent  Yes    GoAhead Web Server LD_PRELOAD Arbitrary Module Load
   93    linux/http/goautodial_3_rce_command_injection                     2015-04-21       excellent  Yes    GoAutoDial 3.3 Authentication Bypass / Command Injection
   94    linux/http/gpsd_format_string                                     2005-05-25       average    No     Berlios GPSD Format String Vulnerability
   95    linux/http/groundwork_monarch_cmd_exec                            2013-03-08       excellent  Yes    GroundWork monarch_scan.cgi OS Command Injection
   96    linux/http/hadoop_unauth_exec                                     2016-10-19       excellent  Yes    Hadoop YARN ResourceManager Unauthenticated Command Execution
   97    linux/http/hp_system_management                                   2012-09-01       normal     Yes    HP System Management Anonymous Access Code Execution
   98    linux/http/hp_van_sdn_cmd_inject                                  2018-06-25       excellent  Yes    HP VAN SDN Controller Root Command Injection
   99    linux/http/huawei_hg532n_cmdinject                                2017-04-15       excellent  Yes    Huawei HG532n Command Injection
   100   linux/http/ibm_qradar_unauth_rce                                  2018-05-28       excellent  Yes    IBM QRadar SIEM Unauthenticated Remote Code Execution
   101   linux/http/imperva_securesphere_exec                              2018-10-08       excellent  Yes    Imperva SecureSphere PWS Command Injection
   102   linux/http/ipfire_bashbug_exec                                    2014-09-29       excellent  Yes    IPFire Bash Environment Variable Injection (Shellshock)
   103   linux/http/ipfire_oinkcode_exec                                   2017-06-09       excellent  Yes    IPFire proxy.cgi RCE
   104   linux/http/ipfire_proxy_exec                                      2016-05-04       excellent  Yes    IPFire proxy.cgi RCE
   105   linux/http/kaltura_unserialize_cookie_rce                         2017-09-12       excellent  Yes    Kaltura Remote PHP Code Execution over Cookie
   106   linux/http/kaltura_unserialize_rce                                2016-03-15       excellent  Yes    Kaltura Remote PHP Code Execution
   107   linux/http/kloxo_sqli                                             2014-01-28       manual     Yes    Kloxo SQL Injection and Remote Code Execution
   108   linux/http/librenms_addhost_cmd_inject                            2018-12-16       excellent  No     LibreNMS addhost Command Injection
   109   linux/http/lifesize_uvc_ping_rce                                  2014-03-21       excellent  No     LifeSize UVC Authenticated RCE via Ping
   110   linux/http/linksys_apply_cgi                                      2005-09-13       great      No     Linksys WRT54 Access Point apply.cgi Buffer Overflow
   111   linux/http/linksys_e1500_apply_exec                               2013-02-05       excellent  No     Linksys E1500/E2500 apply.cgi Remote Command Injection
   112   linux/http/linksys_themoon_exec                                   2014-02-13       excellent  Yes    Linksys E-Series TheMoon Remote Command Injection
   113   linux/http/linksys_wrt110_cmd_exec                                2013-07-12       excellent  Yes    Linksys Devices pingstr Remote Command Injection
   114   linux/http/linksys_wrt160nv2_apply_exec                           2013-02-11       excellent  No     Linksys WRT160nv2 apply.cgi Remote Command Injection
   115   linux/http/linksys_wrt54gl_apply_exec                             2013-01-18       manual     No     Linksys WRT54GL apply.cgi Command Execution
   116   linux/http/linksys_wvbr0_user_agent_exec_noauth                   2017-12-13       excellent  Yes    Linksys WVBR0-25 User-Agent Command Execution
   117   linux/http/logsign_exec                                           2017-02-26       excellent  Yes    Logsign Remote Command Injection
   118   linux/http/mailcleaner_exec                                       2018-12-19       excellent  No     Mailcleaner Remote Code Execution
   119   linux/http/microfocus_secure_messaging_gateway                    2018-06-19       excellent  Yes    MicroFocus Secure Messaging Gateway Remote Code Execution
   120   linux/http/multi_ncc_ping_exec                                    2015-02-26       normal     Yes    D-Link/TRENDnet NCC Service Command Injection
   121   linux/http/mutiny_frontend_upload                                 2013-05-15       excellent  Yes    Mutiny 5 Arbitrary File Upload
   122   linux/http/mvpower_dvr_shell_exec                                 2015-08-23       excellent  Yes    MVPower DVR Shell Unauthenticated Command Execution
   123   linux/http/nagios_xi_chained_rce                                  2016-03-06       excellent  Yes    Nagios XI Chained Remote Code Execution
   124   linux/http/nagios_xi_chained_rce_2_electric_boogaloo              2018-04-17       manual     Yes    Nagios XI Chained Remote Code Execution
   125   linux/http/nagios_xi_magpie_debug                                 2018-11-14       excellent  Yes    Nagios XI Magpie_debug.php Root Remote Code Execution
   126   linux/http/netgear_dgn1000_setup_unauth_exec                      2013-06-05       excellent  Yes    Netgear DGN1000 Setup.cgi Unauthenticated RCE
   127   linux/http/netgear_dgn1000b_setup_exec                            2013-02-06       excellent  No     Netgear DGN1000B setup.cgi Remote Command Execution
   128   linux/http/netgear_dgn2200b_pppoe_exec                            2013-02-15       manual     No     Netgear DGN2200B pppoe.cgi Remote Command Execution
   129   linux/http/netgear_dnslookup_cmd_exec                             2017-02-25       excellent  Yes    Netgear DGN2200 dnslookup.cgi Command Injection
   130   linux/http/netgear_r7000_cgibin_exec                              2016-12-06       excellent  Yes    Netgear R7000 and R6400 cgi-bin Command Injection
   131   linux/http/netgear_readynas_exec                                  2013-07-12       manual     Yes    NETGEAR ReadyNAS Perl Code Evaluation
   132   linux/http/netgear_unauth_exec                                    2016-02-25       excellent  Yes    Netgear Devices Unauthenticated Remote Command Execution
   133   linux/http/netgear_wnr2000_rce                                    2016-12-20       excellent  Yes    NETGEAR WNR2000v5 (Un)authenticated hidden_lang_avi Stack Overflow
   134   linux/http/nginx_chunked_size                                     2013-05-07       great      Yes    Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow
   135   linux/http/nuuo_nvrmini_auth_rce                                  2016-08-04       excellent  No     NUUO NVRmini 2 / Crystal / NETGEAR ReadyNAS Surveillance Authenticated Remote Code Execution
   136   linux/http/nuuo_nvrmini_unauth_rce                                2016-08-04       excellent  Yes    NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Unauthenticated Remote Code Execution
   137   linux/http/op5_config_exec                                        2016-04-08       excellent  Yes    op5 v7.1.9 Configuration Command Execution
   138   linux/http/openfiler_networkcard_exec                             2012-09-04       excellent  Yes    Openfiler v2.x NetworkCard Command Execution
   139   linux/http/pandora_fms_exec                                       2014-01-29       excellent  Yes    Pandora FMS Remote Code Execution
   140   linux/http/pandora_fms_sqli                                       2014-02-01       excellent  Yes    Pandora FMS Default Credential / SQLi Remote Code Execution
   141   linux/http/panos_readsessionvars                                  2017-12-11       excellent  No     Palo Alto Networks readSessionVarsFromFile() Session Corruption
   142   linux/http/peercast_url                                           2006-03-08       average    No     PeerCast URL Handling Buffer Overflow
   143   linux/http/php_imap_open_rce                                      2018-10-23       good       Yes    php imap_open Remote Code Execution
   144   linux/http/pineapp_ldapsyncnow_exec                               2013-07-26       excellent  Yes    PineApp Mail-SeCure ldapsyncnow.php Arbitrary Command Execution
   145   linux/http/pineapp_livelog_exec                                   2013-07-26       excellent  Yes    PineApp Mail-SeCure livelog.html Arbitrary Command Execution
   146   linux/http/pineapp_test_li_conn_exec                              2013-07-26       excellent  Yes    PineApp Mail-SeCure test_li_connection.php Arbitrary Command Execution
   147   linux/http/pineapple_bypass_cmdinject                             2015-08-01       excellent  Yes    Hak5 WiFi Pineapple Preconfiguration Command Injection
   148   linux/http/pineapple_preconfig_cmdinject                          2015-08-01       excellent  Yes    Hak5 WiFi Pineapple Preconfiguration Command Injection
   149   linux/http/piranha_passwd_exec                                    2000-04-04       excellent  No     RedHat Piranha Virtual Server Package passwd.php3 Arbitrary Command Execution
   150   linux/http/qnap_qcenter_change_passwd_exec                        2018-07-11       excellent  Yes    QNAP Q'Center change_passwd Command Execution
   151   linux/http/raidsonic_nas_ib5220_exec_noauth                       2013-02-04       manual     No     Raidsonic NAS Devices Unauthenticated Remote Command Execution
   152   linux/http/railo_cfml_rfi                                         2014-08-26       excellent  Yes    Railo Remote File Include
   153   linux/http/rancher_server                                         2017-07-27       excellent  Yes    Rancher Server - Docker Exploit
   154   linux/http/realtek_miniigd_upnp_exec_noauth                       2015-04-24       normal     Yes    Realtek SDK Miniigd UPnP SOAP Command Execution
   155   linux/http/riverbed_netprofiler_netexpress_exec                   2016-06-27       excellent  Yes    Riverbed SteelCentral NetProfiler/NetExpress Remote Code Execution
   156   linux/http/samsung_srv_1670d_upload_exec                          2017-03-14       good       Yes    Samsung SRN-1670D Web Viewer Version 1.0.0.193 Arbitrary File Read and Upload
   157   linux/http/seagate_nas_php_exec_noauth                            2015-03-01       normal     Yes    Seagate Business NAS Unauthenticated Remote Command Execution
   158   linux/http/smt_ipmi_close_window_bof                              2013-11-06       good       Yes    Supermicro Onboard IPMI close_window.cgi Buffer Overflow
   159   linux/http/sophos_wpa_iface_exec                                  2014-04-08       excellent  No     Sophos Web Protection Appliance Interface Authenticated Arbitrary Command Execution
   160   linux/http/sophos_wpa_sblistpack_exec                             2013-09-06       excellent  Yes    Sophos Web Protection Appliance sblistpack Arbitrary Command Execution
   161   linux/http/spark_unauth_rce                                       2017-12-12       excellent  Yes    Apache Spark Unauthenticated Command Execution
   162   linux/http/supervisor_xmlrpc_exec                                 2017-07-19       excellent  Yes    Supervisor XML-RPC Authenticated Remote Code Execution
   163   linux/http/symantec_messaging_gateway_exec                        2017-04-26       excellent  No     Symantec Messaging Gateway Remote Code Execution
   164   linux/http/symantec_web_gateway_exec                              2012-05-17       excellent  Yes    Symantec Web Gateway 5.0.2.8 ipchange.php Command Injection
   165   linux/http/symantec_web_gateway_file_upload                       2012-05-17       excellent  Yes    Symantec Web Gateway 5.0.2.8 Arbitrary PHP File Upload Vulnerability
   166   linux/http/symantec_web_gateway_lfi                               2012-05-17       excellent  Yes    Symantec Web Gateway 5.0.2.8 relfile File Inclusion Vulnerability
   167   linux/http/symantec_web_gateway_pbcontrol                         2012-07-23       excellent  Yes    Symantec Web Gateway 5.0.2.18 pbcontrol.php Command Injection
   168   linux/http/symantec_web_gateway_restore                           2014-12-16       excellent  Yes    Symantec Web Gateway 5 restore.php Post Authentication Command Injection
   169   linux/http/synology_dsm_sliceupload_exec_noauth                   2013-10-31       excellent  Yes    Synology DiskStation Manager SLICEUPLOAD Remote Command Execution
   170   linux/http/tiki_calendar_exec                                     2016-06-06       excellent  Yes    Tiki-Wiki CMS Calendar Command Execution
   171   linux/http/tp_link_sc2020n_authenticated_telnet_injection         2015-12-20       excellent  No     TP-Link SC2020n Authenticated Telnet Injection
   172   linux/http/tr064_ntpserver_cmdinject                              2016-11-07       normal     Yes    Zyxel/Eir D1000 DSL Modem NewNTPServer Command Injection Over TR-064
   173   linux/http/trend_micro_imsva_exec                                 2017-01-15       excellent  No     Trend Micro InterScan Messaging Security (Virtual Appliance) Remote Code Execution
   174   linux/http/trendmicro_imsva_widget_exec                           2017-10-07       excellent  Yes    Trend Micro InterScan Messaging Security (Virtual Appliance) Remote Code Execution
   175   linux/http/trendmicro_sps_exec                                    2016-08-08       excellent  Yes    Trend Micro Smart Protection Server Exec Remote Code Injection
   176   linux/http/trueonline_billion_5200w_rce                           2016-12-26       excellent  No     TrueOnline / Billion 5200W-T Router Unauthenticated Command Injection
   177   linux/http/trueonline_p660hn_v1_rce                               2016-12-26       excellent  Yes    TrueOnline / ZyXEL P660HN-T v1 Router Unauthenticated Command Injection
   178   linux/http/trueonline_p660hn_v2_rce                               2016-12-26       excellent  Yes    TrueOnline / ZyXEL P660HN-T v2 Router Authenticated Command Injection
   179   linux/http/ueb_api_rce                                            2017-08-08       excellent  Yes    Unitrends UEB http api remote code execution
   180   linux/http/vap2500_tools_command_exec                             2014-11-25       normal     Yes    Arris VAP2500 tools_command.php Command Execution
   181   linux/http/vcms_upload                                            2011-11-27       excellent  Yes    V-CMS PHP File Upload and Execute
   182   linux/http/wanem_exec                                             2012-08-12       excellent  Yes    WAN Emulator v2.3 Command Execution
   183   linux/http/wd_mycloud_multiupload_upload                          2017-07-29       excellent  Yes    Western Digital MyCloud multi_uploadify File Upload Vulnerability
   184   linux/http/webcalendar_settings_exec                              2012-04-23       excellent  Yes    WebCalendar 1.2.4 Pre-Auth Remote Code Injection
   185   linux/http/webid_converter                                        2011-07-05       excellent  Yes    WeBid converter.php Remote PHP Code Injection
   186   linux/http/webmin_packageup_rce                                   2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   187   linux/http/wipg1000_cmd_injection                                 2017-04-20       excellent  Yes    WePresent WiPG-1000 Command Injection
   188   linux/http/xplico_exec                                            2017-10-29       excellent  Yes    Xplico Remote Code Execution
   189   linux/http/zabbix_sqli                                            2013-09-23       excellent  Yes    Zabbix 2.0.8 SQL Injection and Remote Code Execution
   190   linux/http/zen_load_balancer_exec                                 2012-09-14       excellent  Yes    ZEN Load Balancer Filelog Command Execution
   191   linux/http/zenoss_showdaemonxmlconfig_exec                        2012-07-30       good       Yes    Zenoss 3 showDaemonXMLConfig Command Execution
   192   linux/http/zimbra_xxe_rce                                         2019-03-13       excellent  Yes    Zimbra Collaboration Autodiscover Servlet XXE and ProxyServlet SSRF
   193   linux/ids/alienvault_centerd_soap_exec                            2014-05-05       excellent  Yes    AlienVault OSSIM av-centerd Command Injection
   194   linux/ids/snortbopre                                              2005-10-18       good       No     Snort Back Orifice Pre-Preprocessor Buffer Overflow
   195   linux/imap/imap_uw_lsub                                           2000-04-16       good       Yes    UoW IMAP Server LSUB Buffer Overflow
   196   linux/local/abrt_raceabrt_priv_esc                                2015-04-14       excellent  Yes    ABRT raceabrt Privilege Escalation
   197   linux/local/af_packet_chocobo_root_priv_esc                       2016-08-12       good       Yes    AF_PACKET chocobo_root Privilege Escalation
   198   linux/local/af_packet_packet_set_ring_priv_esc                    2017-03-29       good       Yes    AF_PACKET packet_set_ring Privilege Escalation
   199   linux/local/apport_abrt_chroot_priv_esc                           2015-03-31       excellent  Yes    Apport / ABRT chroot Privilege Escalation
   200   linux/local/apt_package_manager_persistence                       1999-03-09       excellent  No     APT Package Manager Persistence
   201   linux/local/asan_suid_executable_priv_esc                         2016-02-17       excellent  Yes    AddressSanitizer (ASan) SUID Executable Privilege Escalation
   202   linux/local/autostart_persistence                                 2006-02-13       excellent  No     Autostart Desktop Item Persistence
   203   linux/local/blueman_set_dhcp_handler_dbus_priv_esc                2015-12-18       excellent  Yes    blueman set_dhcp_handler D-Bus Privilege Escalation
   204   linux/local/bpf_priv_esc                                          2016-05-04       good       Yes    Linux BPF doubleput UAF Privilege Escalation
   205   linux/local/bpf_sign_extension_priv_esc                           2017-11-12       great      Yes    Linux BPF Sign Extension Local Privilege Escalation
   206   linux/local/cpi_runrshell_priv_esc                                2018-12-08       excellent  No     Cisco Prime Infrastructure Runrshell Privilege Escalation
   207   linux/local/cron_persistence                                      1979-07-01       excellent  No     Cron Persistence
   208   linux/local/desktop_privilege_escalation                          2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
   209   linux/local/docker_daemon_privilege_escalation                    2016-06-28       excellent  Yes    Docker Daemon Privilege Escalation
   210   linux/local/glibc_ld_audit_dso_load_priv_esc                      2010-10-18       excellent  Yes    glibc LD_AUDIT Arbitrary DSO Load Privilege Escalation
   211   linux/local/glibc_origin_expansion_priv_esc                       2010-10-18       excellent  Yes    glibc '$ORIGIN' Expansion Privilege Escalation
   212   linux/local/glibc_realpath_priv_esc                               2018-01-16       normal     Yes    glibc 'realpath()' Privilege Escalation
   213   linux/local/hp_smhstart                                           2013-03-30       normal     No     HP System Management Homepage Local Privilege Escalation
   214   linux/local/juju_run_agent_priv_esc                               2017-04-13       excellent  Yes    Juju-run Agent Privilege Escalation
   215   linux/local/kloxo_lxsuexec                                        2012-09-18       excellent  No     Kloxo Local Privilege Escalation
   216   linux/local/lastore_daemon_dbus_priv_esc                          2016-02-02       excellent  Yes    lastore-daemon D-Bus Privilege Escalation
   217   linux/local/libuser_roothelper_priv_esc                           2015-07-24       great      Yes    Libuser roothelper Privilege Escalation
   218   linux/local/nested_namespace_idmap_limit_priv_esc                 2018-11-15       great      Yes    Linux Nested User Namespace idmap Limit Local Privilege Escalation
   219   linux/local/netfilter_priv_esc_ipv4                               2016-06-03       good       Yes    Linux Kernel 4.6.3 Netfilter Privilege Escalation
   220   linux/local/network_manager_vpnc_username_priv_esc                2018-07-26       excellent  Yes    Network Manager VPNC Username Privilege Escalation
   221   linux/local/ntfs3g_priv_esc                                       2017-01-05       good       Yes    Debian/Ubuntu ntfs-3g Local Privilege Escalation
   222   linux/local/overlayfs_priv_esc                                    2015-06-16       good       Yes    Overlayfs Privilege Escalation
   223   linux/local/pkexec                                                2011-04-01       great      Yes    Linux PolicyKit Race Condition Privilege Escalation
   224   linux/local/rc_local_persistence                                  1980-10-01       excellent  No     rc.local Persistence
   225   linux/local/rds_priv_esc                                          2010-10-20       great      Yes    Reliable Datagram Sockets (RDS) Privilege Escalation
   226   linux/local/recvmmsg_priv_esc                                     2014-02-02       good       Yes    Linux Kernel recvmmsg Privilege Escalation
   227   linux/local/service_persistence                                   1983-01-01       excellent  No     Service Persistence
   228   linux/local/servu_ftp_server_prepareinstallation_priv_esc         2019-06-05       excellent  Yes    Serv-U FTP Server prepareinstallation Privilege Escalation
   229   linux/local/sock_sendpage                                         2009-08-13       great      Yes    Linux Kernel Sendpage Local Privilege Escalation
   230   linux/local/sophos_wpa_clear_keys                                 2013-09-06       excellent  Yes    Sophos Web Protection Appliance clear_keys.pl Local Privilege Escalation
   231   linux/local/systemtap_modprobe_options_priv_esc                   2010-11-17       excellent  Yes    SystemTap MODPROBE_OPTIONS Privilege Escalation
   232   linux/local/udev_netlink                                          2009-04-16       great      No     Linux udev Netlink Local Privilege Escalation
   233   linux/local/ueb_bpserverd_privesc                                 2018-03-14       excellent  No     Unitrends Enterprise Backup bpserverd Privilege Escalation
   234   linux/local/ufo_privilege_escalation                              2017-08-10       good       Yes    Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation
   235   linux/local/vmware_alsa_config                                    2017-05-22       excellent  Yes    VMware Workstation ALSA Config File Local Privilege Escalation
   236   linux/local/vmware_mount                                          2013-08-22       excellent  Yes    VMWare Setuid vmware-mount Unsafe popen(3)
   237   linux/local/yum_package_manager_persistence                       2003-12-17       excellent  No     Yum Package Manager Persistence
   238   linux/local/zpanel_zsudo                                          2013-06-07       excellent  Yes    ZPanel zsudo Local Privilege Escalation Exploit
   239   linux/misc/accellion_fta_mpipe2                                   2011-02-07       excellent  No     Accellion FTA MPIPE2 Command Execution
   240   linux/misc/asus_infosvr_auth_bypass_exec                          2015-01-04       excellent  No     ASUS infosvr Auth Bypass Command Execution
   241   linux/misc/drb_remote_codeexec                                    2011-03-23       excellent  No     Distributed Ruby Remote Code Execution
   242   linux/misc/gld_postfix                                            2005-04-12       good       No     GLD (Greylisting Daemon) Postfix Buffer Overflow
   243   linux/misc/hid_discoveryd_command_blink_on_unauth_rce             2016-03-28       excellent  Yes    HID discoveryd command_blink_on Unauthenticated RCE
   244   linux/misc/hikvision_rtsp_bof                                     2014-11-19       normal     No     Hikvision DVR RTSP Request Remote Code Execution
   245   linux/misc/hp_data_protector_cmd_exec                             2011-02-07       excellent  No     HP Data Protector 6 EXEC_CMD Remote Code Execution
   246   linux/misc/hp_jetdirect_path_traversal                            2017-04-05       normal     No     HP Jetdirect Path Traversal Arbitrary Code Execution
   247   linux/misc/hp_nnmi_pmd_bof                                        2014-09-09       normal     Yes    HP Network Node Manager I PMD Buffer Overflow
   248   linux/misc/hp_vsa_login_bof                                       2013-06-28       normal     Yes    HP StorageWorks P4000 Virtual SAN Appliance Login Buffer Overflow
   249   linux/misc/hplip_hpssd_exec                                       2007-10-04       excellent  No     HPLIP hpssd.py From Address Arbitrary Command Execution
   250   linux/misc/ib_inet_connect                                        2007-10-03       good       No     Borland InterBase INET_connect() Buffer Overflow
   251   linux/misc/ib_jrd8_create_database                                2007-10-03       good       No     Borland InterBase jrd8_create_database() Buffer Overflow
   252   linux/misc/ib_open_marker_file                                    2007-10-03       good       No     Borland InterBase open_marker_file() Buffer Overflow
   253   linux/misc/ib_pwd_db_aliased                                      2007-10-03       good       No     Borland InterBase PWD_db_aliased() Buffer Overflow
   254   linux/misc/jenkins_java_deserialize                               2015-11-18       excellent  Yes    Jenkins CLI RMI Java Deserialization Vulnerability
   255   linux/misc/jenkins_ldap_deserialize                               2016-11-16       excellent  Yes    Jenkins CLI HTTP Java Deserialization Vulnerability
   256   linux/misc/lprng_format_string                                    2000-09-25       normal     No     LPRng use_syslog Remote Format String Vulnerability
   257   linux/misc/mongod_native_helper                                   2013-03-24       normal     No     MongoDB nativeHelper.apply Remote Code Execution
   258   linux/misc/nagios_nrpe_arguments                                  2013-02-21       excellent  Yes    Nagios Remote Plugin Executor Arbitrary Command Execution
   259   linux/misc/netcore_udp_53413_backdoor                             2014-08-25       normal     Yes    Netcore Router Udp 53413 Backdoor
   260   linux/misc/netsupport_manager_agent                               2011-01-08       average    No     NetSupport Manager Agent Remote Buffer Overflow
   261   linux/misc/novell_edirectory_ncp_bof                              2012-12-12       normal     Yes    Novell eDirectory 8 Buffer Overflow
   262   linux/misc/opennms_java_serialize                                 2015-11-06       normal     No     OpenNMS Java Object Unserialization Remote Code Execution
   263   linux/misc/qnap_transcode_server                                  2017-08-06       excellent  Yes    QNAP Transcode Server Command Execution
   264   linux/misc/quest_pmmasterd_bof                                    2017-04-09       normal     Yes    Quest Privilege Manager pmmasterd Buffer Overflow
   265   linux/misc/sercomm_exec                                           2013-12-31       great      Yes    SerComm Device Remote Code Execution
   266   linux/misc/ueb9_bpserverd                                         2017-08-08       excellent  Yes    Unitrends UEB bpserverd authentication bypass RCE
   267   linux/misc/zabbix_server_exec                                     2009-09-10       excellent  Yes    Zabbix Server Arbitrary Command Execution
   268   linux/mysql/mysql_yassl_getname                                   2010-01-25       good       No     MySQL yaSSL CertDecoder::GetName Buffer Overflow
   269   linux/mysql/mysql_yassl_hello                                     2008-01-04       good       No     MySQL yaSSL SSL Hello Message Buffer Overflow
   270   linux/pop3/cyrus_pop3d_popsubfolders                              2006-05-21       normal     No     Cyrus IMAPD pop3d popsubfolders USER Buffer Overflow
   271   linux/postgres/postgres_payload                                   2007-06-05       excellent  Yes    PostgreSQL for Linux Payload Execution
   272   linux/pptp/poptop_negative_read                                   2003-04-09       great      Yes    Poptop Negative Read Overflow
   273   linux/proxy/squid_ntlm_authenticate                               2004-06-08       great      No     Squid NTLM Authenticate Overflow
   274   linux/redis/redis_unauth_exec                                     2018-11-13       good       Yes    Redis Unauthenticated Code Execution
   275   linux/samba/chain_reply                                           2010-06-16       good       No     Samba chain_reply Memory Corruption (Linux x86)
   276   linux/samba/is_known_pipename                                     2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
   277   linux/samba/lsa_transnames_heap                                   2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   278   linux/samba/setinfopolicy_heap                                    2012-04-10       normal     Yes    Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   279   linux/samba/trans2open                                            2003-04-07       great      No     Samba trans2open Overflow (Linux x86)
   280   linux/smtp/exim4_dovecot_exec                                     2013-05-03       excellent  No     Exim and Dovecot Insecure Configuration Command Injection
   281   linux/smtp/exim_gethostbyname_bof                                 2015-01-27       great      Yes    Exim GHOST (glibc gethostbyname) Buffer Overflow
   282   linux/smtp/haraka                                                 2017-01-26       excellent  Yes    Haraka SMTP Command Injection
   283   linux/ssh/ceragon_fibeair_known_privkey                           2015-04-01       excellent  No     Ceragon FibeAir IP-10 SSH Private Key Exposure
   284   linux/ssh/exagrid_known_privkey                                   2016-04-07       excellent  No     ExaGrid Known SSH Key and Default Password
   285   linux/ssh/f5_bigip_known_privkey                                  2012-06-11       excellent  No     F5 BIG-IP SSH Private Key Exposure
   286   linux/ssh/loadbalancerorg_enterprise_known_privkey                2014-03-17       excellent  No     Loadbalancer.org Enterprise VA SSH Private Key Exposure
   287   linux/ssh/mercurial_ssh_exec                                      2017-04-18       excellent  No     Mercurial Custom hg-ssh Wrapper Remote Code Exec
   288   linux/ssh/quantum_dxi_known_privkey                               2014-03-17       excellent  No     Quantum DXi V1000 SSH Private Key Exposure
   289   linux/ssh/quantum_vmpro_backdoor                                  2014-03-17       excellent  No     Quantum vmPRO Backdoor Command
   290   linux/ssh/solarwinds_lem_exec                                     2017-03-17       excellent  No     SolarWind LEM Default SSH Password Remote Code Execution
   291   linux/ssh/symantec_smg_ssh                                        2012-08-27       excellent  No     Symantec Messaging Gateway 9.5 Default SSH Password Vulnerability
   292   linux/ssh/ubiquiti_airos_file_upload                              2016-02-13       excellent  No     Ubiquiti airOS Arbitrary File Upload
   293   linux/ssh/vmware_vdp_known_privkey                                2016-12-20       excellent  No     VMware VDP Known SSH Key
   294   linux/telnet/netgear_telnetenable                                 2009-10-30       excellent  Yes    NETGEAR TelnetEnable
   295   linux/telnet/telnet_encrypt_keyid                                 2011-12-23       great      No     Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow
   296   linux/upnp/belkin_wemo_upnp_exec                                  2014-04-04       excellent  Yes    Belkin Wemo UPnP Remote Code Execution
   297   linux/upnp/dlink_upnp_msearch_exec                                2013-02-01       excellent  Yes    D-Link Unauthenticated UPnP M-SEARCH Multicast Command Injection
   298   linux/upnp/miniupnpd_soap_bof                                     2013-03-27       normal     Yes    MiniUPnPd 1.0 Stack Buffer Overflow Remote Code Execution
   299   mainframe/ftp/ftp_jcl_creds                                       2013-05-12       normal     Yes    FTP JCL Execution
   300   multi/browser/adobe_flash_hacking_team_uaf                        2015-07-06       great      No     Adobe Flash Player ByteArray Use After Free
   301   multi/browser/adobe_flash_nellymoser_bof                          2015-06-23       great      No     Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow
   302   multi/browser/adobe_flash_net_connection_confusion                2015-03-12       great      No     Adobe Flash Player NetConnection Type Confusion
   303   multi/browser/adobe_flash_opaque_background_uaf                   2015-07-06       great      No     Adobe Flash opaqueBackground Use After Free
   304   multi/browser/adobe_flash_pixel_bender_bof                        2014-04-28       great      No     Adobe Flash Player Shader Buffer Overflow
   305   multi/browser/adobe_flash_shader_drawing_fill                     2015-05-12       great      No     Adobe Flash Player Drawing Fill Shader Memory Corruption
   306   multi/browser/adobe_flash_shader_job_overflow                     2015-05-12       great      No     Adobe Flash Player ShaderJob Buffer Overflow
   307   multi/browser/adobe_flash_uncompress_zlib_uaf                     2014-04-28       great      No     Adobe Flash Player ByteArray UncompressViaZlibVariant Use After Free
   308   multi/browser/firefox_escape_retval                               2009-07-13       normal     No     Firefox 3.5 escape() Return Value Memory Corruption
   309   multi/browser/firefox_pdfjs_privilege_escalation                  2015-03-31       manual     No     Firefox PDF.js Privileged Javascript Injection
   310   multi/browser/firefox_proto_crmfrequest                           2013-08-06       excellent  No     Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution
   311   multi/browser/firefox_proxy_prototype                             2014-01-20       manual     No     Firefox Proxy Prototype Privileged Javascript Injection
   312   multi/browser/firefox_queryinterface                              2006-02-02       normal     No     Firefox location.QueryInterface() Code Execution
   313   multi/browser/firefox_svg_plugin                                  2013-01-08       excellent  No     Firefox 17.0.1 Flash Privileged Code Injection
   314   multi/browser/firefox_tostring_console_injection                  2013-05-14       excellent  No     Firefox toString console.time Privileged Javascript Injection
   315   multi/browser/firefox_webidl_injection                            2014-03-17       excellent  No     Firefox WebIDL Privileged Javascript Injection
   316   multi/browser/firefox_xpi_bootstrapped_addon                      2007-06-27       excellent  No     Mozilla Firefox Bootstrapped Addon Social Engineering Code Execution
   317   multi/browser/itms_overflow                                       2009-06-01       great      No     Apple OS X iTunes 8.1.1 ITMS Overflow
   318   multi/browser/java_atomicreferencearray                           2012-02-14       excellent  No     Java AtomicReferenceArray Type Violation Vulnerability
   319   multi/browser/java_calendar_deserialize                           2008-12-03       excellent  No     Sun Java Calendar Deserialization Privilege Escalation
   320   multi/browser/java_getsoundbank_bof                               2009-11-04       great      No     Sun Java JRE getSoundbank file:// URI Buffer Overflow
   321   multi/browser/java_jre17_driver_manager                           2013-01-10       excellent  No     Java Applet Driver Manager Privileged toString() Remote Code Execution
   322   multi/browser/java_jre17_exec                                     2012-08-26       excellent  No     Java 7 Applet Remote Code Execution
   323   multi/browser/java_jre17_glassfish_averagerangestatisticimpl      2012-10-16       excellent  No     Java Applet AverageRangeStatisticImpl Remote Code Execution
   324   multi/browser/java_jre17_jaxws                                    2012-10-16       excellent  No     Java Applet JAX-WS Remote Code Execution
   325   multi/browser/java_jre17_jmxbean                                  2013-01-10       excellent  No     Java Applet JMX Remote Code Execution
   326   multi/browser/java_jre17_jmxbean_2                                2013-01-19       excellent  No     Java Applet JMX Remote Code Execution
   327   multi/browser/java_jre17_method_handle                            2012-10-16       excellent  No     Java Applet Method Handle Remote Code Execution
   328   multi/browser/java_jre17_provider_skeleton                        2013-06-18       great      No     Java Applet ProviderSkeleton Insecure Invoke Method
   329   multi/browser/java_jre17_reflection_types                         2013-01-10       excellent  No     Java Applet Reflection Type Confusion Remote Code Execution
   330   multi/browser/java_rhino                                          2011-10-18       excellent  No     Java Applet Rhino Script Engine Remote Code Execution
   331   multi/browser/java_rmi_connection_impl                            2010-03-31       excellent  No     Java RMIConnectionImpl Deserialization Privilege Escalation
   332   multi/browser/java_setdifficm_bof                                 2009-11-04       great      No     Sun Java JRE AWT setDiffICM Buffer Overflow
   333   multi/browser/java_signed_applet                                  1997-02-19       excellent  No     Java Signed Applet Social Engineering Code Execution
   334   multi/browser/java_storeimagearray                                2013-08-12       great      No     Java storeImageArray() Invalid Array Indexing Vulnerability
   335   multi/browser/java_trusted_chain                                  2010-03-31       excellent  No     Java Statement.invoke() Trusted Method Chain Privilege Escalation
   336   multi/browser/java_verifier_field_access                          2012-06-06       excellent  No     Java Applet Field Bytecode Verifier Cache Remote Code Execution
   337   multi/browser/mozilla_compareto                                   2005-07-13       normal     No     Mozilla Suite/Firefox compareTo() Code Execution
   338   multi/browser/mozilla_navigatorjava                               2006-07-25       normal     No     Mozilla Suite/Firefox Navigator Object Code Execution
   339   multi/browser/msfd_rce_browser                                    2018-04-11       normal     No     Metasploit msfd Remote Code Execution via Browser
   340   multi/browser/opera_configoverwrite                               2007-03-05       excellent  No     Opera 9 Configuration Overwrite
   341   multi/browser/opera_historysearch                                 2008-10-23       excellent  No     Opera historysearch XSS
   342   multi/browser/qtjava_pointer                                      2007-04-23       excellent  No     Apple QTJava toQTPointer() Arbitrary Memory Access
   343   multi/elasticsearch/script_mvel_rce                               2013-12-09       excellent  Yes    ElasticSearch Dynamic Script Arbitrary Java Execution
   344   multi/elasticsearch/search_groovy_script                          2015-02-11       excellent  Yes    ElasticSearch Search Groovy Sandbox Bypass
   345   multi/fileformat/adobe_u3d_meshcont                               2009-10-13       good       No     Adobe U3D CLODProgressiveMeshDeclaration Array Overrun
   346   multi/fileformat/evince_cbt_cmd_injection                         2017-07-13       excellent  No     Evince CBT File Command Injection
   347   multi/fileformat/ghostscript_failed_restore                       2018-08-21       excellent  No     Ghostscript Failed Restore Command Execution
   348   multi/fileformat/js_unpacker_eval_injection                       2015-02-18       excellent  No     Javascript Injection for Eval-based Unpackers
   349   multi/fileformat/libreoffice_macro_exec                           2018-10-18       normal     No     LibreOffice Macro Code Execution
   350   multi/fileformat/maple_maplet                                     2010-04-26       excellent  No     Maple Maplet File Creation and Command Execution
   351   multi/fileformat/nodejs_js_yaml_load_code_exec                    2013-06-28       excellent  No     Nodejs js-yaml load() Code Execution
   352   multi/fileformat/office_word_macro                                2012-01-10       excellent  No     Microsoft Office Word Malicious Macro Execution
   353   multi/fileformat/peazip_command_injection                         2009-06-05       excellent  No     PeaZip Zip Processing Command Injection
   354   multi/fileformat/swagger_param_inject                             2016-06-23       excellent  No     JSON Swagger CodeGen Parameter Injector
   355   multi/ftp/pureftpd_bash_env_exec                                  2014-09-24       excellent  Yes    Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)
   356   multi/ftp/wuftpd_site_exec_format                                 2000-06-22       great      Yes    WU-FTPD SITE EXEC/INDEX Format String Vulnerability
   357   multi/gdb/gdb_server_exec                                         2014-08-24       great      No     GDB Server Remote Payload Execution
   358   multi/hams/steamed                                                2018-04-01       manual     No     Steamed Hams
   359   multi/handler                                                                      manual     No     Generic Payload Handler
   360   multi/http/activecollab_chat                                      2012-05-30       excellent  Yes    Active Collab "chat module" Remote PHP Code Injection Exploit
   361   multi/http/ajaxplorer_checkinstall_exec                           2010-04-04       excellent  Yes    AjaXplorer checkInstall.php Remote Command Execution
   362   multi/http/apache_activemq_upload_jsp                             2016-06-01       excellent  No     ActiveMQ web shell upload
   363   multi/http/apache_jetspeed_file_upload                            2016-03-06       manual     No     Apache Jetspeed Arbitrary File Upload
   364   multi/http/apache_mod_cgi_bash_env_exec                           2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   365   multi/http/apache_roller_ognl_injection                           2013-10-31       excellent  Yes    Apache Roller OGNL Injection
   366   multi/http/apprain_upload_exec                                    2012-01-19       excellent  Yes    appRain CMF Arbitrary PHP File Upload Vulnerability
   367   multi/http/atutor_sqli                                            2016-03-01       excellent  Yes    ATutor 2.2.1 SQL Injection / Remote Code Execution
   368   multi/http/auxilium_upload_exec                                   2012-09-14       excellent  Yes    Auxilium RateMyPet Arbitrary File Upload Vulnerability
   369   multi/http/axis2_deployer                                         2010-12-30       excellent  No     Axis2 / SAP BusinessObjects Authenticated Code Execution (via SOAP)
   370   multi/http/bassmaster_js_injection                                2016-11-01       excellent  Yes    Bassmaster Batch Arbitrary JavaScript Injection Remote Code Execution
   371   multi/http/bolt_file_upload                                       2015-08-17       excellent  Yes    CMS Bolt File Upload Vulnerability
   372   multi/http/builderengine_upload_exec                              2016-09-18       excellent  Yes    BuilderEngine Arbitrary File Upload Vulnerability and execution
   373   multi/http/caidao_php_backdoor_exec                               2015-10-27       excellent  Yes    China Chopper Caidao PHP Backdoor Code Execution
   374   multi/http/cisco_dcnm_upload                                      2013-09-18       excellent  Yes    Cisco Prime Data Center Network Manager Arbitrary File Upload
   375   multi/http/clipbucket_fileupload_exec                             2018-03-03       excellent  Yes    ClipBucket beats_uploader Unauthenticated Arbitrary File Upload
   376   multi/http/cmsms_showtime2_rce                                    2019-03-11       normal     Yes    CMS Made Simple (CMSMS) Showtime2 File Upload RCE
   377   multi/http/cmsms_upload_rename_rce                                2018-07-03       excellent  Yes    CMS Made Simple Authenticated RCE via File Upload/Copy
   378   multi/http/coldfusion_ckeditor_file_upload                        2018-09-11       excellent  No     Adobe ColdFusion CKEditor unrestricted file upload
   379   multi/http/coldfusion_rds                                         2013-08-08       great      Yes    Adobe ColdFusion 9 Administrative Login Bypass
   380   multi/http/confluence_widget_connector                            2019-03-25       excellent  Yes    Atlassian Confluence Widget Connector Macro Velocity Template Injection
   381   multi/http/cups_bash_env_exec                                     2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)
   382   multi/http/cuteflow_upload_exec                                   2012-07-27       excellent  Yes    CuteFlow v2.11.2 Arbitrary File Upload Vulnerability
   383   multi/http/dexter_casinoloader_exec                               2014-02-08       excellent  Yes    Dexter (CasinoLoader) SQL Injection
   384   multi/http/drupal_drupageddon                                     2014-10-15       excellent  No     Drupal HTTP Parameter Key/Value SQL Injection
   385   multi/http/eaton_nsm_code_exec                                    2012-06-26       excellent  Yes    Network Shutdown Module (sort_values) Remote PHP Code Injection
   386   multi/http/eventlog_file_upload                                   2014-08-31       excellent  Yes    ManageEngine Eventlog Analyzer Arbitrary File Upload
   387   multi/http/extplorer_upload_exec                                  2012-12-31       excellent  Yes    eXtplorer v2.1 Arbitrary File Upload Vulnerability
   388   multi/http/familycms_less_exec                                    2011-11-29       excellent  Yes    Family Connections less.php Remote Command Execution
   389   multi/http/freenas_exec_raw                                       2010-11-06       great      No     FreeNAS exec_raw.php Arbitrary Command Execution
   390   multi/http/gestioip_exec                                          2013-10-04       excellent  No     GestioIP Remote Command Execution
   391   multi/http/getsimplecms_unauth_code_exec                          2019-04-28       excellent  Yes    GetSimpleCMS Unauthenticated RCE
   392   multi/http/git_client_command_exec                                2014-12-18       excellent  No     Malicious Git and Mercurial HTTP Server For CVE-2014-9390
   393   multi/http/git_submodule_command_exec                             2017-08-10       excellent  No     Malicious Git HTTP Server For CVE-2017-1000117
   394   multi/http/git_submodule_url_exec                                 2018-10-05       excellent  No     Malicious Git HTTP Server For CVE-2018-17456
   395   multi/http/gitlab_shell_exec                                      2013-11-04       excellent  Yes    Gitlab-shell Code Execution
   396   multi/http/gitlist_arg_injection                                  2018-04-26       excellent  Yes    GitList v0.6.0 Argument Injection Vulnerability
   397   multi/http/gitorious_graph                                        2012-01-19       excellent  No     Gitorious Arbitrary Command Execution
   398   multi/http/glassfish_deployer                                     2011-08-04       excellent  No     Sun/Oracle GlassFish Server Authenticated Code Execution
   399   multi/http/glossword_upload_exec                                  2013-02-05       excellent  Yes    Glossword v1.8.8 - 1.8.12 Arbitrary File Upload Vulnerability
   400   multi/http/glpi_install_rce                                       2013-09-12       manual     Yes    GLPI install.php Remote Command Execution
   401   multi/http/horde_form_file_upload                                 2019-03-24       excellent  No     Horde Form File Upload Vulnerability
   402   multi/http/horde_href_backdoor                                    2012-02-13       excellent  No     Horde 3.3.12 Backdoor Arbitrary PHP Code Execution
   403   multi/http/hp_sitescope_issuesiebelcmd                            2013-10-30       great      Yes    HP SiteScope issueSiebelCmd Remote Code Execution
   404   multi/http/hp_sitescope_uploadfileshandler                        2012-08-29       good       No     HP SiteScope Remote Code Execution
   405   multi/http/hp_sys_mgmt_exec                                       2013-06-11       excellent  Yes    HP System Management Homepage JustGetSNMPQueue Command Injection
   406   multi/http/hyperic_hq_script_console                              2013-10-10       excellent  Yes    VMware Hyperic HQ Groovy Script-Console Java Execution
   407   multi/http/ibm_openadmin_tool_soap_welcomeserver_exec             2017-05-30       excellent  Yes    IBM OpenAdmin Tool SOAP welcomeServer PHP Code Execution
   408   multi/http/ispconfig_php_exec                                     2013-10-30       excellent  No     ISPConfig Authenticated Arbitrary PHP Code Execution
   409   multi/http/jboss_bshdeployer                                      2010-04-26       excellent  No     JBoss JMX Console Beanshell Deployer WAR Upload and Deployment
   410   multi/http/jboss_deploymentfilerepository                         2010-04-26       excellent  No     JBoss Java Class DeploymentFileRepository WAR Deployment
   411   multi/http/jboss_invoke_deploy                                    2007-02-20       excellent  Yes    JBoss DeploymentFileRepository WAR Deployment (via JMXInvokerServlet)
   412   multi/http/jboss_maindeployer                                     2007-02-20       excellent  No     JBoss JMX Console Deployer Upload and Execute
   413   multi/http/jboss_seam_upload_exec                                 2010-08-05       normal     Yes    JBoss Seam 2 File Upload and Execute
   414   multi/http/jenkins_metaprogramming                                2019-01-08       excellent  Yes    Jenkins ACL Bypass and Metaprogramming RCE
   415   multi/http/jenkins_script_console                                 2013-01-18       good       Yes    Jenkins-CI Script-Console Java Execution
   416   multi/http/jenkins_xstream_deserialize                            2016-02-24       excellent  Yes    Jenkins XStream Groovy classpath Deserialization Vulnerability
   417   multi/http/jira_hipchat_template                                  2015-10-28       excellent  Yes    Atlassian HipChat for Jira Plugin Velocity Template Injection
   418   multi/http/jira_plugin_upload                                     2018-02-22       excellent  Yes    Atlassian Jira Authenticated Upload Code Execution
   419   multi/http/joomla_http_header_rce                                 2015-12-14       excellent  Yes    Joomla HTTP Header Unauthenticated Remote Code Execution
   420   multi/http/kordil_edms_upload_exec                                2013-02-22       excellent  Yes    Kordil EDMS v2.2.60rc3 Unauthenticated Arbitrary File Upload Vulnerability
   421   multi/http/lcms_php_exec                                          2011-03-03       excellent  Yes    LotusCMS 3.0 eval() Remote Command Execution
   422   multi/http/log1cms_ajax_create_folder                             2011-04-11       excellent  Yes    Log1 CMS writeInfo() PHP Code Injection
   423   multi/http/magento_unserialize                                    2016-05-17       excellent  Yes    Magento 2.0.6 Unserialize Remote Code Execution
   424   multi/http/makoserver_cmd_exec                                    2017-09-03       excellent  Yes    Mako Server v2.5, 2.6 OS Command Injection RCE
   425   multi/http/manage_engine_dc_pmp_sqli                              2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   426   multi/http/manageengine_auth_upload                               2014-12-15       excellent  Yes    ManageEngine Multiple Products Authenticated File Upload
   427   multi/http/manageengine_sd_uploader                               2015-08-20       excellent  Yes    ManageEngine ServiceDesk Plus Arbitrary File Upload
   428   multi/http/manageengine_search_sqli                               2012-10-18       excellent  Yes    ManageEngine Security Manager Plus 5.5 Build 5505 SQL Injection
   429   multi/http/mantisbt_manage_proj_page_rce                          2008-10-16       excellent  Yes    Mantis manage_proj_page PHP Code Execution
   430   multi/http/mantisbt_php_exec                                      2014-11-08       great      Yes    MantisBT XmlImportExport Plugin PHP Code Injection Vulnerability
   431   multi/http/mediawiki_syntaxhighlight                              2017-04-06       good       Yes    MediaWiki SyntaxHighlight extension option injection vulnerability
   432   multi/http/mediawiki_thumb                                        2014-01-28       excellent  Yes    MediaWiki Thumb.php Remote Command Execution
   433   multi/http/metasploit_static_secret_key_base                      2016-09-15       excellent  Yes    Metasploit Web UI Static secret_key_base Value
   434   multi/http/metasploit_webui_console_command_execution             2016-08-23       excellent  No     Metasploit Web UI Diagnostic Console Command Execution
   435   multi/http/mma_backdoor_upload                                    2012-04-02       excellent  Yes    Th3 MMA mma.php Backdoor Arbitrary File Upload
   436   multi/http/mobilecartly_upload_exec                               2012-08-10       excellent  Yes    MobileCartly 1.0 Arbitrary File Creation Vulnerability
   437   multi/http/monstra_fileupload_exec                                2017-12-18       excellent  Yes    Monstra CMS Authenticated Arbitrary File Upload
   438   multi/http/moodle_cmd_exec                                        2013-10-30       good       No     Moodle Remote Command Execution
   439   multi/http/movabletype_upgrade_exec                               2013-01-07       excellent  Yes    Movable Type 4.2x, 4.3x Web Upgrade Remote Code Execution
   440   multi/http/mutiny_subnetmask_exec                                 2012-10-22       excellent  Yes    Mutiny Remote Command Execution
   441   multi/http/nas4free_php_exec                                      2013-10-30       great      No     NAS4Free Arbitrary Remote Code Execution
   442   multi/http/navigate_cms_rce                                       2018-09-26       excellent  Yes    Navigate CMS Unauthenticated Remote Code Execution
   443   multi/http/netwin_surgeftp_exec                                   2012-12-06       good       Yes    Netwin SurgeFTP Remote Command Execution
   444   multi/http/nibbleblog_file_upload                                 2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability
   445   multi/http/novell_servicedesk_rce                                 2016-03-30       excellent  Yes    Novell ServiceDesk Authenticated File Upload
   446   multi/http/nuuo_nvrmini_upgrade_rce                               2018-08-04       excellent  Yes    NUUO NVRmini upgrade_handle.php Remote Command Execution
   447   multi/http/op5_license                                            2012-01-05       excellent  Yes    OP5 license.php Remote Command Execution
   448   multi/http/op5_welcome                                            2012-01-05       excellent  Yes    OP5 welcome Remote Command Execution
   449   multi/http/openfire_auth_bypass                                   2008-11-10       excellent  Yes    Openfire Admin Console Authentication Bypass
   450   multi/http/openmediavault_cmd_exec                                2013-10-30       excellent  No     OpenMediaVault Cron Remote Command Execution
   451   multi/http/openx_backdoor_php                                     2013-08-07       excellent  Yes    OpenX Backdoor PHP Code Execution
   452   multi/http/opmanager_socialit_file_upload                         2014-09-27       excellent  Yes    ManageEngine OpManager and Social IT Arbitrary File Upload
   453   multi/http/oracle_ats_file_upload                                 2016-01-20       excellent  Yes    Oracle ATS Arbitrary File Upload
   454   multi/http/oracle_reports_rce                                     2014-01-15       great      Yes    Oracle Forms and Reports Remote Code Execution
   455   multi/http/oracle_weblogic_wsat_deserialization_rce               2017-10-19       excellent  No     Oracle WebLogic wls-wsat Component Deserialization RCE
   456   multi/http/orientdb_exec                                          2017-07-13       good       Yes    OrientDB 2.2.x Remote Code Execution
   457   multi/http/oscommerce_installer_unauth_code_exec                  2018-04-30       excellent  Yes    osCommerce Installer Unauthenticated Code Execution
   458   multi/http/pandora_upload_exec                                    2010-11-30       excellent  Yes    Pandora FMS v3.1 Auth Bypass and Arbitrary File Upload Vulnerability
   459   multi/http/phoenix_exec                                           2016-07-01       excellent  Yes    Phoenix Exploit Kit Remote Code Execution
   460   multi/http/php_cgi_arg_injection                                  2012-05-03       excellent  Yes    PHP CGI Argument Injection
   461   multi/http/php_utility_belt_rce                                   2015-12-08       excellent  Yes    PHP Utility Belt Remote Code Execution
   462   multi/http/php_volunteer_upload_exec                              2012-05-28       excellent  No     PHP Volunteer Management System v1.0.2 Arbitrary File Upload Vulnerability
   463   multi/http/phpfilemanager_rce                                     2015-08-28       excellent  Yes    phpFileManager 0.9.8 Remote Code Execution
   464   multi/http/phpldapadmin_query_engine                              2011-10-24       excellent  Yes    phpLDAPadmin query_engine Remote PHP Code Injection
   465   multi/http/phpmailer_arg_injection                                2016-12-26       manual     No     PHPMailer Sendmail Argument Injection
   466   multi/http/phpmoadmin_exec                                        2015-03-03       excellent  Yes    PHPMoAdmin 1.1.2 Remote Code Execution
   467   multi/http/phpmyadmin_3522_backdoor                               2012-09-25       normal     No     phpMyAdmin 3.5.2.2 server_sync.php Backdoor
   468   multi/http/phpmyadmin_lfi_rce                                     2018-06-19       good       Yes    phpMyAdmin Authenticated Remote Code Execution
   469   multi/http/phpmyadmin_null_termination_exec                       2016-06-23       excellent  Yes    phpMyAdmin Authenticated Remote Code Execution
   470   multi/http/phpmyadmin_preg_replace                                2013-04-25       excellent  Yes    phpMyAdmin Authenticated Remote Code Execution via preg_replace()
   471   multi/http/phpscheduleit_start_date                               2008-10-01       excellent  Yes    phpScheduleIt PHP reserve.php start_date Parameter Arbitrary Code Injection
   472   multi/http/phptax_exec                                            2012-10-08       excellent  Yes    PhpTax pfilez Parameter Exec Remote Code Injection
   473   multi/http/phpwiki_ploticus_exec                                  2014-09-11       excellent  No     Phpwiki Ploticus Remote Code Execution
   474   multi/http/pimcore_unserialize_rce                                2019-03-11       normal     Yes    Pimcore Unserialize RCE
   475   multi/http/playsms_filename_exec                                  2017-05-21       excellent  Yes    PlaySMS sendfromfile.php Authenticated "Filename" Field Code Execution
   476   multi/http/playsms_uploadcsv_exec                                 2017-05-21       excellent  Yes    PlaySMS import.php Authenticated CSV File Upload Code Execution
   477   multi/http/plone_popen2                                           2011-10-04       excellent  Yes    Plone and Zope XMLTools Remote Command Execution
   478   multi/http/pmwiki_pagelist                                        2011-11-09       excellent  Yes    PmWiki pagelist.php Remote PHP Code Injection Exploit
   479   multi/http/polarcms_upload_exec                                   2012-01-21       excellent  Yes    PolarBear CMS PHP File Upload Vulnerability
   480   multi/http/processmaker_exec                                      2013-10-24       excellent  Yes    ProcessMaker Open Source Authenticated PHP Code Execution
   481   multi/http/processmaker_plugin_upload                             2010-08-25       excellent  No     ProcessMaker Plugin Upload
   482   multi/http/qdpm_upload_exec                                       2012-06-14       excellent  Yes    qdPM v7 Arbitrary PHP File Upload Vulnerability
   483   multi/http/rails_actionpack_inline_exec                           2016-03-01       excellent  No     Ruby on Rails ActionPack Inline ERB Code Execution
   484   multi/http/rails_double_tap                                       2019-03-13       excellent  Yes    Ruby On Rails DoubleTap Development Mode secret_key_base Vulnerability
   485   multi/http/rails_dynamic_render_code_exec                         2016-10-16       excellent  Yes    Ruby on Rails Dynamic Render File Upload Remote Code Execution
   486   multi/http/rails_json_yaml_code_exec                              2013-01-28       excellent  No     Ruby on Rails JSON Processor YAML Deserialization Code Execution
   487   multi/http/rails_secret_deserialization                           2013-04-11       excellent  No     Ruby on Rails Known Secret Session Cookie Remote Code Execution
   488   multi/http/rails_web_console_v2_code_exec                         2015-06-16       excellent  No     Ruby on Rails Web Console (v2) Whitelist Bypass Code Execution
   489   multi/http/rails_xml_yaml_code_exec                               2013-01-07       excellent  No     Ruby on Rails XML Processor YAML Deserialization Code Execution
   490   multi/http/rocket_servergraph_file_requestor_rce                  2013-10-30       great      Yes    Rocket Servergraph Admin Center fileRequestor Remote Code Execution
   491   multi/http/sflog_upload_exec                                      2012-07-06       excellent  Yes    Sflog! CMS 1.0 Arbitrary File Upload Vulnerability
   492   multi/http/shopware_createinstancefromnamedarguments_rce          2019-05-09       excellent  Yes    Shopware createInstanceFromNamedArguments PHP Object Instantiation RCE
   493   multi/http/simple_backdoors_exec                                  2015-09-08       excellent  Yes    Simple Backdoor Shell Remote Code Execution
   494   multi/http/sit_file_upload                                        2011-11-10       excellent  Yes    Support Incident Tracker Remote Command Execution
   495   multi/http/snortreport_exec                                       2011-09-19       excellent  No     Snortreport nmap.php/nbtscan.php Remote Command Execution
   496   multi/http/solarwinds_store_manager_auth_filter                   2014-08-19       excellent  Yes    SolarWinds Storage Manager Authentication Bypass
   497   multi/http/sonicwall_gms_upload                                   2012-01-17       excellent  Yes    SonicWALL GMS 6 Arbitrary File Upload
   498   multi/http/sonicwall_scrutinizer_methoddetail_sqli                2014-07-24       excellent  Yes    Dell SonicWALL Scrutinizer 11.01 methodDetail SQL Injection
   499   multi/http/splunk_mappy_exec                                      2011-12-12       excellent  Yes    Splunk Search Remote Code Execution
   500   multi/http/splunk_upload_app_exec                                 2012-09-27       good       Yes    Splunk Custom App Remote Code Execution
   501   multi/http/spree_search_exec                                      2011-10-05       excellent  No     Spreecommerce 0.60.1 Arbitrary Command Execution
   502   multi/http/spree_searchlogic_exec                                 2011-04-19       excellent  No     Spreecommerce Arbitrary Command Execution
   503   multi/http/struts2_code_exec_showcase                             2017-07-07       excellent  Yes    Apache Struts 2 Struts 1 Plugin Showcase OGNL Code Execution
   504   multi/http/struts2_content_type_ognl                              2017-03-07       excellent  Yes    Apache Struts Jakarta Multipart Parser OGNL Injection
   505   multi/http/struts2_namespace_ognl                                 2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   506   multi/http/struts2_rest_xstream                                   2017-09-05       excellent  Yes    Apache Struts 2 REST Plugin XStream RCE
   507   multi/http/struts_code_exec                                       2010-07-13       good       No     Apache Struts Remote Command Execution
   508   multi/http/struts_code_exec_classloader                           2014-03-06       manual     No     Apache Struts ClassLoader Manipulation Remote Code Execution
   509   multi/http/struts_code_exec_exception_delegator                   2012-01-06       excellent  No     Apache Struts Remote Command Execution
   510   multi/http/struts_code_exec_parameters                            2011-10-01       excellent  Yes    Apache Struts ParametersInterceptor Remote Code Execution
   511   multi/http/struts_default_action_mapper                           2013-07-02       excellent  Yes    Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution
   512   multi/http/struts_dev_mode                                        2012-01-06       excellent  Yes    Apache Struts 2 Developer Mode OGNL Execution
   513   multi/http/struts_dmi_exec                                        2016-04-27       excellent  Yes    Apache Struts Dynamic Method Invocation Remote Code Execution
   514   multi/http/struts_dmi_rest_exec                                   2016-06-01       excellent  Yes    Apache Struts REST Plugin With Dynamic Method Invocation Remote Code Execution
   515   multi/http/struts_include_params                                  2013-05-24       great      Yes    Apache Struts includeParams Remote Code Execution
   516   multi/http/stunshell_eval                                         2013-03-23       great      Yes    STUNSHELL Web Shell Remote PHP Code Execution
   517   multi/http/stunshell_exec                                         2013-03-23       great      Yes    STUNSHELL Web Shell Remote Code Execution
   518   multi/http/sun_jsws_dav_options                                   2010-01-20       great      Yes    Sun Java System Web Server WebDAV OPTIONS Buffer Overflow
   519   multi/http/sysaid_auth_file_upload                                2015-06-03       excellent  Yes    SysAid Help Desk Administrator Portal Arbitrary File Upload
   520   multi/http/sysaid_rdslogs_file_upload                             2015-06-03       excellent  Yes    SysAid Help Desk 'rdslogs' Arbitrary File Upload
   521   multi/http/testlink_upload_exec                                   2012-08-13       excellent  Yes    TestLink v1.9.3 Arbitrary File Upload Vulnerability
   522   multi/http/tomcat_jsp_upload_bypass                               2017-10-03       excellent  Yes    Tomcat RCE via JSP Upload Bypass
   523   multi/http/tomcat_mgr_deploy                                      2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   524   multi/http/tomcat_mgr_upload                                      2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   525   multi/http/traq_plugin_exec                                       2011-12-12       excellent  Yes    Traq admincp/common.php Remote Code Execution
   526   multi/http/trendmicro_threat_discovery_admin_sys_time_cmdi        2017-04-10       excellent  Yes    Trend Micro Threat Discovery Appliance admin_sys_time.cgi Remote Command Execution
   527   multi/http/uptime_file_upload_1                                   2013-11-19       excellent  Yes    Idera Up.Time Monitoring Station 7.0 post2file.php Arbitrary File Upload
   528   multi/http/uptime_file_upload_2                                   2013-11-18       excellent  Yes    Idera Up.Time Monitoring Station 7.4 post2file.php Arbitrary File Upload
   529   multi/http/v0pcr3w_exec                                           2013-03-23       great      Yes    v0pCr3w Web Shell Remote Code Execution
   530   multi/http/vbseo_proc_deutf                                       2012-01-23       excellent  Yes    vBSEO proc_deutf() Remote PHP Code Injection
   531   multi/http/vbulletin_unserialize                                  2015-11-04       excellent  Yes    vBulletin 5.1.2 Unserialize Code Execution
   532   multi/http/visual_mining_netcharts_upload                         2014-11-03       excellent  Yes    Visual Mining NetCharts Server Remote Code Execution
   533   multi/http/vtiger_install_rce                                     2014-03-05       manual     No     Vtiger Install Unauthenticated Remote Command Execution
   534   multi/http/vtiger_logo_upload_exec                                2015-09-28       excellent  Yes    Vtiger CRM - Authenticated Logo Upload RCE
   535   multi/http/vtiger_php_exec                                        2013-10-30       excellent  Yes    vTigerCRM v5.4.0/v5.3.0 Authenticated Remote Code Execution
   536   multi/http/vtiger_soap_upload                                     2013-03-26       excellent  Yes    vTiger CRM SOAP AddEmailAttachment Arbitrary File Upload
   537   multi/http/webnms_file_upload                                     2016-07-04       excellent  Yes    WebNMS Framework Server Arbitrary File Upload
   538   multi/http/webpagetest_upload_exec                                2012-07-13       excellent  Yes    WebPageTest Arbitrary PHP File Upload
   539   multi/http/werkzeug_debug_rce                                     2015-06-28       excellent  Yes    Werkzeug Debug Shell Command Execution
   540   multi/http/wikka_spam_exec                                        2011-11-30       excellent  Yes    WikkaWiki 1.3.2 Spam Logging PHP Injection
   541   multi/http/wp_crop_rce                                            2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload
   542   multi/http/wp_db_backup_rce                                       2019-04-24       excellent  Yes    WP Database Backup RCE
   543   multi/http/wp_ninja_forms_unauthenticated_file_upload             2016-05-04       excellent  Yes    WordPress Ninja Forms Unauthenticated File Upload
   544   multi/http/wp_responsive_thumbnail_slider_upload                  2015-08-28       excellent  Yes    WordPress Responsive Thumbnail Slider Arbitrary File Upload
   545   multi/http/x7chat2_php_exec                                       2014-10-27       excellent  Yes    X7 Chat 2.0.5 lib/message.php preg_replace() PHP Code Execution
   546   multi/http/zabbix_script_exec                                     2013-10-30       excellent  Yes    Zabbix Authenticated Remote Command Execution
   547   multi/http/zemra_panel_rce                                        2012-06-28       excellent  Yes    Zemra Botnet CnC Web Panel Remote Code Execution
   548   multi/http/zenworks_configuration_management_upload               2015-04-07       excellent  Yes    Novell ZENworks Configuration Management Arbitrary File Upload
   549   multi/http/zenworks_control_center_upload                         2013-03-22       great      Yes    Novell ZENworks Configuration Management Remote Execution
   550   multi/http/zpanel_information_disclosure_rce                      2014-01-30       excellent  No     Zpanel Remote Unauthenticated RCE
   551   multi/ids/snort_dce_rpc                                           2007-02-19       good       No     Snort 2 DCE/RPC Preprocessor Buffer Overflow
   552   multi/local/allwinner_backdoor                                    2016-04-30       excellent  Yes    Allwinner 3.4 Legacy Kernel Local Privilege Escalation
   553   multi/local/magnicomp_sysinfo_mcsiwrapper_priv_esc                2016-09-23       excellent  Yes    MagniComp SysInfo mcsiwrapper Privilege Escalation
   554   multi/local/xorg_x11_suid_server                                  2018-10-25       good       Yes    Xorg X11 Server SUID logfile Privilege Escalation
   555   multi/misc/arkeia_agent_exec                                      2015-07-10       great      Yes    Western Digital Arkeia Remote Code Execution
   556   multi/misc/batik_svg_java                                         2012-05-11       excellent  No     Squiggle 1.7 SVG Browser Java Code Execution
   557   multi/misc/bmc_patrol_cmd_exec                                    2019-01-17       excellent  No     BMC Patrol Agent Privilege Escalation Cmd Execution
   558   multi/misc/bmc_server_automation_rscd_nsh_rce                     2016-03-16       excellent  Yes    BMC Server Automation RSCD Agent NSH Remote Command Execution
   559   multi/misc/claymore_dual_miner_remote_manager_rce                 2018-02-09       excellent  Yes    Nanopool Claymore Dual Miner APIs RCE
   560   multi/misc/consul_rexec_exec                                      2018-08-11       excellent  Yes    Hashicorp Consul Remote Command Execution via Rexec
   561   multi/misc/consul_service_exec                                    2018-08-11       excellent  Yes    Hashicorp Consul Remote Command Execution via Services API
   562   multi/misc/erlang_cookie_rce                                      2009-11-20       great      No     Erlang Port Mapper Daemon Cookie RCE
   563   multi/misc/hp_data_protector_exec_integutil                       2014-10-02       great      Yes    HP Data Protector EXEC_INTEGUTIL Remote Code Execution
   564   multi/misc/hp_vsa_exec                                            2011-11-11       excellent  No     HP StorageWorks P4000 Virtual SAN Appliance Command Execution
   565   multi/misc/indesign_server_soap                                   2012-11-11       excellent  Yes    Adobe IndesignServer 5.5 SOAP Server Arbitrary Script Execution
   566   multi/misc/java_jdwp_debugger                                     2010-03-12       good       Yes    Java Debug Wire Protocol Remote Code Execution
   567   multi/misc/java_jmx_server                                        2013-05-22       excellent  Yes    Java JMX Server Insecure Configuration Java Code Execution
   568   multi/misc/java_rmi_server                                        2011-10-15       excellent  No     Java RMI Server Insecure Default Configuration Java Code Execution
   569   multi/misc/legend_bot_exec                                        2015-04-27       excellent  Yes    Legend Perl IRC Bot Remote Code Execution
   570   multi/misc/msf_rpc_console                                        2011-05-22       excellent  No     Metasploit RPC Console Command Execution
   571   multi/misc/msfd_rce_remote                                        2018-04-11       excellent  Yes    Metasploit msfd Remote Code Execution
   572   multi/misc/nodejs_v8_debugger                                     2016-08-15       excellent  Yes    NodeJS Debugger Command Injection
   573   multi/misc/openoffice_document_macro                              2017-02-08       excellent  No     Apache OpenOffice Text Document Malicious Macro Execution
   574   multi/misc/openview_omniback_exec                                 2001-02-28       excellent  Yes    HP OpenView OmniBack II Command Execution
   575   multi/misc/osgi_console_exec                                      2018-02-13       normal     Yes    Eclipse Equinoxe OSGi Console Command Execution
   576   multi/misc/pbot_exec                                              2009-11-02       excellent  Yes    PHP IRC Bot pbot eval() Remote Code Execution
   577   multi/misc/persistent_hpca_radexec_exec                           2014-01-02       great      Yes    HP Client Automation Command Injection
   578   multi/misc/ra1nx_pubcall_exec                                     2013-03-24       great      Yes    Ra1NX PHP Bot PubCall Authentication Bypass Remote Code Execution
   579   multi/misc/teamcity_agent_xmlrpc_exec                             2015-04-14       excellent  Yes    TeamCity Agent XML-RPC Command Execution
   580   multi/misc/veritas_netbackup_cmdexec                              2004-10-21       excellent  Yes    VERITAS NetBackup Remote Command Execution
   581   multi/misc/w3tw0rk_exec                                           2015-06-04       excellent  Yes    w3tw0rk / Pitbul IRC Bot  Remote Code Execution
   582   multi/misc/weblogic_deserialize                                   2018-04-17       manual     Yes    Oracle Weblogic Server Deserialization RCE
   583   multi/misc/weblogic_deserialize_asyncresponseservice              2019-04-23       excellent  Yes    Oracle Weblogic Server Deserialization RCE - AsyncResponseService 
   584   multi/misc/weblogic_deserialize_marshalledobject                  2016-07-19       manual     No     Oracle Weblogic Server Deserialization RCE - MarshalledObject
   585   multi/misc/weblogic_deserialize_rawobject                         2015-01-28       excellent  No     Oracle Weblogic Server Deserialization RCE - Raw Object
   586   multi/misc/weblogic_deserialize_unicastref                        2017-01-25       excellent  No     Oracle Weblogic Server Deserialization RCE - RMI UnicastRef
   587   multi/misc/wireshark_lwres_getaddrbyname                          2010-01-27       great      No     Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow
   588   multi/misc/wireshark_lwres_getaddrbyname_loop                     2010-01-27       great      No     Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)
   589   multi/misc/xdh_x_exec                                             2015-12-04       excellent  Yes    Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution
   590   multi/misc/zend_java_bridge                                       2011-03-28       great      No     Zend Server Java Bridge Arbitrary Java Code Execution
   591   multi/mysql/mysql_udf_payload                                     2009-01-16       excellent  No     Oracle MySQL UDF Payload Execution
   592   multi/ntp/ntp_overflow                                            2001-04-04       good       No     NTP Daemon readvar Buffer Overflow
   593   multi/php/php_unserialize_zval_cookie                             2007-03-04       average    Yes    PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)
   594   multi/php/wp_duplicator_code_inject                               2018-08-29       manual     Yes    Snap Creek Duplicator WordPress plugin code injection
   595   multi/postgres/postgres_copy_from_program_cmd_exec                2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   596   multi/postgres/postgres_createlang                                2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution
   597   multi/realserver/describe                                         2002-12-20       great      Yes    RealServer Describe Buffer Overflow
   598   multi/samba/nttrans                                               2003-04-07       average    No     Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   599   multi/samba/usermap_script                                        2007-05-14       excellent  No     Samba "username map script" Command Execution
   600   multi/sap/sap_mgmt_con_osexec_payload                             2011-03-08       excellent  Yes    SAP Management Console OSExecute Payload Execution
   601   multi/sap/sap_soap_rfc_sxpg_call_system_exec                      2013-03-26       great      Yes    SAP SOAP RFC SXPG_CALL_SYSTEM Remote Command Execution
   602   multi/sap/sap_soap_rfc_sxpg_command_exec                          2012-05-08       great      Yes    SAP SOAP RFC SXPG_COMMAND_EXECUTE Remote Command Execution
   603   multi/script/web_delivery                                         2013-07-19       manual     No     Script Web Delivery
   604   multi/ssh/sshexec                                                 1999-01-01       manual     No     SSH User Code Execution
   605   multi/svn/svnserve_date                                           2004-05-19       average    No     Subversion Date Svnserve
   606   multi/upnp/libupnp_ssdp_overflow                                  2013-01-29       normal     No     Portable UPnP SDK unique_service_name() Remote Code Execution
   607   multi/vnc/vnc_keyboard_exec                                       2015-07-10       great      No     VNC Keyboard Remote Code Execution
   608   multi/vpn/tincd_bof                                               2013-04-22       average    No     Tincd Post-Authentication Remote TCP Stack Buffer Overflow
   609   multi/wyse/hagent_untrusted_hsdata                                2009-07-10       excellent  No     Wyse Rapport Hagent Fake Hserver Command Execution
   610   netware/smb/lsass_cifs                                            2007-01-21       average    No     Novell NetWare LSASS CIFS.NLM Driver Stack Buffer Overflow
   611   netware/sunrpc/pkernel_callit                                     2009-09-30       good       No     NetWare 6.5 SunRPC Portmapper CALLIT Stack Buffer Overflow
   612   osx/afp/loginext                                                  2004-05-03       average    No     AppleFileServer LoginExt PathName Overflow
   613   osx/arkeia/type77                                                 2005-02-18       average    Yes    Arkeia Backup Client Type 77 Overflow (Mac OS X)
   614   osx/browser/adobe_flash_delete_range_tl_op                        2016-04-27       great      No     Adobe Flash Player DeleteRangeTimelineOperation Type-Confusion
   615   osx/browser/mozilla_mchannel                                      2011-05-10       normal     No     Mozilla Firefox 3.6.16 mChannel Use-After-Free
   616   osx/browser/safari_file_policy                                    2011-10-12       normal     No     Apple Safari file:// Arbitrary Code Execution
   617   osx/browser/safari_metadata_archive                               2006-02-21       excellent  No     Safari Archive Metadata Command Execution
   618   osx/browser/safari_proxy_object_type_confusion                    2018-03-15       manual     No     Safari Proxy Object Type Confusion
   619   osx/browser/safari_user_assisted_applescript_exec                 2015-10-16       manual     No     Safari User-Assisted Applescript Exec Attack
   620   osx/browser/safari_user_assisted_download_launch                  2014-03-10       manual     No     Safari User-Assisted Download and Run Attack
   621   osx/browser/software_update                                       2007-12-17       excellent  No     Apple OS X Software Update Command Execution
   622   osx/email/mailapp_image_exec                                      2006-03-01       manual     No     Mail.app Image Attachment Command Execution
   623   osx/ftp/webstar_ftp_user                                          2004-07-13       average    No     WebSTAR FTP Server USER Overflow
   624   osx/http/evocam_webserver                                         2010-06-01       average    No     MacOS X EvoCam HTTP GET Buffer Overflow
   625   osx/local/dyld_print_to_file_root                                 2015-07-21       great      Yes    Apple OS X DYLD_PRINT_TO_FILE Privilege Escalation
   626   osx/local/feedback_assistant_root                                 2019-04-13       excellent  Yes    Mac OS X Feedback Assistant Race Condition
   627   osx/local/iokit_keyboard_root                                     2014-09-24       manual     Yes    Mac OS X IOKit Keyboard Driver Root Privilege Escalation
   628   osx/local/libxpc_mitm_ssudo                                       2018-03-15       excellent  Yes    Mac OS X libxpc MITM Privilege Escalation
   629   osx/local/nfs_mount_root                                          2014-04-11       normal     Yes    Mac OS X NFS Mount Privilege Escalation Exploit
   630   osx/local/persistence                                             2012-04-01       excellent  No     Mac OS X Persistent Payload Installer
   631   osx/local/root_no_password                                        2017-11-29       excellent  No     Mac OS X Root Privilege Escalation
   632   osx/local/rootpipe                                                2015-04-09       great      Yes    Apple OS X Rootpipe Privilege Escalation
   633   osx/local/rootpipe_entitlements                                   2015-07-01       great      Yes    Apple OS X Entitlements Rootpipe Privilege Escalation
   634   osx/local/rsh_libmalloc                                           2015-10-01       normal     No     Mac OS X 10.9.5 / 10.10.5 - rsh/libmalloc Privilege Escalation
   635   osx/local/setuid_tunnelblick                                      2012-08-11       excellent  Yes    Setuid Tunnelblick Privilege Escalation
   636   osx/local/setuid_viscosity                                        2012-08-12       excellent  Yes    Viscosity setuid-set ViscosityHelper Privilege Escalation
   637   osx/local/sudo_password_bypass                                    2013-02-28       normal     Yes    Mac OS X Sudo Password Bypass
   638   osx/local/timemachine_cmd_injection                               2019-04-13       excellent  Yes    Mac OS X TimeMachine (tmdiagnose) Command Injection Privilege Escalation
   639   osx/local/tpwn                                                    2015-08-16       normal     Yes    Mac OS X "tpwn" Privilege Escalation
   640   osx/local/vmware_bash_function_root                               2014-09-24       normal     Yes    OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)
   641   osx/mdns/upnp_location                                            2007-05-25       average    Yes    Mac OS X mDNSResponder UPnP Location Overflow
   642   osx/misc/ufo_ai                                                   2009-10-28       average    No     UFO: Alien Invasion IRC Client Buffer Overflow
   643   osx/rtsp/quicktime_rtsp_content_type                              2007-11-23       average    No     MacOS X QuickTime RTSP Content-Type Overflow
   644   osx/samba/lsa_transnames_heap                                     2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   645   osx/samba/trans2open                                              2003-04-07       great      No     Samba trans2open Overflow (Mac OS X PPC)
   646   qnx/local/ifwatchd_priv_esc                                       2014-03-10       excellent  Yes    ifwatchd Privilege Escalation
   647   qnx/qconn/qconn_exec                                              2012-09-04       excellent  Yes    QNX qconn Command Execution
   648   solaris/dtspcd/heap_noir                                          2002-07-10       great      Yes    Solaris dtspcd Heap Overflow
   649   solaris/local/extremeparr_dtappgather_priv_esc                    2017-04-24       excellent  Yes    Solaris 'EXTREMEPARR' dtappgather Privilege Escalation
   650   solaris/local/libnspr_nspr_log_file_priv_esc                      2006-10-11       excellent  Yes    Solaris libnspr NSPR_LOG_FILE Privilege Escalation
   651   solaris/local/rsh_stack_clash_priv_esc                            2017-06-19       good       Yes    Solaris RSH Stack Clash Privilege Escalation
   652   solaris/lpd/sendmail_exec                                         2001-08-31       excellent  No     Solaris LPD Command Execution
   653   solaris/samba/lsa_transnames_heap                                 2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   654   solaris/samba/trans2open                                          2003-04-07       great      No     Samba trans2open Overflow (Solaris SPARC)
   655   solaris/sunrpc/sadmind_adm_build_path                             2008-10-14       great      No     Sun Solaris sadmind adm_build_path() Buffer Overflow
   656   solaris/sunrpc/sadmind_exec                                       2003-09-13       excellent  No     Solaris sadmind Command Execution
   657   solaris/sunrpc/ypupdated_exec                                     1994-12-12       excellent  No     Solaris ypupdated Command Execution
   658   solaris/telnet/fuser                                              2007-02-12       excellent  No     Sun Solaris Telnet Remote Authentication Bypass Vulnerability
   659   solaris/telnet/ttyprompt                                          2002-01-18       excellent  No     Solaris in.telnetd TTYPROMPT Buffer Overflow
   660   unix/dhcp/bash_environment                                        2014-09-24       excellent  No     Dhclient Bash Environment Variable Injection (Shellshock)
   661   unix/dhcp/rhel_dhcp_client_command_injection                      2018-05-15       excellent  No     DHCP Client Command Injection (DynoRoot)
   662   unix/fileformat/ghostscript_type_confusion                        2017-04-27       excellent  No     Ghostscript Type Confusion Arbitrary Command Execution
   663   unix/fileformat/imagemagick_delegate                              2016-05-03       excellent  No     ImageMagick Delegate Arbitrary Command Execution
   664   unix/ftp/proftpd_133c_backdoor                                    2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution
   665   unix/ftp/proftpd_modcopy_exec                                     2015-04-22       excellent  Yes    ProFTPD 1.3.5 Mod_Copy Command Execution
   666   unix/ftp/vsftpd_234_backdoor                                      2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
   667   unix/http/contentkeeperweb_mimencode                              2009-02-25       excellent  Yes    ContentKeeper Web Remote Command Execution
   668   unix/http/ctek_skyrouter                                          2011-09-08       average    No     CTEK SkyRouter 4200 and 4300 Command Execution
   669   unix/http/dell_kace_k1000_upload                                  2014-03-07       excellent  Yes    Dell KACE K1000 File Upload
   670   unix/http/epmp1000_get_chart_cmd_shell                            2017-12-18       excellent  Yes    Cambium ePMP1000 'get_chart' Shell via Command Injection (v3.1-3.5-RC7)
   671   unix/http/epmp1000_ping_cmd_shell                                 2015-11-28       excellent  Yes    Cambium ePMP1000 'ping' Shell via Command Injection (up to v2.5)
   672   unix/http/freepbx_callmenum                                       2012-03-20       manual     No     FreePBX 2.10.0 / 2.9.0 callmenum Remote Code Execution
   673   unix/http/laravel_token_unserialize_exec                          2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution
   674   unix/http/lifesize_room                                           2011-07-13       excellent  No     LifeSize Room Command Injection
   675   unix/http/pfsense_clickjacking                                    2017-11-21       normal     No     Clickjacking Vulnerability In CSRF Error Page pfSense
   676   unix/http/pfsense_graph_injection_exec                            2016-04-18       excellent  No     pfSense authenticated graph status RCE
   677   unix/http/pfsense_group_member_exec                               2017-11-06       excellent  Yes    pfSense authenticated group member RCE
   678   unix/http/quest_kace_systems_management_rce                       2018-05-31       excellent  Yes    Quest KACE Systems Management Command Injection
   679   unix/http/schneider_electric_net55xx_encoder                      2019-01-25       excellent  Yes    Schneider Electric Pelco Endura NET55XX Encoder
   680   unix/http/tnftp_savefile                                          2014-10-28       excellent  No     tnftp "savefile" Arbitrary Command Execution
   681   unix/http/twiki_debug_plugins                                     2014-10-09       excellent  Yes    TWiki Debugenableplugins Remote Code Execution
   682   unix/http/vmturbo_vmtadmin_exec_noauth                            2014-06-25       excellent  Yes    VMTurbo Operations Manager vmtadmin.cgi Remote Command Execution
   683   unix/http/xdebug_unauth_exec                                      2017-09-17       excellent  Yes    xdebug Unauthenticated OS Command Execution
   684   unix/irc/unreal_ircd_3281_backdoor                                2010-06-12       excellent  No     UnrealIRCD 3.2.8.1 Backdoor Command Execution
   685   unix/local/at_persistence                                         1997-01-01       excellent  Yes    at(1) Persistence
   686   unix/local/chkrootkit                                             2014-06-04       manual     Yes    Chkrootkit Local Privilege Escalation
   687   unix/local/emacs_movemail                                         1986-08-01       excellent  Yes    Emacs movemail Privilege Escalation
   688   unix/local/exim_perl_startup                                      2016-03-10       excellent  Yes    Exim "perl_startup" Privilege Escalation
   689   unix/local/netbsd_mail_local                                      2016-07-07       excellent  No     NetBSD mail.local Privilege Escalation
   690   unix/local/setuid_nmap                                            2012-07-19       excellent  Yes    Setuid Nmap Exploit
   691   unix/misc/distcc_exec                                             2002-02-01       excellent  Yes    DistCC Daemon Command Execution
   692   unix/misc/polycom_hdx_auth_bypass                                 2013-01-18       normal     Yes    Polycom Command Shell Authorization Bypass
   693   unix/misc/polycom_hdx_traceroute_exec                             2017-11-12       excellent  Yes    Polycom Shell HDX Series Traceroute Command Execution
   694   unix/misc/qnx_qconn_exec                                          2012-09-04       excellent  Yes    QNX qconn Command Execution
   695   unix/misc/spamassassin_exec                                       2006-06-06       excellent  No     SpamAssassin spamd Remote Command Execution
   696   unix/misc/xerox_mfp                                               2012-03-07       good       No     Xerox Multifunction Printers (MFP) "Patch" DLM Vulnerability
   697   unix/misc/zabbix_agent_exec                                       2009-09-10       excellent  No     Zabbix Agent net.tcp.listen Command Injection
   698   unix/polycom_hdx_auth_bypass                                      2013-01-18       normal     Yes    Polycom Command Shell Authorization Bypass
   699   unix/smtp/clamav_milter_blackhole                                 2007-08-24       excellent  No     ClamAV Milter Blackhole-Mode Remote Code Execution
   700   unix/smtp/exim4_string_format                                     2010-12-07       excellent  No     Exim4 string_format Function Heap Buffer Overflow
   701   unix/smtp/morris_sendmail_debug                                   1988-11-02       average    Yes    Morris Worm sendmail Debug Mode Shell Escape
   702   unix/smtp/qmail_bash_env_exec                                     2014-09-24       normal     No     Qmail SMTP Bash Environment Variable Injection (Shellshock)
   703   unix/sonicwall/sonicwall_xmlrpc_rce                               2016-07-22       excellent  Yes    SonicWall Global Management System XMLRPC set_time_zone Unauth RCE
   704   unix/ssh/array_vxag_vapv_privkey_privesc                          2014-02-03       excellent  No     Array Networks vAPV and vxAG Private Key Privilege Escalation Code Execution
   705   unix/ssh/tectia_passwd_changereq                                  2012-12-01       excellent  Yes    Tectia SSH USERAUTH Change Request Password Reset Vulnerability
   706   unix/webapp/actualanalyzer_ant_cookie_exec                        2014-08-28       excellent  Yes    ActualAnalyzer 'ant' Cookie Command Execution
   707   unix/webapp/arkeia_upload_exec                                    2013-09-16       excellent  Yes    Western Digital Arkeia Remote Code Execution
   708   unix/webapp/awstats_configdir_exec                                2005-01-15       excellent  Yes    AWStats configdir Remote Command Execution
   709   unix/webapp/awstats_migrate_exec                                  2006-05-04       excellent  Yes    AWStats migrate Remote Command Execution
   710   unix/webapp/awstatstotals_multisort                               2008-08-26       excellent  Yes    AWStats Totals multisort Remote Command Execution
   711   unix/webapp/barracuda_img_exec                                    2005-09-01       excellent  Yes    Barracuda IMG.PL Remote Command Execution
   712   unix/webapp/base_qry_common                                       2008-06-14       excellent  No     BASE base_qry_common Remote File Include
   713   unix/webapp/basilic_diff_exec                                     2012-06-28       excellent  Yes    Basilic 1.5.14 diff.php Arbitrary Command Execution
   714   unix/webapp/cacti_graphimage_exec                                 2005-01-15       excellent  No     Cacti graph_view.php Remote Command Execution
   715   unix/webapp/cakephp_cache_corruption                              2010-11-15       excellent  No     CakePHP Cache Corruption Code Execution
   716   unix/webapp/carberp_backdoor_exec                                 2013-06-28       great      Yes    Carberp Web Panel C2 Backdoor Remote PHP Code Execution
   717   unix/webapp/citrix_access_gateway_exec                            2010-12-21       excellent  Yes    Citrix Access Gateway Command Execution
   718   unix/webapp/clipbucket_upload_exec                                2013-10-04       excellent  Yes    ClipBucket Remote Code Execution
   719   unix/webapp/coppermine_piceditor                                  2008-01-30       excellent  Yes    Coppermine Photo Gallery picEditor.php Command Execution
   720   unix/webapp/datalife_preview_exec                                 2013-01-28       excellent  Yes    DataLife Engine preview.php PHP Code Injection
   721   unix/webapp/dogfood_spell_exec                                    2009-03-03       excellent  Yes    Dogfood CRM spell.php Remote Command Execution
   722   unix/webapp/drupal_coder_exec                                     2016-07-13       excellent  Yes    Drupal CODER Module Remote Command Execution
   723   unix/webapp/drupal_drupalgeddon2                                  2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection
   724   unix/webapp/drupal_restws_exec                                    2016-07-13       excellent  Yes    Drupal RESTWS Module Remote PHP Code Execution
   725   unix/webapp/drupal_restws_unserialize                             2019-02-20       normal     Yes    Drupal RESTful Web Services unserialize() RCE
   726   unix/webapp/egallery_upload_exec                                  2012-07-08       excellent  Yes    EGallery PHP File Upload Vulnerability
   727   unix/webapp/elfinder_php_connector_exiftran_cmd_injection         2019-02-26       excellent  Yes    elFinder PHP Connector exiftran Command Injection
   728   unix/webapp/flashchat_upload_exec                                 2013-10-04       excellent  Yes    FlashChat Arbitrary File Upload
   729   unix/webapp/foswiki_maketext                                      2012-12-03       excellent  Yes    Foswiki MAKETEXT Remote Command Execution
   730   unix/webapp/freepbx_config_exec                                   2014-03-21       excellent  Yes    FreePBX config.php Remote Code Execution
   731   unix/webapp/generic_exec                                          1993-11-14       excellent  No     Generic Web Application Unix Command Execution
   732   unix/webapp/get_simple_cms_upload_exec                            2014-01-04       excellent  Yes    GetSimpleCMS PHP File Upload Vulnerability
   733   unix/webapp/google_proxystylesheet_exec                           2005-08-16       excellent  Yes    Google Appliance ProxyStyleSheet Command Execution
   734   unix/webapp/graphite_pickle_exec                                  2013-08-20       excellent  Yes    Graphite Web Unsafe Pickle Handling
   735   unix/webapp/guestbook_ssi_exec                                    1999-11-05       excellent  No     Matt Wright guestbook.pl Arbitrary Command Execution
   736   unix/webapp/hastymail_exec                                        2011-11-22       excellent  Yes    Hastymail 2.1.1 RC1 Command Injection
   737   unix/webapp/havalite_upload_exec                                  2013-06-17       excellent  Yes    Havalite CMS Arbitary File Upload Vulnerability
   738   unix/webapp/horde_unserialize_exec                                2013-06-27       excellent  Yes    Horde Framework Unserialize PHP Code Execution
   739   unix/webapp/hybridauth_install_php_exec                           2014-08-04       manual     Yes    HybridAuth install.php PHP Code Execution
   740   unix/webapp/instantcms_exec                                       2013-06-26       excellent  Yes    InstantCMS 1.6 Remote PHP Code Execution
   741   unix/webapp/invision_pboard_unserialize_exec                      2012-10-25       excellent  Yes    Invision IP.Board unserialize() PHP Code Execution
   742   unix/webapp/joomla_akeeba_unserialize                             2014-09-29       excellent  Yes    Joomla Akeeba Kickstart Unserialize Remote Code Execution
   743   unix/webapp/joomla_comfields_sqli_rce                             2017-05-17       excellent  Yes    Joomla Component Fields SQLi Remote Code Execution
   744   unix/webapp/joomla_comjce_imgmanager                              2012-08-02       excellent  Yes    Joomla Component JCE File Upload Remote Code Execution
   745   unix/webapp/joomla_contenthistory_sqli_rce                        2015-10-23       excellent  Yes    Joomla Content History SQLi Remote Code Execution
   746   unix/webapp/joomla_media_upload_exec                              2013-08-01       excellent  Yes    Joomla Media Manager File Upload Vulnerability
   747   unix/webapp/joomla_tinybrowser                                    2009-07-22       excellent  Yes    Joomla 1.5.12 TinyBrowser File Upload Code Execution
   748   unix/webapp/jquery_file_upload                                    2018-10-09       excellent  Yes    blueimp's jQuery (Arbitrary) File Upload
   749   unix/webapp/kimai_sqli                                            2013-05-21       average    Yes    Kimai v0.9.2 'db_restore.php' SQL Injection
   750   unix/webapp/libretto_upload_exec                                  2013-06-14       excellent  Yes    LibrettoCMS File Manager Arbitary File Upload Vulnerability
   751   unix/webapp/maarch_letterbox_file_upload                          2015-02-11       excellent  Yes    Maarch LetterBox Unrestricted File Upload
   752   unix/webapp/mambo_cache_lite                                      2008-06-14       excellent  No     Mambo Cache_Lite Class mosConfig_absolute_path Remote File Include
   753   unix/webapp/mitel_awc_exec                                        2010-12-12       excellent  No     Mitel Audio and Web Conferencing Command Injection
   754   unix/webapp/moinmoin_twikidraw                                    2012-12-30       manual     Yes    MoinMoin twikidraw Action Traversal File Upload
   755   unix/webapp/mybb_backdoor                                         2011-10-06       excellent  Yes    myBB 1.6.4 Backdoor Arbitrary Command Execution
   756   unix/webapp/nagios3_history_cgi                                   2012-12-09       great      Yes    Nagios3 history.cgi Host Command Execution
   757   unix/webapp/nagios3_statuswml_ping                                2009-06-22       excellent  No     Nagios3 statuswml.cgi Ping Command Execution
   758   unix/webapp/nagios_graph_explorer                                 2012-11-30       excellent  Yes    Nagios XI Network Monitor Graph Explorer Component Command Injection
   759   unix/webapp/narcissus_backend_exec                                2012-11-14       excellent  Yes    Narcissus Image Configuration Passthru Vulnerability
   760   unix/webapp/open_flash_chart_upload_exec                          2009-12-14       great      Yes    Open Flash Chart v2 Arbitrary File Upload
   761   unix/webapp/openemr_sqli_privesc_upload                           2013-09-16       excellent  Yes    OpenEMR 4.1.1 Patch 14 SQLi Privilege Escalation Remote Code Execution
   762   unix/webapp/openemr_upload_exec                                   2013-02-13       excellent  Yes    OpenEMR PHP File Upload Vulnerability
   763   unix/webapp/opensis_modname_exec                                  2012-12-04       excellent  Yes    OpenSIS 'modname' PHP Code Execution
   764   unix/webapp/openview_connectednodes_exec                          2005-08-25       excellent  No     HP Openview connectedNodes.ovpl Remote Command Execution
   765   unix/webapp/openx_banner_edit                                     2009-11-24       excellent  Yes    OpenX banner-edit.php File Upload PHP Code Execution
   766   unix/webapp/oracle_vm_agent_utl                                   2010-10-12       excellent  Yes    Oracle VM Server Virtual Server Agent Command Injection
   767   unix/webapp/oscommerce_filemanager                                2009-08-31       excellent  No     osCommerce 2.2 Arbitrary PHP Code Execution
   768   unix/webapp/pajax_remote_exec                                     2006-03-30       excellent  No     PAJAX Remote Command Execution
   769   unix/webapp/php_charts_exec                                       2013-01-16       excellent  Yes    PHP-Charts v1.0 PHP Code Execution Vulnerability
   770   unix/webapp/php_eval                                              2008-10-13       manual     Yes    Generic PHP Code Evaluation
   771   unix/webapp/php_include                                           2006-12-17       normal     Yes    PHP Remote File Include Generic Code Execution
   772   unix/webapp/php_vbulletin_template                                2005-02-25       excellent  Yes    vBulletin misc.php Template Name Arbitrary Code Execution
   773   unix/webapp/php_xmlrpc_eval                                       2005-06-29       excellent  Yes    PHP XML-RPC Arbitrary Code Execution
   774   unix/webapp/phpbb_highlight                                       2004-11-12       excellent  No     phpBB viewtopic.php Arbitrary Code Execution
   775   unix/webapp/phpcollab_upload_exec                                 2017-09-29       excellent  Yes    phpCollab 2.5.1 Unauthenticated File Upload
   776   unix/webapp/phpmyadmin_config                                     2009-03-24       excellent  No     PhpMyAdmin Config File Code Injection
   777   unix/webapp/piwik_superuser_plugin_upload                         2017-02-05       excellent  No     Piwik Superuser Plugin Upload
   778   unix/webapp/projectpier_upload_exec                               2012-10-08       excellent  Yes    Project Pier Arbitrary File Upload Vulnerability
   779   unix/webapp/projectsend_upload_exec                               2014-12-02       excellent  Yes    ProjectSend Arbitrary File Upload
   780   unix/webapp/qtss_parse_xml_exec                                   2003-02-24       excellent  No     QuickTime Streaming Server parse_xml.cgi Remote Execution
   781   unix/webapp/redmine_scm_exec                                      2010-12-19       excellent  No     Redmine SCM Repository Arbitrary Command Execution
   782   unix/webapp/seportal_sqli_exec                                    2014-03-20       excellent  Yes    SePortal SQLi Remote Code Execution
   783   unix/webapp/simple_e_document_upload_exec                         2014-01-23       excellent  Yes    Simple E-Document Arbitrary File Upload
   784   unix/webapp/sixapart_movabletype_storable_exec                    2015-02-11       good       Yes    SixApart MovableType Storable Perl Code Execution
   785   unix/webapp/skybluecanvas_exec                                    2014-01-28       excellent  Yes    SkyBlueCanvas CMS Remote Code Execution
   786   unix/webapp/sphpblog_file_upload                                  2005-08-25       excellent  Yes    Simple PHP Blog Remote Command Execution
   787   unix/webapp/spip_connect_exec                                     2012-07-04       excellent  Yes    SPIP connect Parameter PHP Injection
   788   unix/webapp/squash_yaml_exec                                      2013-08-06       excellent  Yes    Squash YAML Code Execution
   789   unix/webapp/squirrelmail_pgp_plugin                               2007-07-09       manual     No     SquirrelMail PGP Plugin Command Execution (SMTP)
   790   unix/webapp/sugarcrm_rest_unserialize_exec                        2016-06-23       excellent  No     SugarCRM REST Unserialize PHP Code Execution
   791   unix/webapp/sugarcrm_unserialize_exec                             2012-06-23       excellent  No     SugarCRM unserialize() PHP Code Execution
   792   unix/webapp/tikiwiki_graph_formula_exec                           2007-10-10       excellent  Yes    TikiWiki tiki-graph_formula Remote PHP Code Execution
   793   unix/webapp/tikiwiki_jhot_exec                                    2006-09-02       excellent  Yes    TikiWiki jhot Remote Command Execution
   794   unix/webapp/tikiwiki_unserialize_exec                             2012-07-04       excellent  No     Tiki Wiki unserialize() PHP Code Execution
   795   unix/webapp/tikiwiki_upload_exec                                  2016-07-11       excellent  Yes    Tiki Wiki Unauthenticated File Upload Vulnerability
   796   unix/webapp/trixbox_langchoice                                    2008-07-09       manual     Yes    Trixbox langChoice PHP Local File Inclusion
   797   unix/webapp/tuleap_rest_unserialize_exec                          2017-10-23       excellent  Yes    Tuleap 9.6 Second-Order PHP Object Injection
   798   unix/webapp/tuleap_unserialize_exec                               2014-11-27       excellent  Yes    Tuleap PHP Unserialize Code Execution
   799   unix/webapp/twiki_history                                         2005-09-14       excellent  Yes    TWiki History TWikiUsers rev Parameter Command Execution
   800   unix/webapp/twiki_maketext                                        2012-12-15       excellent  Yes    TWiki MAKETEXT Remote Command Execution
   801   unix/webapp/twiki_search                                          2004-10-01       excellent  Yes    TWiki Search Function Arbitrary Command Execution
   802   unix/webapp/vbulletin_vote_sqli_exec                              2013-03-25       excellent  Yes    vBulletin index.php/ajax/api/reputation/vote nodeid Parameter SQL Injection
   803   unix/webapp/vicidial_manager_send_cmd_exec                        2013-10-23       excellent  Yes    VICIdial Manager Send OS Command Injection
   804   unix/webapp/vicidial_user_authorization_unauth_cmd_exec           2017-05-26       excellent  Yes    VICIdial user_authorization Unauthenticated Command Execution
   805   unix/webapp/webmin_show_cgi_exec                                  2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   806   unix/webapp/webmin_upload_exec                                    2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE
   807   unix/webapp/webtester_exec                                        2013-10-17       excellent  Yes    WebTester 5.x Command Execution
   808   unix/webapp/wp_admin_shell_upload                                 2015-02-21       excellent  Yes    WordPress Admin Shell Upload
   809   unix/webapp/wp_advanced_custom_fields_exec                        2012-11-14       excellent  Yes    WordPress Plugin Advanced Custom Fields Remote File Inclusion
   810   unix/webapp/wp_ajax_load_more_file_upload                         2015-10-10       excellent  Yes    Wordpress Ajax Load More PHP Upload Vulnerability
   811   unix/webapp/wp_asset_manager_upload_exec                          2012-05-26       excellent  Yes    WordPress Asset-Manager PHP File Upload Vulnerability
   812   unix/webapp/wp_creativecontactform_file_upload                    2014-10-22       excellent  Yes    Wordpress Creative Contact Form Upload Vulnerability
   813   unix/webapp/wp_downloadmanager_upload                             2014-12-03       excellent  Yes    Wordpress Download Manager (download-manager) Unauthenticated File Upload
   814   unix/webapp/wp_easycart_unrestricted_file_upload                  2015-01-08       excellent  No     WordPress WP EasyCart Unrestricted File Upload
   815   unix/webapp/wp_foxypress_upload                                   2012-06-05       excellent  Yes    WordPress Plugin Foxypress uploadify.php Arbitrary Code Execution
   816   unix/webapp/wp_frontend_editor_file_upload                        2012-07-04       excellent  Yes    Wordpress Front-end Editor File Upload
   817   unix/webapp/wp_google_document_embedder_exec                      2013-01-03       normal     Yes    WordPress Plugin Google Document Embedder Arbitrary File Disclosure
   818   unix/webapp/wp_holding_pattern_file_upload                        2015-02-11       excellent  Yes    WordPress Holding Pattern Theme Arbitrary File Upload
   819   unix/webapp/wp_inboundio_marketing_file_upload                    2015-03-24       excellent  Yes    Wordpress InBoundio Marketing PHP Upload Vulnerability
   820   unix/webapp/wp_infusionsoft_upload                                2014-09-25       excellent  Yes    Wordpress InfusionSoft Upload Vulnerability
   821   unix/webapp/wp_lastpost_exec                                      2005-08-09       excellent  No     WordPress cache_lastpostdate Arbitrary Code Execution
   822   unix/webapp/wp_mobile_detector_upload_execute                     2016-05-31       excellent  Yes    WordPress WP Mobile Detector 3.5 Shell Upload
   823   unix/webapp/wp_nmediawebsite_file_upload                          2015-04-12       excellent  Yes    Wordpress N-Media Website Contact Form Upload Vulnerability
   824   unix/webapp/wp_optimizepress_upload                               2013-11-29       excellent  Yes    WordPress OptimizePress Theme File Upload Vulnerability
   825   unix/webapp/wp_photo_gallery_unrestricted_file_upload             2014-11-11       excellent  Yes    WordPress Photo Gallery Unrestricted File Upload
   826   unix/webapp/wp_phpmailer_host_header                              2017-05-03       average    Yes    WordPress PHPMailer Host Header Command Injection
   827   unix/webapp/wp_pixabay_images_upload                              2015-01-19       excellent  Yes    WordPress Pixabay Images PHP Code Upload
   828   unix/webapp/wp_platform_exec                                      2015-01-21       excellent  No     WordPress Platform Theme File Upload Vulnerability
   829   unix/webapp/wp_property_upload_exec                               2012-03-26       excellent  Yes    WordPress WP-Property PHP File Upload Vulnerability
   830   unix/webapp/wp_reflexgallery_file_upload                          2012-12-30       excellent  Yes    Wordpress Reflex Gallery Upload Vulnerability
   831   unix/webapp/wp_revslider_upload_execute                           2014-11-26       excellent  Yes    WordPress RevSlider File Upload and Execute Vulnerability
   832   unix/webapp/wp_slideshowgallery_upload                            2014-08-28       excellent  Yes    Wordpress SlideShow Gallery Authenticated File Upload
   833   unix/webapp/wp_symposium_shell_upload                             2014-12-11       excellent  Yes    WordPress WP Symposium 14.11 Shell Upload
   834   unix/webapp/wp_total_cache_exec                                   2013-04-17       excellent  Yes    WordPress W3 Total Cache PHP Code Execution
   835   unix/webapp/wp_worktheflow_upload                                 2015-03-14       excellent  Yes    Wordpress Work The Flow Upload Vulnerability
   836   unix/webapp/wp_wpshop_ecommerce_file_upload                       2015-03-09       excellent  Yes    WordPress WPshop eCommerce Arbitrary File Upload Vulnerability
   837   unix/webapp/wp_wptouch_file_upload                                2014-07-14       excellent  Yes    WordPress WPTouch Authenticated File Upload
   838   unix/webapp/wp_wysija_newsletters_upload                          2014-07-01       excellent  Yes    Wordpress MailPoet Newsletters (wysija-newsletters) Unauthenticated File Upload
   839   unix/webapp/xoda_file_upload                                      2012-08-21       excellent  Yes    XODA 0.4.5 Arbitrary PHP File Upload Vulnerability
   840   unix/webapp/xymon_useradm_cmd_exec                                2016-02-14       excellent  Yes    Xymon useradm Command Execution
   841   unix/webapp/zeroshell_exec                                        2013-09-22       excellent  Yes    ZeroShell Remote Code Execution
   842   unix/webapp/zimbra_lfi                                            2013-12-06       excellent  Yes    Zimbra Collaboration Server LFI
   843   unix/webapp/zoneminder_packagecontrol_exec                        2013-01-22       excellent  Yes    ZoneMinder Video Server packageControl Command Execution
   844   unix/webapp/zpanel_username_exec                                  2013-06-07       excellent  Yes    ZPanel 10.0.0.2 htpasswd Module Username Command Execution
   845   unix/x11/x11_keyboard_exec                                        2015-07-10       excellent  No     X11 Keyboard Command Injection
   846   windows/antivirus/ams_hndlrsvc                                    2010-07-26       excellent  No     Symantec System Center Alert Management System (hndlrsvc.exe) Arbitrary Command Execution
   847   windows/antivirus/ams_xfr                                         2009-04-28       excellent  No     Symantec System Center Alert Management System (xfr.exe) Arbitrary Command Execution
   848   windows/antivirus/symantec_endpoint_manager_rce                   2014-02-24       excellent  Yes    Symantec Endpoint Protection Manager /servlet/ConsoleServlet Remote Command Execution
   849   windows/antivirus/symantec_iao                                    2009-04-28       good       No     Symantec Alert Management System Intel Alert Originator Service Buffer Overflow
   850   windows/antivirus/symantec_rtvscan                                2006-05-24       good       No     Symantec Remote Management Buffer Overflow
   851   windows/antivirus/symantec_workspace_streaming_exec               2014-05-12       excellent  Yes    Symantec Workspace Streaming ManagementAgentServer.putFile XMLRPC Request Arbitrary File Upload
   852   windows/antivirus/trendmicro_serverprotect                        2007-02-20       good       No     Trend Micro ServerProtect 5.58 Buffer Overflow
   853   windows/antivirus/trendmicro_serverprotect_createbinding          2007-05-07       good       No     Trend Micro ServerProtect 5.58 CreateBinding() Buffer Overflow
   854   windows/antivirus/trendmicro_serverprotect_earthagent             2007-05-07       good       No     Trend Micro ServerProtect 5.58 EarthAgent.EXE Buffer Overflow
   855   windows/arkeia/type77                                             2005-02-18       good       Yes    Arkeia Backup Client Type 77 Overflow (Win32)
   856   windows/backdoor/energizer_duo_payload                            2010-03-05       excellent  No     Energizer DUO USB Battery Charger Arucer.dll Trojan Code Execution
   857   windows/backupexec/name_service                                   2004-12-16       average    No     Veritas Backup Exec Name Service Overflow
   858   windows/backupexec/remote_agent                                   2005-06-22       great      Yes    Veritas Backup Exec Windows Remote Agent Overflow
   859   windows/backupexec/ssl_uaf                                        2017-05-10       normal     Yes    Veritas/Symantec Backup Exec SSL NDMP Connection Use-After-Free
   860   windows/brightstor/ca_arcserve_342                                2008-10-09       average    No     Computer Associates ARCserve REPORTREMOTEEXECUTECML Buffer Overflow
   861   windows/brightstor/discovery_tcp                                  2005-02-14       average    Yes    CA BrightStor Discovery Service TCP Overflow
   862   windows/brightstor/discovery_udp                                  2004-12-20       average    Yes    CA BrightStor Discovery Service Stack Buffer Overflow
   863   windows/brightstor/etrust_itm_alert                               2008-04-04       average    No     Computer Associates Alert Notification Buffer Overflow
   864   windows/brightstor/hsmserver                                      2007-09-27       great      No     CA BrightStor HSM Buffer Overflow
   865   windows/brightstor/lgserver                                       2007-01-31       average    No     CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow
   866   windows/brightstor/lgserver_multi                                 2007-06-06       average    Yes    CA BrightStor ARCserve for Laptops and Desktops LGServer Multiple Commands Buffer Overflow
   867   windows/brightstor/lgserver_rxrlogin                              2007-06-06       average    Yes    CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow
   868   windows/brightstor/lgserver_rxssetdatagrowthscheduleandfilter     2007-06-06       average    Yes    CA BrightStor ARCserve for Laptops and Desktops LGServer rxsSetDataGrowthScheduleAndFilter Buffer Overflow
   869   windows/brightstor/lgserver_rxsuselicenseini                      2007-06-06       average    Yes    CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow
   870   windows/brightstor/license_gcr                                    2005-03-02       average    No     CA BrightStor ARCserve License Service GCR NETWORK Buffer Overflow
   871   windows/brightstor/mediasrv_sunrpc                                2007-04-25       average    No     CA BrightStor ArcServe Media Service Stack Buffer Overflow
   872   windows/brightstor/message_engine                                 2007-01-11       average    No     CA BrightStor ARCserve Message Engine Buffer Overflow
   873   windows/brightstor/message_engine_72                              2010-10-04       average    No     CA BrightStor ARCserve Message Engine 0x72 Buffer Overflow
   874   windows/brightstor/message_engine_heap                            2006-10-05       average    No     CA BrightStor ARCserve Message Engine Heap Overflow
   875   windows/brightstor/sql_agent                                      2005-08-02       average    No     CA BrightStor Agent for Microsoft SQL Overflow
   876   windows/brightstor/tape_engine                                    2006-11-21       average    No     CA BrightStor ARCserve Tape Engine Buffer Overflow
   877   windows/brightstor/tape_engine_0x8a                               2010-10-04       average    No     CA BrightStor ARCserve Tape Engine 0x8A Buffer Overflow
   878   windows/brightstor/universal_agent                                2005-04-11       average    No     CA BrightStor Universal Agent Overflow
   879   windows/browser/adobe_cooltype_sing                               2010-09-07       great      No     Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow
   880   windows/browser/adobe_flash_avm2                                  2014-02-05       normal     No     Adobe Flash Player Integer Underflow Remote Code Execution
   881   windows/browser/adobe_flash_casi32_int_overflow                   2014-10-14       great      No     Adobe Flash Player casi32 Integer Overflow
   882   windows/browser/adobe_flash_copy_pixels_to_byte_array             2014-09-23       great      No     Adobe Flash Player copyPixelsToByteArray Method Integer Overflow
   883   windows/browser/adobe_flash_domain_memory_uaf                     2014-04-14       great      No     Adobe Flash Player domainMemory ByteArray Use After Free
   884   windows/browser/adobe_flash_filters_type_confusion                2013-12-10       normal     No     Adobe Flash Player Type Confusion Remote Code Execution
   885   windows/browser/adobe_flash_mp4_cprt                              2012-02-15       normal     No     Adobe Flash Player MP4 'cprt' Overflow
   886   windows/browser/adobe_flash_otf_font                              2012-08-09       normal     No     Adobe Flash Player 11.3 Kern Table Parsing Integer Overflow
   887   windows/browser/adobe_flash_pcre                                  2014-11-25       normal     No     Adobe Flash Player PCRE Regex Vulnerability
   888   windows/browser/adobe_flash_regex_value                           2013-02-08       normal     No     Adobe Flash Player Regular Expression Heap Overflow
   889   windows/browser/adobe_flash_rtmp                                  2012-05-04       normal     No     Adobe Flash Player Object Type Confusion
   890   windows/browser/adobe_flash_sps                                   2011-08-09       normal     No     Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow
   891   windows/browser/adobe_flash_uncompress_zlib_uninitialized         2014-11-11       good       No     Adobe Flash Player UncompressViaZlibVariant Uninitialized Memory
   892   windows/browser/adobe_flash_worker_byte_array_uaf                 2015-02-02       great      No     Adobe Flash Player ByteArray With Workers Use After Free
   893   windows/browser/adobe_flashplayer_arrayindexing                   2012-06-21       great      No     Adobe Flash Player AVM Verification Logic Array Indexing Code Execution
   894   windows/browser/adobe_flashplayer_avm                             2011-03-15       good       No     Adobe Flash Player AVM Bytecode Verification Vulnerability
   895   windows/browser/adobe_flashplayer_flash10o                        2011-04-11       normal     No     Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability
   896   windows/browser/adobe_flashplayer_newfunction                     2010-06-04       normal     No     Adobe Flash Player "newfunction" Invalid Pointer Use
   897   windows/browser/adobe_flatedecode_predictor02                     2009-10-08       good       No     Adobe FlateDecode Stream Predictor 02 Integer Overflow
   898   windows/browser/adobe_geticon                                     2009-03-24       good       No     Adobe Collab.getIcon() Buffer Overflow
   899   windows/browser/adobe_jbig2decode                                 2009-02-19       good       No     Adobe JBIG2Decode Heap Corruption
   900   windows/browser/adobe_media_newplayer                             2009-12-14       good       No     Adobe Doc.media.newPlayer Use After Free Vulnerability
   901   windows/browser/adobe_shockwave_rcsl_corruption                   2010-10-21       normal     No     Adobe Shockwave rcsL Memory Corruption
   902   windows/browser/adobe_toolbutton                                  2013-08-08       normal     No     Adobe Reader ToolButton Use After Free
   903   windows/browser/adobe_utilprintf                                  2008-02-08       good       No     Adobe util.printf() Buffer Overflow
   904   windows/browser/advantech_webaccess_dvs_getcolor                  2014-07-17       normal     No     Advantech WebAccess dvs.ocx GetColor Buffer Overflow
   905   windows/browser/aim_goaway                                        2004-08-09       great      No     AOL Instant Messenger goaway Overflow
   906   windows/browser/aladdin_choosefilepath_bof                        2012-04-01       normal     No     Aladdin Knowledge System Ltd ChooseFilePath Buffer Overflow
   907   windows/browser/amaya_bdo                                         2009-01-28       normal     No     Amaya Browser v11.0 'bdo' Tag Overflow
   908   windows/browser/aol_ampx_convertfile                              2009-05-19       normal     No     AOL Radio AmpX ActiveX Control ConvertFile() Buffer Overflow
   909   windows/browser/aol_icq_downloadagent                             2006-11-06       excellent  No     America Online ICQ ActiveX Control Arbitrary File Download and Execute
   910   windows/browser/apple_itunes_playlist                             2005-01-11       normal     No     Apple ITunes 4.7 Playlist Buffer Overflow
   911   windows/browser/apple_quicktime_marshaled_punk                    2010-08-30       great      No     Apple QuickTime 7.6.7 _Marshaled_pUnk Code Execution
   912   windows/browser/apple_quicktime_mime_type                         2012-11-07       normal     No     Apple QuickTime 7.7.2 MIME Type Buffer Overflow
   913   windows/browser/apple_quicktime_rdrf                              2013-05-22       normal     No     Apple Quicktime 7 Invalid Atom Length Buffer Overflow
   914   windows/browser/apple_quicktime_rtsp                              2007-01-01       normal     No     Apple QuickTime 7.1.3 RTSP URI Buffer Overflow
   915   windows/browser/apple_quicktime_smil_debug                        2010-08-12       good       No     Apple QuickTime 7.6.6 Invalid SMIL URI Buffer Overflow
   916   windows/browser/apple_quicktime_texml_font_table                  2012-11-07       normal     No     Apple QuickTime 7.7.2 TeXML Style Element font-table Field Stack Buffer Overflow
   917   windows/browser/ask_shortformat                                   2007-09-24       normal     No     Ask.com Toolbar askBar.dll ActiveX Control Buffer Overflow
   918   windows/browser/asus_net4switch_ipswcom                           2012-02-17       normal     No     ASUS Net4Switch ipswcom.dll ActiveX Stack Buffer Overflow
   919   windows/browser/athocgov_completeinstallation                     2008-02-15       normal     No     AtHocGov IWSAlerts ActiveX Control Buffer Overflow
   920   windows/browser/autodesk_idrop                                    2009-04-02       normal     No     Autodesk IDrop ActiveX Control Heap Memory Corruption
   921   windows/browser/aventail_epi_activex                              2010-08-19       normal     No     SonicWALL Aventail epi.dll AuthCredential Format String
   922   windows/browser/awingsoft_web3d_bof                               2009-07-10       average    No     AwingSoft Winds3D Player SceneURL Buffer Overflow
   923   windows/browser/awingsoft_winds3d_sceneurl                        2009-11-14       excellent  No     AwingSoft Winds3D Player 3.5 SceneURL Download and Execute
   924   windows/browser/baofeng_storm_onbeforevideodownload               2009-04-30       normal     No     BaoFeng Storm mps.dll ActiveX OnBeforeVideoDownload Buffer Overflow
   925   windows/browser/barcode_ax49                                      2007-06-22       normal     No     RKD Software BarCodeAx.dll v4.9 ActiveX Remote Stack Buffer Overflow
   926   windows/browser/blackice_downloadimagefileurl                     2008-06-05       excellent  No     Black Ice Cover Page ActiveX Control Arbitrary File Download
   927   windows/browser/c6_messenger_downloaderactivex                    2008-06-03       excellent  No     Icona SpA C6 Messenger DownloaderActiveX Control Arbitrary File Download and Execute
   928   windows/browser/ca_brightstor_addcolumn                           2008-03-16       normal     No     CA BrightStor ARCserve Backup AddColumn() ActiveX Buffer Overflow
   929   windows/browser/chilkat_crypt_writefile                           2008-11-03       excellent  No     Chilkat Crypt ActiveX WriteFile Unsafe Method
   930   windows/browser/chrome_filereader_uaf                             2019-03-21       manual     No     Chrome 72.0.3626.119 FileReader UaF exploit for Windows 7 x86
   931   windows/browser/cisco_anyconnect_exec                             2011-06-01       excellent  No     Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute
   932   windows/browser/cisco_playerpt_setsource                          2012-03-22       normal     No     Cisco Linksys PlayerPT ActiveX Control Buffer Overflow
   933   windows/browser/cisco_playerpt_setsource_surl                     2012-07-17       normal     No     Cisco Linksys PlayerPT ActiveX Control SetSource sURL Argument Buffer Overflow
   934   windows/browser/cisco_webex_ext                                   2017-01-21       great      No     Cisco WebEx Chrome Extension RCE (CVE-2017-3823)
   935   windows/browser/citrix_gateway_actx                               2011-07-14       normal     No     Citrix Gateway ActiveX Control Stack Based Buffer Overflow Vulnerability
   936   windows/browser/clear_quest_cqole                                 2012-05-19       normal     No     IBM Rational ClearQuest CQOle Remote Code Execution
   937   windows/browser/communicrypt_mail_activex                         2010-05-19       great      No     CommuniCrypt Mail 1.16 SMTP ActiveX Stack Buffer Overflow
   938   windows/browser/creative_software_cachefolder                     2008-05-28       normal     No     Creative Software AutoUpdate Engine ActiveX Control Buffer Overflow
   939   windows/browser/crystal_reports_printcontrol                      2010-12-14       normal     No     Crystal Reports CrystalPrintControl ActiveX ServerResourceVersion Property Overflow
   940   windows/browser/dell_webcam_crazytalk                             2012-03-19       normal     No     Dell Webcam CrazyTalk ActiveX BackImage Vulnerability
   941   windows/browser/dxstudio_player_exec                              2009-06-09       excellent  No     Worldweaver DX Studio Player shell.execute() Command Execution
   942   windows/browser/ea_checkrequirements                              2007-10-08       normal     No     Electronic Arts SnoopyCtrl ActiveX Control Buffer Overflow
   943   windows/browser/ebook_flipviewer_fviewerloading                   2007-06-06       normal     No     FlipViewer FViewerLoading ActiveX Control Buffer Overflow
   944   windows/browser/enjoysapgui_comp_download                         2009-04-15       excellent  No     EnjoySAP SAP GUI ActiveX Control Arbitrary File Download
   945   windows/browser/enjoysapgui_preparetoposthtml                     2007-07-05       normal     No     EnjoySAP SAP GUI ActiveX Control Buffer Overflow
   946   windows/browser/exodus                                            2018-01-25       manual     No     Exodus Wallet (ElectronJS Framework) remote Code Execution
   947   windows/browser/facebook_extractiptc                              2008-01-31       normal     No     Facebook Photo Uploader 4 ActiveX Control Buffer Overflow
   948   windows/browser/firefox_smil_uaf                                  2016-11-30       normal     No     Firefox nsSMILTimeContainer::NotifyTimeChange() RCE
   949   windows/browser/foxit_reader_plugin_url_bof                       2013-01-07       normal     No     Foxit Reader Plugin URL Processing Buffer Overflow
   950   windows/browser/getgodm_http_response_bof                         2014-03-09       normal     No     GetGo Download Manager HTTP Response Buffer Overflow
   951   windows/browser/gom_openurl                                       2007-10-27       normal     No     GOM Player ActiveX Control Buffer Overflow
   952   windows/browser/greendam_url                                      2009-06-11       normal     No     Green Dam URL Processing Buffer Overflow
   953   windows/browser/honeywell_hscremotedeploy_exec                    2013-02-22       excellent  No     Honeywell HSC Remote Deployer ActiveX Remote Code Execution
   954   windows/browser/honeywell_tema_exec                               2011-10-20       excellent  No     Honeywell Tema Remote Installer ActiveX Remote Code Execution
   955   windows/browser/hp_alm_xgo_setshapenodetype_exec                  2012-08-29       normal     No     HP Application Lifecycle Management XGO.ocx ActiveX SetShapeNodeType() Remote Code Execution
   956   windows/browser/hp_easy_printer_care_xmlcachemgr                  2012-01-11       great      No     HP Easy Printer Care XMLCacheMgr Class ActiveX Control Remote Code Execution
   957   windows/browser/hp_easy_printer_care_xmlsimpleaccessor            2011-08-16       great      No     HP Easy Printer Care XMLSimpleAccessor Class ActiveX Control Remote Code Execution
   958   windows/browser/hp_loadrunner_addfile                             2008-01-25       normal     No     Persits XUpload ActiveX AddFile Buffer Overflow
   959   windows/browser/hp_loadrunner_addfolder                           2007-12-25       good       No     HP LoadRunner 9.0 ActiveX AddFolder Buffer Overflow
   960   windows/browser/hp_loadrunner_writefilebinary                     2013-07-24       normal     No     HP LoadRunner lrFileIOService ActiveX Remote Code Execution
   961   windows/browser/hp_loadrunner_writefilestring                     2013-07-24       normal     No     HP LoadRunner lrFileIOService ActiveX WriteFileString Remote Code Execution
   962   windows/browser/hpmqc_progcolor                                   2007-04-04       normal     No     HP Mercury Quality Center ActiveX Control ProgColor Buffer Overflow
   963   windows/browser/hyleos_chemviewx_activex                          2010-02-10       good       No     Hyleos ChemView ActiveX Control Stack Buffer Overflow
   964   windows/browser/ibm_spss_c1sizer                                  2013-04-26       normal     No     IBM SPSS SamplePower C1Tab ActiveX Heap Overflow
   965   windows/browser/ibm_tivoli_pme_activex_bof                        2012-03-01       normal     No     IBM Tivoli Provisioning Manager Express for Software Distribution Isig.isigCtl.1 ActiveX RunAndUploadFile() Method Overflow
   966   windows/browser/ibmegath_getxmlvalue                              2009-03-24       normal     No     IBM Access Support ActiveX Control Buffer Overflow
   967   windows/browser/ibmlotusdomino_dwa_uploadmodule                   2007-12-20       normal     No     IBM Lotus Domino Web Access Upload Module Buffer Overflow
   968   windows/browser/ie_cbutton_uaf                                    2012-12-27       normal     No     MS13-008 Microsoft Internet Explorer CButton Object Use-After-Free Vulnerability
   969   windows/browser/ie_cgenericelement_uaf                            2013-05-03       good       No     MS13-038 Microsoft Internet Explorer CGenericElement Object Use-After-Free Vulnerability
   970   windows/browser/ie_createobject                                   2006-04-11       excellent  No     MS06-014 Microsoft Internet Explorer COM CreateObject Code Execution
   971   windows/browser/ie_execcommand_uaf                                2012-09-14       good       No     MS12-063 Microsoft Internet Explorer execCommand Use-After-Free Vulnerability 
   972   windows/browser/ie_iscomponentinstalled                           2006-02-24       normal     No     Microsoft Internet Explorer isComponentInstalled Overflow
   973   windows/browser/ie_setmousecapture_uaf                            2013-09-17       normal     No     MS13-080 Microsoft Internet Explorer SetMouseCapture Use-After-Free
   974   windows/browser/ie_unsafe_scripting                               2010-09-20       manual     No     Microsoft Internet Explorer Unsafe Scripting Misconfiguration
   975   windows/browser/imgeviewer_tifmergemultifiles                     2010-03-03       normal     No     Viscom Image Viewer CP Pro 8.0/Gold 6.0 ActiveX Control
   976   windows/browser/indusoft_issymbol_internationalseparator          2012-04-28       normal     No     InduSoft Web Studio ISSymbol.ocx InternationalSeparator() Heap Overflow
   977   windows/browser/inotes_dwa85w_bof                                 2012-06-01       normal     No     IBM Lotus iNotes dwa85W ActiveX Buffer Overflow
   978   windows/browser/intrust_annotatex_add                             2012-03-28       average    No     Quest InTrust Annotation Objects Uninitialized Pointer
   979   windows/browser/java_basicservice_impl                            2010-10-12       excellent  No     Sun Java Web Start BasicServiceImpl Code Execution
   980   windows/browser/java_cmm                                          2013-03-01       normal     No     Java CMM Remote Code Execution
   981   windows/browser/java_codebase_trust                               2011-02-15       excellent  No     Sun Java Applet2ClassLoader Remote Code Execution
   982   windows/browser/java_docbase_bof                                  2010-10-12       great      No     Sun Java Runtime New Plugin docbase Buffer Overflow
   983   windows/browser/java_mixer_sequencer                              2010-03-30       great      No     Java MixerSequencer Object GM_Song Structure Handling Vulnerability
   984   windows/browser/java_ws_arginject_altjvm                          2010-04-09       excellent  No     Sun Java Web Start Plugin Command Line Argument Injection
   985   windows/browser/java_ws_double_quote                              2012-10-16       excellent  No     Sun Java Web Start Double Quote Injection
   986   windows/browser/java_ws_vmargs                                    2012-02-14       excellent  No     Sun Java Web Start Plugin Command Line Argument Injection
   987   windows/browser/juniper_sslvpn_ive_setupdll                       2006-04-26       normal     No     Juniper SSL-VPN IVE JuniperSetupDLL.dll ActiveX Control Buffer Overflow
   988   windows/browser/kazaa_altnet_heap                                 2007-10-03       normal     No     Kazaa Altnet Download Manager ActiveX Control Buffer Overflow
   989   windows/browser/keyhelp_launchtripane_exec                        2012-06-26       excellent  No     KeyHelp ActiveX LaunchTriPane Remote Code Execution Vulnerability
   990   windows/browser/logitechvideocall_start                           2007-05-31       normal     No     Logitech VideoCall ActiveX Control Buffer Overflow
   991   windows/browser/lpviewer_url                                      2008-10-06       normal     No     iseemedia / Roxio / MGI Software LPViewer ActiveX Control Buffer Overflow
   992   windows/browser/macrovision_downloadandexecute                    2007-10-31       normal     No     Macrovision InstallShield Update Service Buffer Overflow
   993   windows/browser/macrovision_unsafe                                2007-10-20       excellent  No     Macrovision InstallShield Update Service ActiveX Unsafe Method
   994   windows/browser/malwarebytes_update_exec                          2014-12-16       good       No     Malwarebytes Anti-Malware and Anti-Exploit Update Remote Code Execution
   995   windows/browser/maxthon_history_xcs                               2012-11-26       excellent  No     Maxthon3 about:history XCS Trusted Zone Code Execution
   996   windows/browser/mcafee_mcsubmgr_vsprintf                          2006-08-01       normal     No     McAfee Subscription Manager Stack Buffer Overflow
   997   windows/browser/mcafee_mvt_exec                                   2012-04-30       excellent  No     McAfee Virtual Technician MVTControl 6.3.0.1911 GetObject Vulnerability
   998   windows/browser/mcafeevisualtrace_tracetarget                     2007-07-07       normal     No     McAfee Visual Trace ActiveX Control Buffer Overflow
   999   windows/browser/mirc_irc_url                                      2003-10-13       normal     No     mIRC IRC URL Buffer Overflow
   1000  windows/browser/mozilla_attribchildremoved                        2011-12-06       average    No     Firefox 8/9 AttributeChildRemoved() Use-After-Free
   1001  windows/browser/mozilla_firefox_onreadystatechange                2013-06-25       normal     No     Firefox onreadystatechange Event DocumentViewerImpl Use After Free
   1002  windows/browser/mozilla_firefox_xmlserializer                     2013-01-08       normal     No     Firefox XMLSerializer Use After Free
   1003  windows/browser/mozilla_interleaved_write                         2010-10-25       normal     No     Mozilla Firefox Interleaved document.write/appendChild Memory Corruption
   1004  windows/browser/mozilla_mchannel                                  2011-05-10       normal     No     Mozilla Firefox 3.6.16 mChannel Use-After-Free Vulnerability
   1005  windows/browser/mozilla_nssvgvalue                                2011-12-06       average    No     Firefox nsSVGValue Out-of-Bounds Access Vulnerability
   1006  windows/browser/mozilla_nstreerange                               2011-02-02       normal     No     Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability
   1007  windows/browser/mozilla_reduceright                               2011-06-21       normal     No     Mozilla Firefox Array.reduceRight() Integer Overflow
   1008  windows/browser/ms03_020_ie_objecttype                            2003-06-04       normal     No     MS03-020 Microsoft Internet Explorer Object Type
   1009  windows/browser/ms05_054_onload                                   2005-11-21       normal     No     MS05-054 Microsoft Internet Explorer JavaScript OnLoad Handler Remote Code Execution
   1010  windows/browser/ms06_001_wmf_setabortproc                         2005-12-27       great      No     Windows XP/2003/Vista Metafile Escape() SetAbortProc Code Execution
   1011  windows/browser/ms06_013_createtextrange                          2006-03-19       normal     No     MS06-013 Microsoft Internet Explorer createTextRange() Code Execution
   1012  windows/browser/ms06_055_vml_method                               2006-09-19       normal     No     MS06-055 Microsoft Internet Explorer VML Fill Method Code Execution
   1013  windows/browser/ms06_057_webview_setslice                         2006-07-17       normal     No     MS06-057 Microsoft Internet Explorer WebViewFolderIcon setSlice() Overflow
   1014  windows/browser/ms06_067_keyframe                                 2006-11-14       normal     No     MS06-067 Microsoft Internet Explorer Daxctle.OCX KeyFrame Method Heap Buffer Overflow Vulnerability
   1015  windows/browser/ms06_071_xml_core                                 2006-10-10       normal     No     MS06-071 Microsoft Internet Explorer XML Core Services HTTP Request Handling
   1016  windows/browser/ms07_017_ani_loadimage_chunksize                  2007-03-28       great      No     Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (HTTP)
   1017  windows/browser/ms08_041_snapshotviewer                           2008-07-07       excellent  No     Snapshot Viewer for Microsoft Access ActiveX Control Arbitrary File Download
   1018  windows/browser/ms08_053_mediaencoder                             2008-09-09       normal     No     Windows Media Encoder 9 wmex.dll ActiveX Buffer Overflow
   1019  windows/browser/ms08_070_visual_studio_msmask                     2008-08-13       normal     No     Microsoft Visual Studio Mdmask32.ocx ActiveX Buffer Overflow
   1020  windows/browser/ms08_078_xml_corruption                           2008-12-07       normal     No     MS08-078 Microsoft Internet Explorer Data Binding Memory Corruption
   1021  windows/browser/ms09_002_memory_corruption                        2009-02-10       normal     No     MS09-002 Microsoft Internet Explorer 7 CFunctionPointer Uninitialized Memory Corruption
   1022  windows/browser/ms09_043_owc_htmlurl                              2009-08-11       normal     No     Microsoft OWC Spreadsheet HTMLURL Buffer Overflow
   1023  windows/browser/ms09_043_owc_msdso                                2009-07-13       normal     No     Microsoft OWC Spreadsheet msDataSourceObject Memory Corruption
   1024  windows/browser/ms09_072_style_object                             2009-11-20       normal     No     MS09-072 Microsoft Internet Explorer Style getElementsByTagName Memory Corruption
   1025  windows/browser/ms10_002_aurora                                   2010-01-14       normal     No     MS10-002 Microsoft Internet Explorer "Aurora" Memory Corruption
   1026  windows/browser/ms10_002_ie_object                                2010-01-21       normal     No     MS10-002 Microsoft Internet Explorer Object Memory Use-After-Free
   1027  windows/browser/ms10_018_ie_behaviors                             2010-03-09       good       No     MS10-018 Microsoft Internet Explorer DHTML Behaviors Use After Free
   1028  windows/browser/ms10_018_ie_tabular_activex                       2010-03-09       good       No     MS10-018 Microsoft Internet Explorer Tabular Data Control ActiveX Memory Corruption
   1029  windows/browser/ms10_022_ie_vbscript_winhlp32                     2010-02-26       great      No     MS10-022 Microsoft Internet Explorer Winhlp32.exe MsgBox Code Execution
   1030  windows/browser/ms10_026_avi_nsamplespersec                       2010-04-13       normal     No     MS10-026 Microsoft MPEG Layer-3 Audio Stack Based Overflow
   1031  windows/browser/ms10_042_helpctr_xss_cmd_exec                     2010-06-09       excellent  No     Microsoft Help Center XSS and Command Execution
   1032  windows/browser/ms10_046_shortcut_icon_dllloader                  2010-07-16       excellent  No     Microsoft Windows Shell LNK Code Execution
   1033  windows/browser/ms10_090_ie_css_clip                              2010-11-03       good       No     MS10-090 Microsoft Internet Explorer CSS SetUserClip Memory Corruption
   1034  windows/browser/ms11_003_ie_css_import                            2010-11-29       good       No     MS11-003 Microsoft Internet Explorer CSS Recursive Import Use After Free
   1035  windows/browser/ms11_050_mshtml_cobjectelement                    2011-06-16       normal     No     MS11-050 IE mshtml!CObjectElement Use After Free
   1036  windows/browser/ms11_081_option                                   2012-10-11       normal     No     MS11-081 Microsoft Internet Explorer Option Element Use-After-Free
   1037  windows/browser/ms11_093_ole32                                    2011-12-13       normal     No     MS11-093 Microsoft Windows OLE Object File Handling Remote Code Execution
   1038  windows/browser/ms12_004_midi                                     2012-01-10       normal     No     MS12-004 midiOutPlayNextPolyEvent Heap Overflow
   1039  windows/browser/ms12_037_ie_colspan                               2012-06-12       normal     No     MS12-037 Microsoft Internet Explorer Fixed Table Col Span Heap Overflow
   1040  windows/browser/ms12_037_same_id                                  2012-06-12       normal     No     MS12-037 Microsoft Internet Explorer Same ID Property Deleted Object Handling Memory Corruption
   1041  windows/browser/ms13_009_ie_slayoutrun_uaf                        2013-02-13       average    No     MS13-009 Microsoft Internet Explorer SLayoutRun Use-After-Free
   1042  windows/browser/ms13_022_silverlight_script_object                2013-03-12       normal     No     MS13-022 Microsoft Silverlight ScriptObject Unsafe Memory Access
   1043  windows/browser/ms13_037_svg_dashstyle                            2013-03-06       normal     No     MS13-037 Microsoft Internet Explorer COALineDashStyleArray Integer Overflow
   1044  windows/browser/ms13_055_canchor                                  2013-07-09       normal     No     MS13-055 Microsoft Internet Explorer CAnchorElement Use-After-Free
   1045  windows/browser/ms13_059_cflatmarkuppointer                       2013-06-27       normal     No     MS13-059 Microsoft Internet Explorer CFlatMarkupPointer Use-After-Free
   1046  windows/browser/ms13_069_caret                                    2013-09-10       normal     No     MS13-069 Microsoft Internet Explorer CCaret Use-After-Free
   1047  windows/browser/ms13_080_cdisplaypointer                          2013-10-08       normal     No     MS13-080 Microsoft Internet Explorer CDisplayPointer Use-After-Free
   1048  windows/browser/ms13_090_cardspacesigninhelper                    2013-11-08       normal     No     MS13-090 CardSpaceClaimCollection ActiveX Integer Underflow
   1049  windows/browser/ms14_012_cmarkup_uaf                              2014-02-13       normal     No     MS14-012 Microsoft Internet Explorer CMarkup Use-After-Free
   1050  windows/browser/ms14_012_textrange                                2014-03-11       normal     No     MS14-012 Microsoft Internet Explorer TextRange Use-After-Free
   1051  windows/browser/ms14_064_ole_code_execution                       2014-11-13       good       No     MS14-064 Microsoft Internet Explorer Windows OLE Automation Array Remote Code Execution
   1052  windows/browser/ms16_051_vbscript                                 2016-05-10       normal     No     Internet Explorer 11 VBScript Engine Memory Corruption
   1053  windows/browser/msvidctl_mpeg2                                    2009-07-05       normal     No     Microsoft DirectShow (msvidctl.dll) MPEG-2 Memory Corruption
   1054  windows/browser/mswhale_checkforupdates                           2009-04-15       normal     No     Microsoft Whale Intelligent Application Gateway ActiveX Control Buffer Overflow
   1055  windows/browser/msxml_get_definition_code_exec                    2012-06-12       good       No     MS12-043 Microsoft XML Core Services MSXML Uninitialized Memory Corruption
   1056  windows/browser/nctaudiofile2_setformatlikesample                 2007-01-24       normal     No     NCTAudioFile2 v2.x ActiveX Control SetFormatLikeSample() Buffer Overflow
   1057  windows/browser/nis2004_antispam                                  2004-03-19       normal     No     Norton AntiSpam 2004 SymSpamHelper ActiveX Control Buffer Overflow
   1058  windows/browser/nis2004_get                                       2007-05-16       normal     No     Symantec Norton Internet Security 2004 ActiveX Control Buffer Overflow
   1059  windows/browser/notes_handler_cmdinject                           2012-06-18       excellent  No     IBM Lotus Notes Client URL Handler Command Injection
   1060  windows/browser/novell_groupwise_gwcls1_actvx                     2013-01-30       normal     No     Novell GroupWise Client gwcls1.dll ActiveX Remote Code Execution
   1061  windows/browser/novelliprint_callbackurl                          2010-08-20       normal     No     Novell iPrint Client ActiveX Control call-back-url Buffer Overflow
   1062  windows/browser/novelliprint_datetime                             2009-12-08       great      No     Novell iPrint Client ActiveX Control Date/Time Buffer Overflow
   1063  windows/browser/novelliprint_executerequest                       2008-02-22       normal     No     Novell iPrint Client ActiveX Control ExecuteRequest Buffer Overflow
   1064  windows/browser/novelliprint_executerequest_dbg                   2010-08-04       normal     No     Novell iPrint Client ActiveX Control ExecuteRequest debug Buffer Overflow
   1065  windows/browser/novelliprint_getdriversettings                    2008-06-16       normal     No     Novell iPrint Client ActiveX Control Buffer Overflow
   1066  windows/browser/novelliprint_getdriversettings_2                  2010-11-15       normal     No     Novell iPrint Client ActiveX Control Buffer Overflow
   1067  windows/browser/novelliprint_target_frame                         2009-12-08       great      No     Novell iPrint Client ActiveX Control target-frame Buffer Overflow
   1068  windows/browser/ntr_activex_check_bof                             2012-01-11       normal     No     NTR ActiveX Control Check() Method Buffer Overflow
   1069  windows/browser/ntr_activex_stopmodule                            2012-01-11       normal     No     NTR ActiveX Control StopModule() Remote Code Execution
   1070  windows/browser/oracle_autovue_setmarkupmode                      2012-04-18       normal     No     Oracle AutoVue ActiveX Control SetMarkupMode Buffer Overflow
   1071  windows/browser/oracle_dc_submittoexpress                         2009-08-28       normal     No     Oracle Document Capture 10g ActiveX Control Buffer Overflow
   1072  windows/browser/oracle_webcenter_checkoutandopen                  2013-04-16       excellent  No     Oracle WebCenter Content CheckOutAndOpen.dll ActiveX Remote Code Execution
   1073  windows/browser/orbit_connecting                                  2009-02-03       normal     No     Orbit Downloader Connecting Log Creation Buffer Overflow
   1074  windows/browser/ovftool_format_string                             2012-11-08       normal     No     VMWare OVF Tools Format String Vulnerability
   1075  windows/browser/pcvue_func                                        2011-10-05       average    No     PcVue 10.0 SV.UIGrdCtrl.1 'LoadObject()/SaveObject()' Trusted DWORD Vulnerability
   1076  windows/browser/persits_xupload_traversal                         2009-09-29       excellent  No     Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   1077  windows/browser/quickr_qp2_bof                                    2012-05-23       normal     No     IBM Lotus QuickR qp2 ActiveX Buffer Overflow
   1078  windows/browser/real_arcade_installerdlg                          2011-04-03       normal     No     Real Networks Arcade Games StubbyUtil.ProcessMgr ActiveX Arbitrary Code Execution
   1079  windows/browser/realplayer_cdda_uri                               2010-11-15       normal     No     RealNetworks RealPlayer CDDA URI Initialization Vulnerability
   1080  windows/browser/realplayer_console                                2008-03-08       normal     No     RealPlayer rmoc3260.dll ActiveX Control Heap Corruption
   1081  windows/browser/realplayer_import                                 2007-10-18       normal     No     RealPlayer ierpplug.dll ActiveX Control Playlist Name Buffer Overflow
   1082  windows/browser/realplayer_qcp                                    2011-08-16       average    No     RealNetworks Realplayer QCP Parsing Heap Overflow
   1083  windows/browser/realplayer_smil                                   2005-03-01       normal     No     RealNetworks RealPlayer SMIL Buffer Overflow
   1084  windows/browser/roxio_cineplayer                                  2007-04-11       normal     No     Roxio CinePlayer ActiveX Control Buffer Overflow
   1085  windows/browser/safari_xslt_output                                2011-07-20       excellent  No     Apple Safari Webkit libxslt Arbitrary File Creation
   1086  windows/browser/samsung_neti_wiewer_backuptoavi_bof               2012-04-21       normal     No     Samsung NET-i Viewer Multiple ActiveX BackupToAvi() Remote Overflow
   1087  windows/browser/samsung_security_manager_put                      2016-08-05       excellent  No     Samsung Security Manager 1.4 ActiveMQ Broker Service PUT Method Remote Code Execution
   1088  windows/browser/sapgui_saveviewtosessionfile                      2009-03-31       normal     No     SAP AG SAPgui EAI WebViewer3D Buffer Overflow
   1089  windows/browser/siemens_solid_edge_selistctrlx                    2013-05-26       normal     No     Siemens Solid Edge ST4 SEListCtrlX ActiveX Remote Code Execution
   1090  windows/browser/softartisans_getdrivename                         2008-08-25       normal     No     SoftArtisans XFile FileManager ActiveX Control Buffer Overflow
   1091  windows/browser/sonicwall_addrouteentry                           2007-11-01       normal     No     SonicWall SSL-VPN NetExtender ActiveX Control Buffer Overflow
   1092  windows/browser/symantec_altirisdeployment_downloadandinstall     2009-09-09       excellent  No     Symantec Altiris Deployment Solution ActiveX Control Arbitrary File Download and Execute
   1093  windows/browser/symantec_altirisdeployment_runcmd                 2009-11-04       normal     No     Symantec Altiris Deployment Solution ActiveX Control Buffer Overflow
   1094  windows/browser/symantec_appstream_unsafe                         2009-01-15       excellent  No     Symantec AppStream LaunchObj ActiveX Control Arbitrary File Download and Execute
   1095  windows/browser/symantec_backupexec_pvcalendar                    2008-02-28       normal     No     Symantec BackupExec Calendar Control Buffer Overflow
   1096  windows/browser/symantec_consoleutilities_browseandsavefile       2009-11-02       normal     No     Symantec ConsoleUtilities ActiveX Control Buffer Overflow
   1097  windows/browser/synactis_connecttosynactis_bof                    2013-05-30       normal     No     Synactis PDF In-The-Box ConnectToSynactic Stack Buffer Overflow
   1098  windows/browser/systemrequirementslab_unsafe                      2008-10-16       excellent  No     Husdawg, LLC. System Requirements Lab ActiveX Unsafe Method
   1099  windows/browser/teechart_pro                                      2011-08-11       normal     No     TeeChart Professional ActiveX Control Trusted Integer Dereference
   1100  windows/browser/tom_sawyer_tsgetx71ex552                          2011-05-03       normal     No     Tom Sawyer Software GET Extension Factory Remote Code Execution
   1101  windows/browser/trendmicro_extsetowner                            2010-08-25       normal     No     Trend Micro Internet Security Pro 2010 ActiveX extSetOwner() Remote Code Execution
   1102  windows/browser/trendmicro_officescan                             2007-02-12       normal     No     Trend Micro OfficeScan Client ActiveX Control Buffer Overflow
   1103  windows/browser/tumbleweed_filetransfer                           2008-04-07       great      No     Tumbleweed FileTransfer vcst_eu.dll ActiveX Control Buffer Overflow
   1104  windows/browser/ubisoft_uplay_cmd_exec                            2012-07-29       normal     No     Ubisoft uplay 2.0.3 ActiveX Control Arbitrary Code Execution
   1105  windows/browser/ultramjcam_openfiledig_bof                        2012-03-28       normal     No     TRENDnet SecurView Internet Camera UltraMJCam OpenFileDlg Buffer Overflow
   1106  windows/browser/ultraoffice_httpupload                            2008-08-27       good       No     Ultra Shareware Office Control ActiveX HttpUpload Buffer Overflow
   1107  windows/browser/verypdf_pdfview                                   2008-06-16       normal     No     VeryPDF PDFView OCX ActiveX OpenPDF Heap Overflow
   1108  windows/browser/viscom_movieplayer_drawtext                       2010-01-12       normal     No     Viscom Software Movie Player Pro SDK ActiveX 6.8
   1109  windows/browser/vlc_amv                                           2011-03-23       good       No     VLC AMV Dangling Pointer Vulnerability
   1110  windows/browser/vlc_mms_bof                                       2012-03-15       normal     No     VLC MMS Stream Handling Buffer Overflow
   1111  windows/browser/webdav_dll_hijacker                               2010-08-18       manual     No     WebDAV Application DLL Hijacker
   1112  windows/browser/webex_ucf_newobject                               2008-08-06       good       No     WebEx UCF atucfobj.dll ActiveX NewObject Method Buffer Overflow
   1113  windows/browser/wellintech_kingscada_kxclientdownload             2014-01-14       good       No     KingScada kxClientDownload.ocx ActiveX Remote Code Execution
   1114  windows/browser/winamp_playlist_unc                               2006-01-29       great      No     Winamp Playlist UNC Path Computer Name Overflow
   1115  windows/browser/winamp_ultravox                                   2008-01-18       normal     No     Winamp Ultravox Streaming Metadata (in_mp3.dll) Buffer Overflow
   1116  windows/browser/windvd7_applicationtype                           2007-03-20       normal     No     WinDVD7 IASystemInfo.DLL ActiveX Control Buffer Overflow
   1117  windows/browser/winzip_fileview                                   2007-11-02       normal     No     WinZip FileView (WZFILEVIEW.FileViewCtrl.61) ActiveX Buffer Overflow
   1118  windows/browser/wmi_admintools                                    2010-12-21       great      No     Microsoft WMI Administration Tools ActiveX Buffer Overflow
   1119  windows/browser/x360_video_player_set_text_bof                    2015-01-30       normal     No     X360 VideoPlayer ActiveX Control Buffer Overflow
   1120  windows/browser/xmplay_asx                                        2006-11-21       good       No     XMPlay 3.3.0.4 (ASX Filename) Buffer Overflow
   1121  windows/browser/yahoomessenger_fvcom                              2007-08-30       normal     No     Yahoo! Messenger YVerInfo.dll ActiveX Control Buffer Overflow
   1122  windows/browser/yahoomessenger_server                             2007-06-05       good       No     Yahoo! Messenger 8.1.0.249 ActiveX Control Buffer Overflow
   1123  windows/browser/zenturiprogramchecker_unsafe                      2007-05-29       excellent  No     Zenturi ProgramChecker ActiveX Control Arbitrary File Download
   1124  windows/browser/zenworks_helplauncher_exec                        2011-10-19       normal     No     AdminStudio LaunchHelp.dll ActiveX Arbitrary Code Execution
   1125  windows/dcerpc/ms03_026_dcom                                      2003-07-16       great      No     MS03-026 Microsoft RPC DCOM Interface Overflow
   1126  windows/dcerpc/ms05_017_msmq                                      2005-04-12       good       No     MS05-017 Microsoft Message Queueing Service Path Overflow
   1127  windows/dcerpc/ms07_029_msdns_zonename                            2007-04-12       great      No     MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (TCP)
   1128  windows/dcerpc/ms07_065_msmq                                      2007-12-11       good       No     MS07-065 Microsoft Message Queueing Service DNS Name Path Overflow
   1129  windows/email/ms07_017_ani_loadimage_chunksize                    2007-03-28       great      No     Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (SMTP)
   1130  windows/email/ms10_045_outlook_ref_only                           2010-06-01       excellent  No     Outlook ATTACH_BY_REF_ONLY File Execution
   1131  windows/email/ms10_045_outlook_ref_resolve                        2010-06-01       excellent  No     Outlook ATTACH_BY_REF_RESOLVE File Execution
   1132  windows/emc/alphastor_agent                                       2008-05-27       great      No     EMC AlphaStor Agent Buffer Overflow
   1133  windows/emc/alphastor_device_manager_exec                         2013-01-18       excellent  Yes    EMC AlphaStor Device Manager Opcode 0x75 Command Injection
   1134  windows/emc/networker_format_string                               2012-08-29       normal     No     EMC Networker Format String
   1135  windows/emc/replication_manager_exec                              2011-02-07       great      No     EMC Replication Manager Command Execution
   1136  windows/fileformat/a_pdf_wav_to_mp3                               2010-08-17       normal     No     A-PDF WAV to MP3 v1.0.0 Buffer Overflow
   1137  windows/fileformat/abbs_amp_lst                                   2013-06-30       normal     No     ABBS Audio Media Player .LST Buffer Overflow
   1138  windows/fileformat/acdsee_fotoslate_string                        2011-09-12       good       No     ACDSee FotoSlate PLP File id Parameter Overflow
   1139  windows/fileformat/acdsee_xpm                                     2007-11-23       good       No     ACDSee XPM File Section Buffer Overflow
   1140  windows/fileformat/actfax_import_users_bof                        2012-08-28       normal     No     ActiveFax (ActFax) 4.3 Client Importer Buffer Overflow
   1141  windows/fileformat/activepdf_webgrabber                           2008-08-26       low        No     activePDF WebGrabber ActiveX Control Buffer Overflow
   1142  windows/fileformat/adobe_collectemailinfo                         2008-02-08       good       No     Adobe Collab.collectEmailInfo() Buffer Overflow
   1143  windows/fileformat/adobe_cooltype_sing                            2010-09-07       great      No     Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow
   1144  windows/fileformat/adobe_flashplayer_button                       2010-10-28       normal     No     Adobe Flash Player "Button" Remote Code Execution
   1145  windows/fileformat/adobe_flashplayer_newfunction                  2010-06-04       normal     No     Adobe Flash Player "newfunction" Invalid Pointer Use
   1146  windows/fileformat/adobe_flatedecode_predictor02                  2009-10-08       good       No     Adobe FlateDecode Stream Predictor 02 Integer Overflow
   1147  windows/fileformat/adobe_geticon                                  2009-03-24       good       No     Adobe Collab.getIcon() Buffer Overflow
   1148  windows/fileformat/adobe_illustrator_v14_eps                      2009-12-03       great      No     Adobe Illustrator CS4 v14.0.0
   1149  windows/fileformat/adobe_jbig2decode                              2009-02-19       good       No     Adobe JBIG2Decode Memory Corruption
   1150  windows/fileformat/adobe_libtiff                                  2010-02-16       good       No     Adobe Acrobat Bundled LibTIFF Integer Overflow
   1151  windows/fileformat/adobe_media_newplayer                          2009-12-14       good       No     Adobe Doc.media.newPlayer Use After Free Vulnerability
   1152  windows/fileformat/adobe_pdf_embedded_exe                         2010-03-29       excellent  No     Adobe PDF Embedded EXE Social Engineering
   1153  windows/fileformat/adobe_pdf_embedded_exe_nojs                    2010-03-29       excellent  No     Adobe PDF Escape EXE Social Engineering (No JavaScript)
   1154  windows/fileformat/adobe_reader_u3d                               2011-12-06       average    No     Adobe Reader U3D Memory Corruption Vulnerability
   1155  windows/fileformat/adobe_toolbutton                               2013-08-08       normal     No     Adobe Reader ToolButton Use After Free
   1156  windows/fileformat/adobe_u3d_meshdecl                             2009-10-13       good       No     Adobe U3D CLODProgressiveMeshDeclaration Array Overrun
   1157  windows/fileformat/adobe_utilprintf                               2008-02-08       good       No     Adobe util.printf() Buffer Overflow
   1158  windows/fileformat/allplayer_m3u_bof                              2013-10-09       normal     No     ALLPlayer M3U Buffer Overflow
   1159  windows/fileformat/altap_salamander_pdb                           2007-06-19       good       No     Altap Salamander 2.5 PE Viewer Buffer Overflow
   1160  windows/fileformat/aol_desktop_linktag                            2011-01-31       normal     No     AOL Desktop 9.6 RTX Buffer Overflow
   1161  windows/fileformat/aol_phobos_bof                                 2010-01-20       average    No     AOL 9.5 Phobos.Playlist Import() Stack-based Buffer Overflow
   1162  windows/fileformat/apple_quicktime_pnsize                         2011-08-08       good       No     Apple QuickTime PICT PnSize Buffer Overflow
   1163  windows/fileformat/apple_quicktime_rdrf                           2013-05-22       normal     No     Apple Quicktime 7 Invalid Atom Length Buffer Overflow
   1164  windows/fileformat/apple_quicktime_texml                          2012-05-15       normal     No     Apple QuickTime TeXML Style Element Stack Buffer Overflow
   1165  windows/fileformat/audio_coder_m3u                                2013-05-01       normal     No     AudioCoder .M3U Buffer Overflow
   1166  windows/fileformat/audio_wkstn_pls                                2009-12-08       good       No     Audio Workstation 6.4.2.4.3 pls Buffer Overflow
   1167  windows/fileformat/audiotran_pls                                  2010-01-09       good       No     Audiotran 1.4.1 (PLS File) Stack Buffer Overflow
   1168  windows/fileformat/audiotran_pls_1424                             2010-09-09       good       No     Audiotran PLS File Stack Buffer Overflow
   1169  windows/fileformat/aviosoft_plf_buf                               2011-11-09       good       No     Aviosoft Digital TV Player Professional 1.0 Stack Buffer Overflow
   1170  windows/fileformat/bacnet_csv                                     2010-09-16       good       No     BACnet OPC Client Buffer Overflow
   1171  windows/fileformat/beetel_netconfig_ini_bof                       2013-10-12       normal     No     Beetel Connection Manager NetConfig.ini Buffer Overflow
   1172  windows/fileformat/blazedvd_hdtv_bof                              2012-04-03       normal     No     BlazeVideo HDTV Player Pro v6.6 Filename Handling Vulnerability
   1173  windows/fileformat/blazedvd_plf                                   2009-08-03       good       No     BlazeDVD 6.1 PLF Buffer Overflow
   1174  windows/fileformat/boxoft_wav_to_mp3                              2015-08-31       normal     No     Boxoft WAV to MP3 Converter v1.1 Buffer Overflow
   1175  windows/fileformat/bpftp_client_bps_bof                           2014-07-24       normal     No     BulletProof FTP Client BPS Buffer Overflow
   1176  windows/fileformat/bsplayer_m3u                                   2010-01-07       normal     No     BS.Player 2.57 Buffer Overflow (Unicode SEH)
   1177  windows/fileformat/ca_cab                                         2007-06-05       good       No     CA Antivirus Engine CAB Buffer Overflow
   1178  windows/fileformat/cain_abel_4918_rdp                             2008-11-30       good       No     Cain and Abel RDP Buffer Overflow
   1179  windows/fileformat/ccmplayer_m3u_bof                              2011-11-30       good       No     CCMPlayer 1.5 m3u Playlist Stack Based Buffer Overflow
   1180  windows/fileformat/chasys_draw_ies_bmp_bof                        2013-07-26       normal     No     Chasys Draw IES Buffer Overflow
   1181  windows/fileformat/coolpdf_image_stream_bof                       2013-01-18       normal     No     Cool PDF Image Stream Buffer Overflow
   1182  windows/fileformat/corelpdf_fusion_bof                            2013-07-08       normal     No     Corel PDF Fusion Stack Buffer Overflow
   1183  windows/fileformat/csound_getnum_bof                              2012-02-23       normal     No     Csound hetro File Handling Stack Buffer Overflow
   1184  windows/fileformat/cutezip_bof                                    2011-02-12       normal     No     GlobalSCAPE CuteZIP Stack Buffer Overflow
   1185  windows/fileformat/cve_2017_8464_lnk_rce                          2017-06-13       excellent  No     LNK Code Execution Vulnerability
   1186  windows/fileformat/cyberlink_lpp_bof                              2017-09-23       normal     No     CyberLink LabelPrint 2.5 Stack Buffer Overflow
   1187  windows/fileformat/cyberlink_p2g_bof                              2011-09-12       great      No     CyberLink Power2Go name Attribute (p2g) Stack Buffer Overflow Exploit
   1188  windows/fileformat/cytel_studio_cy3                               2011-10-02       good       No     Cytel Studio 9.0 (CY3 File) Stack Buffer Overflow
   1189  windows/fileformat/deepburner_path                                2006-12-19       great      No     AstonSoft DeepBurner (DBR File) Path Buffer Overflow
   1190  windows/fileformat/destinymediaplayer16                           2009-01-03       good       No     Destiny Media Player 1.61 PLS M3U Buffer Overflow
   1191  windows/fileformat/digital_music_pad_pls                          2010-09-17       normal     No     Digital Music Pad Version 8.2.3.3.4 Stack Buffer Overflow
   1192  windows/fileformat/djstudio_pls_bof                               2009-12-30       normal     No     DJ Studio Pro 5.1 .pls Stack Buffer Overflow
   1193  windows/fileformat/djvu_imageurl                                  2008-10-30       low        No     DjVu DjVu_ActiveX_MSOffice.dll ActiveX ComponentBuffer Overflow
   1194  windows/fileformat/dupscout_xml                                   2017-03-29       normal     No     Dup Scout Enterprise v10.4.16 - Import Command Buffer Overflow
   1195  windows/fileformat/dvdx_plf_bof                                   2007-06-02       normal     No     DVD X Player 5.5 .plf PlayList Buffer Overflow
   1196  windows/fileformat/easycdda_pls_bof                               2010-06-07       normal     No     Easy CD-DA Recorder PLS Buffer Overflow
   1197  windows/fileformat/emc_appextender_keyworks                       2009-09-29       average    No     EMC ApplicationXtender (KeyWorks) ActiveX Control Buffer Overflow
   1198  windows/fileformat/erdas_er_viewer_bof                            2013-04-23       normal     No     ERS Viewer 2011 ERS File Handling Buffer Overflow
   1199  windows/fileformat/erdas_er_viewer_rf_report_error                2013-05-23       normal     No     ERS Viewer 2013 ERS File Handling Buffer Overflow
   1200  windows/fileformat/esignal_styletemplate_bof                      2011-09-06       normal     No     eSignal and eSignal Pro File Parsing Buffer Overflow in QUO
   1201  windows/fileformat/etrust_pestscan                                2009-11-02       average    No     CA eTrust PestPatrol ActiveX Control Buffer Overflow
   1202  windows/fileformat/ezip_wizard_bof                                2009-03-09       good       No     eZip Wizard 3.0 Stack Buffer Overflow
   1203  windows/fileformat/fatplayer_wav                                  2010-10-18       normal     No     Fat Player Media Player 0.6b0 Buffer Overflow
   1204  windows/fileformat/fdm_torrent                                    2009-02-02       good       No     Free Download Manager Torrent Parsing Buffer Overflow
   1205  windows/fileformat/feeddemon_opml                                 2009-02-09       great      No     FeedDemon Stack Buffer Overflow
   1206  windows/fileformat/foxit_reader_filewrite                         2011-03-05       normal     No     Foxit PDF Reader 4.2 Javascript File Write
   1207  windows/fileformat/foxit_reader_launch                            2009-03-09       good       No     Foxit Reader 3.0 Open Execute Action Stack Based Buffer Overflow
   1208  windows/fileformat/foxit_reader_uaf                               2018-04-20       normal     No     Foxit PDF Reader Pointer Overwrite UAF
   1209  windows/fileformat/foxit_title_bof                                2010-11-13       great      No     Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow
   1210  windows/fileformat/free_mp3_ripper_wav                            2011-08-27       great      No     Free MP3 CD Ripper 1.1 WAV File Stack Buffer Overflow
   1211  windows/fileformat/galan_fileformat_bof                           2009-12-07       normal     No     gAlan 0.2.1 Buffer Overflow
   1212  windows/fileformat/gsm_sim                                        2010-07-07       normal     No     GSM SIM Editor 5.15 Buffer Overflow
   1213  windows/fileformat/gta_samp                                       2011-09-18       normal     No     GTA SA-MP server.cfg Buffer Overflow
   1214  windows/fileformat/hhw_hhp_compiledfile_bof                       2006-02-06       good       No     HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow
   1215  windows/fileformat/hhw_hhp_contentfile_bof                        2006-02-06       good       No     HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow
   1216  windows/fileformat/hhw_hhp_indexfile_bof                          2009-01-17       good       No     HTML Help Workshop 4.74 (hhp Project File) Buffer Overflow
   1217  windows/fileformat/homm3_h3m                                      2015-07-29       normal     No     Heroes of Might and Magic III .h3m Map file Buffer Overflow
   1218  windows/fileformat/ht_mp3player_ht3_bof                           2009-06-29       good       No     HT-MP3Player 1.0 HT3 File Parsing Buffer Overflow
   1219  windows/fileformat/ibm_forms_viewer_fontname                      2013-12-05       normal     No     IBM Forms Viewer Unicode Buffer Overflow
   1220  windows/fileformat/ibm_pcm_ws                                     2012-02-28       great      No     IBM Personal Communications iSeries Access WorkStation 5.9 Profile
   1221  windows/fileformat/icofx_bof                                      2013-12-10       normal     No     IcoFX Stack Buffer Overflow
   1222  windows/fileformat/ideal_migration_ipj                            2009-12-05       great      No     PointDev IDEAL Migration Buffer Overflow
   1223  windows/fileformat/iftp_schedule_bof                              2014-11-06       normal     No     i-FTP Schedule Buffer Overflow
   1224  windows/fileformat/irfanview_jpeg2000_bof                         2012-01-16       normal     No     Irfanview JPEG2000 jp2 Stack Buffer Overflow
   1225  windows/fileformat/ispvm_xcf_ispxcf                               2012-05-16       normal     No     Lattice Semiconductor ispVM System XCF File Handling Overflow
   1226  windows/fileformat/kingview_kingmess_kvl                          2012-11-20       normal     No     KingView Log File Parsing Buffer Overflow
   1227  windows/fileformat/lattice_pac_bof                                2012-05-16       normal     No     Lattice Semiconductor PAC-Designer 6.21 Symbol Value Buffer Overflow
   1228  windows/fileformat/lotusnotes_lzh                                 2011-05-24       good       No     Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)
   1229  windows/fileformat/magix_musikmaker_16_mmm                        2011-04-26       good       No     Magix Musik Maker 16 .mmm Stack Buffer Overflow
   1230  windows/fileformat/mcafee_hercules_deletesnapshot                 2008-08-04       low        No     McAfee Remediation Client ActiveX Control Buffer Overflow
   1231  windows/fileformat/mcafee_showreport_exec                         2012-01-12       normal     No     McAfee SaaS MyCioScan ShowReport Remote Command Execution
   1232  windows/fileformat/mediacoder_m3u                                 2013-06-24       normal     No     MediaCoder .M3U Buffer Overflow
   1233  windows/fileformat/mediajukebox                                   2009-07-01       normal     No     Media Jukebox 8.0.400 Buffer Overflow (SEH)
   1234  windows/fileformat/microp_mppl                                    2010-08-23       great      No     MicroP 0.1.1.1600 (MPPL File) Stack Buffer Overflow
   1235  windows/fileformat/microsoft_windows_contact                      2019-01-17       normal     No     Microsoft Windows Contact File Format Arbitary Code Execution
   1236  windows/fileformat/millenium_mp3_pls                              2009-07-30       great      No     Millenium MP3 Studio 2.0 (PLS File) Stack Buffer Overflow
   1237  windows/fileformat/mini_stream_pls_bof                            2010-07-16       great      No     Mini-Stream RM-MP3 Converter v3.1.2.1 PLS File Stack Buffer Overflow
   1238  windows/fileformat/mjm_coreplayer2011_s3m                         2011-04-30       good       No     MJM Core Player 2011 .s3m Stack Buffer Overflow
   1239  windows/fileformat/mjm_quickplayer_s3m                            2011-04-30       good       No     MJM QuickPlayer 1.00 Beta 60a / QuickPlayer 2010 .s3m Stack Buffer Overflow
   1240  windows/fileformat/moxa_mediadbplayback                           2010-10-19       average    No     MOXA MediaDBPlayback ActiveX Control Buffer Overflow
   1241  windows/fileformat/mplayer_m3u_bof                                2011-03-19       average    No     MPlayer Lite M3U Buffer Overflow
   1242  windows/fileformat/mplayer_sami_bof                               2011-05-19       normal     No     MPlayer SAMI Subtitle File Buffer Overflow
   1243  windows/fileformat/ms09_067_excel_featheader                      2009-11-10       good       No     MS09-067 Microsoft Excel Malformed FEATHEADER Record Vulnerability
   1244  windows/fileformat/ms10_004_textbytesatom                         2010-02-09       good       No     MS10-004 Microsoft PowerPoint Viewer TextBytesAtom Stack Buffer Overflow
   1245  windows/fileformat/ms10_038_excel_obj_bof                         2010-06-08       normal     No     MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow
   1246  windows/fileformat/ms10_087_rtf_pfragments_bof                    2010-11-09       great      No     MS10-087 Microsoft Word RTF pFragments Stack Buffer Overflow (File Format)
   1247  windows/fileformat/ms11_006_createsizeddibsection                 2010-12-15       great      No     MS11-006 Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow
   1248  windows/fileformat/ms11_021_xlb_bof                               2011-08-09       normal     No     MS11-021 Microsoft Office 2007 Excel .xlb Buffer Overflow
   1249  windows/fileformat/ms12_005                                       2012-01-10       excellent  No     MS12-005 Microsoft Office ClickOnce Unsafe Object Package Handling Vulnerability
   1250  windows/fileformat/ms12_027_mscomctl_bof                          2012-04-10       average    No     MS12-027 MSCOMCTL ActiveX Buffer Overflow
   1251  windows/fileformat/ms13_071_theme                                 2013-09-10       excellent  No     MS13-071 Microsoft Windows Theme File Handling Arbitrary Code Execution
   1252  windows/fileformat/ms14_017_rtf                                   2014-04-01       normal     No     MS14-017 Microsoft Word RTF Object Confusion
   1253  windows/fileformat/ms14_060_sandworm                              2014-10-14       excellent  No     MS14-060 Microsoft Windows OLE Package Manager Code Execution
   1254  windows/fileformat/ms14_064_packager_python                       2014-11-12       excellent  No     MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python
   1255  windows/fileformat/ms14_064_packager_run_as_admin                 2014-10-21       excellent  No     MS14-064 Microsoft Windows OLE Package Manager Code Execution
   1256  windows/fileformat/ms15_020_shortcut_icon_dllloader               2015-03-10       excellent  No     Microsoft Windows Shell LNK Code Execution
   1257  windows/fileformat/ms15_100_mcl_exe                               2015-09-08       excellent  No     MS15-100 Microsoft Windows Media Center MCL Vulnerability
   1258  windows/fileformat/ms_visual_basic_vbp                            2007-09-04       good       No     Microsoft Visual Basic VBP Buffer Overflow
   1259  windows/fileformat/mswin_tiff_overflow                            2013-11-05       average    No     MS13-096 Microsoft Tagged Image File Format (TIFF) Integer Overflow
   1260  windows/fileformat/msworks_wkspictureinterface                    2008-11-28       low        No     Microsoft Works 7 WkImgSrv.dll WKsPictureInterface() ActiveX Code Execution
   1261  windows/fileformat/mymp3player_m3u                                2010-03-18       good       No     Steinberg MyMP3Player 3.0 Buffer Overflow
   1262  windows/fileformat/netop                                          2011-04-28       normal     No     NetOp Remote Control Client 9.5 Buffer Overflow
   1263  windows/fileformat/nitro_reader_jsapi                             2017-07-24       excellent  No     Nitro Pro PDF Reader 11.0.3.173 Javascript API Remote Code Execution
   1264  windows/fileformat/nuance_pdf_launch_overflow                     2010-10-08       great      No     Nuance PDF Reader v6.0 Launch Stack Buffer Overflow
   1265  windows/fileformat/office_dde_delivery                            2017-10-09       manual     No     Microsoft Office DDE Payload Delivery
   1266  windows/fileformat/office_excel_slk                               2018-10-07       manual     No     Microsoft Excel .SLK Payload Delivery
   1267  windows/fileformat/office_ms17_11882                              2017-11-15       manual     No     Microsoft Office CVE-2017-11882
   1268  windows/fileformat/office_ole_multiple_dll_hijack                 2015-12-08       normal     No     Office OLE Multiple DLL Side Loading Vulnerabilities
   1269  windows/fileformat/office_word_hta                                2017-04-14       excellent  No     Microsoft Office Word Malicious Hta Execution
   1270  windows/fileformat/openoffice_ole                                 2008-04-17       normal     No     OpenOffice OLE Importer DocumentSummaryInformation Stream Handling Overflow
   1271  windows/fileformat/orbit_download_failed_bof                      2008-04-03       normal     No     Orbit Downloader URL Unicode Conversion Overflow
   1272  windows/fileformat/orbital_viewer_orb                             2010-02-27       great      No     Orbital Viewer ORB File Parsing Buffer Overflow
   1273  windows/fileformat/ovf_format_string                              2012-11-08       normal     No     VMWare OVF Tools Format String Vulnerability
   1274  windows/fileformat/proshow_cellimage_bof                          2009-08-20       great      No     ProShow Gold v4.0.2549 (PSH File) Stack Buffer Overflow
   1275  windows/fileformat/proshow_load_bof                               2012-06-06       normal     No     Photodex ProShow Producer 5.0.3256 load File Handling Buffer Overflow
   1276  windows/fileformat/publishit_pui                                  2014-02-05       normal     No     Publish-It PUI Buffer Overflow (SEH)
   1277  windows/fileformat/real_networks_netzip_bof                       2011-01-30       good       No     Real Networks Netzip Classic 7.5.1 86 File Parsing Buffer Overflow Vulnerability
   1278  windows/fileformat/real_player_url_property_bof                   2012-12-14       normal     No     RealPlayer RealMedia File Handling Buffer Overflow
   1279  windows/fileformat/realplayer_ver_attribute_bof                   2013-12-20       normal     No     RealNetworks RealPlayer Version Attribute Buffer Overflow
   1280  windows/fileformat/safenet_softremote_groupname                   2009-10-30       good       No     SafeNet SoftRemote GROUPNAME Buffer Overflow
   1281  windows/fileformat/sascam_get                                     2008-12-29       low        No     SasCam Webcam Server v.2.6.5 Get() Method Buffer Overflow
   1282  windows/fileformat/scadaphone_zip                                 2011-09-12       good       No     ScadaTEC ScadaPhone Stack Buffer Overflow
   1283  windows/fileformat/shadow_stream_recorder_bof                     2010-03-29       normal     No     Shadow Stream Recorder 3.0.1.7 Buffer Overflow
   1284  windows/fileformat/shaper_pdf_bof                                 2015-10-03       normal     No     PDF Shaper Buffer Overflow
   1285  windows/fileformat/somplplayer_m3u                                2010-01-22       great      No     S.O.M.P.L 1.0 Player Buffer Overflow
   1286  windows/fileformat/subtitle_processor_m3u_bof                     2011-04-26       normal     No     Subtitle Processor 7.7.1 .M3U SEH Unicode Buffer Overflow
   1287  windows/fileformat/syncbreeze_xml                                 2017-03-29       normal     No     Sync Breeze Enterprise 9.5.16 - Import Command Buffer Overflow
   1288  windows/fileformat/tfm_mmplayer_m3u_ppl_bof                       2012-03-23       good       No     TFM MMPlayer (m3u/ppl File) Buffer Overflow
   1289  windows/fileformat/total_video_player_ini_bof                     2013-11-24       normal     No     Total Video Player 1.3.1 (Settings.ini) - SEH Buffer Overflow
   1290  windows/fileformat/tugzip                                         2008-10-28       good       No     TugZip 3.5 Zip File Parsing Buffer Overflow Vulnerability
   1291  windows/fileformat/ultraiso_ccd                                   2009-04-03       great      No     UltraISO CCD File Parsing Buffer Overflow
   1292  windows/fileformat/ultraiso_cue                                   2007-05-24       great      No     UltraISO CUE File Parsing Buffer Overflow
   1293  windows/fileformat/ursoft_w32dasm                                 2005-01-24       good       No     URSoft W32Dasm Disassembler Function Buffer Overflow
   1294  windows/fileformat/varicad_dwb                                    2010-03-17       great      No     VariCAD 2010-2.05 EN (DWB File) Stack Buffer Overflow
   1295  windows/fileformat/videocharge_studio                             2013-10-27       normal     No     VideoCharge Studio Buffer Overflow (SEH)
   1296  windows/fileformat/videolan_tivo                                  2008-10-22       good       No     VideoLAN VLC TiVo Buffer Overflow
   1297  windows/fileformat/videospirit_visprj                             2011-04-11       good       No     VeryTools Video Spirit Pro
   1298  windows/fileformat/visio_dxf_bof                                  2010-05-04       good       No     Microsoft Office Visio VISIODWG.DLL DXF File Handling Vulnerability
   1299  windows/fileformat/visiwave_vwr_type                              2011-05-20       great      No     VisiWave VWR File Parsing Vulnerability
   1300  windows/fileformat/vlc_mkv                                        2018-05-24       great      No     VLC Media Player MKV Use After Free
   1301  windows/fileformat/vlc_modplug_s3m                                2011-04-07       average    No     VideoLAN VLC ModPlug ReadS3M Stack Buffer Overflow
   1302  windows/fileformat/vlc_realtext                                   2008-11-05       good       No     VLC Media Player RealText Subtitle Overflow
   1303  windows/fileformat/vlc_smb_uri                                    2009-06-24       great      No     VideoLAN Client (VLC) Win32 smb:// URI Buffer Overflow
   1304  windows/fileformat/vlc_webm                                       2011-01-31       good       No     VideoLAN VLC MKV Memory Corruption
   1305  windows/fileformat/vuplayer_cue                                   2009-08-18       good       No     VUPlayer CUE Buffer Overflow
   1306  windows/fileformat/vuplayer_m3u                                   2009-08-18       good       No     VUPlayer M3U Buffer Overflow
   1307  windows/fileformat/watermark_master                               2013-11-01       normal     No     Watermark Master Buffer Overflow (SEH)
   1308  windows/fileformat/winamp_maki_bof                                2009-05-20       normal     No     Winamp MAKI Buffer Overflow
   1309  windows/fileformat/winrar_ace                                     2019-02-05       excellent  No     RARLAB WinRAR ACE Format Input Validation Remote Code Execution
   1310  windows/fileformat/winrar_name_spoofing                           2009-09-28       excellent  No     WinRAR Filename Spoofing
   1311  windows/fileformat/wireshark_mpeg_overflow                        2014-03-20       good       No     Wireshark wiretap/mpeg.c Stack Buffer Overflow
   1312  windows/fileformat/wireshark_packet_dect                          2011-04-18       good       No     Wireshark packet-dect.c Stack Buffer Overflow (local)
   1313  windows/fileformat/wm_downloader_m3u                              2010-07-28       normal     No     WM Downloader 3.1.2.2 Buffer Overflow
   1314  windows/fileformat/xenorate_xpl_bof                               2009-08-19       great      No     Xenorate 2.50 (.xpl) Universal Local Buffer Overflow (SEH)
   1315  windows/fileformat/xion_m3u_sehbof                                2010-11-23       great      No     Xion Audio Player 1.0.126 Unicode Stack Buffer Overflow
   1316  windows/fileformat/xradio_xrl_sehbof                              2011-02-08       normal     No     xRadio 0.95b Buffer Overflow
   1317  windows/fileformat/zahir_enterprise_plus_csv                      2018-09-28       normal     No     Zahir Enterprise Plus 6 Stack Buffer Overflow
   1318  windows/fileformat/zinfaudioplayer221_pls                         2004-09-24       good       No     Zinf Audio Player 2.2.1 (PLS File) Stack Buffer Overflow
   1319  windows/firewall/blackice_pam_icq                                 2004-03-18       great      No     ISS PAM.dll ICQ Parser Buffer Overflow
   1320  windows/firewall/kerio_auth                                       2003-04-28       average    No     Kerio Firewall 2.1.4 Authentication Packet Overflow
   1321  windows/ftp/32bitftp_list_reply                                   2010-10-12       good       No     32bit FTP Client Stack Buffer Overflow 
   1322  windows/ftp/3cdaemon_ftp_user                                     2005-01-04       average    Yes    3Com 3CDaemon 2.0 FTP Username Overflow
   1323  windows/ftp/aasync_list_reply                                     2010-10-12       good       No     AASync v2.2.1.0 (Win32) Stack Buffer Overflow (LIST)
   1324  windows/ftp/ability_server_stor                                   2004-10-22       normal     Yes    Ability Server 2.34 STOR Command Stack Buffer Overflow
   1325  windows/ftp/absolute_ftp_list_bof                                 2011-11-09       normal     No     AbsoluteFTP 1.9.6 - 2.2.10 LIST Command Remote Buffer Overflow
   1326  windows/ftp/ayukov_nftp                                           2017-10-21       normal     No     Ayukov NFTP FTP Client Buffer Overflow
   1327  windows/ftp/bison_ftp_bof                                         2011-08-07       normal     Yes    BisonWare BisonFTP Server Buffer Overflow
   1328  windows/ftp/cesarftp_mkd                                          2006-06-12       average    Yes    Cesar FTP 0.99g MKD Command Buffer Overflow
   1329  windows/ftp/comsnd_ftpd_fmtstr                                    2012-06-08       good       Yes    ComSndFTP v1.3.7 Beta USER Format String (Write4) Vulnerability
   1330  windows/ftp/dreamftp_format                                       2004-03-03       good       Yes    BolinTech Dream FTP Server 1.02 Format String
   1331  windows/ftp/easyfilesharing_pass                                  2006-07-31       average    Yes    Easy File Sharing FTP Server 2.0 PASS Overflow
   1332  windows/ftp/easyftp_cwd_fixret                                    2010-02-16       great      Yes    EasyFTP Server CWD Command Stack Buffer Overflow
   1333  windows/ftp/easyftp_list_fixret                                   2010-07-05       great      Yes    EasyFTP Server LIST Command Stack Buffer Overflow
   1334  windows/ftp/easyftp_mkd_fixret                                    2010-04-04       great      Yes    EasyFTP Server MKD Command Stack Buffer Overflow
   1335  windows/ftp/filecopa_list_overflow                                2006-07-19       average    No     FileCopa FTP Server Pre 18 Jul Version
   1336  windows/ftp/filewrangler_list_reply                               2010-10-12       good       No     FileWrangler 5.30 Stack Buffer Overflow
   1337  windows/ftp/freefloatftp_user                                     2012-06-12       normal     Yes    Free Float FTP Server USER Command Buffer Overflow
   1338  windows/ftp/freefloatftp_wbem                                     2012-12-07       excellent  Yes    FreeFloat FTP Server Arbitrary File Upload
   1339  windows/ftp/freeftpd_pass                                         2013-08-20       normal     Yes    freeFTPd PASS Command Buffer Overflow
   1340  windows/ftp/freeftpd_user                                         2005-11-16       average    Yes    freeFTPd 1.0 Username Overflow
   1341  windows/ftp/ftpgetter_pwd_reply                                   2010-10-12       good       No     FTPGetter Standard v3.55.0.05 Stack Buffer Overflow (PWD)
   1342  windows/ftp/ftppad_list_reply                                     2010-10-12       good       No     FTPPad 1.2.0 Stack Buffer Overflow
   1343  windows/ftp/ftpshell51_pwd_reply                                  2010-10-12       good       No     FTPShell 5.1 Stack Buffer Overflow
   1344  windows/ftp/ftpshell_cli_bof                                      2017-03-04       normal     No     FTPShell client 6.70 (Enterprise edition) Stack Buffer Overflow
   1345  windows/ftp/ftpsynch_list_reply                                   2010-10-12       good       No     FTP Synchronizer Professional 4.0.73.274 Stack Buffer Overflow
   1346  windows/ftp/gekkomgr_list_reply                                   2010-10-12       good       No     Gekko Manager FTP Client Stack Buffer Overflow
   1347  windows/ftp/globalscapeftp_input                                  2005-05-01       great      No     GlobalSCAPE Secure FTP Server Input Overflow
   1348  windows/ftp/goldenftp_pass_bof                                    2011-01-23       average    Yes    GoldenFTP PASS Stack Buffer Overflow
   1349  windows/ftp/httpdx_tolog_format                                   2009-11-17       great      Yes    HTTPDX tolog() Function Format String Vulnerability
   1350  windows/ftp/kmftp_utility_cwd                                     2015-08-23       normal     Yes    Konica Minolta FTP Utility 1.00 Post Auth CWD Command SEH Overflow
   1351  windows/ftp/labf_nfsaxe                                           2017-05-15       normal     No     LabF nfsAxe 3.7 FTP Client Stack Buffer Overflow
   1352  windows/ftp/leapftp_list_reply                                    2010-10-12       good       No     LeapFTP 3.0.1 Stack Buffer Overflow
   1353  windows/ftp/leapftp_pasv_reply                                    2003-06-09       normal     No     LeapWare LeapFTP v2.7.3.600 PASV Reply Client Overflow
   1354  windows/ftp/ms09_053_ftpd_nlst                                    2009-08-31       great      No     MS09-053 Microsoft IIS FTP Server NLST Response Overflow
   1355  windows/ftp/netterm_netftpd_user                                  2005-04-26       great      Yes    NetTerm NetFTPD USER Buffer Overflow
   1356  windows/ftp/odin_list_reply                                       2010-10-12       good       No     Odin Secure FTP 4.1 Stack Buffer Overflow (LIST)
   1357  windows/ftp/open_ftpd_wbem                                        2012-06-18       excellent  Yes    Open-FTPD 1.2 Arbitrary File Upload
   1358  windows/ftp/oracle9i_xdb_ftp_pass                                 2003-08-18       great      Yes    Oracle 9i XDB FTP PASS Overflow (win32)
   1359  windows/ftp/oracle9i_xdb_ftp_unlock                               2003-08-18       great      Yes    Oracle 9i XDB FTP UNLOCK Overflow (win32)
   1360  windows/ftp/pcman_put                                             2015-08-07       normal     Yes    PCMAN FTP Server Buffer Overflow - PUT Command
   1361  windows/ftp/pcman_stor                                            2013-06-27       normal     Yes    PCMAN FTP Server Post-Authentication STOR Command Stack Buffer Overflow
   1362  windows/ftp/proftp_banner                                         2009-08-25       normal     No     ProFTP 2.9 Banner Remote Buffer Overflow
   1363  windows/ftp/quickshare_traversal_write                            2011-02-03       excellent  Yes    QuickShare File Server 1.2.1 Directory Traversal Vulnerability
   1364  windows/ftp/ricoh_dl_bof                                          2012-03-01       normal     Yes    Ricoh DC DL-10 SR10 FTP USER Command Buffer Overflow
   1365  windows/ftp/sami_ftpd_list                                        2013-02-27       low        No     Sami FTP Server LIST Command Buffer Overflow
   1366  windows/ftp/sami_ftpd_user                                        2006-01-24       normal     Yes    KarjaSoft Sami FTP Server v2.02 USER Overflow
   1367  windows/ftp/sasser_ftpd_port                                      2004-05-10       average    No     Sasser Worm avserve FTP PORT Buffer Overflow
   1368  windows/ftp/scriptftp_list                                        2011-10-12       good       No     ScriptFTP LIST Remote Buffer Overflow
   1369  windows/ftp/seagull_list_reply                                    2010-10-12       good       No     Seagull FTP v3.3 Build 409 Stack Buffer Overflow
   1370  windows/ftp/servu_chmod                                           2004-12-31       normal     Yes    Serv-U FTP Server Buffer Overflow
   1371  windows/ftp/servu_mdtm                                            2004-02-26       good       Yes    Serv-U FTPD MDTM Overflow
   1372  windows/ftp/slimftpd_list_concat                                  2005-07-21       great      No     SlimFTPd LIST Concatenation Overflow
   1373  windows/ftp/trellian_client_pasv                                  2010-04-11       normal     No     Trellian FTP Client 3.01 PASV Remote Buffer Overflow
   1374  windows/ftp/turboftp_port                                         2012-10-03       great      Yes    Turbo FTP Server 1.30.823 PORT Overflow
   1375  windows/ftp/vermillion_ftpd_port                                  2009-09-23       great      Yes    Vermillion FTP Daemon PORT Command Memory Corruption
   1376  windows/ftp/warftpd_165_pass                                      1998-03-19       average    No     War-FTPD 1.65 Password Overflow
   1377  windows/ftp/warftpd_165_user                                      1998-03-19       average    No     War-FTPD 1.65 Username Overflow
   1378  windows/ftp/wftpd_size                                            2006-08-23       average    No     Texas Imperial Software WFTPD 3.23 SIZE Overflow
   1379  windows/ftp/winaxe_server_ready                                   2016-11-03       good       No     WinaXe 7.7 FTP Client Remote Buffer Overflow
   1380  windows/ftp/wing_ftp_admin_exec                                   2014-06-19       excellent  Yes    Wing FTP Server Authenticated Command Execution
   1381  windows/ftp/wsftp_server_503_mkd                                  2004-11-29       great      Yes    WS-FTP Server 5.03 MKD Overflow
   1382  windows/ftp/wsftp_server_505_xmd5                                 2006-09-14       average    Yes    Ipswitch WS_FTP Server 5.05 XMD5 Overflow
   1383  windows/ftp/xftp_client_pwd                                       2010-04-22       normal     No     Xftp FTP Client 3.0 PWD Remote Buffer Overflow
   1384  windows/ftp/xlink_client                                          2009-10-03       normal     No     Xlink FTP Client Buffer Overflow
   1385  windows/ftp/xlink_server                                          2009-10-03       good       Yes    Xlink FTP Server Buffer Overflow
   1386  windows/games/mohaa_getinfo                                       2004-07-17       great      No     Medal of Honor Allied Assault getinfo Stack Buffer Overflow
   1387  windows/games/racer_503beta5                                      2008-08-10       great      No     Racer v0.5.3 Beta 5 Buffer Overflow
   1388  windows/games/ut2004_secure                                       2004-06-18       good       Yes    Unreal Tournament 2004 "secure" Overflow (Win32)
   1389  windows/http/adobe_robohelper_authbypass                          2009-09-23       excellent  No     Adobe RoboHelp Server 8 Arbitrary File Upload and Execute
   1390  windows/http/altn_securitygateway                                 2008-06-02       average    Yes    Alt-N SecurityGateway username Buffer Overflow
   1391  windows/http/altn_webadmin                                        2003-06-24       average    No     Alt-N WebAdmin USER Buffer Overflow
   1392  windows/http/amlibweb_webquerydll_app                             2010-08-03       normal     Yes    Amlibweb NetOpacs webquery.dll Stack Buffer Overflow
   1393  windows/http/apache_chunked                                       2002-06-19       good       Yes    Apache Win32 Chunked Encoding
   1394  windows/http/apache_mod_rewrite_ldap                              2006-07-28       great      Yes    Apache Module mod_rewrite LDAP Protocol Buffer Overflow
   1395  windows/http/apache_modjk_overflow                                2007-03-02       great      Yes    Apache mod_jk 1.2.20 Buffer Overflow
   1396  windows/http/apache_tika_jp2_jscript                              2018-04-25       excellent  Yes    Apache Tika Header Command Injection
   1397  windows/http/avaya_ccr_imageupload_exec                           2012-06-28       excellent  No     Avaya IP Office Customer Call Reporter ImageUpload.ashx Remote Command Execution
   1398  windows/http/badblue_ext_overflow                                 2003-04-20       great      Yes    BadBlue 2.5 EXT.dll Buffer Overflow
   1399  windows/http/badblue_passthru                                     2007-12-10       great      No     BadBlue 2.72b PassThru Buffer Overflow
   1400  windows/http/bea_weblogic_jsessionid                              2009-01-13       good       No     BEA WebLogic JSESSIONID Cookie Value Overflow
   1401  windows/http/bea_weblogic_post_bof                                2008-07-17       great      Yes    Oracle Weblogic Apache Connector POST Request Buffer Overflow
   1402  windows/http/bea_weblogic_transfer_encoding                       2008-09-09       great      No     BEA Weblogic Transfer-Encoding Buffer Overflow
   1403  windows/http/belkin_bulldog                                       2009-03-08       average    No     Belkin Bulldog Plus Web Service Buffer Overflow
   1404  windows/http/ca_arcserve_rpc_authbypass                           2011-07-25       excellent  No     CA Arcserve D2D GWT RPC Credential Information Disclosure
   1405  windows/http/ca_igateway_debug                                    2005-10-06       average    Yes    CA iTechnology iGateway Debug Mode Buffer Overflow
   1406  windows/http/ca_totaldefense_regeneratereports                    2011-04-13       excellent  No     CA Total Defense Suite reGenerateReports Stored Procedure SQL Injection
   1407  windows/http/cogent_datahub_command                               2014-04-29       manual     Yes    Cogent DataHub Command Injection
   1408  windows/http/cogent_datahub_request_headers_bof                   2013-07-26       normal     Yes    Cogent DataHub HTTP Server Buffer Overflow
   1409  windows/http/coldfusion_fckeditor                                 2009-07-03       excellent  No     ColdFusion 8.0.1 Arbitrary File Upload and Execute
   1410  windows/http/cyclope_ess_sqli                                     2012-08-08       excellent  Yes    Cyclope Employee Surveillance Solution v6 SQL Injection
   1411  windows/http/desktopcentral_file_upload                           2013-11-11       excellent  Yes    ManageEngine Desktop Central AgentLogUpload Arbitrary File Upload
   1412  windows/http/desktopcentral_statusupdate_upload                   2014-08-31       excellent  Yes    ManageEngine Desktop Central StatusUpdate Arbitrary File Upload
   1413  windows/http/disk_pulse_enterprise_bof                            2016-10-03       excellent  Yes    Disk Pulse Enterprise Login Buffer Overflow
   1414  windows/http/disk_pulse_enterprise_get                            2017-08-25       excellent  Yes    Disk Pulse Enterprise GET Buffer Overflow
   1415  windows/http/diskboss_get_bof                                     2016-12-05       excellent  Yes    DiskBoss Enterprise GET Buffer Overflow
   1416  windows/http/disksavvy_get_bof                                    2016-12-01       excellent  Yes    DiskSavvy Enterprise GET Buffer Overflow
   1417  windows/http/disksorter_bof                                       2017-03-15       great      Yes    Disk Sorter Enterprise GET Buffer Overflow
   1418  windows/http/dup_scout_enterprise_login_bof                       2017-11-14       excellent  Yes    Dup Scout Enterprise Login Buffer Overflow
   1419  windows/http/dupscts_bof                                          2017-03-15       great      Yes    Dup Scout Enterprise GET Buffer Overflow
   1420  windows/http/easychatserver_seh                                   2017-10-09       normal     No     Easy Chat Server User Registeration Buffer Overflow (SEH)
   1421  windows/http/easyfilesharing_post                                 2017-06-12       normal     No     Easy File Sharing HTTP Server 7.2 POST Buffer Overflow
   1422  windows/http/easyfilesharing_seh                                  2015-12-02       normal     No     Easy File Sharing HTTP Server 7.2 SEH Overflow
   1423  windows/http/easyftp_list                                         2010-02-18       great      Yes    EasyFTP Server list.html path Stack Buffer Overflow
   1424  windows/http/edirectory_host                                      2006-10-21       great      No     Novell eDirectory NDS Server Host Header Overflow
   1425  windows/http/edirectory_imonitor                                  2005-08-11       great      No     eDirectory 8.7.3 iMonitor Remote Stack Buffer Overflow
   1426  windows/http/efs_easychatserver_username                          2007-08-14       great      Yes    EFS Easy Chat Server Authentication Request Handling Buffer Overflow
   1427  windows/http/efs_fmws_userid_bof                                  2014-05-20       normal     Yes    Easy File Management Web Server Stack Buffer Overflow
   1428  windows/http/ektron_xslt_exec                                     2012-10-16       excellent  Yes    Ektron 8.02 XSLT Transform Remote Code Execution
   1429  windows/http/ektron_xslt_exec_ws                                  2015-02-05       excellent  Yes    Ektron 8.5, 8.7, 9.0 XSLT Transform Remote Code Execution
   1430  windows/http/ericom_access_now_bof                                2014-06-02       normal     Yes    Ericom AccessNow Server Buffer Overflow
   1431  windows/http/ezserver_http                                        2012-06-18       excellent  No     EZHomeTech EzServer Stack Buffer Overflow Vulnerability
   1432  windows/http/fdm_auth_header                                      2009-02-02       great      No     Free Download Manager Remote Control Server Buffer Overflow
   1433  windows/http/generic_http_dll_injection                           2015-03-04       manual     No     Generic Web Application DLL Injection
   1434  windows/http/geutebrueck_gcore_x64_rce_bo                         2017-01-24       normal     Yes    Geutebrueck GCore - GCoreServer.exe Buffer Overflow RCE
   1435  windows/http/gitstack_rce                                         2018-01-15       great      No     GitStack Unsanitized Argument RCE
   1436  windows/http/hp_autopass_license_traversal                        2014-01-10       great      Yes    HP AutoPass License Server File Upload
   1437  windows/http/hp_imc_bims_upload                                   2013-10-08       excellent  Yes    HP Intelligent Management Center BIMS UploadServlet Directory Traversal
   1438  windows/http/hp_imc_java_deserialize                              2017-10-03       excellent  Yes    HP Intelligent Management Java Deserialization RCE
   1439  windows/http/hp_imc_mibfileupload                                 2013-03-07       great      Yes    HP Intelligent Management Center Arbitrary File Upload
   1440  windows/http/hp_loadrunner_copyfiletoserver                       2013-10-30       excellent  Yes    HP LoadRunner EmulationAdmin Web Service Directory Traversal
   1441  windows/http/hp_mpa_job_acct                                      2011-12-21       excellent  Yes    HP Managed Printing Administration jobAcct Remote Command Execution
   1442  windows/http/hp_nnm_getnnmdata_hostname                           2010-05-11       great      No     HP OpenView Network Node Manager getnnmdata.exe (Hostname) CGI Buffer Overflow
   1443  windows/http/hp_nnm_getnnmdata_icount                             2010-05-11       great      No     HP OpenView Network Node Manager getnnmdata.exe (ICount) CGI Buffer Overflow
   1444  windows/http/hp_nnm_getnnmdata_maxage                             2010-05-11       great      No     HP OpenView Network Node Manager getnnmdata.exe (MaxAge) CGI Buffer Overflow
   1445  windows/http/hp_nnm_nnmrptconfig_nameparams                       2011-01-10       normal     No     HP OpenView NNM nnmRptConfig nameParams Buffer Overflow
   1446  windows/http/hp_nnm_nnmrptconfig_schdparams                       2011-01-10       normal     No     HP OpenView NNM nnmRptConfig.exe schdParams Buffer Overflow
   1447  windows/http/hp_nnm_openview5                                     2007-12-06       great      No     HP OpenView Network Node Manager OpenView5.exe CGI Buffer Overflow
   1448  windows/http/hp_nnm_ovalarm_lang                                  2009-12-09       great      No     HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow
   1449  windows/http/hp_nnm_ovas                                          2008-04-02       good       Yes    HP OpenView NNM 7.53, 7.51 OVAS.EXE Pre-Authentication Stack Buffer Overflow
   1450  windows/http/hp_nnm_ovbuildpath_textfile                          2011-11-01       normal     No     HP OpenView Network Node Manager ov.dll _OVBuildPath Buffer Overflow
   1451  windows/http/hp_nnm_ovwebhelp                                     2009-12-09       great      No     HP OpenView Network Node Manager OvWebHelp.exe CGI Buffer Overflow
   1452  windows/http/hp_nnm_ovwebsnmpsrv_main                             2010-06-16       great      No     HP OpenView Network Node Manager ovwebsnmpsrv.exe main Buffer Overflow
   1453  windows/http/hp_nnm_ovwebsnmpsrv_ovutil                           2010-06-16       great      No     HP OpenView Network Node Manager ovwebsnmpsrv.exe ovutil Buffer Overflow
   1454  windows/http/hp_nnm_ovwebsnmpsrv_uro                              2010-06-08       great      No     HP OpenView Network Node Manager ovwebsnmpsrv.exe Unrecognized Option Buffer Overflow
   1455  windows/http/hp_nnm_snmp                                          2009-12-09       great      No     HP OpenView Network Node Manager Snmp.exe CGI Buffer Overflow
   1456  windows/http/hp_nnm_snmpviewer_actapp                             2010-05-11       great      No     HP OpenView Network Node Manager snmpviewer.exe Buffer Overflow
   1457  windows/http/hp_nnm_toolbar_01                                    2009-01-07       great      No     HP OpenView Network Node Manager Toolbar.exe CGI Buffer Overflow
   1458  windows/http/hp_nnm_toolbar_02                                    2009-01-21       normal     No     HP OpenView Network Node Manager Toolbar.exe CGI Cookie Handling Buffer Overflow
   1459  windows/http/hp_nnm_webappmon_execvp                              2010-07-20       great      No     HP OpenView Network Node Manager execvp_nc Buffer Overflow
   1460  windows/http/hp_nnm_webappmon_ovjavalocale                        2010-08-03       great      No     HP NNM CGI webappmon.exe OvJavaLocale Buffer Overflow
   1461  windows/http/hp_openview_insight_backdoor                         2011-01-31       excellent  No     HP OpenView Performance Insight Server Backdoor Account Code Execution
   1462  windows/http/hp_pcm_snac_update_certificates                      2013-09-09       excellent  Yes    HP ProCurve Manager SNAC UpdateCertificatesServlet File Upload
   1463  windows/http/hp_pcm_snac_update_domain                            2013-09-09       excellent  Yes    HP ProCurve Manager SNAC UpdateDomainControllerServlet File Upload
   1464  windows/http/hp_power_manager_filename                            2011-10-19       normal     No     HP Power Manager 'formExportDataLogs' Buffer Overflow
   1465  windows/http/hp_power_manager_login                               2009-11-04       average    No     Hewlett-Packard Power Manager Administration Buffer Overflow
   1466  windows/http/hp_sitescope_dns_tool                                2015-10-09       good       No     HP SiteScope DNS Tool Command Injection
   1467  windows/http/hp_sitescope_runomagentcommand                       2013-07-29       manual     Yes    HP SiteScope Remote Code Execution
   1468  windows/http/httpdx_handlepeer                                    2009-10-08       great      Yes    HTTPDX h_handlepeer() Function Buffer Overflow
   1469  windows/http/httpdx_tolog_format                                  2009-11-17       great      Yes    HTTPDX tolog() Function Format String Vulnerability
   1470  windows/http/ia_webmail                                           2003-11-03       average    No     IA WebMail 3.x Buffer Overflow
   1471  windows/http/ibm_tivoli_endpoint_bof                              2011-05-31       good       No     IBM Tivoli Endpoint Manager POST Query Buffer Overflow
   1472  windows/http/ibm_tpmfosd_overflow                                 2007-05-02       good       No     IBM TPM for OS Deployment 5.1.0.x rembo.exe Buffer Overflow
   1473  windows/http/ibm_tsm_cad_header                                   2007-09-24       good       No     IBM Tivoli Storage Manager Express CAD Service Buffer Overflow
   1474  windows/http/icecast_header                                       2004-09-28       great      No     Icecast Header Overwrite
   1475  windows/http/integard_password_bof                                2010-09-07       great      No     Race River Integard Home/Pro LoginAdmin Password Stack Buffer Overflow
   1476  windows/http/intersystems_cache                                   2009-09-29       great      No     InterSystems Cache UtilConfigHome.csp Argument Buffer Overflow
   1477  windows/http/intrasrv_bof                                         2013-05-30       manual     Yes    Intrasrv 1.0 Buffer Overflow
   1478  windows/http/ipswitch_wug_maincfgret                              2004-08-25       great      No     Ipswitch WhatsUp Gold 8.03 Buffer Overflow
   1479  windows/http/jira_collector_traversal                             2014-02-26       normal     Yes    JIRA Issues Collector Directory Traversal
   1480  windows/http/kaseya_uploader                                      2015-09-23       excellent  Yes    Kaseya VSA uploader.aspx Arbitrary File Upload
   1481  windows/http/kaseya_uploadimage_file_upload                       2013-11-11       excellent  Yes    Kaseya uploadImage Arbitrary File Upload
   1482  windows/http/kolibri_http                                         2010-12-26       good       Yes    Kolibri HTTP Server HEAD Buffer Overflow
   1483  windows/http/landesk_thinkmanagement_upload_asp                   2012-02-15       excellent  No     LANDesk Lenovo ThinkManagement Console Remote Command Execution
   1484  windows/http/lexmark_markvision_gfd_upload                        2014-12-09       excellent  Yes    Lexmark MarkVision Enterprise Arbitrary File Upload
   1485  windows/http/mailenable_auth_header                               2005-04-24       great      Yes    MailEnable Authorization Header Buffer Overflow
   1486  windows/http/manage_engine_opmanager_rce                          2015-09-14       manual     Yes    ManageEngine OpManager Remote Code Execution
   1487  windows/http/manageengine_adshacluster_rce                        2018-06-28       excellent  Yes    Manage Engine Exchange Reporter Plus Unauthenticated RCE
   1488  windows/http/manageengine_appmanager_exec                         2018-03-07       excellent  Yes    ManageEngine Applications Manager Remote Code Execution
   1489  windows/http/manageengine_apps_mngr                               2011-04-08       average    No     ManageEngine Applications Manager Authenticated Code Execution
   1490  windows/http/manageengine_connectionid_write                      2015-12-14       excellent  Yes    ManageEngine Desktop Central 9 FileUploadServlet ConnectionId Vulnerability
   1491  windows/http/maxdb_webdbm_database                                2006-08-29       good       No     MaxDB WebDBM Database Parameter Overflow
   1492  windows/http/maxdb_webdbm_get_overflow                            2005-04-26       good       No     MaxDB WebDBM GET Buffer Overflow
   1493  windows/http/mcafee_epolicy_source                                2006-07-17       average    Yes    McAfee ePolicy Orchestrator / ProtectionPilot Overflow
   1494  windows/http/mdaemon_worldclient_form2raw                         2003-12-29       great      Yes    MDaemon WorldClient form2raw.cgi Stack Buffer Overflow
   1495  windows/http/minishare_get_overflow                               2004-11-07       average    No     Minishare 1.4.1 Buffer Overflow
   1496  windows/http/miniweb_upload_wbem                                  2013-04-09       excellent  Yes    MiniWeb (Build 300) Arbitrary File Upload
   1497  windows/http/navicopa_get_overflow                                2006-09-28       great      Yes    NaviCOPA 2.0.1 URL Handling Buffer Overflow
   1498  windows/http/netdecision_http_bof                                 2012-02-24       normal     Yes    NetDecision 4.5.1 HTTP Server Buffer Overflow
   1499  windows/http/netgear_nms_rce                                      2016-02-04       excellent  Yes    NETGEAR ProSafe Network Management System 300 Arbitrary File Upload
   1500  windows/http/novell_imanager_upload                               2010-10-01       excellent  No     Novell iManager getMultiPartParameters Arbitrary File Upload
   1501  windows/http/novell_mdm_lfi                                       2013-03-13       excellent  Yes    Novell Zenworks Mobile Managment MDM.php Local File Inclusion Vulnerability
   1502  windows/http/novell_messenger_acceptlang                          2006-04-13       average    No     Novell Messenger Server 2.0 Accept-Language Overflow
   1503  windows/http/nowsms                                               2008-02-19       good       No     Now SMS/MMS Gateway Buffer Overflow
   1504  windows/http/oats_weblogic_console                                2019-03-13       excellent  Yes    Oracle Application Testing Suite WebLogic Server Administration Console War Deployment
   1505  windows/http/octopusdeploy_deploy                                 2017-05-15       excellent  Yes    Octopus Deploy Authenticated Code Execution
   1506  windows/http/oracle9i_xdb_pass                                    2003-08-18       great      Yes    Oracle 9i XDB HTTP PASS Overflow (win32)
   1507  windows/http/oracle_beehive_evaluation                            2010-06-09       excellent  Yes    Oracle BeeHive 2 voice-servlet processEvaluation() Vulnerability
   1508  windows/http/oracle_beehive_prepareaudiotoplay                    2015-11-10       excellent  Yes    Oracle BeeHive 2 voice-servlet prepareAudioToPlay() Arbitrary File Upload
   1509  windows/http/oracle_btm_writetofile                               2012-08-07       excellent  No     Oracle Business Transaction Management FlashTunnelService Remote Code Execution
   1510  windows/http/oracle_endeca_exec                                   2013-07-16       excellent  Yes    Oracle Endeca Server Remote Command Execution
   1511  windows/http/oracle_event_processing_upload                       2014-04-21       excellent  Yes    Oracle Event Processing FileUploadServlet Arbitrary File Upload
   1512  windows/http/osb_uname_jlist                                      2010-07-13       excellent  No     Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability
   1513  windows/http/peercast_url                                         2006-03-08       average    No     PeerCast URL Handling Buffer Overflow
   1514  windows/http/php_apache_request_headers_bof                       2012-05-08       normal     No     PHP apache_request_headers Function Buffer Overflow
   1515  windows/http/privatewire_gateway                                  2006-06-26       average    No     Private Wire Gateway Buffer Overflow
   1516  windows/http/psoproxy91_overflow                                  2004-02-20       average    Yes    PSO Proxy v0.91 Stack Buffer Overflow
   1517  windows/http/rabidhamster_r4_log                                  2012-02-09       normal     Yes    RabidHamster R4 Log Entry sprintf() Buffer Overflow
   1518  windows/http/rejetto_hfs_exec                                     2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution
   1519  windows/http/sambar6_search_results                               2003-06-21       normal     Yes    Sambar 6 Search Results Buffer Overflow
   1520  windows/http/sap_configservlet_exec_noauth                        2012-11-01       great      Yes    SAP ConfigServlet Remote Code Execution
   1521  windows/http/sap_host_control_cmd_exec                            2012-08-14       average    Yes    SAP NetWeaver HostControl Command Injection
   1522  windows/http/sapdb_webtools                                       2007-07-05       great      No     SAP DB 7.4 WebTools Buffer Overflow
   1523  windows/http/savant_31_overflow                                   2002-09-10       great      Yes    Savant 3.1 Web Server Overflow
   1524  windows/http/sepm_auth_bypass_rce                                 2015-07-31       excellent  No     Symantec Endpoint Protection Manager Authentication Bypass and Code Execution
   1525  windows/http/serviio_checkstreamurl_cmd_exec                      2017-05-03       excellent  Yes    Serviio Media Server checkStreamUrl Command Execution
   1526  windows/http/servu_session_cookie                                 2009-11-01       good       Yes    Rhinosoft Serv-U Session Cookie Buffer Overflow
   1527  windows/http/shoutcast_format                                     2004-12-23       average    Yes    SHOUTcast DNAS/win32 1.9.4 File Request Format String Overflow
   1528  windows/http/shttpd_post                                          2006-10-06       average    No     SHTTPD URI-Encoded POST Request Overflow
   1529  windows/http/solarwinds_fsm_userlogin                             2015-03-13       excellent  Yes    Solarwinds Firewall Security Manager 6.6.5 Client Session Handling Vulnerability
   1530  windows/http/solarwinds_storage_manager_sql                       2011-12-07       excellent  Yes    Solarwinds Storage Manager 5.1.0 SQL Injection
   1531  windows/http/sonicwall_scrutinizer_sqli                           2012-07-22       excellent  Yes    Dell SonicWALL (Plixer) Scrutinizer 9 SQL Injection
   1532  windows/http/steamcast_useragent                                  2008-01-24       average    Yes    Streamcast HTTP User-Agent Buffer Overflow
   1533  windows/http/sws_connection_bof                                   2012-07-20       normal     Yes    Simple Web Server Connection Header Buffer Overflow
   1534  windows/http/sybase_easerver                                      2005-07-25       average    No     Sybase EAServer 5.2 Remote Stack Buffer Overflow
   1535  windows/http/syncbreeze_bof                                       2017-03-15       great      Yes    Sync Breeze Enterprise GET Buffer Overflow
   1536  windows/http/sysax_create_folder                                  2012-07-29       normal     No     Sysax Multi Server 5.64 Create Folder Buffer Overflow
   1537  windows/http/tomcat_cgi_cmdlineargs                               2019-04-10       excellent  Yes    Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability
   1538  windows/http/trackercam_phparg_overflow                           2005-02-18       average    Yes    TrackerCam PHP Argument Buffer Overflow
   1539  windows/http/trackit_file_upload                                  2014-10-07       excellent  Yes    Numara / BMC Track-It! FileStorageService Arbitrary File Upload
   1540  windows/http/trendmicro_officescan                                2007-06-28       good       No     Trend Micro OfficeScan Remote Stack Buffer Overflow
   1541  windows/http/trendmicro_officescan_widget_exec                    2017-10-07       excellent  Yes    Trend Micro OfficeScan Remote Code Execution
   1542  windows/http/ultraminihttp_bof                                    2013-07-10       normal     No     Ultra Mini HTTPD Stack Buffer Overflow
   1543  windows/http/umbraco_upload_aspx                                  2012-06-28       excellent  No     Umbraco CMS Remote Command Execution
   1544  windows/http/vmware_vcenter_chargeback_upload                     2013-05-15       excellent  Yes    VMware vCenter Chargeback Manager ImageUploadServlet Arbitrary File Upload
   1545  windows/http/vxsrchs_bof                                          2017-03-15       great      Yes    VX Search Enterprise GET Buffer Overflow
   1546  windows/http/webster_http                                         2002-12-02       average    No     Webster HTTP Server GET Buffer Overflow
   1547  windows/http/xampp_webdav_upload_php                              2012-01-14       excellent  No     XAMPP WebDAV PHP Upload
   1548  windows/http/xitami_if_mod_since                                  2007-09-24       average    Yes    Xitami 2.5c2 Web Server If-Modified-Since Overflow
   1549  windows/http/zenworks_assetmgmt_uploadservlet                     2011-11-02       excellent  No     Novell ZENworks Asset Management Remote Execution
   1550  windows/http/zenworks_uploadservlet                               2010-03-30       excellent  No     Novell ZENworks Configuration Management Remote Execution
   1551  windows/ibm/ibm_was_dmgr_java_deserialization_rce                 2019-05-15       excellent  No     IBM Websphere Application Server Network Deployment Untrusted Data Deserialization Remote Code Execution
   1552  windows/iis/iis_webdav_scstoragepathfromurl                       2017-03-26       manual     Yes     Microsoft IIS WebDav ScStoragePathFromUrl Overflow
   1553  windows/iis/iis_webdav_upload_asp                                 2004-12-31       excellent  No     Microsoft IIS WebDAV Write Access Code Execution
   1554  windows/iis/ms01_023_printer                                      2001-05-01       good       Yes    MS01-023 Microsoft IIS 5.0 Printer Host Header Overflow
   1555  windows/iis/ms01_026_dbldecode                                    2001-05-15       excellent  Yes    MS01-026 Microsoft IIS/PWS CGI Filename Double Decode Command Execution
   1556  windows/iis/ms01_033_idq                                          2001-06-18       good       No     MS01-033 Microsoft IIS 5.0 IDQ Path Overflow
   1557  windows/iis/ms02_018_htr                                          2002-04-10       good       No     MS02-018 Microsoft IIS 4.0 .HTR Path Overflow
   1558  windows/iis/ms02_065_msadc                                        2002-11-20       normal     Yes    MS02-065 Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow
   1559  windows/iis/ms03_007_ntdll_webdav                                 2003-05-30       great      Yes    MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow
   1560  windows/iis/msadc                                                 1998-07-17       excellent  Yes    MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution
   1561  windows/imap/eudora_list                                          2005-12-20       great      Yes    Qualcomm WorldMail 3.0 IMAPD LIST Buffer Overflow
   1562  windows/imap/imail_delete                                         2004-11-12       average    No     IMail IMAP4D Delete Overflow
   1563  windows/imap/ipswitch_search                                      2007-07-18       average    No     Ipswitch IMail IMAP SEARCH Buffer Overflow
   1564  windows/imap/mailenable_login                                     2006-12-11       great      No     MailEnable IMAPD (2.34/2.35) Login Request Buffer Overflow
   1565  windows/imap/mailenable_status                                    2005-07-13       great      No     MailEnable IMAPD (1.54) STATUS Request Buffer Overflow
   1566  windows/imap/mailenable_w3c_select                                2005-10-03       great      Yes    MailEnable IMAPD W3C Logging Buffer Overflow
   1567  windows/imap/mdaemon_cram_md5                                     2004-11-12       great      No     Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow
   1568  windows/imap/mdaemon_fetch                                        2008-03-13       great      Yes    MDaemon 9.6.4 IMAPD FETCH Buffer Overflow
   1569  windows/imap/mercur_imap_select_overflow                          2006-03-17       average    No     Mercur v5.0 IMAP SP3 SELECT Buffer Overflow
   1570  windows/imap/mercur_login                                         2006-03-17       average    No     Mercur Messaging 2005 IMAP Login Buffer Overflow
   1571  windows/imap/mercury_login                                        2007-03-06       normal     Yes    Mercury/32 4.01 IMAP LOGIN SEH Buffer Overflow
   1572  windows/imap/mercury_rename                                       2004-11-29       average    Yes    Mercury/32 v4.01a IMAP RENAME Buffer Overflow
   1573  windows/imap/novell_netmail_append                                2006-12-23       average    No     Novell NetMail IMAP APPEND Buffer Overflow
   1574  windows/imap/novell_netmail_auth                                  2007-01-07       average    No     Novell NetMail IMAP AUTHENTICATE Buffer Overflow
   1575  windows/imap/novell_netmail_status                                2005-11-18       average    No     Novell NetMail IMAP STATUS Buffer Overflow
   1576  windows/imap/novell_netmail_subscribe                             2006-12-23       average    No     Novell NetMail IMAP SUBSCRIBE Buffer Overflow
   1577  windows/isapi/ms00_094_pbserver                                   2000-12-04       good       Yes    MS00-094 Microsoft IIS Phone Book Service Overflow
   1578  windows/isapi/ms03_022_nsiislog_post                              2003-06-25       good       Yes    MS03-022 Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow
   1579  windows/isapi/ms03_051_fp30reg_chunked                            2003-11-11       good       Yes    MS03-051 Microsoft IIS ISAPI FrontPage fp30reg.dll Chunked Overflow
   1580  windows/isapi/rsa_webagent_redirect                               2005-10-21       good       Yes    Microsoft IIS ISAPI RSA WebAgent Redirect Overflow
   1581  windows/isapi/w3who_query                                         2004-12-06       good       Yes    Microsoft IIS ISAPI w3who.dll Query String Overflow
   1582  windows/ldap/imail_thc                                            2004-02-17       average    No     IMail LDAP Service Buffer Overflow
   1583  windows/ldap/pgp_keyserver7                                       2001-07-16       good       No     Network Associates PGP KeyServer 7 LDAP Buffer Overflow
   1584  windows/license/calicclnt_getconfig                               2005-03-02       average    No     Computer Associates License Client GETCONFIG Overflow
   1585  windows/license/calicserv_getconfig                               2005-03-02       normal     Yes    Computer Associates License Server GETCONFIG Overflow
   1586  windows/license/flexnet_lmgrd_bof                                 2012-03-23       normal     No     FlexNet License Server Manager lmgrd Buffer Overflow
   1587  windows/license/sentinel_lm7_udp                                  2005-03-07       average    Yes    SentinelLM UDP Buffer Overflow
   1588  windows/local/adobe_sandbox_adobecollabsync                       2013-05-14       great      Yes    AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass
   1589  windows/local/agnitum_outpost_acs                                 2013-08-02       excellent  Yes    Agnitum Outpost Internet Security Local Privilege Escalation
   1590  windows/local/alpc_taskscheduler                                  2018-08-27       normal     No     Microsoft Windows ALPC Task Scheduler Local Privilege Elevation
   1591  windows/local/always_install_elevated                             2010-03-18       excellent  Yes    Windows AlwaysInstallElevated MSI
   1592  windows/local/applocker_bypass                                    2015-08-03       excellent  No     AppLocker Execution Prevention Bypass
   1593  windows/local/appxsvc_hard_link_privesc                           2019-04-09       normal     Yes    AppXSvc Hard Link Privilege Escalation
   1594  windows/local/ask                                                 2012-01-03       excellent  No     Windows Escalate UAC Execute RunAs
   1595  windows/local/bthpan                                              2014-07-18       average    Yes    MS14-062 Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
   1596  windows/local/bypassuac                                           2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass
   1597  windows/local/bypassuac_comhijack                                 1900-01-01       excellent  Yes    Windows Escalate UAC Protection Bypass (Via COM Handler Hijack)
   1598  windows/local/bypassuac_eventvwr                                  2016-08-15       excellent  Yes    Windows Escalate UAC Protection Bypass (Via Eventvwr Registry Key)
   1599  windows/local/bypassuac_fodhelper                                 2017-05-12       excellent  Yes    Windows UAC Protection Bypass (Via FodHelper Registry Key)
   1600  windows/local/bypassuac_injection                                 2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection)
   1601  windows/local/bypassuac_injection_winsxs                          2017-04-06       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection) abusing WinSXS
   1602  windows/local/bypassuac_silentcleanup                             2019-02-24       excellent  No     Windows Escalate UAC Protection Bypass (Via SilentCleanup)
   1603  windows/local/bypassuac_sluihijack                                2018-01-15       excellent  Yes    Windows UAC Protection Bypass (Via Slui File Handler Hijack)
   1604  windows/local/bypassuac_vbs                                       2015-08-22       excellent  No     Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability)
   1605  windows/local/capcom_sys_exec                                     1999-01-01       normal     Yes    Windows Capcom.sys Kernel Execution Exploit (x64 only)
   1606  windows/local/current_user_psexec                                 1999-01-01       excellent  No     PsExec via Current User Token
   1607  windows/local/cve_2017_8464_lnk_lpe                               2017-06-13       excellent  Yes    LNK Code Execution Vulnerability
   1608  windows/local/cve_2018_8453_win32k_priv_esc                       2018-10-09       manual     No     Windows NtUserSetWindowFNID Win32k User Callback
   1609  windows/local/ikeext_service                                      2012-10-09       good       Yes    IKE and AuthIP IPsec Keyring Modules Service (IKEEXT) Missing DLL
   1610  windows/local/ipass_launch_app                                    2015-03-12       excellent  Yes    iPass Mobile Client Service Privilege Escalation
   1611  windows/local/lenovo_systemupdate                                 2015-04-12       excellent  Yes    Lenovo System Update Privilege Escalation
   1612  windows/local/mov_ss                                              2018-05-08       excellent  No     Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability
   1613  windows/local/mqac_write                                          2014-07-22       average    Yes    MQAC.sys Arbitrary Write Privilege Escalation
   1614  windows/local/ms10_015_kitrap0d                                   2010-01-19       great      Yes    Windows SYSTEM Escalation via KiTrap0D
   1615  windows/local/ms10_092_schelevator                                2010-09-13       excellent  Yes    Windows Escalate Task Scheduler XML Privilege Escalation
   1616  windows/local/ms11_080_afdjoinleaf                                2011-11-30       average    No     MS11-080 AfdJoinLeaf Privilege Escalation
   1617  windows/local/ms13_005_hwnd_broadcast                             2012-11-27       excellent  No     MS13-005 HWND_BROADCAST Low to Medium Integrity Privilege Escalation
   1618  windows/local/ms13_053_schlamperei                                2013-12-01       average    Yes    Windows NTUserMessageCall Win32k Kernel Pool Overflow (Schlamperei)
   1619  windows/local/ms13_081_track_popup_menu                           2013-10-08       average    Yes    Windows TrackPopupMenuEx Win32k NULL Page
   1620  windows/local/ms13_097_ie_registry_symlink                        2013-12-10       great      No     MS13-097 Registry Symlink IE Sandbox Escape
   1621  windows/local/ms14_009_ie_dfsvc                                   2014-02-11       great      Yes    MS14-009 .NET Deployment Service IE Sandbox Escape
   1622  windows/local/ms14_058_track_popup_menu                           2014-10-14       normal     Yes    Windows TrackPopupMenu Win32k NULL Pointer Dereference
   1623  windows/local/ms14_070_tcpip_ioctl                                2014-11-11       average    Yes    MS14-070 Windows tcpip!SetAddrOptions NULL Pointer Dereference
   1624  windows/local/ms15_004_tswbproxy                                  2015-01-13       good       Yes    MS15-004 Microsoft Remote Desktop Services Web Proxy IE Sandbox Escape
   1625  windows/local/ms15_051_client_copy_image                          2015-05-12       normal     Yes    Windows ClientCopyImage Win32k Exploit
   1626  windows/local/ms15_078_atmfd_bof                                  2015-07-11       manual     Yes    MS15-078 Microsoft Windows Font Driver Buffer Overflow
   1627  windows/local/ms16_014_wmi_recv_notif                             2015-12-04       normal     Yes    Windows WMI Recieve Notification Exploit
   1628  windows/local/ms16_016_webdav                                     2016-02-09       excellent  Yes    MS16-016 mrxdav.sys WebDav Local Privilege Escalation
   1629  windows/local/ms16_032_secondary_logon_handle_privesc             2016-03-21       normal     Yes    MS16-032 Secondary Logon Handle Privilege Escalation
   1630  windows/local/ms16_075_reflection                                 2016-01-16       normal     Yes    Windows Net-NTLMv2 Reflection DCOM/RPC
   1631  windows/local/ms16_075_reflection_juicy                           2016-01-16       great      Yes    Windows Net-NTLMv2 Reflection DCOM/RPC (Juicy)
   1632  windows/local/ms18_8120_win32k_privesc                            2018-05-09       good       No     Windows SetImeInfoEx Win32k NULL Pointer Dereference
   1633  windows/local/ms_ndproxy                                          2013-11-27       average    Yes    MS14-002 Microsoft Windows ndproxy.sys Local Privilege Escalation
   1634  windows/local/novell_client_nicm                                  2013-05-22       average    Yes    Novell Client 2 SP3 nicm.sys Local Privilege Escalation
   1635  windows/local/novell_client_nwfs                                  2008-06-26       average    No     Novell Client 4.91 SP4 nwfs.sys Local Privilege Escalation
   1636  windows/local/ntapphelpcachecontrol                               2014-09-30       normal     Yes    MS15-001 Microsoft Windows NtApphelpCacheControl Improper Authorization Check
   1637  windows/local/nvidia_nvsvc                                        2012-12-25       average    Yes    Nvidia (nvsvc) Display Driver Service Local Privilege Escalation
   1638  windows/local/panda_psevents                                      2016-06-27       excellent  Yes    Panda Security PSEvents Privilege Escalation
   1639  windows/local/payload_inject                                      2011-10-12       excellent  No     Windows Manage Memory Payload Injection
   1640  windows/local/persistence                                         2011-10-19       excellent  No     Windows Persistent Registry Startup Payload Installer
   1641  windows/local/persistence_service                                 2018-10-20       excellent  No     Windows Persistent Service Installer
   1642  windows/local/powershell_cmd_upgrade                              1999-01-01       excellent  No     Windows Command Shell Upgrade (Powershell)
   1643  windows/local/powershell_remoting                                 1999-01-01       excellent  No     Powershell Remoting Remote Command Execution
   1644  windows/local/ppr_flatten_rec                                     2013-05-15       average    Yes    Windows EPATHOBJ::pprFlattenRec Local Privilege Escalation
   1645  windows/local/ps_persist                                          2012-08-14       excellent  No     Powershell Payload Execution
   1646  windows/local/ps_wmi_exec                                         2012-08-19       excellent  No     Authenticated WMI Exec via Powershell
   1647  windows/local/pxeexploit                                          2011-08-05       excellent  No     PXE Exploit Server
   1648  windows/local/razer_zwopenprocess                                 2017-03-22       normal     Yes    Razer Synapse rzpnk.sys ZwOpenProcess
   1649  windows/local/registry_persistence                                2015-07-01       excellent  Yes    Windows Registry Only Persistence
   1650  windows/local/run_as                                              1999-01-01       excellent  No     Windows Run Command As User
   1651  windows/local/s4u_persistence                                     2013-01-02       excellent  No     Windows Manage User Level Persistent Payload Installer
   1652  windows/local/service_permissions                                 2012-10-15       great      No     Windows Escalate Service Permissions Local Privilege Escalation
   1653  windows/local/trusted_service_path                                2001-10-25       excellent  Yes    Windows Service Trusted Path Privilege Escalation
   1654  windows/local/virtual_box_guest_additions                         2014-07-15       average    Yes    VirtualBox Guest Additions VBoxGuest.sys Privilege Escalation
   1655  windows/local/virtual_box_opengl_escape                           2014-03-11       average    Yes    VirtualBox 3D Acceleration Virtual Machine Escape
   1656  windows/local/vss_persistence                                     2011-10-21       excellent  No     Persistent Payload in Windows Volume Shadow Copy
   1657  windows/local/webexec                                             2018-10-09       good       Yes    WebEx Local Service Permissions Exploit
   1658  windows/local/wmi                                                 1999-01-01       excellent  No     Windows Management Instrumentation (WMI) Remote Command Execution
   1659  windows/local/wmi_persistence                                     2017-06-06       normal     No     WMI Event Subscription Persistence
   1660  windows/lotus/domino_http_accept_language                         2008-05-20       average    No     IBM Lotus Domino Web Server Accept-Language Stack Buffer Overflow
   1661  windows/lotus/domino_icalendar_organizer                          2010-09-14       normal     Yes    IBM Lotus Domino iCalendar MAILTO Buffer Overflow
   1662  windows/lotus/domino_sametime_stmux                               2008-05-21       average    Yes    IBM Lotus Domino Sametime STMux.exe Stack Buffer Overflow
   1663  windows/lotus/lotusnotes_lzh                                      2011-05-24       normal     No     Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)
   1664  windows/lpd/hummingbird_exceed                                    2005-05-27       average    No     Hummingbird Connectivity 10 SP5 LPD Buffer Overflow
   1665  windows/lpd/niprint                                               2003-11-05       good       No     NIPrint LPD Request Overflow
   1666  windows/lpd/saplpd                                                2008-02-04       good       No     SAP SAPLPD 6.28 Buffer Overflow
   1667  windows/lpd/wincomlpd_admin                                       2008-02-04       good       No     WinComLPD Buffer Overflow
   1668  windows/misc/achat_bof                                            2014-12-18       normal     No     Achat Unicode SEH Buffer Overflow
   1669  windows/misc/actfax_raw_server_bof                                2013-02-05       normal     No     ActFax 5.01 RAW Server Buffer Overflow
   1670  windows/misc/agentxpp_receive_agentx                              2010-04-16       good       No     AgentX++ Master AgentX::receive_agentx Stack Buffer Overflow
   1671  windows/misc/ahsay_backup_fileupload                              2019-06-01       excellent  Yes    Ahsay Backup v7.x-v8.1.1.50 (authenticated) file upload
   1672  windows/misc/ais_esel_server_rce                                  2019-03-27       excellent  Yes    AIS logistics ESEL-Server Unauth SQL Injection RCE
   1673  windows/misc/allmediaserver_bof                                   2012-07-04       normal     No     ALLMediaServer 0.8 Buffer Overflow
   1674  windows/misc/altiris_ds_sqli                                      2008-05-15       normal     Yes    Symantec Altiris DS SQL Injection
   1675  windows/misc/apple_quicktime_rtsp_response                        2007-11-23       normal     No     Apple QuickTime 7.3 RTSP Response Header Buffer Overflow
   1676  windows/misc/asus_dpcproxy_overflow                               2008-03-21       average    No     Asus Dpcproxy Buffer Overflow
   1677  windows/misc/avaya_winpmd_unihostrouter                           2011-05-23       normal     No     Avaya WinPMD UniteHostRouter Buffer Overflow
   1678  windows/misc/avidphoneticindexer                                  2011-11-29       normal     No     Avid Media Composer 5.5 - Avid Phonetic Indexer Buffer Overflow
   1679  windows/misc/bakbone_netvault_heap                                2005-04-01       average    Yes    BakBone NetVault Remote Heap Overflow
   1680  windows/misc/bcaaa_bof                                            2011-04-04       good       No     Blue Coat Authentication and Authorization Agent (BCAAA) 5 Buffer Overflow
   1681  windows/misc/bigant_server                                        2008-04-15       average    No     BigAnt Server 2.2 Buffer Overflow
   1682  windows/misc/bigant_server_250                                    2008-04-15       great      No     BigAnt Server 2.50 SP1 Buffer Overflow
   1683  windows/misc/bigant_server_dupf_upload                            2013-01-09       excellent  No     BigAnt Server DUPF Command Arbitrary File Upload
   1684  windows/misc/bigant_server_sch_dupf_bof                           2013-01-09       normal     No     BigAnt Server 2 SCH And DUPF Buffer Overflow
   1685  windows/misc/bigant_server_usv                                    2009-12-29       great      No     BigAnt Server 2.52 USV Buffer Overflow
   1686  windows/misc/bomberclone_overflow                                 2006-02-16       average    No     Bomberclone 0.11.6 Buffer Overflow
   1687  windows/misc/bopup_comm                                           2009-06-18       good       No     Bopup Communications Server Buffer Overflow
   1688  windows/misc/borland_interbase                                    2007-07-24       average    No     Borland Interbase Create-Request Buffer Overflow
   1689  windows/misc/borland_starteam                                     2008-04-02       average    No     Borland CaliberRM StarTeam Multicast Service Buffer Overflow
   1690  windows/misc/citrix_streamprocess                                 2011-01-20       good       No     Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow
   1691  windows/misc/citrix_streamprocess_data_msg                        2011-11-04       normal     No     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020000 Buffer Overflow
   1692  windows/misc/citrix_streamprocess_get_boot_record_request         2011-11-04       normal     No     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020004 Buffer Overflow
   1693  windows/misc/citrix_streamprocess_get_footer                      2011-11-04       normal     No     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020002 Buffer Overflow
   1694  windows/misc/citrix_streamprocess_get_objects                     2011-11-04       normal     No     Citrix Provisioning Services 5.6 SP1 Streamprocess Opcode 0x40020006 Buffer Overflow
   1695  windows/misc/cloudme_sync                                         2018-01-17       great      No     CloudMe Sync v1.10.9
   1696  windows/misc/commvault_cmd_exec                                   2017-12-12       good       No     Commvault Communications Service (cvd) Command Injection
   1697  windows/misc/disk_savvy_adm                                       2017-01-31       great      No     Disk Savvy Enterprise v10.4.18
   1698  windows/misc/doubletake                                           2008-06-04       average    No     DoubleTake/HP StorageWorks Storage Mirroring Service Authentication Overflow
   1699  windows/misc/eiqnetworks_esa                                      2006-07-24       average    No     eIQNetworks ESA License Manager LICMGR_ADDLICENSE Overflow
   1700  windows/misc/eiqnetworks_esa_topology                             2006-07-25       average    No     eIQNetworks ESA Topology DELETEDEVICE Overflow
   1701  windows/misc/enterasys_netsight_syslog_bof                        2011-12-19       normal     No     Enterasys NetSight nssyslogd.exe Buffer Overflow
   1702  windows/misc/eureka_mail_err                                      2009-10-22       normal     No     Eureka Email 2.2q ERR Remote Buffer Overflow
   1703  windows/misc/fb_cnct_group                                        2013-01-31       normal     Yes    Firebird Relational Database CNCT Group Number Buffer Overflow
   1704  windows/misc/fb_isc_attach_database                               2007-10-03       average    No     Firebird Relational Database isc_attach_database() Buffer Overflow
   1705  windows/misc/fb_isc_create_database                               2007-10-03       average    No     Firebird Relational Database isc_create_database() Buffer Overflow
   1706  windows/misc/fb_svc_attach                                        2007-10-03       average    No     Firebird Relational Database SVC_attach() Buffer Overflow
   1707  windows/misc/gh0st                                                2017-07-27       normal     Yes    Gh0st Client buffer Overflow
   1708  windows/misc/gimp_script_fu                                       2012-05-18       normal     No     GIMP script-fu Server Buffer Overflow
   1709  windows/misc/hp_dataprotector_cmd_exec                            2014-11-02       excellent  Yes    HP Data Protector 8.10 Remote Command Execution
   1710  windows/misc/hp_dataprotector_crs                                 2013-06-03       normal     Yes    HP Data Protector Cell Request Service Buffer Overflow
   1711  windows/misc/hp_dataprotector_dtbclslogin                         2010-09-09       normal     Yes    HP Data Protector DtbClsLogin Buffer Overflow
   1712  windows/misc/hp_dataprotector_encrypted_comms                     2016-04-18       normal     Yes    HP Data Protector Encrypted Communication Remote Command Execution
   1713  windows/misc/hp_dataprotector_exec_bar                            2014-01-02       excellent  Yes    HP Data Protector Backup Client Service Remote Code Execution
   1714  windows/misc/hp_dataprotector_install_service                     2011-11-02       excellent  Yes    HP Data Protector 6.10/6.11/6.20 Install Service
   1715  windows/misc/hp_dataprotector_new_folder                          2012-03-12       normal     No     HP Data Protector Create New Folder Buffer Overflow
   1716  windows/misc/hp_dataprotector_traversal                           2014-01-02       great      Yes    HP Data Protector Backup Client Service Directory Traversal
   1717  windows/misc/hp_imc_dbman_restartdb_unauth_rce                    2017-05-15       excellent  Yes    HPE iMC dbman RestartDB Unauthenticated RCE
   1718  windows/misc/hp_imc_dbman_restoredbase_unauth_rce                 2017-05-15       excellent  Yes    HPE iMC dbman RestoreDBase Unauthenticated RCE
   1719  windows/misc/hp_imc_uam                                           2012-08-29       normal     No     HP Intelligent Management Center UAM Buffer Overflow
   1720  windows/misc/hp_loadrunner_magentproc                             2013-07-27       normal     No     HP LoadRunner magentproc.exe Overflow
   1721  windows/misc/hp_loadrunner_magentproc_cmdexec                     2010-05-06       excellent  No     HP Mercury LoadRunner Agent magentproc.exe Remote Command Execution
   1722  windows/misc/hp_magentservice                                     2012-01-12       average    No     HP Diagnostics Server magentservice.exe Overflow
   1723  windows/misc/hp_omniinet_1                                        2009-12-17       great      Yes    HP OmniInet.exe MSG_PROTOCOL Buffer Overflow
   1724  windows/misc/hp_omniinet_2                                        2009-12-17       great      Yes    HP OmniInet.exe MSG_PROTOCOL Buffer Overflow
   1725  windows/misc/hp_omniinet_3                                        2011-06-29       great      Yes    HP OmniInet.exe Opcode 27 Buffer Overflow
   1726  windows/misc/hp_omniinet_4                                        2011-06-29       good       No     HP OmniInet.exe Opcode 20 Buffer Overflow
   1727  windows/misc/hp_operations_agent_coda_34                          2012-07-09       normal     Yes    HP Operations Agent Opcode coda.exe 0x34 Buffer Overflow
   1728  windows/misc/hp_operations_agent_coda_8c                          2012-07-09       normal     Yes    HP Operations Agent Opcode coda.exe 0x8c Buffer Overflow
   1729  windows/misc/hp_ovtrace                                           2007-08-09       average    No     HP OpenView Operations OVTrace Buffer Overflow
   1730  windows/misc/hta_server                                           2016-10-06       manual     No     HTA Web Server
   1731  windows/misc/ib_isc_attach_database                               2007-10-03       good       No     Borland InterBase isc_attach_database() Buffer Overflow
   1732  windows/misc/ib_isc_create_database                               2007-10-03       good       No     Borland InterBase isc_create_database() Buffer Overflow
   1733  windows/misc/ib_svc_attach                                        2007-10-03       good       No     Borland InterBase SVC_attach() Buffer Overflow
   1734  windows/misc/ibm_cognos_tm1admsd_bof                              2012-04-02       normal     No     IBM Cognos tm1admsd.exe Overflow
   1735  windows/misc/ibm_director_cim_dllinject                           2009-03-10       excellent  Yes    IBM System Director Agent DLL Injection
   1736  windows/misc/ibm_tsm_cad_ping                                     2009-11-04       good       No     IBM Tivoli Storage Manager Express CAD Service Buffer Overflow
   1737  windows/misc/ibm_tsm_rca_dicugetidentify                          2009-11-04       great      No     IBM Tivoli Storage Manager Express RCA Service Buffer Overflow
   1738  windows/misc/ibm_websphere_java_deserialize                       2015-11-06       excellent  No     IBM WebSphere RCE Java Deserialization Vulnerability
   1739  windows/misc/itunes_extm3u_bof                                    2012-06-21       normal     No     Apple iTunes 10 Extended M3U Stack Buffer Overflow
   1740  windows/misc/landesk_aolnsrvr                                     2007-04-13       average    No     LANDesk Management Suite 8.7 Alert Service Buffer Overflow
   1741  windows/misc/lianja_db_net                                        2013-05-22       normal     Yes    Lianja SQL 1.0.0RC5.1 db_netserver Stack Buffer Overflow
   1742  windows/misc/manageengine_eventlog_analyzer_rce                   2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   1743  windows/misc/mercury_phonebook                                    2005-12-19       average    No     Mercury/32 PH Server Module Buffer Overflow
   1744  windows/misc/mini_stream                                          2009-12-25       normal     No     Mini-Stream 3.0.1.1 Buffer Overflow
   1745  windows/misc/mirc_privmsg_server                                  2008-10-02       normal     No     mIRC PRIVMSG Handling Stack Buffer Overflow
   1746  windows/misc/ms07_064_sami                                        2007-12-11       normal     No     MS07-064 Microsoft DirectX DirectShow SAMI Buffer Overflow
   1747  windows/misc/ms10_104_sharepoint                                  2010-12-14       excellent  Yes    MS10-104 Microsoft Office SharePoint Server 2007 Remote Code Execution
   1748  windows/misc/netcat110_nt                                         2004-12-27       great      No     Netcat v1.10 NT Stack Buffer Overflow
   1749  windows/misc/nettransport                                         2010-01-02       normal     No     NetTransport Download Manager 2.90.510 Buffer Overflow
   1750  windows/misc/nvidia_mental_ray                                    2013-12-10       excellent  No     Nvidia Mental Ray Satellite Service Arbitrary DLL Injection
   1751  windows/misc/plugx                                                2017-07-27       normal     Yes    PlugX Controller Stack Overflow
   1752  windows/misc/poisonivy_21x_bof                                    2016-06-03       normal     Yes    Poison Ivy 2.1.x C2 Buffer Overflow
   1753  windows/misc/poisonivy_bof                                        2012-06-24       normal     Yes    Poison Ivy Server Buffer Overflow
   1754  windows/misc/poppeeper_date                                       2009-02-27       normal     No     POP Peeper v3.4 DATE Buffer Overflow
   1755  windows/misc/poppeeper_uidl                                       2009-02-27       normal     No     POP Peeper v3.4 UIDL Buffer Overflow
   1756  windows/misc/realtek_playlist                                     2008-12-16       great      No     Realtek Media Player Playlist Buffer Overflow
   1757  windows/misc/sap_2005_license                                     2009-08-01       great      No     SAP Business One License Manager 2005 Buffer Overflow
   1758  windows/misc/sap_netweaver_dispatcher                             2012-05-08       normal     No     SAP NetWeaver Dispatcher DiagTraceR3Info Buffer Overflow
   1759  windows/misc/shixxnote_font                                       2004-10-04       great      No     ShixxNOTE 6.net Font Field Overflow
   1760  windows/misc/solidworks_workgroup_pdmwservice_file_write          2014-02-22       good       Yes    SolidWorks Workgroup PDM 2014 pdmwService.exe Arbitrary File Write
   1761  windows/misc/splayer_content_type                                 2011-05-04       normal     No     SPlayer 3.7 Content-Type Buffer Overflow
   1762  windows/misc/stream_down_bof                                      2011-12-27       good       No     CoCSoft StreamDown 6.8.0 Buffer Overflow
   1763  windows/misc/talkative_response                                   2009-03-17       normal     No     Talkative IRC v0.4.4.16 Response Buffer Overflow
   1764  windows/misc/tiny_identd_overflow                                 2007-05-14       average    No     TinyIdentD 2.2 Stack Buffer Overflow
   1765  windows/misc/trendmicro_cmdprocessor_addtask                      2011-12-07       good       No     TrendMicro Control Manger CmdProcessor.exe Stack Buffer Overflow
   1766  windows/misc/ufo_ai                                               2009-10-28       average    No     UFO: Alien Invasion IRC Client Buffer Overflow
   1767  windows/misc/vmhgfs_webdav_dll_sideload                           2016-08-05       normal     No     DLL Side Loading Vulnerability in VMware Host Guest Client Redirector
   1768  windows/misc/webdav_delivery                                      1999-01-01       manual     No     Serve DLL via webdav server
   1769  windows/misc/windows_rsh                                          2007-07-24       average    No     Windows RSH Daemon Buffer Overflow
   1770  windows/misc/wireshark_lua                                        2011-07-18       excellent  No     Wireshark console.lua Pre-Loading Script Execution
   1771  windows/misc/wireshark_packet_dect                                2011-04-18       good       No     Wireshark packet-dect.c Stack Buffer Overflow
   1772  windows/mmsp/ms10_025_wmss_connect_funnel                         2010-04-13       great      No     Windows Media Services ConnectFunnel Stack Buffer Overflow
   1773  windows/motorola/timbuktu_fileupload                              2008-05-10       excellent  No     Timbuktu Pro Directory Traversal/File Upload
   1774  windows/mssql/lyris_listmanager_weak_pass                         2005-12-08       excellent  No     Lyris ListManager MSDE Weak sa Password
   1775  windows/mssql/ms02_039_slammer                                    2002-07-24       good       Yes    MS02-039 Microsoft SQL Server Resolution Overflow
   1776  windows/mssql/ms02_056_hello                                      2002-08-05       good       Yes    MS02-056 Microsoft SQL Server Hello Overflow
   1777  windows/mssql/ms09_004_sp_replwritetovarbin                       2008-12-09       good       Yes    MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption
   1778  windows/mssql/ms09_004_sp_replwritetovarbin_sqli                  2008-12-09       excellent  Yes    MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection
   1779  windows/mssql/mssql_clr_payload                                   1999-01-01       excellent  Yes    Microsoft SQL Server Clr Stored Procedure Payload Execution
   1780  windows/mssql/mssql_linkcrawler                                   2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
   1781  windows/mssql/mssql_payload                                       2000-05-30       excellent  Yes    Microsoft SQL Server Payload Execution
   1782  windows/mssql/mssql_payload_sqli                                  2000-05-30       excellent  No     Microsoft SQL Server Payload Execution via SQL Injection
   1783  windows/mysql/mysql_mof                                           2012-12-01       excellent  Yes    Oracle MySQL for Microsoft Windows MOF Execution
   1784  windows/mysql/mysql_start_up                                      2012-12-01       excellent  Yes    Oracle MySQL for Microsoft Windows FILE Privilege Abuse
   1785  windows/mysql/mysql_yassl_hello                                   2008-01-04       average    No     MySQL yaSSL SSL Hello Message Buffer Overflow
   1786  windows/mysql/scrutinizer_upload_exec                             2012-07-27       excellent  Yes    Plixer Scrutinizer NetFlow and sFlow Analyzer 9 Default MySQL Credential
   1787  windows/nfs/xlink_nfsd                                            2006-11-06       average    No     Omni-NFS Server Buffer Overflow
   1788  windows/nntp/ms05_030_nntp                                        2005-06-14       normal     No     MS05-030 Microsoft Outlook Express NNTP Response Parsing Buffer Overflow
   1789  windows/novell/file_reporter_fsfui_upload                         2012-11-16       great      No     NFR Agent FSFUI Record File Upload RCE
   1790  windows/novell/groupwisemessenger_client                          2008-07-02       normal     No     Novell GroupWise Messenger Client Buffer Overflow
   1791  windows/novell/netiq_pum_eval                                     2012-11-15       excellent  Yes    NetIQ Privileged User Manager 2.3.1 ldapagnt_eval() Remote Perl Code Execution
   1792  windows/novell/nmap_stor                                          2006-12-23       average    No     Novell NetMail NMAP STOR Buffer Overflow
   1793  windows/novell/zenworks_desktop_agent                             2005-05-19       good       No     Novell ZENworks 6.5 Desktop/Server Management Overflow
   1794  windows/novell/zenworks_preboot_op21_bof                          2010-03-30       normal     No     Novell ZENworks Configuration Management Preboot Service 0x21 Buffer Overflow
   1795  windows/novell/zenworks_preboot_op4c_bof                          2012-02-22       normal     No     Novell ZENworks Configuration Management Preboot Service 0x4c Buffer Overflow
   1796  windows/novell/zenworks_preboot_op6_bof                           2010-03-30       normal     No     Novell ZENworks Configuration Management Preboot Service 0x06 Buffer Overflow
   1797  windows/novell/zenworks_preboot_op6c_bof                          2012-02-22       normal     No     Novell ZENworks Configuration Management Preboot Service 0x6c Buffer Overflow
   1798  windows/nuuo/nuuo_cms_fu                                          2018-10-11       manual     No     Nuuo Central Management Server Authenticated Arbitrary File Upload
   1799  windows/nuuo/nuuo_cms_sqli                                        2018-10-11       normal     No     Nuuo Central Management Authenticated SQL Server SQLi
   1800  windows/oracle/client_system_analyzer_upload                      2011-01-18       excellent  Yes    Oracle Database Client System Analyzer Arbitrary File Upload
   1801  windows/oracle/extjob                                             2007-01-01       excellent  Yes    Oracle Job Scheduler Named Pipe Command Execution
   1802  windows/oracle/osb_ndmp_auth                                      2009-01-14       good       No     Oracle Secure Backup NDMP_CONNECT_CLIENT_AUTH Buffer Overflow
   1803  windows/oracle/tns_arguments                                      2001-06-28       good       Yes    Oracle 8i TNS Listener (ARGUMENTS) Buffer Overflow
   1804  windows/oracle/tns_auth_sesskey                                   2009-10-20       great      Yes    Oracle 10gR2 TNS Listener AUTH_SESSKEY Buffer Overflow
   1805  windows/oracle/tns_service_name                                   2002-05-27       good       Yes    Oracle 8i TNS Listener SERVICE_NAME Buffer Overflow
   1806  windows/pop3/seattlelab_pass                                      2003-05-07       great      No     Seattle Lab Mail 5.5 POP3 Buffer Overflow
   1807  windows/postgres/postgres_payload                                 2009-04-10       excellent  Yes    PostgreSQL for Microsoft Windows Payload Execution
   1808  windows/proxy/bluecoat_winproxy_host                              2005-01-05       great      No     Blue Coat WinProxy Host Header Overflow
   1809  windows/proxy/ccproxy_telnet_ping                                 2004-11-11       average    Yes    CCProxy Telnet Proxy Ping Overflow
   1810  windows/proxy/proxypro_http_get                                   2004-02-23       great      No     Proxy-Pro Professional GateKeeper 4.7 GET Request Overflow
   1811  windows/proxy/qbik_wingate_wwwproxy                               2006-06-07       good       Yes    Qbik WinGate WWW Proxy Server URL Processing Overflow
   1812  windows/scada/abb_wserver_exec                                    2013-04-05       excellent  Yes    ABB MicroSCADA wserver.exe Remote Code Execution
   1813  windows/scada/advantech_webaccess_dashboard_file_upload           2016-02-05       excellent  Yes    Advantech WebAccess Dashboard Viewer uploadImageCommon Arbitrary File Upload
   1814  windows/scada/advantech_webaccess_webvrpcs_bof                    2017-11-02       good       No     Advantech WebAccess Webvrpcs Service Opcode 80061 Stack Buffer Overflow
   1815  windows/scada/citect_scada_odbc                                   2008-06-11       normal     No     CitectSCADA/CitectFacilities ODBC Buffer Overflow
   1816  windows/scada/codesys_gateway_server_traversal                    2013-02-02       excellent  No     SCADA 3S CoDeSys Gateway Server Directory Traversal
   1817  windows/scada/codesys_web_server                                  2011-12-02       normal     Yes    SCADA 3S CoDeSys CmpWebServer Stack Buffer Overflow
   1818  windows/scada/daq_factory_bof                                     2011-09-13       good       No     DaqFactory HMI NETB Request Overflow
   1819  windows/scada/delta_ia_commgr_bof                                 2018-07-02       normal     No     Delta Electronics Delta Industrial Automation COMMGR 1.08 Stack Buffer Overflow
   1820  windows/scada/factorylink_csservice                               2011-03-25       normal     No     Siemens FactoryLink 8 CSService Logging Path Param Buffer Overflow
   1821  windows/scada/factorylink_vrn_09                                  2011-03-21       average    No     Siemens FactoryLink vrn.exe Opcode 9 Buffer Overflow
   1822  windows/scada/ge_proficy_cimplicity_gefebt                        2014-01-23       excellent  Yes    GE Proficy CIMPLICITY gefebt.exe Remote Code Execution
   1823  windows/scada/iconics_genbroker                                   2011-03-21       good       No     Iconics GENESIS32 Integer Overflow Version 9.21.201.01
   1824  windows/scada/iconics_webhmi_setactivexguid                       2011-05-05       good       No     ICONICS WebHMI ActiveX Buffer Overflow
   1825  windows/scada/igss9_igssdataserver_listall                        2011-03-24       good       No     7-Technologies IGSS IGSSdataServer.exe Stack Buffer Overflow
   1826  windows/scada/igss9_igssdataserver_rename                         2011-03-24       normal     No     7-Technologies IGSS 9 IGSSdataServer .RMS Rename Buffer Overflow
   1827  windows/scada/igss9_misc                                          2011-03-24       excellent  No     7-Technologies IGSS 9 Data Server/Collector Packet Handling Vulnerabilities
   1828  windows/scada/igss_exec_17                                        2011-03-21       excellent  No     Interactive Graphical SCADA System Remote Command Injection
   1829  windows/scada/indusoft_webstudio_exec                             2011-11-04       excellent  Yes    InduSoft Web Studio Arbitrary Upload Remote Code Execution
   1830  windows/scada/moxa_mdmtool                                        2010-10-20       great      No     MOXA Device Manager Tool 2.1 Buffer Overflow
   1831  windows/scada/procyon_core_server                                 2011-09-08       normal     Yes    Procyon Core Server HMI Coreservice.exe Stack Buffer Overflow
   1832  windows/scada/realwin                                             2008-09-26       great      No     DATAC RealWin SCADA Server Buffer Overflow
   1833  windows/scada/realwin_on_fc_binfile_a                             2011-03-21       great      No     DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow
   1834  windows/scada/realwin_on_fcs_login                                2011-03-21       great      No     RealWin SCADA Server DATAC Login Buffer Overflow
   1835  windows/scada/realwin_scpc_initialize                             2010-10-15       great      No     DATAC RealWin SCADA Server SCPC_INITIALIZE Buffer Overflow
   1836  windows/scada/realwin_scpc_initialize_rf                          2010-10-15       great      No     DATAC RealWin SCADA Server SCPC_INITIALIZE_RF Buffer Overflow
   1837  windows/scada/realwin_scpc_txtevent                               2010-11-18       great      No     DATAC RealWin SCADA Server SCPC_TXTEVENT Buffer Overflow
   1838  windows/scada/scadapro_cmdexe                                     2011-09-16       excellent  No     Measuresoft ScadaPro Remote Command Execution
   1839  windows/scada/sunway_force_control_netdbsrv                       2011-09-22       great      No     Sunway Forcecontrol SNMP NetDBServer.exe Opcode 0x57
   1840  windows/scada/winlog_runtime                                      2011-01-13       great      No     Sielco Sistemi Winlog Buffer Overflow
   1841  windows/scada/winlog_runtime_2                                    2012-06-04       normal     No     Sielco Sistemi Winlog Buffer Overflow 2.07.14 - 2.07.16
   1842  windows/scada/yokogawa_bkbcopyd_bof                               2014-03-10       normal     Yes    Yokogawa CENTUM CS 3000 BKBCopyD.exe Buffer Overflow
   1843  windows/scada/yokogawa_bkesimmgr_bof                              2014-03-10       normal     Yes    Yokogawa CS3000 BKESimmgr.exe Buffer Overflow
   1844  windows/scada/yokogawa_bkfsim_vhfd                                2014-05-23       normal     No     Yokogawa CS3000 BKFSim_vhfd.exe Buffer Overflow
   1845  windows/scada/yokogawa_bkhodeq_bof                                2014-03-10       average    Yes    Yokogawa CENTUM CS 3000 BKHOdeq.exe Buffer Overflow
   1846  windows/sip/aim_triton_cseq                                       2006-07-10       great      No     AIM Triton 1.0.4 CSeq Buffer Overflow
   1847  windows/sip/sipxezphone_cseq                                      2006-07-10       great      No     SIPfoundry sipXezPhone 0.35a CSeq Field Overflow
   1848  windows/sip/sipxphone_cseq                                        2006-07-10       great      No     SIPfoundry sipXphone 2.6.0.27 CSeq Buffer Overflow
   1849  windows/smb/generic_smb_dll_injection                             2015-03-04       manual     No     Generic DLL Injection From Shared Resource
   1850  windows/smb/group_policy_startup                                  2015-01-26       manual     No     Group Policy Script Execution From Shared Resource
   1851  windows/smb/ipass_pipe_exec                                       2015-01-21       excellent  Yes    IPass Control Pipe Remote Command Execution
   1852  windows/smb/ms03_049_netapi                                       2003-11-11       good       No     MS03-049 Microsoft Workstation Service NetAddAlternateComputerName Overflow
   1853  windows/smb/ms04_007_killbill                                     2004-02-10       low        No     MS04-007 Microsoft ASN.1 Library Bitstring Heap Overflow
   1854  windows/smb/ms04_011_lsass                                        2004-04-13       good       No     MS04-011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow
   1855  windows/smb/ms04_031_netdde                                       2004-10-12       good       No     MS04-031 Microsoft NetDDE Service Overflow
   1856  windows/smb/ms05_039_pnp                                          2005-08-09       good       Yes    MS05-039 Microsoft Plug and Play Service Overflow
   1857  windows/smb/ms06_025_rasmans_reg                                  2006-06-13       good       No     MS06-025 Microsoft RRAS Service RASMAN Registry Overflow
   1858  windows/smb/ms06_025_rras                                         2006-06-13       average    No     MS06-025 Microsoft RRAS Service Overflow
   1859  windows/smb/ms06_040_netapi                                       2006-08-08       good       No     MS06-040 Microsoft Server Service NetpwPathCanonicalize Overflow
   1860  windows/smb/ms06_066_nwapi                                        2006-11-14       good       No     MS06-066 Microsoft Services nwapi32.dll Module Exploit
   1861  windows/smb/ms06_066_nwwks                                        2006-11-14       good       No     MS06-066 Microsoft Services nwwks.dll Module Exploit
   1862  windows/smb/ms06_070_wkssvc                                       2006-11-14       manual     No     MS06-070 Microsoft Workstation Service NetpManageIPCConnect Overflow
   1863  windows/smb/ms07_029_msdns_zonename                               2007-04-12       manual     No     MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB)
   1864  windows/smb/ms08_067_netapi                                       2008-10-28       great      Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
   1865  windows/smb/ms09_050_smb2_negotiate_func_index                    2009-09-07       good       No     MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   1866  windows/smb/ms10_046_shortcut_icon_dllloader                      2010-07-16       excellent  No     Microsoft Windows Shell LNK Code Execution
   1867  windows/smb/ms10_061_spoolss                                      2010-09-14       excellent  No     MS10-061 Microsoft Print Spooler Service Impersonation Vulnerability
   1868  windows/smb/ms15_020_shortcut_icon_dllloader                      2015-03-10       excellent  No     Microsoft Windows Shell LNK Code Execution
   1869  windows/smb/ms17_010_eternalblue                                  2017-03-14       average    Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1870  windows/smb/ms17_010_eternalblue_win8                             2017-03-14       average    No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   1871  windows/smb/ms17_010_psexec                                       2017-03-14       normal     Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   1872  windows/smb/netidentity_xtierrpcpipe                              2009-04-06       great      No     Novell NetIdentity Agent XTIERRPCPIPE Named Pipe Buffer Overflow
   1873  windows/smb/psexec                                                1999-01-01       manual     No     Microsoft Windows Authenticated User Code Execution
   1874  windows/smb/psexec_psh                                            1999-01-01       manual     No     Microsoft Windows Authenticated Powershell Command Execution
   1875  windows/smb/smb_delivery                                          2016-07-26       excellent  No     SMB Delivery
   1876  windows/smb/smb_relay                                             2001-03-31       excellent  No     MS08-068 Microsoft Windows SMB Relay Code Execution
   1877  windows/smb/timbuktu_plughntcommand_bof                           2009-06-25       great      No     Timbuktu PlughNTCommand Named Pipe Buffer Overflow
   1878  windows/smb/webexec                                               2018-10-24       manual     No     WebExec Authenticated User Code Execution
   1879  windows/smtp/mailcarrier_smtp_ehlo                                2004-10-26       good       Yes    TABS MailCarrier v2.51 SMTP EHLO Overflow
   1880  windows/smtp/mercury_cram_md5                                     2007-08-18       great      No     Mercury Mail SMTP AUTH CRAM-MD5 Buffer Overflow
   1881  windows/smtp/ms03_046_exchange2000_xexch50                        2003-10-15       good       Yes    MS03-046 Exchange 2000 XEXCH50 Heap Overflow
   1882  windows/smtp/njstar_smtp_bof                                      2011-10-31       normal     Yes    NJStar Communicator 3.00 MiniSMTP Buffer Overflow
   1883  windows/smtp/sysgauge_client_bof                                  2017-02-28       normal     No     SysGauge SMTP Validation Buffer Overflow
   1884  windows/smtp/wmailserver                                          2005-07-11       average    No     SoftiaCom WMailserver 1.0 Buffer Overflow
   1885  windows/smtp/ypops_overflow1                                      2004-09-27       average    Yes    YPOPS 0.6 Buffer Overflow
   1886  windows/ssh/freeftpd_key_exchange                                 2006-05-12       average    No     FreeFTPd 1.0.10 Key Exchange Algorithm String Buffer Overflow
   1887  windows/ssh/freesshd_authbypass                                   2010-08-11       excellent  Yes    Freesshd Authentication Bypass
   1888  windows/ssh/freesshd_key_exchange                                 2006-05-12       average    No     FreeSSHd 1.0.9 Key Exchange Algorithm String Buffer Overflow
   1889  windows/ssh/putty_msg_debug                                       2002-12-16       normal     No     PuTTY Buffer Overflow
   1890  windows/ssh/securecrt_ssh1                                        2002-07-23       average    No     SecureCRT SSH1 Buffer Overflow
   1891  windows/ssh/sysax_ssh_username                                    2012-02-27       normal     Yes    Sysax 5.53 SSH Username Buffer Overflow
   1892  windows/ssl/ms04_011_pct                                          2004-04-13       average    No     MS04-011 Microsoft Private Communications Transport Overflow
   1893  windows/telnet/gamsoft_telsrv_username                            2000-07-17       average    Yes    GAMSoft TelSrv 1.5 Username Buffer Overflow
   1894  windows/telnet/goodtech_telnet                                    2005-03-15       average    No     GoodTech Telnet Server Buffer Overflow
   1895  windows/tftp/attftp_long_filename                                 2006-11-27       average    No     Allied Telesyn TFTP Server 1.9 Long Filename Overflow
   1896  windows/tftp/distinct_tftp_traversal                              2012-04-08       excellent  No     Distinct TFTP 3.10 Writable Directory Traversal Execution
   1897  windows/tftp/dlink_long_filename                                  2007-03-12       good       No     D-Link TFTP 1.0 Long Filename Buffer Overflow
   1898  windows/tftp/futuresoft_transfermode                              2005-05-31       average    No     FutureSoft TFTP Server 2000 Transfer-Mode Overflow
   1899  windows/tftp/netdecision_tftp_traversal                           2009-05-16       excellent  No     NetDecision 4.2 TFTP Writable Directory Traversal Execution
   1900  windows/tftp/opentftp_error_code                                  2008-07-05       average    No     OpenTFTP SP 1.4 Error Packet Overflow
   1901  windows/tftp/quick_tftp_pro_mode                                  2008-03-27       good       No     Quick FTP Pro 2.1 Transfer-Mode Overflow
   1902  windows/tftp/tftpd32_long_filename                                2002-11-19       average    No     TFTPD32 Long Filename Buffer Overflow
   1903  windows/tftp/tftpdwin_long_filename                               2006-09-21       great      No     TFTPDWIN v0.4.2 Long Filename Buffer Overflow
   1904  windows/tftp/tftpserver_wrq_bof                                   2008-03-26       normal     No     TFTP Server for Windows 1.4 ST WRQ Buffer Overflow
   1905  windows/tftp/threectftpsvc_long_mode                              2006-11-27       great      No     3CTftpSvc TFTP Long Mode Buffer Overflow
   1906  windows/unicenter/cam_log_security                                2005-08-22       great      Yes    CA CAM log_security() Stack Buffer Overflow (Win32)
   1907  windows/vnc/realvnc_client                                        2001-01-29       normal     No     RealVNC 3.3.7 Client Buffer Overflow
   1908  windows/vnc/ultravnc_client                                       2006-04-04       normal     No     UltraVNC 1.0.1 Client Buffer Overflow
   1909  windows/vnc/ultravnc_viewer_bof                                   2008-02-06       normal     No     UltraVNC 1.0.2 Client (vncviewer.exe) Buffer Overflow
   1910  windows/vnc/winvnc_http_get                                       2001-01-29       average    No     WinVNC Web Server GET Overflow
   1911  windows/vpn/safenet_ike_11                                        2009-06-01       average    No     SafeNet SoftRemote IKE Service Buffer Overflow
   1912  windows/winrm/winrm_script_exec                                   2012-11-01       manual     No     WinRM Script Exec Remote Code Execution
   1913  windows/wins/ms04_045_wins                                        2004-12-14       great      Yes    MS04-045 Microsoft WINS Service Memory Overwrite
"""
    msfpayloads="""
Payloads
========

   #    Name                                                Disclosure Date  Rank    Check  Description
   -    ----                                                ---------------  ----    -----  -----------
   0    aix/ppc/shell_bind_tcp                                               normal  No     AIX Command Shell, Bind TCP Inline
   1    aix/ppc/shell_find_port                                              normal  No     AIX Command Shell, Find Port Inline
   2    aix/ppc/shell_interact                                               normal  No     AIX execve Shell for inetd
   3    aix/ppc/shell_reverse_tcp                                            normal  No     AIX Command Shell, Reverse TCP Inline
   4    android/meterpreter/reverse_http                                     normal  No     Android Meterpreter, Android Reverse HTTP Stager
   5    android/meterpreter/reverse_https                                    normal  No     Android Meterpreter, Android Reverse HTTPS Stager
   6    android/meterpreter/reverse_tcp                                      normal  No     Android Meterpreter, Android Reverse TCP Stager
   7    android/meterpreter_reverse_http                                     normal  No     Android Meterpreter Shell, Reverse HTTP Inline
   8    android/meterpreter_reverse_https                                    normal  No     Android Meterpreter Shell, Reverse HTTPS Inline
   9    android/meterpreter_reverse_tcp                                      normal  No     Android Meterpreter Shell, Reverse TCP Inline
   10   android/shell/reverse_http                                           normal  No     Command Shell, Android Reverse HTTP Stager
   11   android/shell/reverse_https                                          normal  No     Command Shell, Android Reverse HTTPS Stager
   12   android/shell/reverse_tcp                                            normal  No     Command Shell, Android Reverse TCP Stager
   13   apple_ios/aarch64/meterpreter_reverse_http                           normal  No     Apple_iOS Meterpreter, Reverse HTTP Inline
   14   apple_ios/aarch64/meterpreter_reverse_https                          normal  No     Apple_iOS Meterpreter, Reverse HTTPS Inline
   15   apple_ios/aarch64/meterpreter_reverse_tcp                            normal  No     Apple_iOS Meterpreter, Reverse TCP Inline
   16   apple_ios/aarch64/shell_reverse_tcp                                  normal  No     Apple iOS aarch64 Command Shell, Reverse TCP Inline
   17   apple_ios/armle/meterpreter_reverse_http                             normal  No     Apple_iOS Meterpreter, Reverse HTTP Inline
   18   apple_ios/armle/meterpreter_reverse_https                            normal  No     Apple_iOS Meterpreter, Reverse HTTPS Inline
   19   apple_ios/armle/meterpreter_reverse_tcp                              normal  No     Apple_iOS Meterpreter, Reverse TCP Inline
   20   bsd/sparc/shell_bind_tcp                                             normal  No     BSD Command Shell, Bind TCP Inline
   21   bsd/sparc/shell_reverse_tcp                                          normal  No     BSD Command Shell, Reverse TCP Inline
   22   bsd/vax/shell_reverse_tcp                                            normal  No     BSD Command Shell, Reverse TCP Inline
   23   bsd/x64/exec                                                         normal  No     BSD x64 Execute Command
   24   bsd/x64/shell_bind_ipv6_tcp                                          normal  No     BSD x64 Command Shell, Bind TCP Inline (IPv6)
   25   bsd/x64/shell_bind_tcp                                               normal  No     BSD x64 Shell Bind TCP
   26   bsd/x64/shell_bind_tcp_small                                         normal  No     BSD x64 Command Shell, Bind TCP Inline
   27   bsd/x64/shell_reverse_ipv6_tcp                                       normal  No     BSD x64 Command Shell, Reverse TCP Inline (IPv6)
   28   bsd/x64/shell_reverse_tcp                                            normal  No     BSD x64 Shell Reverse TCP
   29   bsd/x64/shell_reverse_tcp_small                                      normal  No     BSD x64 Command Shell, Reverse TCP Inline
   30   bsd/x86/exec                                                         normal  No     BSD Execute Command
   31   bsd/x86/metsvc_bind_tcp                                              normal  No     FreeBSD Meterpreter Service, Bind TCP
   32   bsd/x86/metsvc_reverse_tcp                                           normal  No     FreeBSD Meterpreter Service, Reverse TCP Inline
   33   bsd/x86/shell/bind_ipv6_tcp                                          normal  No     BSD Command Shell, Bind TCP Stager (IPv6)
   34   bsd/x86/shell/bind_tcp                                               normal  No     BSD Command Shell, Bind TCP Stager
   35   bsd/x86/shell/find_tag                                               normal  No     BSD Command Shell, Find Tag Stager
   36   bsd/x86/shell/reverse_ipv6_tcp                                       normal  No     BSD Command Shell, Reverse TCP Stager (IPv6)
   37   bsd/x86/shell/reverse_tcp                                            normal  No     BSD Command Shell, Reverse TCP Stager
   38   bsd/x86/shell_bind_tcp                                               normal  No     BSD Command Shell, Bind TCP Inline
   39   bsd/x86/shell_bind_tcp_ipv6                                          normal  No     BSD Command Shell, Bind TCP Inline (IPv6)
   40   bsd/x86/shell_find_port                                              normal  No     BSD Command Shell, Find Port Inline
   41   bsd/x86/shell_find_tag                                               normal  No     BSD Command Shell, Find Tag Inline
   42   bsd/x86/shell_reverse_tcp                                            normal  No     BSD Command Shell, Reverse TCP Inline
   43   bsd/x86/shell_reverse_tcp_ipv6                                       normal  No     BSD Command Shell, Reverse TCP Inline (IPv6)
   44   bsdi/x86/shell/bind_tcp                                              normal  No     BSDi Command Shell, Bind TCP Stager
   45   bsdi/x86/shell/reverse_tcp                                           normal  No     BSDi Command Shell, Reverse TCP Stager
   46   bsdi/x86/shell_bind_tcp                                              normal  No     BSDi Command Shell, Bind TCP Inline
   47   bsdi/x86/shell_find_port                                             normal  No     BSDi Command Shell, Find Port Inline
   48   bsdi/x86/shell_reverse_tcp                                           normal  No     BSDi Command Shell, Reverse TCP Inline
   49   cmd/mainframe/apf_privesc_jcl                                        normal  No     JCL to Escalate Privileges
   50   cmd/mainframe/bind_shell_jcl                                         normal  No     Z/OS (MVS) Command Shell, Bind TCP
   51   cmd/mainframe/generic_jcl                                            normal  No     Generic JCL Test for Mainframe Exploits
   52   cmd/mainframe/reverse_shell_jcl                                      normal  No     Z/OS (MVS) Command Shell, Reverse TCP
   53   cmd/unix/bind_awk                                                    normal  No     Unix Command Shell, Bind TCP (via AWK)
   54   cmd/unix/bind_busybox_telnetd                                        normal  No     Unix Command Shell, Bind TCP (via BusyBox telnetd)
   55   cmd/unix/bind_inetd                                                  normal  No     Unix Command Shell, Bind TCP (inetd)
   56   cmd/unix/bind_lua                                                    normal  No     Unix Command Shell, Bind TCP (via Lua)
   57   cmd/unix/bind_netcat                                                 normal  No     Unix Command Shell, Bind TCP (via netcat)
   58   cmd/unix/bind_netcat_gaping                                          normal  No     Unix Command Shell, Bind TCP (via netcat -e)
   59   cmd/unix/bind_netcat_gaping_ipv6                                     normal  No     Unix Command Shell, Bind TCP (via netcat -e) IPv6
   60   cmd/unix/bind_nodejs                                                 normal  No     Unix Command Shell, Bind TCP (via nodejs)
   61   cmd/unix/bind_perl                                                   normal  No     Unix Command Shell, Bind TCP (via Perl)
   62   cmd/unix/bind_perl_ipv6                                              normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   63   cmd/unix/bind_r                                                      normal  No     Unix Command Shell, Bind TCP (via R)
   64   cmd/unix/bind_ruby                                                   normal  No     Unix Command Shell, Bind TCP (via Ruby)
   65   cmd/unix/bind_ruby_ipv6                                              normal  No     Unix Command Shell, Bind TCP (via Ruby) IPv6
   66   cmd/unix/bind_socat_udp                                              normal  No     Unix Command Shell, Bind UDP (via socat)
   67   cmd/unix/bind_stub                                                   normal  No     Unix Command Shell, Bind TCP (stub)
   68   cmd/unix/bind_zsh                                                    normal  No     Unix Command Shell, Bind TCP (via Zsh)
   69   cmd/unix/generic                                                     normal  No     Unix Command, Generic Command Execution
   70   cmd/unix/interact                                                    normal  No     Unix Command, Interact with Established Connection
   71   cmd/unix/pingback_bind                                               normal  No     Unix Command Shell, Pingback Bind TCP (via netcat)
   72   cmd/unix/pingback_reverse                                            normal  No     Unix Command Shell, Pingback Reverse TCP (via netcat)
   73   cmd/unix/reverse                                                     normal  No     Unix Command Shell, Double Reverse TCP (telnet)
   74   cmd/unix/reverse_awk                                                 normal  No     Unix Command Shell, Reverse TCP (via AWK)
   75   cmd/unix/reverse_bash                                                normal  No     Unix Command Shell, Reverse TCP (/dev/tcp)
   76   cmd/unix/reverse_bash_telnet_ssl                                     normal  No     Unix Command Shell, Reverse TCP SSL (telnet)
   77   cmd/unix/reverse_bash_udp                                            normal  No     Unix Command Shell, Reverse UDP (/dev/udp)
   78   cmd/unix/reverse_ksh                                                 normal  No     Unix Command Shell, Reverse TCP (via Ksh)
   79   cmd/unix/reverse_lua                                                 normal  No     Unix Command Shell, Reverse TCP (via Lua)
   80   cmd/unix/reverse_ncat_ssl                                            normal  No     Unix Command Shell, Reverse TCP (via ncat)
   81   cmd/unix/reverse_netcat                                              normal  No     Unix Command Shell, Reverse TCP (via netcat)
   82   cmd/unix/reverse_netcat_gaping                                       normal  No     Unix Command Shell, Reverse TCP (via netcat -e)
   83   cmd/unix/reverse_nodejs                                              normal  No     Unix Command Shell, Reverse TCP (via nodejs)
   84   cmd/unix/reverse_openssl                                             normal  No     Unix Command Shell, Double Reverse TCP SSL (openssl)
   85   cmd/unix/reverse_perl                                                normal  No     Unix Command Shell, Reverse TCP (via Perl)
   86   cmd/unix/reverse_perl_ssl                                            normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   87   cmd/unix/reverse_php_ssl                                             normal  No     Unix Command Shell, Reverse TCP SSL (via php)
   88   cmd/unix/reverse_python                                              normal  No     Unix Command Shell, Reverse TCP (via Python)
   89   cmd/unix/reverse_python_ssl                                          normal  No     Unix Command Shell, Reverse TCP SSL (via python)
   90   cmd/unix/reverse_r                                                   normal  No     Unix Command Shell, Reverse TCP (via R)
   91   cmd/unix/reverse_ruby                                                normal  No     Unix Command Shell, Reverse TCP (via Ruby)
   92   cmd/unix/reverse_ruby_ssl                                            normal  No     Unix Command Shell, Reverse TCP SSL (via Ruby)
   93   cmd/unix/reverse_socat_udp                                           normal  No     Unix Command Shell, Reverse UDP (via socat)
   94   cmd/unix/reverse_ssl_double_telnet                                   normal  No     Unix Command Shell, Double Reverse TCP SSL (telnet)
   95   cmd/unix/reverse_stub                                                normal  No     Unix Command Shell, Reverse TCP (stub)
   96   cmd/unix/reverse_zsh                                                 normal  No     Unix Command Shell, Reverse TCP (via Zsh)
   97   cmd/windows/adduser                                                  normal  No     Windows Execute net user /ADD CMD
   98   cmd/windows/bind_lua                                                 normal  No     Windows Command Shell, Bind TCP (via Lua)
   99   cmd/windows/bind_perl                                                normal  No     Windows Command Shell, Bind TCP (via Perl)
   100  cmd/windows/bind_perl_ipv6                                           normal  No     Windows Command Shell, Bind TCP (via perl) IPv6
   101  cmd/windows/bind_ruby                                                normal  No     Windows Command Shell, Bind TCP (via Ruby)
   102  cmd/windows/download_eval_vbs                                        normal  No     Windows Executable Download and Evaluate VBS
   103  cmd/windows/download_exec_vbs                                        normal  No     Windows Executable Download and Execute (via .vbs)
   104  cmd/windows/generic                                                  normal  No     Windows Command, Generic Command Execution
   105  cmd/windows/powershell_bind_tcp                                      normal  No     Windows Interactive Powershell Session, Bind TCP
   106  cmd/windows/powershell_reverse_tcp                                   normal  No     Windows Interactive Powershell Session, Reverse TCP
   107  cmd/windows/reverse_lua                                              normal  No     Windows Command Shell, Reverse TCP (via Lua)
   108  cmd/windows/reverse_perl                                             normal  No     Windows Command, Double Reverse TCP Connection (via Perl)
   109  cmd/windows/reverse_powershell                                       normal  No     Windows Command Shell, Reverse TCP (via Powershell)
   110  cmd/windows/reverse_ruby                                             normal  No     Windows Command Shell, Reverse TCP (via Ruby)
   111  firefox/exec                                                         normal  No     Firefox XPCOM Execute Command
   112  firefox/shell_bind_tcp                                               normal  No     Command Shell, Bind TCP (via Firefox XPCOM script)
   113  firefox/shell_reverse_tcp                                            normal  No     Command Shell, Reverse TCP (via Firefox XPCOM script)
   114  generic/custom                                                       normal  No     Custom Payload
   115  generic/debug_trap                                                   normal  No     Generic x86 Debug Trap
   116  generic/shell_bind_tcp                                               normal  No     Generic Command Shell, Bind TCP Inline
   117  generic/shell_reverse_tcp                                            normal  No     Generic Command Shell, Reverse TCP Inline
   118  generic/tight_loop                                                   normal  No     Generic x86 Tight Loop
   119  java/jsp_shell_bind_tcp                                              normal  No     Java JSP Command Shell, Bind TCP Inline
   120  java/jsp_shell_reverse_tcp                                           normal  No     Java JSP Command Shell, Reverse TCP Inline
   121  java/meterpreter/bind_tcp                                            normal  No     Java Meterpreter, Java Bind TCP Stager
   122  java/meterpreter/reverse_http                                        normal  No     Java Meterpreter, Java Reverse HTTP Stager
   123  java/meterpreter/reverse_https                                       normal  No     Java Meterpreter, Java Reverse HTTPS Stager
   124  java/meterpreter/reverse_tcp                                         normal  No     Java Meterpreter, Java Reverse TCP Stager
   125  java/shell/bind_tcp                                                  normal  No     Command Shell, Java Bind TCP Stager
   126  java/shell/reverse_tcp                                               normal  No     Command Shell, Java Reverse TCP Stager
   127  java/shell_reverse_tcp                                               normal  No     Java Command Shell, Reverse TCP Inline
   128  linux/aarch64/meterpreter/reverse_tcp                                normal  No     Linux Meterpreter, Reverse TCP Stager
   129  linux/aarch64/meterpreter_reverse_http                               normal  No     Linux Meterpreter, Reverse HTTP Inline
   130  linux/aarch64/meterpreter_reverse_https                              normal  No     Linux Meterpreter, Reverse HTTPS Inline
   131  linux/aarch64/meterpreter_reverse_tcp                                normal  No     Linux Meterpreter, Reverse TCP Inline
   132  linux/aarch64/shell/reverse_tcp                                      normal  No     Linux dup2 Command Shell, Reverse TCP Stager
   133  linux/aarch64/shell_reverse_tcp                                      normal  No     Linux Command Shell, Reverse TCP Inline
   134  linux/armbe/meterpreter_reverse_http                                 normal  No     Linux Meterpreter, Reverse HTTP Inline
   135  linux/armbe/meterpreter_reverse_https                                normal  No     Linux Meterpreter, Reverse HTTPS Inline
   136  linux/armbe/meterpreter_reverse_tcp                                  normal  No     Linux Meterpreter, Reverse TCP Inline
   137  linux/armbe/shell_bind_tcp                                           normal  No     Linux ARM Big Endian Command Shell, Bind TCP Inline
   138  linux/armle/adduser                                                  normal  No     Linux Add User
   139  linux/armle/exec                                                     normal  No     Linux Execute Command
   140  linux/armle/meterpreter/bind_tcp                                     normal  No     Linux Meterpreter, Bind TCP Stager
   141  linux/armle/meterpreter/reverse_tcp                                  normal  No     Linux Meterpreter, Reverse TCP Stager
   142  linux/armle/meterpreter_reverse_http                                 normal  No     Linux Meterpreter, Reverse HTTP Inline
   143  linux/armle/meterpreter_reverse_https                                normal  No     Linux Meterpreter, Reverse HTTPS Inline
   144  linux/armle/meterpreter_reverse_tcp                                  normal  No     Linux Meterpreter, Reverse TCP Inline
   145  linux/armle/shell/bind_tcp                                           normal  No     Linux dup2 Command Shell, Bind TCP Stager
   146  linux/armle/shell/reverse_tcp                                        normal  No     Linux dup2 Command Shell, Reverse TCP Stager
   147  linux/armle/shell_bind_tcp                                           normal  No     Linux Command Shell, Reverse TCP Inline
   148  linux/armle/shell_reverse_tcp                                        normal  No     Linux Command Shell, Reverse TCP Inline
   149  linux/mips64/meterpreter_reverse_http                                normal  No     Linux Meterpreter, Reverse HTTP Inline
   150  linux/mips64/meterpreter_reverse_https                               normal  No     Linux Meterpreter, Reverse HTTPS Inline
   151  linux/mips64/meterpreter_reverse_tcp                                 normal  No     Linux Meterpreter, Reverse TCP Inline
   152  linux/mipsbe/exec                                                    normal  No     Linux Execute Command
   153  linux/mipsbe/meterpreter/reverse_tcp                                 normal  No     Linux Meterpreter, Reverse TCP Stager
   154  linux/mipsbe/meterpreter_reverse_http                                normal  No     Linux Meterpreter, Reverse HTTP Inline
   155  linux/mipsbe/meterpreter_reverse_https                               normal  No     Linux Meterpreter, Reverse HTTPS Inline
   156  linux/mipsbe/meterpreter_reverse_tcp                                 normal  No     Linux Meterpreter, Reverse TCP Inline
   157  linux/mipsbe/reboot                                                  normal  No     Linux Reboot
   158  linux/mipsbe/shell/reverse_tcp                                       normal  No     Linux Command Shell, Reverse TCP Stager
   159  linux/mipsbe/shell_bind_tcp                                          normal  No     Linux Command Shell, Bind TCP Inline
   160  linux/mipsbe/shell_reverse_tcp                                       normal  No     Linux Command Shell, Reverse TCP Inline
   161  linux/mipsle/exec                                                    normal  No     Linux Execute Command
   162  linux/mipsle/meterpreter/reverse_tcp                                 normal  No     Linux Meterpreter, Reverse TCP Stager
   163  linux/mipsle/meterpreter_reverse_http                                normal  No     Linux Meterpreter, Reverse HTTP Inline
   164  linux/mipsle/meterpreter_reverse_https                               normal  No     Linux Meterpreter, Reverse HTTPS Inline
   165  linux/mipsle/meterpreter_reverse_tcp                                 normal  No     Linux Meterpreter, Reverse TCP Inline
   166  linux/mipsle/reboot                                                  normal  No     Linux Reboot
   167  linux/mipsle/shell/reverse_tcp                                       normal  No     Linux Command Shell, Reverse TCP Stager
   168  linux/mipsle/shell_bind_tcp                                          normal  No     Linux Command Shell, Bind TCP Inline
   169  linux/mipsle/shell_reverse_tcp                                       normal  No     Linux Command Shell, Reverse TCP Inline
   170  linux/ppc/meterpreter_reverse_http                                   normal  No     Linux Meterpreter, Reverse HTTP Inline
   171  linux/ppc/meterpreter_reverse_https                                  normal  No     Linux Meterpreter, Reverse HTTPS Inline
   172  linux/ppc/meterpreter_reverse_tcp                                    normal  No     Linux Meterpreter, Reverse TCP Inline
   173  linux/ppc/shell_bind_tcp                                             normal  No     Linux Command Shell, Bind TCP Inline
   174  linux/ppc/shell_find_port                                            normal  No     Linux Command Shell, Find Port Inline
   175  linux/ppc/shell_reverse_tcp                                          normal  No     Linux Command Shell, Reverse TCP Inline
   176  linux/ppc64/shell_bind_tcp                                           normal  No     Linux Command Shell, Bind TCP Inline
   177  linux/ppc64/shell_find_port                                          normal  No     Linux Command Shell, Find Port Inline
   178  linux/ppc64/shell_reverse_tcp                                        normal  No     Linux Command Shell, Reverse TCP Inline
   179  linux/ppc64le/meterpreter_reverse_http                               normal  No     Linux Meterpreter, Reverse HTTP Inline
   180  linux/ppc64le/meterpreter_reverse_https                              normal  No     Linux Meterpreter, Reverse HTTPS Inline
   181  linux/ppc64le/meterpreter_reverse_tcp                                normal  No     Linux Meterpreter, Reverse TCP Inline
   182  linux/ppce500v2/meterpreter_reverse_http                             normal  No     Linux Meterpreter, Reverse HTTP Inline
   183  linux/ppce500v2/meterpreter_reverse_https                            normal  No     Linux Meterpreter, Reverse HTTPS Inline
   184  linux/ppce500v2/meterpreter_reverse_tcp                              normal  No     Linux Meterpreter, Reverse TCP Inline
   185  linux/x64/exec                                                       normal  No     Linux Execute Command
   186  linux/x64/meterpreter/bind_tcp                                       normal  No     Linux Mettle x64, Bind TCP Stager
   187  linux/x64/meterpreter/reverse_tcp                                    normal  No     Linux Mettle x64, Reverse TCP Stager
   188  linux/x64/meterpreter_reverse_http                                   normal  No     Linux Meterpreter, Reverse HTTP Inline
   189  linux/x64/meterpreter_reverse_https                                  normal  No     Linux Meterpreter, Reverse HTTPS Inline
   190  linux/x64/meterpreter_reverse_tcp                                    normal  No     Linux Meterpreter, Reverse TCP Inline
   191  linux/x64/pingback_bind_tcp                                          normal  No     Linux x64 Pingback, Bind TCP Inline
   192  linux/x64/pingback_reverse_tcp                                       normal  No     Linux x64 Pingback, Reverse TCP Inline
   193  linux/x64/shell/bind_tcp                                             normal  No     Linux Command Shell, Bind TCP Stager
   194  linux/x64/shell/reverse_tcp                                          normal  No     Linux Command Shell, Reverse TCP Stager
   195  linux/x64/shell_bind_ipv6_tcp                                        normal  No     Linux x64 Command Shell, Bind TCP Inline (IPv6)
   196  linux/x64/shell_bind_tcp                                             normal  No     Linux Command Shell, Bind TCP Inline
   197  linux/x64/shell_bind_tcp_random_port                                 normal  No     Linux Command Shell, Bind TCP Random Port Inline
   198  linux/x64/shell_find_port                                            normal  No     Linux Command Shell, Find Port Inline
   199  linux/x64/shell_reverse_ipv6_tcp                                     normal  No     Linux x64 Command Shell, Reverse TCP Inline (IPv6)
   200  linux/x64/shell_reverse_tcp                                          normal  No     Linux Command Shell, Reverse TCP Inline
   201  linux/x86/adduser                                                    normal  No     Linux Add User
   202  linux/x86/chmod                                                      normal  No     Linux Chmod
   203  linux/x86/exec                                                       normal  No     Linux Execute Command
   204  linux/x86/meterpreter/bind_ipv6_tcp                                  normal  No     Linux Mettle x86, Bind IPv6 TCP Stager (Linux x86)
   205  linux/x86/meterpreter/bind_ipv6_tcp_uuid                             normal  No     Linux Mettle x86, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   206  linux/x86/meterpreter/bind_nonx_tcp                                  normal  No     Linux Mettle x86, Bind TCP Stager
   207  linux/x86/meterpreter/bind_tcp                                       normal  No     Linux Mettle x86, Bind TCP Stager (Linux x86)
   208  linux/x86/meterpreter/bind_tcp_uuid                                  normal  No     Linux Mettle x86, Bind TCP Stager with UUID Support (Linux x86)
   209  linux/x86/meterpreter/find_tag                                       normal  No     Linux Mettle x86, Find Tag Stager
   210  linux/x86/meterpreter/reverse_ipv6_tcp                               normal  No     Linux Mettle x86, Reverse TCP Stager (IPv6)
   211  linux/x86/meterpreter/reverse_nonx_tcp                               normal  No     Linux Mettle x86, Reverse TCP Stager
   212  linux/x86/meterpreter/reverse_tcp                                    normal  No     Linux Mettle x86, Reverse TCP Stager
   213  linux/x86/meterpreter/reverse_tcp_uuid                               normal  No     Linux Mettle x86, Reverse TCP Stager
   214  linux/x86/meterpreter_reverse_http                                   normal  No     Linux Meterpreter, Reverse HTTP Inline
   215  linux/x86/meterpreter_reverse_https                                  normal  No     Linux Meterpreter, Reverse HTTPS Inline
   216  linux/x86/meterpreter_reverse_tcp                                    normal  No     Linux Meterpreter, Reverse TCP Inline
   217  linux/x86/metsvc_bind_tcp                                            normal  No     Linux Meterpreter Service, Bind TCP
   218  linux/x86/metsvc_reverse_tcp                                         normal  No     Linux Meterpreter Service, Reverse TCP Inline
   219  linux/x86/read_file                                                  normal  No     Linux Read File
   220  linux/x86/shell/bind_ipv6_tcp                                        normal  No     Linux Command Shell, Bind IPv6 TCP Stager (Linux x86)
   221  linux/x86/shell/bind_ipv6_tcp_uuid                                   normal  No     Linux Command Shell, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   222  linux/x86/shell/bind_nonx_tcp                                        normal  No     Linux Command Shell, Bind TCP Stager
   223  linux/x86/shell/bind_tcp                                             normal  No     Linux Command Shell, Bind TCP Stager (Linux x86)
   224  linux/x86/shell/bind_tcp_uuid                                        normal  No     Linux Command Shell, Bind TCP Stager with UUID Support (Linux x86)
   225  linux/x86/shell/find_tag                                             normal  No     Linux Command Shell, Find Tag Stager
   226  linux/x86/shell/reverse_ipv6_tcp                                     normal  No     Linux Command Shell, Reverse TCP Stager (IPv6)
   227  linux/x86/shell/reverse_nonx_tcp                                     normal  No     Linux Command Shell, Reverse TCP Stager
   228  linux/x86/shell/reverse_tcp                                          normal  No     Linux Command Shell, Reverse TCP Stager
   229  linux/x86/shell/reverse_tcp_uuid                                     normal  No     Linux Command Shell, Reverse TCP Stager
   230  linux/x86/shell_bind_ipv6_tcp                                        normal  No     Linux Command Shell, Bind TCP Inline (IPv6)
   231  linux/x86/shell_bind_tcp                                             normal  No     Linux Command Shell, Bind TCP Inline
   232  linux/x86/shell_bind_tcp_random_port                                 normal  No     Linux Command Shell, Bind TCP Random Port Inline
   233  linux/x86/shell_find_port                                            normal  No     Linux Command Shell, Find Port Inline
   234  linux/x86/shell_find_tag                                             normal  No     Linux Command Shell, Find Tag Inline
   235  linux/x86/shell_reverse_tcp                                          normal  No     Linux Command Shell, Reverse TCP Inline
   236  linux/x86/shell_reverse_tcp_ipv6                                     normal  No     Linux Command Shell, Reverse TCP Inline (IPv6)
   237  linux/zarch/meterpreter_reverse_http                                 normal  No     Linux Meterpreter, Reverse HTTP Inline
   238  linux/zarch/meterpreter_reverse_https                                normal  No     Linux Meterpreter, Reverse HTTPS Inline
   239  linux/zarch/meterpreter_reverse_tcp                                  normal  No     Linux Meterpreter, Reverse TCP Inline
   240  mainframe/shell_reverse_tcp                                          normal  No     Z/OS (MVS) Command Shell, Reverse TCP Inline
   241  multi/meterpreter/reverse_http                                       normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTP Stager (Mulitple Architectures)
   242  multi/meterpreter/reverse_https                                      normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTPS Stager (Mulitple Architectures)
   243  netware/shell/reverse_tcp                                            normal  No     NetWare Command Shell, Reverse TCP Stager
   244  nodejs/shell_bind_tcp                                                normal  No     Command Shell, Bind TCP (via nodejs)
   245  nodejs/shell_reverse_tcp                                             normal  No     Command Shell, Reverse TCP (via nodejs)
   246  nodejs/shell_reverse_tcp_ssl                                         normal  No     Command Shell, Reverse TCP SSL (via nodejs)
   247  osx/armle/execute/bind_tcp                                           normal  No     OS X Write and Execute Binary, Bind TCP Stager
   248  osx/armle/execute/reverse_tcp                                        normal  No     OS X Write and Execute Binary, Reverse TCP Stager
   249  osx/armle/shell/bind_tcp                                             normal  No     OS X Command Shell, Bind TCP Stager
   250  osx/armle/shell/reverse_tcp                                          normal  No     OS X Command Shell, Reverse TCP Stager
   251  osx/armle/shell_bind_tcp                                             normal  No     Apple iOS Command Shell, Bind TCP Inline
   252  osx/armle/shell_reverse_tcp                                          normal  No     Apple iOS Command Shell, Reverse TCP Inline
   253  osx/armle/vibrate                                                    normal  No     Apple iOS iPhone Vibrate
   254  osx/ppc/shell/bind_tcp                                               normal  No     OS X Command Shell, Bind TCP Stager
   255  osx/ppc/shell/find_tag                                               normal  No     OS X Command Shell, Find Tag Stager
   256  osx/ppc/shell/reverse_tcp                                            normal  No     OS X Command Shell, Reverse TCP Stager
   257  osx/ppc/shell_bind_tcp                                               normal  No     OS X Command Shell, Bind TCP Inline
   258  osx/ppc/shell_reverse_tcp                                            normal  No     OS X Command Shell, Reverse TCP Inline
   259  osx/x64/dupandexecve/bind_tcp                                        normal  No     OS X dup2 Command Shell, Bind TCP Stager
   260  osx/x64/dupandexecve/reverse_tcp                                     normal  No     OS X dup2 Command Shell, Reverse TCP Stager
   261  osx/x64/exec                                                         normal  No     OS X x64 Execute Command
   262  osx/x64/meterpreter/bind_tcp                                         normal  No     OSX Meterpreter, Bind TCP Stager
   263  osx/x64/meterpreter/reverse_tcp                                      normal  No     OSX Meterpreter, Reverse TCP Stager
   264  osx/x64/meterpreter_reverse_http                                     normal  No     OSX Meterpreter, Reverse HTTP Inline
   265  osx/x64/meterpreter_reverse_https                                    normal  No     OSX Meterpreter, Reverse HTTPS Inline
   266  osx/x64/meterpreter_reverse_tcp                                      normal  No     OSX Meterpreter, Reverse TCP Inline
   267  osx/x64/say                                                          normal  No     OS X x64 say Shellcode
   268  osx/x64/shell_bind_tcp                                               normal  No     OS X x64 Shell Bind TCP
   269  osx/x64/shell_find_tag                                               normal  No     OSX Command Shell, Find Tag Inline
   270  osx/x64/shell_reverse_tcp                                            normal  No     OS X x64 Shell Reverse TCP
   271  osx/x86/bundleinject/bind_tcp                                        normal  No     Mac OS X Inject Mach-O Bundle, Bind TCP Stager
   272  osx/x86/bundleinject/reverse_tcp                                     normal  No     Mac OS X Inject Mach-O Bundle, Reverse TCP Stager
   273  osx/x86/exec                                                         normal  No     OS X Execute Command
   274  osx/x86/isight/bind_tcp                                              normal  No     Mac OS X x86 iSight Photo Capture, Bind TCP Stager
   275  osx/x86/isight/reverse_tcp                                           normal  No     Mac OS X x86 iSight Photo Capture, Reverse TCP Stager
   276  osx/x86/shell_bind_tcp                                               normal  No     OS X Command Shell, Bind TCP Inline
   277  osx/x86/shell_find_port                                              normal  No     OS X Command Shell, Find Port Inline
   278  osx/x86/shell_reverse_tcp                                            normal  No     OS X Command Shell, Reverse TCP Inline
   279  osx/x86/vforkshell/bind_tcp                                          normal  No     OS X (vfork) Command Shell, Bind TCP Stager
   280  osx/x86/vforkshell/reverse_tcp                                       normal  No     OS X (vfork) Command Shell, Reverse TCP Stager
   281  osx/x86/vforkshell_bind_tcp                                          normal  No     OS X (vfork) Command Shell, Bind TCP Inline
   282  osx/x86/vforkshell_reverse_tcp                                       normal  No     OS X (vfork) Command Shell, Reverse TCP Inline
   283  php/bind_perl                                                        normal  No     PHP Command Shell, Bind TCP (via Perl)
   284  php/bind_perl_ipv6                                                   normal  No     PHP Command Shell, Bind TCP (via perl) IPv6
   285  php/bind_php                                                         normal  No     PHP Command Shell, Bind TCP (via PHP)
   286  php/bind_php_ipv6                                                    normal  No     PHP Command Shell, Bind TCP (via php) IPv6
   287  php/download_exec                                                    normal  No     PHP Executable Download and Execute
   288  php/exec                                                             normal  No     PHP Execute Command 
   289  php/meterpreter/bind_tcp                                             normal  No     PHP Meterpreter, Bind TCP Stager
   290  php/meterpreter/bind_tcp_ipv6                                        normal  No     PHP Meterpreter, Bind TCP Stager IPv6
   291  php/meterpreter/bind_tcp_ipv6_uuid                                   normal  No     PHP Meterpreter, Bind TCP Stager IPv6 with UUID Support
   292  php/meterpreter/bind_tcp_uuid                                        normal  No     PHP Meterpreter, Bind TCP Stager with UUID Support
   293  php/meterpreter/reverse_tcp                                          normal  No     PHP Meterpreter, PHP Reverse TCP Stager
   294  php/meterpreter/reverse_tcp_uuid                                     normal  No     PHP Meterpreter, PHP Reverse TCP Stager
   295  php/meterpreter_reverse_tcp                                          normal  No     PHP Meterpreter, Reverse TCP Inline
   296  php/reverse_perl                                                     normal  No     PHP Command, Double Reverse TCP Connection (via Perl)
   297  php/reverse_php                                                      normal  No     PHP Command Shell, Reverse TCP (via PHP)
   298  php/shell_findsock                                                   normal  No     PHP Command Shell, Find Sock
   299  python/meterpreter/bind_tcp                                          normal  No     Python Meterpreter, Python Bind TCP Stager
   300  python/meterpreter/bind_tcp_uuid                                     normal  No     Python Meterpreter, Python Bind TCP Stager with UUID Support
   301  python/meterpreter/reverse_http                                      normal  No     Python Meterpreter, Python Reverse HTTP Stager
   302  python/meterpreter/reverse_https                                     normal  No     Python Meterpreter, Python Reverse HTTPS Stager
   303  python/meterpreter/reverse_tcp                                       normal  No     Python Meterpreter, Python Reverse TCP Stager
   304  python/meterpreter/reverse_tcp_ssl                                   normal  No     Python Meterpreter, Python Reverse TCP SSL Stager
   305  python/meterpreter/reverse_tcp_uuid                                  normal  No     Python Meterpreter, Python Reverse TCP Stager with UUID Support
   306  python/meterpreter_bind_tcp                                          normal  No     Python Meterpreter Shell, Bind TCP Inline
   307  python/meterpreter_reverse_http                                      normal  No     Python Meterpreter Shell, Reverse HTTP Inline
   308  python/meterpreter_reverse_https                                     normal  No     Python Meterpreter Shell, Reverse HTTPS Inline
   309  python/meterpreter_reverse_tcp                                       normal  No     Python Meterpreter Shell, Reverse TCP Inline
   310  python/pingback_bind_tcp                                             normal  No     Python Pingback, Bind TCP (via python)
   311  python/pingback_reverse_tcp                                          normal  No     Python Pingback, Reverse TCP (via python)
   312  python/shell_bind_tcp                                                normal  No     Command Shell, Bind TCP (via python)
   313  python/shell_reverse_tcp                                             normal  No     Command Shell, Reverse TCP (via python)
   314  python/shell_reverse_tcp_ssl                                         normal  No     Command Shell, Reverse TCP SSL (via python)
   315  python/shell_reverse_udp                                             normal  No     Command Shell, Reverse UDP (via python)
   316  r/shell_bind_tcp                                                     normal  No     R Command Shell, Bind TCP
   317  r/shell_reverse_tcp                                                  normal  No     R Command Shell, Reverse TCP
   318  ruby/pingback_bind_tcp                                               normal  No     Ruby Pingback, Bind TCP
   319  ruby/pingback_reverse_tcp                                            normal  No     Ruby Pingback, Reverse TCP
   320  ruby/shell_bind_tcp                                                  normal  No     Ruby Command Shell, Bind TCP
   321  ruby/shell_bind_tcp_ipv6                                             normal  No     Ruby Command Shell, Bind TCP IPv6
   322  ruby/shell_reverse_tcp                                               normal  No     Ruby Command Shell, Reverse TCP
   323  ruby/shell_reverse_tcp_ssl                                           normal  No     Ruby Command Shell, Reverse TCP SSL
   324  solaris/sparc/shell_bind_tcp                                         normal  No     Solaris Command Shell, Bind TCP Inline
   325  solaris/sparc/shell_find_port                                        normal  No     Solaris Command Shell, Find Port Inline
   326  solaris/sparc/shell_reverse_tcp                                      normal  No     Solaris Command Shell, Reverse TCP Inline
   327  solaris/x86/shell_bind_tcp                                           normal  No     Solaris Command Shell, Bind TCP Inline
   328  solaris/x86/shell_find_port                                          normal  No     Solaris Command Shell, Find Port Inline
   329  solaris/x86/shell_reverse_tcp                                        normal  No     Solaris Command Shell, Reverse TCP Inline
   330  tty/unix/interact                                                    normal  No     Unix TTY, Interact with Established Connection
   331  windows/adduser                                                      normal  No     Windows Execute net user /ADD
   332  windows/dllinject/bind_hidden_ipknock_tcp                            normal  No     Reflective DLL Injection, Hidden Bind Ipknock TCP Stager
   333  windows/dllinject/bind_hidden_tcp                                    normal  No     Reflective DLL Injection, Hidden Bind TCP Stager
   334  windows/dllinject/bind_ipv6_tcp                                      normal  No     Reflective DLL Injection, Bind IPv6 TCP Stager (Windows x86)
   335  windows/dllinject/bind_ipv6_tcp_uuid                                 normal  No     Reflective DLL Injection, Bind IPv6 TCP Stager with UUID Support (Windows x86)
   336  windows/dllinject/bind_named_pipe                                    normal  No     Reflective DLL Injection, Windows x86 Bind Named Pipe Stager
   337  windows/dllinject/bind_nonx_tcp                                      normal  No     Reflective DLL Injection, Bind TCP Stager (No NX or Win7)
   338  windows/dllinject/bind_tcp                                           normal  No     Reflective DLL Injection, Bind TCP Stager (Windows x86)
   339  windows/dllinject/bind_tcp_rc4                                       normal  No     Reflective DLL Injection, Bind TCP Stager (RC4 Stage Encryption, Metasm)
   340  windows/dllinject/bind_tcp_uuid                                      normal  No     Reflective DLL Injection, Bind TCP Stager with UUID Support (Windows x86)
   341  windows/dllinject/find_tag                                           normal  No     Reflective DLL Injection, Find Tag Ordinal Stager
   342  windows/dllinject/reverse_hop_http                                   normal  No     Reflective DLL Injection, Reverse Hop HTTP/HTTPS Stager
   343  windows/dllinject/reverse_http                                       normal  No     Reflective DLL Injection, Windows Reverse HTTP Stager (wininet)
   344  windows/dllinject/reverse_http_proxy_pstore                          normal  No     Reflective DLL Injection, Reverse HTTP Stager Proxy
   345  windows/dllinject/reverse_ipv6_tcp                                   normal  No     Reflective DLL Injection, Reverse TCP Stager (IPv6)
   346  windows/dllinject/reverse_nonx_tcp                                   normal  No     Reflective DLL Injection, Reverse TCP Stager (No NX or Win7)
   347  windows/dllinject/reverse_ord_tcp                                    normal  No     Reflective DLL Injection, Reverse Ordinal TCP Stager (No NX or Win7)
   348  windows/dllinject/reverse_tcp                                        normal  No     Reflective DLL Injection, Reverse TCP Stager
   349  windows/dllinject/reverse_tcp_allports                               normal  No     Reflective DLL Injection, Reverse All-Port TCP Stager
   350  windows/dllinject/reverse_tcp_dns                                    normal  No     Reflective DLL Injection, Reverse TCP Stager (DNS)
   351  windows/dllinject/reverse_tcp_rc4                                    normal  No     Reflective DLL Injection, Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   352  windows/dllinject/reverse_tcp_rc4_dns                                normal  No     Reflective DLL Injection, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   353  windows/dllinject/reverse_tcp_uuid                                   normal  No     Reflective DLL Injection, Reverse TCP Stager with UUID Support
   354  windows/dllinject/reverse_winhttp                                    normal  No     Reflective DLL Injection, Windows Reverse HTTP Stager (winhttp)
   355  windows/dns_txt_query_exec                                           normal  No     DNS TXT Record Payload Download and Execution
   356  windows/download_exec                                                normal  No     Windows Executable Download (http,https,ftp) and Execute
   357  windows/exec                                                         normal  No     Windows Execute Command
   358  windows/format_all_drives                                            manual  No     Windows Drive Formatter
   359  windows/loadlibrary                                                  normal  No     Windows LoadLibrary Path
   360  windows/messagebox                                                   normal  No     Windows MessageBox
   361  windows/meterpreter/bind_hidden_ipknock_tcp                          normal  No     Windows Meterpreter (Reflective Injection), Hidden Bind Ipknock TCP Stager
   362  windows/meterpreter/bind_hidden_tcp                                  normal  No     Windows Meterpreter (Reflective Injection), Hidden Bind TCP Stager
   363  windows/meterpreter/bind_ipv6_tcp                                    normal  No     Windows Meterpreter (Reflective Injection), Bind IPv6 TCP Stager (Windows x86)
   364  windows/meterpreter/bind_ipv6_tcp_uuid                               normal  No     Windows Meterpreter (Reflective Injection), Bind IPv6 TCP Stager with UUID Support (Windows x86)
   365  windows/meterpreter/bind_named_pipe                                  normal  No     Windows Meterpreter (Reflective Injection), Windows x86 Bind Named Pipe Stager
   366  windows/meterpreter/bind_nonx_tcp                                    normal  No     Windows Meterpreter (Reflective Injection), Bind TCP Stager (No NX or Win7)
   367  windows/meterpreter/bind_tcp                                         normal  No     Windows Meterpreter (Reflective Injection), Bind TCP Stager (Windows x86)
   368  windows/meterpreter/bind_tcp_rc4                                     normal  No     Windows Meterpreter (Reflective Injection), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   369  windows/meterpreter/bind_tcp_uuid                                    normal  No     Windows Meterpreter (Reflective Injection), Bind TCP Stager with UUID Support (Windows x86)
   370  windows/meterpreter/find_tag                                         normal  No     Windows Meterpreter (Reflective Injection), Find Tag Ordinal Stager
   371  windows/meterpreter/reverse_hop_http                                 normal  No     Windows Meterpreter (Reflective Injection), Reverse Hop HTTP/HTTPS Stager
   372  windows/meterpreter/reverse_http                                     normal  No     Windows Meterpreter (Reflective Injection), Windows Reverse HTTP Stager (wininet)
   373  windows/meterpreter/reverse_http_proxy_pstore                        normal  No     Windows Meterpreter (Reflective Injection), Reverse HTTP Stager Proxy
   374  windows/meterpreter/reverse_https                                    normal  No     Windows Meterpreter (Reflective Injection), Windows Reverse HTTPS Stager (wininet)
   375  windows/meterpreter/reverse_https_proxy                              normal  No     Windows Meterpreter (Reflective Injection), Reverse HTTPS Stager with Support for Custom Proxy
   376  windows/meterpreter/reverse_ipv6_tcp                                 normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (IPv6)
   377  windows/meterpreter/reverse_named_pipe                               normal  No     Windows Meterpreter (Reflective Injection), Windows x86 Reverse Named Pipe (SMB) Stager
   378  windows/meterpreter/reverse_nonx_tcp                                 normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (No NX or Win7)
   379  windows/meterpreter/reverse_ord_tcp                                  normal  No     Windows Meterpreter (Reflective Injection), Reverse Ordinal TCP Stager (No NX or Win7)
   380  windows/meterpreter/reverse_tcp                                      normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager
   381  windows/meterpreter/reverse_tcp_allports                             normal  No     Windows Meterpreter (Reflective Injection), Reverse All-Port TCP Stager
   382  windows/meterpreter/reverse_tcp_dns                                  normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (DNS)
   383  windows/meterpreter/reverse_tcp_rc4                                  normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   384  windows/meterpreter/reverse_tcp_rc4_dns                              normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   385  windows/meterpreter/reverse_tcp_uuid                                 normal  No     Windows Meterpreter (Reflective Injection), Reverse TCP Stager with UUID Support
   386  windows/meterpreter/reverse_winhttp                                  normal  No     Windows Meterpreter (Reflective Injection), Windows Reverse HTTP Stager (winhttp)
   387  windows/meterpreter/reverse_winhttps                                 normal  No     Windows Meterpreter (Reflective Injection), Windows Reverse HTTPS Stager (winhttp)
   388  windows/meterpreter_bind_named_pipe                                  normal  No     Windows Meterpreter Shell, Bind Named Pipe Inline
   389  windows/meterpreter_bind_tcp                                         normal  No     Windows Meterpreter Shell, Bind TCP Inline
   390  windows/meterpreter_reverse_http                                     normal  No     Windows Meterpreter Shell, Reverse HTTP Inline
   391  windows/meterpreter_reverse_https                                    normal  No     Windows Meterpreter Shell, Reverse HTTPS Inline
   392  windows/meterpreter_reverse_ipv6_tcp                                 normal  No     Windows Meterpreter Shell, Reverse TCP Inline (IPv6)
   393  windows/meterpreter_reverse_tcp                                      normal  No     Windows Meterpreter Shell, Reverse TCP Inline
   394  windows/metsvc_bind_tcp                                              normal  No     Windows Meterpreter Service, Bind TCP
   395  windows/metsvc_reverse_tcp                                           normal  No     Windows Meterpreter Service, Reverse TCP Inline
   396  windows/patchupdllinject/bind_hidden_ipknock_tcp                     normal  No     Windows Inject DLL, Hidden Bind Ipknock TCP Stager
   397  windows/patchupdllinject/bind_hidden_tcp                             normal  No     Windows Inject DLL, Hidden Bind TCP Stager
   398  windows/patchupdllinject/bind_ipv6_tcp                               normal  No     Windows Inject DLL, Bind IPv6 TCP Stager (Windows x86)
   399  windows/patchupdllinject/bind_ipv6_tcp_uuid                          normal  No     Windows Inject DLL, Bind IPv6 TCP Stager with UUID Support (Windows x86)
   400  windows/patchupdllinject/bind_named_pipe                             normal  No     Windows Inject DLL, Windows x86 Bind Named Pipe Stager
   401  windows/patchupdllinject/bind_nonx_tcp                               normal  No     Windows Inject DLL, Bind TCP Stager (No NX or Win7)
   402  windows/patchupdllinject/bind_tcp                                    normal  No     Windows Inject DLL, Bind TCP Stager (Windows x86)
   403  windows/patchupdllinject/bind_tcp_rc4                                normal  No     Windows Inject DLL, Bind TCP Stager (RC4 Stage Encryption, Metasm)
   404  windows/patchupdllinject/bind_tcp_uuid                               normal  No     Windows Inject DLL, Bind TCP Stager with UUID Support (Windows x86)
   405  windows/patchupdllinject/find_tag                                    normal  No     Windows Inject DLL, Find Tag Ordinal Stager
   406  windows/patchupdllinject/reverse_ipv6_tcp                            normal  No     Windows Inject DLL, Reverse TCP Stager (IPv6)
   407  windows/patchupdllinject/reverse_nonx_tcp                            normal  No     Windows Inject DLL, Reverse TCP Stager (No NX or Win7)
   408  windows/patchupdllinject/reverse_ord_tcp                             normal  No     Windows Inject DLL, Reverse Ordinal TCP Stager (No NX or Win7)
   409  windows/patchupdllinject/reverse_tcp                                 normal  No     Windows Inject DLL, Reverse TCP Stager
   410  windows/patchupdllinject/reverse_tcp_allports                        normal  No     Windows Inject DLL, Reverse All-Port TCP Stager
   411  windows/patchupdllinject/reverse_tcp_dns                             normal  No     Windows Inject DLL, Reverse TCP Stager (DNS)
   412  windows/patchupdllinject/reverse_tcp_rc4                             normal  No     Windows Inject DLL, Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   413  windows/patchupdllinject/reverse_tcp_rc4_dns                         normal  No     Windows Inject DLL, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   414  windows/patchupdllinject/reverse_tcp_uuid                            normal  No     Windows Inject DLL, Reverse TCP Stager with UUID Support
   415  windows/patchupmeterpreter/bind_hidden_ipknock_tcp                   normal  No     Windows Meterpreter (skape/jt Injection), Hidden Bind Ipknock TCP Stager
   416  windows/patchupmeterpreter/bind_hidden_tcp                           normal  No     Windows Meterpreter (skape/jt Injection), Hidden Bind TCP Stager
   417  windows/patchupmeterpreter/bind_ipv6_tcp                             normal  No     Windows Meterpreter (skape/jt Injection), Bind IPv6 TCP Stager (Windows x86)
   418  windows/patchupmeterpreter/bind_ipv6_tcp_uuid                        normal  No     Windows Meterpreter (skape/jt Injection), Bind IPv6 TCP Stager with UUID Support (Windows x86)
   419  windows/patchupmeterpreter/bind_named_pipe                           normal  No     Windows Meterpreter (skape/jt Injection), Windows x86 Bind Named Pipe Stager
   420  windows/patchupmeterpreter/bind_nonx_tcp                             normal  No     Windows Meterpreter (skape/jt Injection), Bind TCP Stager (No NX or Win7)
   421  windows/patchupmeterpreter/bind_tcp                                  normal  No     Windows Meterpreter (skape/jt Injection), Bind TCP Stager (Windows x86)
   422  windows/patchupmeterpreter/bind_tcp_rc4                              normal  No     Windows Meterpreter (skape/jt Injection), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   423  windows/patchupmeterpreter/bind_tcp_uuid                             normal  No     Windows Meterpreter (skape/jt Injection), Bind TCP Stager with UUID Support (Windows x86)
   424  windows/patchupmeterpreter/find_tag                                  normal  No     Windows Meterpreter (skape/jt Injection), Find Tag Ordinal Stager
   425  windows/patchupmeterpreter/reverse_ipv6_tcp                          normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (IPv6)
   426  windows/patchupmeterpreter/reverse_nonx_tcp                          normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (No NX or Win7)
   427  windows/patchupmeterpreter/reverse_ord_tcp                           normal  No     Windows Meterpreter (skape/jt Injection), Reverse Ordinal TCP Stager (No NX or Win7)
   428  windows/patchupmeterpreter/reverse_tcp                               normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager
   429  windows/patchupmeterpreter/reverse_tcp_allports                      normal  No     Windows Meterpreter (skape/jt Injection), Reverse All-Port TCP Stager
   430  windows/patchupmeterpreter/reverse_tcp_dns                           normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (DNS)
   431  windows/patchupmeterpreter/reverse_tcp_rc4                           normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   432  windows/patchupmeterpreter/reverse_tcp_rc4_dns                       normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   433  windows/patchupmeterpreter/reverse_tcp_uuid                          normal  No     Windows Meterpreter (skape/jt Injection), Reverse TCP Stager with UUID Support
   434  windows/pingback_bind_tcp                                            normal  No     Windows x86 Pingback, Bind TCP Inline
   435  windows/pingback_reverse_tcp                                         normal  No     Windows x86 Pingback, Reverse TCP Inline
   436  windows/powershell_bind_tcp                                          normal  No     Windows Interactive Powershell Session, Bind TCP
   437  windows/powershell_reverse_tcp                                       normal  No     Windows Interactive Powershell Session, Reverse TCP
   438  windows/shell/bind_hidden_ipknock_tcp                                normal  No     Windows Command Shell, Hidden Bind Ipknock TCP Stager
   439  windows/shell/bind_hidden_tcp                                        normal  No     Windows Command Shell, Hidden Bind TCP Stager
   440  windows/shell/bind_ipv6_tcp                                          normal  No     Windows Command Shell, Bind IPv6 TCP Stager (Windows x86)
   441  windows/shell/bind_ipv6_tcp_uuid                                     normal  No     Windows Command Shell, Bind IPv6 TCP Stager with UUID Support (Windows x86)
   442  windows/shell/bind_named_pipe                                        normal  No     Windows Command Shell, Windows x86 Bind Named Pipe Stager
   443  windows/shell/bind_nonx_tcp                                          normal  No     Windows Command Shell, Bind TCP Stager (No NX or Win7)
   444  windows/shell/bind_tcp                                               normal  No     Windows Command Shell, Bind TCP Stager (Windows x86)
   445  windows/shell/bind_tcp_rc4                                           normal  No     Windows Command Shell, Bind TCP Stager (RC4 Stage Encryption, Metasm)
   446  windows/shell/bind_tcp_uuid                                          normal  No     Windows Command Shell, Bind TCP Stager with UUID Support (Windows x86)
   447  windows/shell/find_tag                                               normal  No     Windows Command Shell, Find Tag Ordinal Stager
   448  windows/shell/reverse_ipv6_tcp                                       normal  No     Windows Command Shell, Reverse TCP Stager (IPv6)
   449  windows/shell/reverse_nonx_tcp                                       normal  No     Windows Command Shell, Reverse TCP Stager (No NX or Win7)
   450  windows/shell/reverse_ord_tcp                                        normal  No     Windows Command Shell, Reverse Ordinal TCP Stager (No NX or Win7)
   451  windows/shell/reverse_tcp                                            normal  No     Windows Command Shell, Reverse TCP Stager
   452  windows/shell/reverse_tcp_allports                                   normal  No     Windows Command Shell, Reverse All-Port TCP Stager
   453  windows/shell/reverse_tcp_dns                                        normal  No     Windows Command Shell, Reverse TCP Stager (DNS)
   454  windows/shell/reverse_tcp_rc4                                        normal  No     Windows Command Shell, Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   455  windows/shell/reverse_tcp_rc4_dns                                    normal  No     Windows Command Shell, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   456  windows/shell/reverse_tcp_uuid                                       normal  No     Windows Command Shell, Reverse TCP Stager with UUID Support
   457  windows/shell/reverse_udp                                            normal  No     Windows Command Shell, Reverse UDP Stager with UUID Support
   458  windows/shell_bind_tcp                                               normal  No     Windows Command Shell, Bind TCP Inline
   459  windows/shell_bind_tcp_xpfw                                          normal  No     Windows Disable Windows ICF, Command Shell, Bind TCP Inline
   460  windows/shell_hidden_bind_tcp                                        normal  No     Windows Command Shell, Hidden Bind TCP Inline
   461  windows/shell_reverse_tcp                                            normal  No     Windows Command Shell, Reverse TCP Inline
   462  windows/speak_pwned                                                  normal  No     Windows Speech API - Say "You Got Pwned!"
   463  windows/upexec/bind_hidden_ipknock_tcp                               normal  No     Windows Upload/Execute, Hidden Bind Ipknock TCP Stager
   464  windows/upexec/bind_hidden_tcp                                       normal  No     Windows Upload/Execute, Hidden Bind TCP Stager
   465  windows/upexec/bind_ipv6_tcp                                         normal  No     Windows Upload/Execute, Bind IPv6 TCP Stager (Windows x86)
   466  windows/upexec/bind_ipv6_tcp_uuid                                    normal  No     Windows Upload/Execute, Bind IPv6 TCP Stager with UUID Support (Windows x86)
   467  windows/upexec/bind_named_pipe                                       normal  No     Windows Upload/Execute, Windows x86 Bind Named Pipe Stager
   468  windows/upexec/bind_nonx_tcp                                         normal  No     Windows Upload/Execute, Bind TCP Stager (No NX or Win7)
   469  windows/upexec/bind_tcp                                              normal  No     Windows Upload/Execute, Bind TCP Stager (Windows x86)
   470  windows/upexec/bind_tcp_rc4                                          normal  No     Windows Upload/Execute, Bind TCP Stager (RC4 Stage Encryption, Metasm)
   471  windows/upexec/bind_tcp_uuid                                         normal  No     Windows Upload/Execute, Bind TCP Stager with UUID Support (Windows x86)
   472  windows/upexec/find_tag                                              normal  No     Windows Upload/Execute, Find Tag Ordinal Stager
   473  windows/upexec/reverse_ipv6_tcp                                      normal  No     Windows Upload/Execute, Reverse TCP Stager (IPv6)
   474  windows/upexec/reverse_nonx_tcp                                      normal  No     Windows Upload/Execute, Reverse TCP Stager (No NX or Win7)
   475  windows/upexec/reverse_ord_tcp                                       normal  No     Windows Upload/Execute, Reverse Ordinal TCP Stager (No NX or Win7)
   476  windows/upexec/reverse_tcp                                           normal  No     Windows Upload/Execute, Reverse TCP Stager
   477  windows/upexec/reverse_tcp_allports                                  normal  No     Windows Upload/Execute, Reverse All-Port TCP Stager
   478  windows/upexec/reverse_tcp_dns                                       normal  No     Windows Upload/Execute, Reverse TCP Stager (DNS)
   479  windows/upexec/reverse_tcp_rc4                                       normal  No     Windows Upload/Execute, Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   480  windows/upexec/reverse_tcp_rc4_dns                                   normal  No     Windows Upload/Execute, Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   481  windows/upexec/reverse_tcp_uuid                                      normal  No     Windows Upload/Execute, Reverse TCP Stager with UUID Support
   482  windows/upexec/reverse_udp                                           normal  No     Windows Upload/Execute, Reverse UDP Stager with UUID Support
   483  windows/vncinject/bind_hidden_ipknock_tcp                            normal  No     VNC Server (Reflective Injection), Hidden Bind Ipknock TCP Stager
   484  windows/vncinject/bind_hidden_tcp                                    normal  No     VNC Server (Reflective Injection), Hidden Bind TCP Stager
   485  windows/vncinject/bind_ipv6_tcp                                      normal  No     VNC Server (Reflective Injection), Bind IPv6 TCP Stager (Windows x86)
   486  windows/vncinject/bind_ipv6_tcp_uuid                                 normal  No     VNC Server (Reflective Injection), Bind IPv6 TCP Stager with UUID Support (Windows x86)
   487  windows/vncinject/bind_named_pipe                                    normal  No     VNC Server (Reflective Injection), Windows x86 Bind Named Pipe Stager
   488  windows/vncinject/bind_nonx_tcp                                      normal  No     VNC Server (Reflective Injection), Bind TCP Stager (No NX or Win7)
   489  windows/vncinject/bind_tcp                                           normal  No     VNC Server (Reflective Injection), Bind TCP Stager (Windows x86)
   490  windows/vncinject/bind_tcp_rc4                                       normal  No     VNC Server (Reflective Injection), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   491  windows/vncinject/bind_tcp_uuid                                      normal  No     VNC Server (Reflective Injection), Bind TCP Stager with UUID Support (Windows x86)
   492  windows/vncinject/find_tag                                           normal  No     VNC Server (Reflective Injection), Find Tag Ordinal Stager
   493  windows/vncinject/reverse_hop_http                                   normal  No     VNC Server (Reflective Injection), Reverse Hop HTTP/HTTPS Stager
   494  windows/vncinject/reverse_http                                       normal  No     VNC Server (Reflective Injection), Windows Reverse HTTP Stager (wininet)
   495  windows/vncinject/reverse_http_proxy_pstore                          normal  No     VNC Server (Reflective Injection), Reverse HTTP Stager Proxy
   496  windows/vncinject/reverse_ipv6_tcp                                   normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (IPv6)
   497  windows/vncinject/reverse_nonx_tcp                                   normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (No NX or Win7)
   498  windows/vncinject/reverse_ord_tcp                                    normal  No     VNC Server (Reflective Injection), Reverse Ordinal TCP Stager (No NX or Win7)
   499  windows/vncinject/reverse_tcp                                        normal  No     VNC Server (Reflective Injection), Reverse TCP Stager
   500  windows/vncinject/reverse_tcp_allports                               normal  No     VNC Server (Reflective Injection), Reverse All-Port TCP Stager
   501  windows/vncinject/reverse_tcp_dns                                    normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (DNS)
   502  windows/vncinject/reverse_tcp_rc4                                    normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   503  windows/vncinject/reverse_tcp_rc4_dns                                normal  No     VNC Server (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption DNS, Metasm)
   504  windows/vncinject/reverse_tcp_uuid                                   normal  No     VNC Server (Reflective Injection), Reverse TCP Stager with UUID Support
   505  windows/vncinject/reverse_winhttp                                    normal  No     VNC Server (Reflective Injection), Windows Reverse HTTP Stager (winhttp)
   506  windows/x64/exec                                                     normal  No     Windows x64 Execute Command
   507  windows/x64/loadlibrary                                              normal  No     Windows x64 LoadLibrary Path
   508  windows/x64/messagebox                                               normal  No     Windows MessageBox x64
   509  windows/x64/meterpreter/bind_ipv6_tcp                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
   510  windows/x64/meterpreter/bind_ipv6_tcp_uuid                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
   511  windows/x64/meterpreter/bind_named_pipe                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
   512  windows/x64/meterpreter/bind_tcp                                     normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
   513  windows/x64/meterpreter/bind_tcp_rc4                                 normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   514  windows/x64/meterpreter/bind_tcp_uuid                                normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager with UUID Support (Windows x64)
   515  windows/x64/meterpreter/reverse_http                                 normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   516  windows/x64/meterpreter/reverse_https                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   517  windows/x64/meterpreter/reverse_named_pipe                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse Named Pipe (SMB) Stager
   518  windows/x64/meterpreter/reverse_tcp                                  normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   519  windows/x64/meterpreter/reverse_tcp_rc4                              normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   520  windows/x64/meterpreter/reverse_tcp_uuid                             normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   521  windows/x64/meterpreter/reverse_winhttp                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (winhttp)
   522  windows/x64/meterpreter/reverse_winhttps                             normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTPS Stager (winhttp)
   523  windows/x64/meterpreter_bind_named_pipe                              normal  No     Windows Meterpreter Shell, Bind Named Pipe Inline (x64)
   524  windows/x64/meterpreter_bind_tcp                                     normal  No     Windows Meterpreter Shell, Bind TCP Inline (x64)
   525  windows/x64/meterpreter_reverse_http                                 normal  No     Windows Meterpreter Shell, Reverse HTTP Inline (x64)
   526  windows/x64/meterpreter_reverse_https                                normal  No     Windows Meterpreter Shell, Reverse HTTPS Inline (x64)
   527  windows/x64/meterpreter_reverse_ipv6_tcp                             normal  No     Windows Meterpreter Shell, Reverse TCP Inline (IPv6) (x64)
   528  windows/x64/meterpreter_reverse_tcp                                  normal  No     Windows Meterpreter Shell, Reverse TCP Inline x64
   529  windows/x64/pingback_reverse_tcp                                     normal  No     Windows x64 Pingback, Reverse TCP Inline
   530  windows/x64/powershell_bind_tcp                                      normal  No     Windows Interactive Powershell Session, Bind TCP
   531  windows/x64/powershell_reverse_tcp                                   normal  No     Windows Interactive Powershell Session, Reverse TCP
   532  windows/x64/shell/bind_ipv6_tcp                                      normal  No     Windows x64 Command Shell, Windows x64 IPv6 Bind TCP Stager
   533  windows/x64/shell/bind_ipv6_tcp_uuid                                 normal  No     Windows x64 Command Shell, Windows x64 IPv6 Bind TCP Stager with UUID Support
   534  windows/x64/shell/bind_named_pipe                                    normal  No     Windows x64 Command Shell, Windows x64 Bind Named Pipe Stager
   535  windows/x64/shell/bind_tcp                                           normal  No     Windows x64 Command Shell, Windows x64 Bind TCP Stager
   536  windows/x64/shell/bind_tcp_rc4                                       normal  No     Windows x64 Command Shell, Bind TCP Stager (RC4 Stage Encryption, Metasm)
   537  windows/x64/shell/bind_tcp_uuid                                      normal  No     Windows x64 Command Shell, Bind TCP Stager with UUID Support (Windows x64)
   538  windows/x64/shell/reverse_tcp                                        normal  No     Windows x64 Command Shell, Windows x64 Reverse TCP Stager
   539  windows/x64/shell/reverse_tcp_rc4                                    normal  No     Windows x64 Command Shell, Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   540  windows/x64/shell/reverse_tcp_uuid                                   normal  No     Windows x64 Command Shell, Reverse TCP Stager with UUID Support (Windows x64)
   541  windows/x64/shell_bind_tcp                                           normal  No     Windows x64 Command Shell, Bind TCP Inline
   542  windows/x64/shell_reverse_tcp                                        normal  No     Windows x64 Command Shell, Reverse TCP Inline
   543  windows/x64/vncinject/bind_ipv6_tcp                                  normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 IPv6 Bind TCP Stager
   544  windows/x64/vncinject/bind_ipv6_tcp_uuid                             normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 IPv6 Bind TCP Stager with UUID Support
   545  windows/x64/vncinject/bind_named_pipe                                normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Bind Named Pipe Stager
   546  windows/x64/vncinject/bind_tcp                                       normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Bind TCP Stager
   547  windows/x64/vncinject/bind_tcp_rc4                                   normal  No     Windows x64 VNC Server (Reflective Injection), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   548  windows/x64/vncinject/bind_tcp_uuid                                  normal  No     Windows x64 VNC Server (Reflective Injection), Bind TCP Stager with UUID Support (Windows x64)
   549  windows/x64/vncinject/reverse_http                                   normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse HTTP Stager (wininet)
   550  windows/x64/vncinject/reverse_https                                  normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse HTTP Stager (wininet)
   551  windows/x64/vncinject/reverse_tcp                                    normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse TCP Stager
   552  windows/x64/vncinject/reverse_tcp_rc4                                normal  No     Windows x64 VNC Server (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   553  windows/x64/vncinject/reverse_tcp_uuid                               normal  No     Windows x64 VNC Server (Reflective Injection), Reverse TCP Stager with UUID Support (Windows x64)
   554  windows/x64/vncinject/reverse_winhttp                                normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse HTTP Stager (winhttp)
   555  windows/x64/vncinject/reverse_winhttps                               normal  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse HTTPS Stager (winhttp)
"""
    msfauxiliary="""
Auxiliary
=========

   #     Name                                                           Disclosure Date  Rank    Check  Description
   -     ----                                                           ---------------  ----    -----  -----------
   0     admin/2wire/xslt_password_reset                                2007-08-15       normal  No     2Wire Cross-Site Request Forgery Password Reset Vulnerability
   1     admin/android/google_play_store_uxss_xframe_rce                                 normal  No     Android Browser RCE Through Google Play Store XFO
   2     admin/appletv/appletv_display_image                                             normal  No     Apple TV Image Remote Control
   3     admin/appletv/appletv_display_video                                             normal  No     Apple TV Video Remote Control
   4     admin/atg/atg_client                                                            normal  Yes    Veeder-Root Automatic Tank Gauge (ATG) Administrative Client
   5     admin/aws/aws_launch_instances                                                  normal  No     Launches Hosts in AWS
   6     admin/backupexec/dump                                                           normal  No     Veritas Backup Exec Windows Remote File Access
   7     admin/backupexec/registry                                                       normal  No     Veritas Backup Exec Server Registry Access
   8     admin/chromecast/chromecast_reset                                               normal  No     Chromecast Factory Reset DoS
   9     admin/chromecast/chromecast_youtube                                             normal  No     Chromecast YouTube Remote Control
   10    admin/cisco/cisco_asa_extrabacon                                                normal  Yes    Cisco ASA Authentication Bypass (EXTRABACON)
   11    admin/cisco/cisco_secure_acs_bypass                                             normal  Yes    Cisco Secure ACS Unauthorized Password Change
   12    admin/cisco/vpn_3000_ftp_bypass                                2006-08-23       normal  No     Cisco VPN Concentrator 3000 FTP Unauthorized Administrative Access
   13    admin/db2/db2rcmd                                              2004-03-04       normal  No     IBM DB2 db2rcmd.exe Command Execution Vulnerability
   14    admin/dns/dyn_dns_update                                                        normal  No     DNS Server Dynamic Update Record Injection
   15    admin/edirectory/edirectory_dhost_cookie                                        normal  No     Novell eDirectory DHOST Predictable Session Cookie
   16    admin/edirectory/edirectory_edirutil                                            normal  No     Novell eDirectory eMBox Unauthenticated File Access
   17    admin/emc/alphastor_devicemanager_exec                         2008-05-27       normal  No     EMC AlphaStor Device Manager Arbitrary Command Execution
   18    admin/emc/alphastor_librarymanager_exec                        2008-05-27       normal  No     EMC AlphaStor Library Manager Arbitrary Command Execution
   19    admin/firetv/firetv_youtube                                                     normal  No     Amazon Fire TV YouTube Remote Control
   20    admin/hp/hp_data_protector_cmd                                 2011-02-07       normal  No     HP Data Protector 6.1 EXEC_CMD Command Execution
   21    admin/hp/hp_ilo_create_admin_account                           2017-08-24       normal  Yes    HP iLO 4 1.00-2.50 Authentication Bypass Administrator Account Creation
   22    admin/hp/hp_imc_som_create_account                             2013-10-08       normal  No     HP Intelligent Management SOM Account Creation
   23    admin/http/allegro_rompager_auth_bypass                        2014-12-17       normal  No     Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Authentication Bypass
   24    admin/http/arris_motorola_surfboard_backdoor_xss               2015-04-08       normal  No     Arris / Motorola Surfboard SBG6580 Web Interface Takeover
   25    admin/http/axigen_file_access                                  2012-10-31       normal  No     Axigen Arbitrary File Read and Delete
   26    admin/http/cfme_manageiq_evm_pass_reset                        2013-11-12       normal  No     Red Hat CloudForms Management Engine 5.1 miq_policy/explorer SQL Injection
   27    admin/http/cnpilot_r_cmd_exec                                                   normal  Yes    Cambium cnPilot r200/r201 Command Execution as 'root'
   28    admin/http/cnpilot_r_fpt                                                        normal  Yes    Cambium cnPilot r200/r201 File Path Traversal
   29    admin/http/contentkeeper_fileaccess                                             normal  Yes    ContentKeeper Web Appliance mimencode File Access
   30    admin/http/dlink_dir_300_600_exec_noauth                       2013-02-04       normal  No     D-Link DIR-600 / DIR-300 Unauthenticated Remote Command Execution
   31    admin/http/dlink_dir_645_password_extractor                                     normal  No     D-Link DIR 645 Password Extractor
   32    admin/http/dlink_dsl320b_password_extractor                                     normal  No     D-Link DSL 320B Password Extractor
   33    admin/http/foreman_openstack_satellite_priv_esc                2013-06-06       normal  No     Foreman (Red Hat OpenStack/Satellite) users/create Mass Assignment
   34    admin/http/gitstack_rest                                       2018-01-15       normal  No     GitStack Unauthenticated REST API Requests
   35    admin/http/hp_web_jetadmin_exec                                2004-04-27       normal  No     HP Web JetAdmin 6.5 Server Arbitrary Command Execution
   36    admin/http/iis_auth_bypass                                     2010-07-02       normal  No     MS10-065 Microsoft IIS 5 NTFS Stream Authentication Bypass
   37    admin/http/intersil_pass_reset                                 2007-09-10       normal  Yes    Intersil (Boa) HTTPd Basic Authentication Password Reset
   38    admin/http/iomega_storcenterpro_sessionid                                       normal  No     Iomega StorCenter Pro NAS Web Authentication Bypass
   39    admin/http/jboss_bshdeployer                                                    normal  No     JBoss JMX Console Beanshell Deployer WAR Upload and Deployment
   40    admin/http/jboss_deploymentfilerepository                                       normal  No     JBoss JMX Console DeploymentFileRepository WAR Upload and Deployment
   41    admin/http/jboss_seam_exec                                     2010-07-19       normal  No     JBoss Seam 2 Remote Command Execution
   42    admin/http/joomla_registration_privesc                         2016-10-25       normal  Yes    Joomla Account Creation and Privilege Escalation
   43    admin/http/kaseya_master_admin                                 2015-09-23       normal  No     Kaseya VSA Master Administrator Account Creation
   44    admin/http/katello_satellite_priv_esc                          2014-03-24       normal  No     Katello (Red Hat Satellite) users/update_roles Missing Authorization
   45    admin/http/limesurvey_file_download                            2015-10-12       normal  No     Limesurvey Unauthenticated File Download
   46    admin/http/linksys_e1500_e2500_exec                            2013-02-05       normal  No     Linksys E1500/E2500 Remote Command Execution
   47    admin/http/linksys_tmunblock_admin_reset_bof                   2014-02-19       normal  No     Linksys WRT120N tmUnblock Stack Buffer Overflow
   48    admin/http/linksys_wrt54gl_exec                                2013-01-18       normal  No     Linksys WRT54GL Remote Command Execution
   49    admin/http/manage_engine_dc_create_admin                       2014-12-31       normal  No     ManageEngine Desktop Central Administrator Account Creation
   50    admin/http/manageengine_dir_listing                            2015-01-28       normal  No     ManageEngine Multiple Products Arbitrary Directory Listing
   51    admin/http/manageengine_file_download                          2015-01-28       normal  No     ManageEngine Multiple Products Arbitrary File Download
   52    admin/http/manageengine_pmp_privesc                            2014-11-08       normal  Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   53    admin/http/mantisbt_password_reset                             2017-04-16       normal  Yes    MantisBT password reset
   54    admin/http/mutiny_frontend_read_delete                         2013-05-15       normal  No     Mutiny 5 Arbitrary File Read and Delete
   55    admin/http/netflow_file_download                               2014-11-30       normal  No     ManageEngine NetFlow Analyzer Arbitrary File Download
   56    admin/http/netgear_auth_download                               2016-02-04       normal  No     NETGEAR ProSafe Network Management System 300 Authenticated File Download
   57    admin/http/netgear_soap_password_extractor                     2015-02-11       normal  No     Netgear Unauthenticated SOAP Password Extractor
   58    admin/http/netgear_wnr2000_pass_recovery                       2016-12-20       normal  No     NETGEAR WNR2000v5 Administrator Password Recovery
   59    admin/http/nexpose_xxe_file_read                                                normal  No     Nexpose XXE Arbitrary File Read
   60    admin/http/novell_file_reporter_filedelete                                      normal  No     Novell File Reporter Agent Arbitrary File Delete
   61    admin/http/nuuo_nvrmini_reset                                  2016-08-04       normal  No     NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Default Configuration Load and Administrator Password Reset
   62    admin/http/openbravo_xxe                                       2013-10-30       normal  No     Openbravo ERP XXE Arbitrary File Read
   63    admin/http/pfadmin_set_protected_alias                         2017-02-03       normal  Yes    Postfixadmin Protected Alias Deletion Vulnerability
   64    admin/http/rails_devise_pass_reset                             2013-01-28       normal  No     Ruby on Rails Devise Authentication Password Reset
   65    admin/http/scadabr_credential_dump                             2017-05-28       normal  No     ScadaBR Credentials Dumper
   66    admin/http/scrutinizer_add_user                                2012-07-27       normal  No     Plixer Scrutinizer NetFlow and sFlow Analyzer HTTP Authentication Bypass
   67    admin/http/sophos_wpa_traversal                                2013-04-03       normal  No     Sophos Web Protection Appliance patience.cgi Directory Traversal
   68    admin/http/supra_smart_cloud_tv_rfi                            2019-06-03       normal  No     Supra Smart Cloud TV Remote File Inclusion
   69    admin/http/sysaid_admin_acct                                   2015-06-03       normal  No     SysAid Help Desk Administrator Account Creation
   70    admin/http/sysaid_file_download                                2015-06-03       normal  No     SysAid Help Desk Arbitrary File Download
   71    admin/http/sysaid_sql_creds                                    2015-06-03       normal  No     SysAid Help Desk Database Credentials Disclosure
   72    admin/http/telpho10_credential_dump                            2016-09-02       normal  No     Telpho10 Backup Credentials Dumper
   73    admin/http/tomcat_administration                                                normal  Yes    Tomcat Administration Tool Default Access
   74    admin/http/tomcat_utf8_traversal                               2009-01-09       normal  Yes    Tomcat UTF-8 Directory Traversal Vulnerability
   75    admin/http/trendmicro_dlp_traversal                            2009-01-09       normal  Yes    TrendMicro Data Loss Prevention 5.5 Directory Traversal
   76    admin/http/typo3_news_module_sqli                              2017-04-06       normal  No     TYPO3 News Module SQL Injection
   77    admin/http/typo3_sa_2009_001                                   2009-01-20       normal  No     TYPO3 sa-2009-001 Weak Encryption Key File Disclosure
   78    admin/http/typo3_sa_2009_002                                   2009-02-10       normal  No     Typo3 sa-2009-002 File Disclosure
   79    admin/http/typo3_sa_2010_020                                                    normal  No     TYPO3 sa-2010-020 Remote File Disclosure
   80    admin/http/typo3_winstaller_default_enc_keys                                    normal  No     TYPO3 Winstaller Default Encryption Keys
   81    admin/http/ulterius_file_download                                               normal  No     Ulterius Server File Download Vulnerability
   82    admin/http/vbulletin_upgrade_admin                             2013-10-09       normal  No     vBulletin Administrator Account Creation
   83    admin/http/webnms_cred_disclosure                              2016-07-04       normal  No     WebNMS Framework Server Credential Disclosure
   84    admin/http/webnms_file_download                                2016-07-04       normal  No     WebNMS Framework Server Arbitrary Text File Download
   85    admin/http/wp_custom_contact_forms                             2014-08-07       normal  No     WordPress custom-contact-forms Plugin SQL Upload
   86    admin/http/wp_easycart_privilege_escalation                    2015-02-25       normal  Yes    WordPress WP EasyCart Plugin Privilege Escalation
   87    admin/http/wp_gdpr_compliance_privesc                          2018-11-08       normal  Yes    WordPress WP GDPR Compliance Plugin Privilege Escalation
   88    admin/http/wp_google_maps_sqli                                 2019-04-02       normal  Yes    WordPress Google Maps Plugin SQL Injection
   89    admin/http/wp_symposium_sql_injection                          2015-08-18       normal  Yes    WordPress Symposium Plugin SQL Injection
   90    admin/http/wp_wplms_privilege_escalation                       2015-02-09       normal  Yes    WordPress WPLMS Theme Privilege Escalation
   91    admin/http/zyxel_admin_password_extractor                                       normal  No     ZyXEL GS1510-16 Password Extractor
   92    admin/kerberos/ms14_068_kerberos_checksum                      2014-11-18       normal  No     MS14-068 Microsoft Kerberos Checksum Validation Vulnerability
   93    admin/maxdb/maxdb_cons_exec                                    2008-01-09       normal  No     SAP MaxDB cons.exe Remote Command Injection
   94    admin/misc/sercomm_dump_config                                 2013-12-31       normal  No     SerComm Device Configuration Dump
   95    admin/misc/wol                                                                  normal  No     UDP Wake-On-Lan (WOL)
   96    admin/motorola/wr850g_cred                                     2004-09-24       normal  No     Motorola WR850G v4.03 Credentials
   97    admin/ms/ms08_059_his2006                                      2008-10-14       normal  No     Microsoft Host Integration Server 2006 Command Execution Vulnerability
   98    admin/mssql/mssql_enum                                                          normal  No     Microsoft SQL Server Configuration Enumerator
   99    admin/mssql/mssql_enum_domain_accounts                                          normal  No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
   100   admin/mssql/mssql_enum_domain_accounts_sqli                                     normal  No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
   101   admin/mssql/mssql_enum_sql_logins                                               normal  No     Microsoft SQL Server SUSER_SNAME SQL Logins Enumeration
   102   admin/mssql/mssql_escalate_dbowner                                              normal  No     Microsoft SQL Server Escalate Db_Owner
   103   admin/mssql/mssql_escalate_dbowner_sqli                                         normal  No     Microsoft SQL Server SQLi Escalate Db_Owner
   104   admin/mssql/mssql_escalate_execute_as                                           normal  No     Microsoft SQL Server Escalate EXECUTE AS
   105   admin/mssql/mssql_escalate_execute_as_sqli                                      normal  No     Microsoft SQL Server SQLi Escalate Execute AS
   106   admin/mssql/mssql_exec                                                          normal  No     Microsoft SQL Server xp_cmdshell Command Execution
   107   admin/mssql/mssql_findandsampledata                                             normal  Yes    Microsoft SQL Server Find and Sample Data
   108   admin/mssql/mssql_idf                                                           normal  No     Microsoft SQL Server Interesting Data Finder
   109   admin/mssql/mssql_ntlm_stealer                                                  normal  Yes    Microsoft SQL Server NTLM Stealer
   110   admin/mssql/mssql_ntlm_stealer_sqli                                             normal  No     Microsoft SQL Server SQLi NTLM Stealer
   111   admin/mssql/mssql_sql                                                           normal  No     Microsoft SQL Server Generic Query
   112   admin/mssql/mssql_sql_file                                                      normal  No     Microsoft SQL Server Generic Query from File
   113   admin/mysql/mysql_enum                                                          normal  No     MySQL Enumeration Module
   114   admin/mysql/mysql_sql                                                           normal  No     MySQL SQL Generic Query
   115   admin/natpmp/natpmp_map                                                         normal  Yes    NAT-PMP Port Mapper
   116   admin/netbios/netbios_spoof                                                     normal  No     NetBIOS Response Brute Force Spoof (Direct)
   117   admin/officescan/tmlisten_traversal                                             normal  Yes    TrendMicro OfficeScanNT Listener Traversal Arbitrary File Access
   118   admin/oracle/ora_ntlm_stealer                                  2009-04-07       normal  No     Oracle SMB Relay Code Execution
   119   admin/oracle/oracle_index_privesc                              2015-01-21       normal  No     Oracle DB Privilege Escalation via Function-Based Index
   120   admin/oracle/oracle_login                                      2008-11-20       normal  No     Oracle Account Discovery
   121   admin/oracle/oracle_sql                                        2007-12-07       normal  No     Oracle SQL Generic Query
   122   admin/oracle/oraenum                                                            normal  No     Oracle Database Enumeration
   123   admin/oracle/osb_execqr                                        2009-01-14       normal  No     Oracle Secure Backup exec_qr() Command Injection Vulnerability
   124   admin/oracle/osb_execqr2                                       2009-08-18       normal  No     Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability
   125   admin/oracle/osb_execqr3                                       2010-07-13       normal  No     Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability
   126   admin/oracle/post_exploitation/win32exec                       2007-12-07       normal  No     Oracle Java execCommand (Win32)
   127   admin/oracle/post_exploitation/win32upload                     2005-02-10       normal  No     Oracle URL Download
   128   admin/oracle/sid_brute                                         2009-01-07       normal  No     Oracle TNS Listener SID Brute Forcer
   129   admin/oracle/tnscmd                                            2009-02-01       normal  No     Oracle TNS Listener Command Issuer
   130   admin/pop2/uw_fileretrieval                                    2000-07-14       normal  No     UoW pop2d Remote File Retrieval Vulnerability
   131   admin/postgres/postgres_readfile                                                normal  No     PostgreSQL Server Generic Query
   132   admin/postgres/postgres_sql                                                     normal  No     PostgreSQL Server Generic Query
   133   admin/sap/sap_configservlet_exec_noauth                        2012-11-01       normal  No     SAP ConfigServlet OS Command Execution
   134   admin/sap/sap_mgmt_con_osexec                                                   normal  Yes    SAP Management Console OSExecute
   135   admin/scada/advantech_webaccess_dbvisitor_sqli                 2014-04-08       normal  Yes    Advantech WebAccess DBVisitor.dll ChartThemeConfig SQL Injection
   136   admin/scada/ge_proficy_substitute_traversal                    2013-01-22       normal  No     GE Proficy Cimplicity WebView substitute.bcl Directory Traversal
   137   admin/scada/modicon_command                                    2012-04-05       normal  No     Schneider Modicon Remote START/STOP Command
   138   admin/scada/modicon_password_recovery                          2012-01-19       normal  Yes    Schneider Modicon Quantum Password Recovery
   139   admin/scada/modicon_stux_transfer                              2012-04-05       normal  No     Schneider Modicon Ladder Logic Upload/Download
   140   admin/scada/moxa_credentials_recovery                          2015-07-28       normal  Yes    Moxa Device Credential Retrieval
   141   admin/scada/multi_cip_command                                  2012-01-19       normal  No     Allen-Bradley/Rockwell Automation EtherNet/IP CIP Commands
   142   admin/scada/pcom_command                                                        normal  No     Unitronics PCOM remote START/STOP/RESET command
   143   admin/scada/phoenix_command                                    2015-05-20       normal  No     PhoenixContact PLC Remote START/STOP Command
   144   admin/scada/yokogawa_bkbcopyd_client                           2014-08-09       normal  No     Yokogawa BKBCopyD.exe Client
   145   admin/serverprotect/file                                                        normal  No     TrendMicro ServerProtect File Access
   146   admin/smb/check_dir_file                                                        normal  Yes    SMB Scanner Check File/Directory Utility
   147   admin/smb/delete_file                                                           normal  Yes    SMB File Delete Utility
   148   admin/smb/download_file                                                         normal  Yes    SMB File Download Utility
   149   admin/smb/list_directory                                                        normal  No     SMB Directory Listing Utility
   150   admin/smb/ms17_010_command                                     2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   151   admin/smb/psexec_command                                                        normal  Yes    Microsoft Windows Authenticated Administration Utility
   152   admin/smb/psexec_ntdsgrab                                                       normal  No     PsExec NTDS.dit And SYSTEM Hive Download Utility
   153   admin/smb/samba_symlink_traversal                                               normal  No     Samba Symlink Directory Traversal
   154   admin/smb/upload_file                                                           normal  Yes    SMB File Upload Utility
   155   admin/smb/webexec_command                                                       normal  Yes    WebEx Remote Command Execution Utility
   156   admin/sunrpc/solaris_kcms_readfile                             2003-01-22       normal  No     Solaris KCMS + TTDB Arbitrary File Read
   157   admin/teradata/teradata_odbc_sql                               2018-03-29       normal  Yes    Teradata ODBC SQL Query Module
   158   admin/tftp/tftp_transfer_util                                                   normal  No     TFTP File Transfer Utility
   159   admin/tikiwiki/tikidblib                                       2006-11-01       normal  No     TikiWiki Information Disclosure
   160   admin/upnp/soap_portmapping                                                     normal  No     UPnP IGD SOAP Port Mapping Utility
   161   admin/vmware/poweroff_vm                                                        normal  No     VMWare Power Off Virtual Machine
   162   admin/vmware/poweron_vm                                                         normal  No     VMWare Power On Virtual Machine
   163   admin/vmware/tag_vm                                                             normal  No     VMWare Tag Virtual Machine
   164   admin/vmware/terminate_esx_sessions                                             normal  No     VMWare Terminate ESX Login Sessions
   165   admin/vnc/realvnc_41_bypass                                    2006-05-15       normal  No     RealVNC NULL Authentication Mode Bypass
   166   admin/vxworks/apple_airport_extreme_password                                    normal  No     Apple Airport Extreme Password Extraction (WDBRPC)
   167   admin/vxworks/dlink_i2eye_autoanswer                                            normal  No     D-Link i2eye Video Conference AutoAnswer (WDBRPC)
   168   admin/vxworks/wdbrpc_memory_dump                                                normal  No     VxWorks WDB Agent Remote Memory Dump
   169   admin/vxworks/wdbrpc_reboot                                                     normal  Yes    VxWorks WDB Agent Remote Reboot
   170   admin/webmin/edit_html_fileaccess                              2012-09-06       normal  No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   171   admin/webmin/file_disclosure                                   2006-06-30       normal  No     Webmin File Disclosure
   172   admin/wemo/crockpot                                                             normal  Yes    Belkin Wemo-Enabled Crock-Pot Remote Control
   173   admin/zend/java_bridge                                         2011-03-28       normal  No     Zend Server Java Bridge Design Flaw Remote Code Execution
   174   analyze/apply_pot                                                               normal  No     Apply Pot File To Hashes
   175   analyze/jtr_aix                                                                 normal  No     John the Ripper AIX Password Cracker
   176   analyze/jtr_linux                                                               normal  No     John the Ripper Linux Password Cracker
   177   analyze/jtr_mssql_fast                                                          normal  No     John the Ripper MS SQL Password Cracker (Fast Mode)
   178   analyze/jtr_mysql_fast                                                          normal  No     John the Ripper MySQL Password Cracker (Fast Mode)
   179   analyze/jtr_oracle_fast                                                         normal  No     John the Ripper Oracle Password Cracker (Fast Mode)
   180   analyze/jtr_postgres_fast                                                       normal  No     John the Ripper Postgres SQL Password Cracker
   181   analyze/jtr_windows_fast                                                        normal  No     John the Ripper Windows Password Cracker (Fast Mode)
   182   analyze/modbus_zip                                                              normal  No     Extract zip from Modbus communication
   183   bnat/bnat_router                                                                normal  No     BNAT Router
   184   bnat/bnat_scan                                                                  normal  Yes    BNAT Scanner
   185   client/hwbridge/connect                                                         normal  No     Hardware Bridge Session Connector
   186   client/iec104/iec104                                                            normal  No     IEC104 Client Utility
   187   client/mms/send_mms                                                             normal  No     MMS Client
   188   client/sms/send_text                                                            normal  No     SMS Client
   189   client/smtp/emailer                                                             normal  No     Generic Emailer (SMTP)
   190   cloud/aws/enum_ec2                                                              normal  No     Amazon Web Services EC2 instance enumeration
   191   cloud/aws/enum_iam                                                              normal  No     Amazon Web Services IAM credential enumeration
   192   cloud/aws/enum_s3                                                               normal  No     Amazon Web Services S3 instance enumeration
   193   crawler/msfcrawler                                                              normal  Yes    Metasploit Web Crawler
   194   docx/word_unc_injector                                                          normal  No     Microsoft Word UNC Path Injector
   195   dos/android/android_stock_browser_iframe                       2012-12-01       normal  No     Android Stock Browser Iframe DOS
   196   dos/apple_ios/webkit_backdrop_filter_blur                      2018-09-15       normal  No     iOS Safari Denial of Service with CSS
   197   dos/cisco/ios_http_percentpercent                              2000-04-26       normal  No     Cisco IOS HTTP GET /%% Request Denial of Service
   198   dos/cisco/ios_telnet_rocem                                     2017-03-17       normal  No     Cisco IOS Telnet Denial of Service
   199   dos/dhcp/isc_dhcpd_clientid                                                     normal  No     ISC DHCP Zero Length ClientID Denial of Service Module
   200   dos/dns/bind_tkey                                              2015-07-28       normal  Yes    BIND TKEY Query Denial of Service
   201   dos/dns/bind_tsig                                              2016-09-27       normal  Yes    BIND TKEY Query Denial of Service
   202   dos/freebsd/nfsd/nfsd_mount                                                     normal  No     FreeBSD Remote NFS RPC Request Denial of Service
   203   dos/hp/data_protector_rds                                      2011-01-08       normal  No     HP Data Protector Manager RDS DOS
   204   dos/http/3com_superstack_switch                                2004-06-24       normal  No     3Com SuperStack Switch Denial of Service
   205   dos/http/apache_commons_fileupload_dos                         2014-02-06       normal  No     Apache Commons FileUpload and Apache Tomcat DoS
   206   dos/http/apache_mod_isapi                                      2010-03-05       normal  No     Apache mod_isapi Dangling Pointer
   207   dos/http/apache_range_dos                                      2011-08-19       normal  Yes    Apache Range Header DoS (Apache Killer)
   208   dos/http/apache_tomcat_transfer_encoding                       2010-07-09       normal  No     Apache Tomcat Transfer-Encoding Information Disclosure and DoS
   209   dos/http/brother_debut_dos                                     2017-11-02       normal  No     Brother Debut http Denial Of Service
   210   dos/http/canon_wireless_printer                                2013-06-18       normal  No     Canon Wireless Printer Denial Of Service
   211   dos/http/dell_openmanage_post                                  2004-02-26       normal  No     Dell OpenManage POST Request Heap Overflow (win32)
   212   dos/http/f5_bigip_apm_max_sessions                                              normal  No     F5 BigIP Access Policy Manager Session Exhaustion Denial of Service
   213   dos/http/flexense_http_server_dos                              2018-03-09       normal  Yes    Flexense HTTP Server Denial Of Service
   214   dos/http/gzip_bomb_dos                                         2004-01-01       normal  No     Gzip Memory Bomb Denial Of Service
   215   dos/http/hashcollision_dos                                     2011-12-28       normal  No     Hashtable Collisions
   216   dos/http/ibm_lotus_notes                                       2017-08-31       normal  No     IBM Notes encodeURI DOS
   217   dos/http/ibm_lotus_notes2                                      2017-08-31       normal  No     IBM Notes Denial Of Service
   218   dos/http/marked_redos                                                           normal  No     marked npm module "heading" ReDoS
   219   dos/http/monkey_headers                                        2013-05-30       normal  No     Monkey HTTPD Header Parsing Denial of Service (DoS)
   220   dos/http/ms15_034_ulonglongadd                                                  normal  Yes    MS15-034 HTTP Protocol Stack Request Handling Denial-of-Service
   221   dos/http/nodejs_pipelining                                     2013-10-18       normal  Yes    Node.js HTTP Pipelining Denial of Service
   222   dos/http/novell_file_reporter_heap_bof                         2012-11-16       normal  No     NFR Agent Heap Overflow Vulnerability
   223   dos/http/rails_action_view                                     2013-12-04       normal  No     Ruby on Rails Action View MIME Memory Exhaustion
   224   dos/http/rails_json_float_dos                                  2013-11-22       normal  No     Ruby on Rails JSON Processor Floating Point Heap Overflow DoS
   225   dos/http/slowloris                                             2009-06-17       normal  No     Slowloris Denial of Service Attack
   226   dos/http/sonicwall_ssl_format                                  2009-05-29       normal  No     SonicWALL SSL-VPN Format String Vulnerability
   227   dos/http/ua_parser_js_redos                                                     normal  No     ua-parser-js npm module ReDoS
   228   dos/http/webkitplus                                            2018-06-03       normal  No     WebKitGTK+ WebKitFaviconDatabase DoS
   229   dos/http/webrick_regex                                         2008-08-08       normal  No     Ruby WEBrick::HTTP::DefaultFileHandler DoS
   230   dos/http/wordpress_directory_traversal_dos                                      normal  No     WordPress Traversal Directory DoS
   231   dos/http/wordpress_long_password_dos                           2014-11-20       normal  No     WordPress Long Password DoS
   232   dos/http/wordpress_xmlrpc_dos                                  2014-08-06       normal  No     Wordpress XMLRPC DoS
   233   dos/http/ws_dos                                                                 normal  No     ws - Denial of Service
   234   dos/mdns/avahi_portzero                                        2008-11-14       normal  No     Avahi Source Port 0 DoS
   235   dos/misc/dopewars                                              2009-10-05       normal  No     Dopewars Denial of Service
   236   dos/misc/ibm_sametime_webplayer_dos                            2013-11-07       normal  No     IBM Lotus Sametime WebPlayer DoS
   237   dos/misc/ibm_tsm_dos                                           2015-12-15       normal  No     IBM Tivoli Storage Manager FastBack Server Opcode 0x534 Denial of Service
   238   dos/misc/memcached                                                              normal  No     Memcached Remote Denial of Service
   239   dos/ntp/ntpd_reserved_dos                                      2009-10-04       normal  Yes    NTP.org ntpd Reserved Mode Denial of Service
   240   dos/pptp/ms02_063_pptp_dos                                     2002-09-26       normal  No     MS02-063 PPTP Malformed Control Data Kernel Denial of Service
   241   dos/rpc/rpcbomb                                                                 normal  Yes    RPC DoS targeting *nix rpcbind/libtirpc
   242   dos/samba/lsa_addprivs_heap                                                     normal  No     Samba lsa_io_privilege_set Heap Overflow
   243   dos/samba/lsa_transnames_heap                                                   normal  No     Samba lsa_io_trans_names Heap Overflow
   244   dos/samba/read_nttrans_ea_list                                                  normal  No     Samba read_nttrans_ea_list Integer Overflow
   245   dos/sap/sap_soap_rfc_eps_delete_file                                            normal  Yes    SAP SOAP EPS_DELETE_FILE File Deletion
   246   dos/scada/allen_bradley_pccc                                                    normal  Yes    DoS Exploitation of Allen-Bradley's Legacy Protocol (PCCC)
   247   dos/scada/beckhoff_twincat                                     2011-09-13       normal  No     Beckhoff TwinCAT SCADA PLC 2.11.0.2004 DoS
   248   dos/scada/d20_tftp_overflow                                    2012-01-19       normal  No     General Electric D20ME TFTP Server Buffer Overflow DoS
   249   dos/scada/igss9_dataserver                                     2011-12-20       normal  No     7-Technologies IGSS 9 IGSSdataServer.exe DoS
   250   dos/scada/siemens_siprotec4                                                     normal  No     Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module - Denial of Service
   251   dos/scada/yokogawa_logsvr                                      2014-03-10       normal  No     Yokogawa CENTUM CS 3000 BKCLogSvr.exe Heap Buffer Overflow
   252   dos/smb/smb_loris                                              2017-06-29       normal  No     SMBLoris NBSS Denial of Service
   253   dos/smtp/sendmail_prescan                                      2003-09-17       normal  No     Sendmail SMTP Address prescan Memory Corruption
   254   dos/solaris/lpd/cascade_delete                                                  normal  No     Solaris LPD Arbitrary File Delete
   255   dos/ssl/dtls_changecipherspec                                  2000-04-26       normal  No     OpenSSL DTLS ChangeCipherSpec Remote DoS
   256   dos/ssl/dtls_fragment_overflow                                 2014-06-05       normal  No     OpenSSL DTLS Fragment Buffer Overflow DoS
   257   dos/ssl/openssl_aesni                                          2013-02-05       normal  No     OpenSSL TLS 1.1 and 1.2 AES-NI DoS
   258   dos/syslog/rsyslog_long_tag                                    2011-09-01       normal  No     rsyslog Long Tag Off-By-Two DoS
   259   dos/tcp/claymore_dos                                           2018-02-06       normal  No     Claymore Dual GPU Miner  Format String dos attack
   260   dos/tcp/junos_tcp_opt                                                           normal  No     Juniper JunOS Malformed TCP Option
   261   dos/tcp/synflood                                                                normal  No     TCP SYN Flooder
   262   dos/upnp/miniupnpd_dos                                         2013-03-27       normal  No     MiniUPnPd 1.4 Denial of Service (DoS) Exploit
   263   dos/windows/appian/appian_bpm                                  2007-12-17       normal  No     Appian Enterprise Business Suite 5.6 SP1 DoS
   264   dos/windows/browser/ms09_065_eot_integer                       2009-11-10       normal  No     Microsoft Windows EOT Font Table Directory Integer Overflow
   265   dos/windows/ftp/filezilla_admin_user                           2005-11-07       normal  No     FileZilla FTP Server Admin Interface Denial of Service
   266   dos/windows/ftp/filezilla_server_port                          2006-12-11       normal  No     FileZilla FTP Server Malformed PORT Denial of Service
   267   dos/windows/ftp/guildftp_cwdlist                               2008-10-12       normal  No     Guild FTPd 0.999.8.11/0.999.14 Heap Corruption
   268   dos/windows/ftp/iis75_ftpd_iac_bof                             2010-12-21       normal  No     Microsoft IIS FTP Server Encoded Response Overflow Trigger
   269   dos/windows/ftp/iis_list_exhaustion                            2009-09-03       normal  No     Microsoft IIS FTP Server LIST Stack Exhaustion
   270   dos/windows/ftp/solarftp_user                                  2011-02-22       normal  No     Solar FTP Server Malformed USER Denial of Service
   271   dos/windows/ftp/titan626_site                                  2008-10-14       normal  No     Titan FTP Server 6.26.630 SITE WHO DoS
   272   dos/windows/ftp/vicftps50_list                                 2008-10-24       normal  No     Victory FTP Server 5.0 LIST DoS
   273   dos/windows/ftp/winftp230_nlst                                 2008-09-26       normal  No     WinFTP 2.3.0 NLST Denial of Service
   274   dos/windows/ftp/xmeasy560_nlst                                 2008-10-13       normal  No     XM Easy Personal FTP Server 5.6.0 NLST DoS
   275   dos/windows/ftp/xmeasy570_nlst                                 2009-03-27       normal  No     XM Easy Personal FTP Server 5.7.0 NLST DoS
   276   dos/windows/games/kaillera                                     2011-07-02       normal  No     Kaillera 0.86 Server Denial of Service
   277   dos/windows/http/ms10_065_ii6_asp_dos                          2010-09-14       normal  No     Microsoft IIS 6.0 ASP Stack Exhaustion Denial of Service
   278   dos/windows/http/pi3web_isapi                                  2008-11-13       normal  No     Pi3Web ISAPI DoS
   279   dos/windows/llmnr/ms11_030_dnsapi                              2011-04-12       normal  No     Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS
   280   dos/windows/nat/nat_helper                                     2006-10-26       normal  No     Microsoft Windows NAT Helper Denial of Service
   281   dos/windows/rdp/ms12_020_maxchannelids                         2012-03-16       normal  No     MS12-020 Microsoft Remote Desktop Use-After-Free DoS
   282   dos/windows/smb/ms05_047_pnp                                                    normal  No     Microsoft Plug and Play Service Registry Overflow
   283   dos/windows/smb/ms06_035_mailslot                              2006-07-11       normal  No     Microsoft SRV.SYS Mailslot Write Corruption
   284   dos/windows/smb/ms06_063_trans                                                  normal  No     Microsoft SRV.SYS Pipe Transaction No Null
   285   dos/windows/smb/ms09_001_write                                                  normal  No     Microsoft SRV.SYS WriteAndX Invalid DataOffset
   286   dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                                 normal  No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   287   dos/windows/smb/ms09_050_smb2_session_logoff                                    normal  No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference
   288   dos/windows/smb/ms10_006_negotiate_response_loop                                normal  No     Microsoft Windows 7 / Server 2008 R2 SMB Client Infinite Loop
   289   dos/windows/smb/ms10_054_queryfs_pool_overflow                                  normal  No     Microsoft Windows SRV.SYS SrvSmbQueryFsInformation Pool Overflow DoS
   290   dos/windows/smb/ms11_019_electbowser                                            normal  No     Microsoft Windows Browser Pool DoS
   291   dos/windows/smb/rras_vls_null_deref                            2006-06-14       normal  No     Microsoft RRAS InterfaceAdjustVLSPointers NULL Dereference
   292   dos/windows/smb/vista_negotiate_stop                                            normal  No     Microsoft Vista SP0 SMB Negotiate Protocol DoS
   293   dos/windows/smtp/ms06_019_exchange                             2004-11-12       normal  No     MS06-019 Exchange MODPROP Heap Overflow
   294   dos/windows/ssh/sysax_sshd_kexchange                           2013-03-17       normal  No     Sysax Multi-Server 6.10 SSHD Key Exchange Denial of Service
   295   dos/windows/tftp/pt360_write                                   2008-10-29       normal  No     PacketTrap TFTP Server 2.2.5459.0 DoS
   296   dos/windows/tftp/solarwinds                                    2010-05-21       normal  No     SolarWinds TFTP Server 10.4.0.10 Denial of Service
   297   dos/wireshark/capwap                                           2014-04-28       normal  No     Wireshark CAPWAP Dissector DoS
   298   dos/wireshark/chunked                                          2007-02-22       normal  No     Wireshark chunked_encoding_dissector Function DOS
   299   dos/wireshark/cldap                                            2011-03-01       normal  No     Wireshark CLDAP Dissector DOS
   300   dos/wireshark/ldap                                             2008-03-28       normal  No     Wireshark LDAP Dissector DOS
   301   fileformat/badpdf                                                               normal  No     BADPDF Malicious PDF Creator
   302   fileformat/multidrop                                                            normal  No     Windows SMB Multi Dropper
   303   fileformat/odt_badodt                                          2018-05-01       normal  No     LibreOffice 6.03 /Apache OpenOffice 4.1.5 Malicious ODT File Generator
   304   fuzzers/dns/dns_fuzzer                                                          normal  Yes    DNS and DNSSEC Fuzzer
   305   fuzzers/ftp/client_ftp                                                          normal  No     Simple FTP Client Fuzzer
   306   fuzzers/ftp/ftp_pre_post                                                        normal  Yes    Simple FTP Fuzzer
   307   fuzzers/http/http_form_field                                                    normal  No     HTTP Form Field Fuzzer
   308   fuzzers/http/http_get_uri_long                                                  normal  No     HTTP GET Request URI Fuzzer (Incrementing Lengths)
   309   fuzzers/http/http_get_uri_strings                                               normal  No     HTTP GET Request URI Fuzzer (Fuzzer Strings)
   310   fuzzers/ntp/ntp_protocol_fuzzer                                                 normal  Yes    NTP Protocol Fuzzer
   311   fuzzers/smb/smb2_negotiate_corrupt                                              normal  No     SMB Negotiate SMB2 Dialect Corruption
   312   fuzzers/smb/smb_create_pipe                                                     normal  No     SMB Create Pipe Request Fuzzer
   313   fuzzers/smb/smb_create_pipe_corrupt                                             normal  No     SMB Create Pipe Request Corruption
   314   fuzzers/smb/smb_negotiate_corrupt                                               normal  No     SMB Negotiate Dialect Corruption
   315   fuzzers/smb/smb_ntlm1_login_corrupt                                             normal  No     SMB NTLMv1 Login Request Corruption
   316   fuzzers/smb/smb_tree_connect                                                    normal  No     SMB Tree Connect Request Fuzzer
   317   fuzzers/smb/smb_tree_connect_corrupt                                            normal  No     SMB Tree Connect Request Corruption
   318   fuzzers/smtp/smtp_fuzzer                                                        normal  Yes    SMTP Simple Fuzzer
   319   fuzzers/ssh/ssh_kexinit_corrupt                                                 normal  No     SSH Key Exchange Init Corruption
   320   fuzzers/ssh/ssh_version_15                                                      normal  No     SSH 1.5 Version Fuzzer
   321   fuzzers/ssh/ssh_version_2                                                       normal  No     SSH 2.0 Version Fuzzer
   322   fuzzers/ssh/ssh_version_corrupt                                                 normal  No     SSH Version Corruption
   323   fuzzers/tds/tds_login_corrupt                                                   normal  No     TDS Protocol Login Request Corruption Fuzzer
   324   fuzzers/tds/tds_login_username                                                  normal  No     TDS Protocol Login Request Username Fuzzer
   325   gather/advantech_webaccess_creds                               2017-01-21       normal  No     Advantech WebAccess 8.1 Post Authentication Credential Collector
   326   gather/alienvault_iso27001_sqli                                2014-03-30       normal  No     AlienVault Authenticated SQL Injection Arbitrary File Read
   327   gather/alienvault_newpolicyform_sqli                           2014-05-09       normal  No     AlienVault Authenticated SQL Injection Arbitrary File Read
   328   gather/android_browser_file_theft                                               normal  No     Android Browser File Theft
   329   gather/android_browser_new_tab_cookie_theft                                     normal  No     Android Browser "Open in New Tab" Cookie Theft
   330   gather/android_htmlfileprovider                                                 normal  No     Android Content Provider File Disclosure
   331   gather/android_object_tag_webview_uxss                         2014-10-04       normal  No     Android Open Source Platform (AOSP) Browser UXSS
   332   gather/android_stock_browser_uxss                                               normal  No     Android Open Source Platform (AOSP) Browser UXSS
   333   gather/apache_rave_creds                                                        normal  No     Apache Rave User Information Disclosure
   334   gather/apple_safari_ftp_url_cookie_theft                       2015-04-08       normal  No     Apple OSX/iOS/Windows Safari Non-HTTPOnly Cookie Theft
   335   gather/apple_safari_webarchive_uxss                            2013-02-22       normal  No     Mac OS X Safari .webarchive File Format UXSS
   336   gather/asterisk_creds                                                           normal  No     Asterisk Gather Credentials
   337   gather/avtech744_dvr_accounts                                                   normal  No     AVTECH 744 DVR Account Information Retrieval
   338   gather/browser_info                                            2016-03-22       normal  No     HTTP Client Information Gather
   339   gather/browser_lanipleak                                       2013-09-05       normal  No     HTTP Client LAN IP Address Gather
   340   gather/c2s_dvr_password_disclosure                             2016-08-19       normal  Yes    C2S DVR Management Password Disclosure
   341   gather/censys_search                                                            normal  No     Censys Search
   342   gather/cerberus_helpdesk_hash_disclosure                       2016-03-07       normal  Yes    Cerberus Helpdesk User Hash Disclosure
   343   gather/checkpoint_hostname                                     2011-12-14       normal  No     CheckPoint Firewall-1 SecuRemote Topology Service Hostname Disclosure
   344   gather/cisco_rv320_config                                      2019-01-24       normal  No     Cisco RV320/RV326 Configuration Disclosure
   345   gather/citrix_published_applications                                            normal  No     Citrix MetaFrame ICA Published Applications Scanner
   346   gather/citrix_published_bruteforce                                              normal  No     Citrix MetaFrame ICA Published Applications Bruteforcer
   347   gather/coldfusion_pwd_props                                    2013-05-07       normal  Yes    ColdFusion 'password.properties' Hash Extraction
   348   gather/corpwatch_lookup_id                                                      normal  No     CorpWatch Company ID Information Search
   349   gather/corpwatch_lookup_name                                                    normal  No     CorpWatch Company Name Information Search
   350   gather/d20pass                                                 2012-01-19       normal  No     General Electric D20 Password Recovery
   351   gather/darkcomet_filedownloader                                2012-10-08       normal  No     DarkComet Server Remote File Download Exploit
   352   gather/dolibarr_creds_sqli                                     2018-05-30       normal  No     Dolibarr Gather Credentials via SQL Injection
   353   gather/doliwamp_traversal_creds                                2014-01-12       normal  Yes    DoliWamp 'jqueryFileTree.php' Traversal Gather Credentials
   354   gather/drupal_openid_xxe                                       2012-10-17       normal  Yes    Drupal OpenID External Entity Injection
   355   gather/eaton_nsm_creds                                         2012-06-26       normal  No     Network Shutdown Module sort_values Credential Dumper
   356   gather/emc_cta_xxe                                             2014-03-31       normal  No     EMC CTA v10.0 Unauthenticated XXE Arbitrary File Read
   357   gather/enum_dns                                                                 normal  No     DNS Record Scanner and Enumerator
   358   gather/eventlog_cred_disclosure                                2014-11-05       normal  No     ManageEngine Eventlog Analyzer Managed Hosts Administrator Credential Disclosure
   359   gather/external_ip                                                              normal  No     Discover External IP via Ifconfig.me
   360   gather/f5_bigip_cookie_disclosure                                               normal  No     F5 BigIP Backend Cookie Disclosure
   361   gather/firefox_pdfjs_file_theft                                                 normal  No     Firefox PDF.js Browser File Theft
   362   gather/flash_rosetta_jsonp_url_disclosure                      2014-07-08       normal  Yes    Flash "Rosetta" JSONP GET/POST Response Disclosure
   363   gather/get_user_spns                                           2014-09-27       normal  Yes    Gather Ticket Granting Service (TGS) tickets for User Service Principal Names (SPN)
   364   gather/hp_enum_perfd                                                            normal  Yes    HP Operations Manager Perfd Environment Scanner
   365   gather/hp_snac_domain_creds                                    2013-09-09       normal  No     HP ProCurve SNAC Domain Controller Credential Dumper
   366   gather/http_pdf_authors                                                         normal  No     Gather PDF Authors
   367   gather/huawei_wifi_info                                        2013-11-11       normal  No     Huawei Datacard Information Disclosure Vulnerability
   368   gather/ibm_bigfix_sites_packages_enum                          2019-03-18       normal  No     IBM BigFix Relay Server Sites and Package Enum
   369   gather/ibm_sametime_enumerate_users                            2013-12-27       normal  No     IBM Lotus Notes Sametime User Enumeration
   370   gather/ibm_sametime_room_brute                                 2013-12-27       normal  No     IBM Lotus Notes Sametime Room Name Bruteforce
   371   gather/ibm_sametime_version                                    2013-12-27       normal  No     IBM Lotus Sametime Version Enumeration
   372   gather/ie_sandbox_findfiles                                    2016-08-09       normal  No     Internet Explorer Iframe Sandbox File Name Disclosure Vulnerability
   373   gather/ie_uxss_injection                                       2015-02-01       normal  No     MS15-018 Microsoft Internet Explorer 10 and 11 Cross-Domain JavaScript Injection
   374   gather/impersonate_ssl                                                          normal  No     HTTP SSL Certificate Impersonation
   375   gather/ipcamera_password_disclosure                            2016-08-16       normal  Yes    JVC/Siemens/Vanderbilt IP-Camera Readfile Password Disclosure
   376   gather/java_rmi_registry                                                        normal  No     Java RMI Registry Interfaces Enumeration
   377   gather/jenkins_cred_recovery                                                    normal  Yes    Jenkins Domain Credential Recovery
   378   gather/joomla_com_realestatemanager_sqli                       2015-10-22       normal  Yes    Joomla Real Estate Manager Component Error-Based SQL Injection
   379   gather/joomla_contenthistory_sqli                              2015-10-22       normal  Yes    Joomla com_contenthistory Error-Based SQL Injection
   380   gather/joomla_weblinks_sqli                                    2014-03-02       normal  Yes    Joomla weblinks-categories Unauthenticated SQL Injection Arbitrary File Read
   381   gather/kerberos_enumusers                                                       normal  No     Kerberos Domain User Enumeration
   382   gather/konica_minolta_pwd_extract                                               normal  Yes    Konica Minolta Password Extractor
   383   gather/lansweeper_collector                                                     normal  No     Lansweeper Credential Collector
   384   gather/mantisbt_admin_sqli                                     2014-02-28       normal  No     MantisBT Admin SQL Injection Arbitrary File Read
   385   gather/mcafee_epo_xxe                                          2015-01-06       normal  No     McAfee ePolicy Orchestrator Authenticated XXE Credentials Exposure
   386   gather/memcached_extractor                                                      normal  Yes    Memcached Extractor
   387   gather/mongodb_js_inject_collection_enum                       2014-06-07       normal  No     MongoDB NoSQL Collection Enumeration Via Injection
   388   gather/ms14_052_xmldom                                         2014-09-09       normal  No     MS14-052 Microsoft Internet Explorer XMLDOM Filename Disclosure
   389   gather/mybb_db_fingerprint                                     2014-02-13       normal  Yes    MyBB Database Fingerprint
   390   gather/natpmp_external_address                                                  normal  Yes    NAT-PMP External Address Scanner
   391   gather/netgear_password_disclosure                                              normal  Yes    NETGEAR Administrator Password Disclosure
   392   gather/nis_bootparamd_domain                                                    normal  No     NIS bootparamd Domain Name Disclosure
   393   gather/nis_ypserv_map                                                           normal  No     NIS ypserv Map Dumper
   394   gather/nuuo_cms_bruteforce                                     2018-10-11       normal  No     Nuuo Central Management Server User Session Token Bruteforce
   395   gather/nuuo_cms_file_download                                  2018-10-11       normal  No     Nuuo Central Management Server Authenticated Arbitrary File Download
   396   gather/oats_downloadservlet_traversal                          2019-04-16       normal  Yes    Oracle Application Testing Suite Post-Auth DownloadServlet Directory Traversal
   397   gather/office365userenum                                       2018-09-05       normal  Yes    Office 365 User Enumeration
   398   gather/opennms_xxe                                             2015-01-08       normal  No     OpenNMS Authenticated XXE
   399   gather/pimcore_creds_sqli                                      2018-08-13       normal  No     Pimcore Gather Credentials via SQL Injection
   400   gather/qnap_backtrace_admin_hash                               2017-01-31       normal  Yes    QNAP NAS/NVR Administrator Hash Disclosure
   401   gather/rails_doubletap_file_read                                                normal  Yes    Ruby On Rails File Content Disclosure ('doubletap')
   402   gather/safari_file_url_navigation                              2014-01-16       normal  No     Mac OS X Safari file:// Redirection Sandbox Escape
   403   gather/samsung_browser_sop_bypass                              2017-11-08       normal  No     Samsung Internet Browser SOP Bypass
   404   gather/search_email_collector                                                   normal  No     Search Engine Domain Email Address Collector
   405   gather/searchengine_subdomains_collector                                        normal  No     Search Engine Subdomains Collector
   406   gather/shodan_honeyscore                                                        normal  No     Shodan Honeyscore Client
   407   gather/shodan_search                                                            normal  No     Shodan Search
   408   gather/snare_registry                                                           normal  No     Snare Lite for Windows Registry Access
   409   gather/solarwinds_orion_sqli                                   2015-02-24       normal  No     Solarwinds Orion AccountManagement.asmx GetAccounts Admin Creation
   410   gather/ssllabs_scan                                                             normal  No     SSL Labs API Client
   411   gather/teamtalk_creds                                                           normal  No     TeamTalk Gather Credentials
   412   gather/trackit_sql_domain_creds                                2014-10-07       normal  No     BMC / Numara Track-It! Domain Administrator and SQL Server User Password Disclosure
   413   gather/vbulletin_vote_sqli                                     2013-03-24       normal  Yes    vBulletin Password Collector via nodeid SQL Injection
   414   gather/windows_deployment_services_shares                                       normal  Yes    Microsoft Windows Deployment Services Unattend Gatherer
   415   gather/wp_all_in_one_migration_export                          2015-03-19       normal  Yes    WordPress All-in-One Migration Export
   416   gather/wp_ultimate_csv_importer_user_extract                   2015-02-02       normal  Yes    WordPress Ultimate CSV Importer User Table Extract
   417   gather/wp_w3_total_cache_hash_extract                                           normal  Yes    WordPress W3-Total-Cache Plugin 0.9.2.4 (or before) Username and Hash Extract
   418   gather/xbmc_traversal                                          2012-11-04       normal  No     XBMC Web Server Directory Traversal
   419   gather/xerox_pwd_extract                                                        normal  No     Xerox Administrator Console Password Extractor
   420   gather/xerox_workcentre_5xxx_ldap                                               normal  No     Xerox Workcentre 5735 LDAP Service Redential Extractor
   421   gather/xymon_info                                                               normal  No     Xymon Daemon Gather Information
   422   gather/zabbix_toggleids_sqli                                   2016-08-11       normal  Yes    Zabbix toggle_ids SQL Injection
   423   gather/zoomeye_search                                                           normal  No     ZoomEye Search
   424   parser/unattend                                                                 normal  No     Auxilliary Parser Windows Unattend Passwords
   425   pdf/foxit/authbypass                                           2009-03-09       normal  No     Foxit Reader Authorization Bypass
   426   scanner/acpp/login                                                              normal  Yes    Apple Airport ACPP Authentication Scanner
   427   scanner/afp/afp_login                                                           normal  Yes    Apple Filing Protocol Login Utility
   428   scanner/afp/afp_server_info                                                     normal  Yes    Apple Filing Protocol Info Enumerator
   429   scanner/backdoor/energizer_duo_detect                                           normal  Yes    Energizer DUO Trojan Scanner
   430   scanner/chargen/chargen_probe                                  1996-02-08       normal  Yes    Chargen Probe Utility
   431   scanner/couchdb/couchdb_enum                                                    normal  Yes    CouchDB Enum Utility
   432   scanner/couchdb/couchdb_login                                                   normal  Yes    CouchDB Login Utility
   433   scanner/db2/db2_auth                                                            normal  Yes    DB2 Authentication Brute Force Utility
   434   scanner/db2/db2_version                                                         normal  Yes    DB2 Probe Utility
   435   scanner/db2/discovery                                                           normal  Yes    DB2 Discovery Service Detection
   436   scanner/dcerpc/endpoint_mapper                                                  normal  Yes    Endpoint Mapper Service Discovery
   437   scanner/dcerpc/hidden                                                           normal  Yes    Hidden DCERPC Service Discovery
   438   scanner/dcerpc/management                                                       normal  Yes    Remote Management Interface Discovery
   439   scanner/dcerpc/tcp_dcerpc_auditor                                               normal  Yes    DCERPC TCP Service Auditor
   440   scanner/dcerpc/windows_deployment_services                                      normal  Yes    Microsoft Windows Deployment Services Unattend Retrieval
   441   scanner/dect/call_scanner                                                       normal  No     DECT Call Scanner
   442   scanner/dect/station_scanner                                                    normal  No     DECT Base Station Scanner
   443   scanner/discovery/arp_sweep                                                     normal  Yes    ARP Sweep Local Network Discovery
   444   scanner/discovery/empty_udp                                                     normal  Yes    UDP Empty Prober
   445   scanner/discovery/ipv6_multicast_ping                                           normal  No     IPv6 Link Local/Node Local Ping Discovery
   446   scanner/discovery/ipv6_neighbor                                                 normal  Yes    IPv6 Local Neighbor Discovery
   447   scanner/discovery/ipv6_neighbor_router_advertisement                            normal  No     IPv6 Local Neighbor Discovery Using Router Advertisement
   448   scanner/discovery/udp_probe                                                     normal  Yes    UDP Service Prober
   449   scanner/discovery/udp_sweep                                                     normal  Yes    UDP Service Sweeper
   450   scanner/dlsw/dlsw_leak_capture                                 2014-11-17       normal  Yes    Cisco DLSw Information Disclosure Scanner
   451   scanner/dns/dns_amp                                                             normal  Yes    DNS Amplification Scanner
   452   scanner/elasticsearch/indices_enum                                              normal  Yes    ElasticSearch Indices Enumeration Utility
   453   scanner/emc/alphastor_devicemanager                                             normal  Yes    EMC AlphaStor Device Manager Service
   454   scanner/emc/alphastor_librarymanager                                            normal  Yes    EMC AlphaStor Library Manager Service
   455   scanner/etcd/open_key_scanner                                  2018-03-16       normal  Yes    Etcd Keys API Information Gathering
   456   scanner/etcd/version                                           2018-03-16       normal  Yes    Etcd Version Scanner
   457   scanner/finger/finger_users                                                     normal  Yes    Finger Service User Enumerator
   458   scanner/ftp/anonymous                                                           normal  Yes    Anonymous FTP Access Detection
   459   scanner/ftp/bison_ftp_traversal                                2015-09-28       normal  Yes    BisonWare BisonFTP Server 3.5 Directory Traversal Information Disclosure
   460   scanner/ftp/colorado_ftp_traversal                             2016-08-11       normal  Yes    ColoradoFTP Server 1.3 Build 8 Directory Traversal Information Disclosure
   461   scanner/ftp/easy_file_sharing_ftp                              2017-03-07       normal  Yes    Easy File Sharing FTP Server 3.6 Directory Traversal
   462   scanner/ftp/ftp_login                                                           normal  Yes    FTP Authentication Scanner
   463   scanner/ftp/ftp_version                                                         normal  Yes    FTP Version Scanner
   464   scanner/ftp/konica_ftp_traversal                               2015-09-22       normal  Yes    Konica Minolta FTP Utility 1.00 Directory Traversal Information Disclosure
   465   scanner/ftp/pcman_ftp_traversal                                2015-09-28       normal  Yes    PCMan FTP Server 2.0.7 Directory Traversal Information Disclosure
   466   scanner/ftp/titanftp_xcrc_traversal                            2010-06-15       normal  Yes    Titan FTP XCRC Directory Traversal Information Disclosure
   467   scanner/gopher/gopher_gophermap                                                 normal  Yes    Gopher gophermap Scanner
   468   scanner/gprs/gtp_echo                                                           normal  Yes    GTP Echo Scanner
   469   scanner/h323/h323_version                                                       normal  Yes    H.323 Version Scanner
   470   scanner/http/a10networks_ax_directory_traversal                2014-01-28       normal  Yes    A10 Networks AX Loadbalancer Directory Traversal
   471   scanner/http/accellion_fta_statecode_file_read                 2015-07-10       normal  Yes    Accellion FTA 'statecode' Cookie Arbitrary File Read
   472   scanner/http/adobe_xml_inject                                                   normal  Yes    Adobe XML External Entity Injection
   473   scanner/http/advantech_webaccess_login                                          normal  Yes    Advantech WebAccess Login
   474   scanner/http/allegro_rompager_misfortune_cookie                2014-12-17       normal  Yes    Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Scanner
   475   scanner/http/apache_activemq_source_disclosure                                  normal  Yes    Apache ActiveMQ JSP Files Source Disclosure
   476   scanner/http/apache_activemq_traversal                                          normal  Yes    Apache ActiveMQ Directory Traversal
   477   scanner/http/apache_mod_cgi_bash_env                           2014-09-24       normal  Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   478   scanner/http/apache_optionsbleed                               2017-09-18       normal  Yes    Apache Optionsbleed Scanner
   479   scanner/http/apache_userdir_enum                                                normal  Yes    Apache "mod_userdir" User Enumeration
   480   scanner/http/appletv_login                                                      normal  Yes    AppleTV AirPlay Login Utility
   481   scanner/http/atlassian_crowd_fileaccess                                         normal  Yes    Atlassian Crowd XML Entity Expansion Remote File Access
   482   scanner/http/axis_local_file_include                                            normal  Yes    Apache Axis2 v1.4.1 Local File Inclusion
   483   scanner/http/axis_login                                                         normal  Yes    Apache Axis2 Brute Force Utility
   484   scanner/http/backup_file                                                        normal  Yes    HTTP Backup File Scanner
   485   scanner/http/barracuda_directory_traversal                     2010-10-08       normal  Yes    Barracuda Multiple Product "locale" Directory Traversal
   486   scanner/http/bavision_cam_login                                                 normal  Yes    BAVision IP Camera Web Server Login
   487   scanner/http/binom3_login_config_pass_dump                                      normal  Yes    Binom3 Web Management Login Scanner, Config and Password File Dump
   488   scanner/http/bitweaver_overlay_type_traversal                  2012-10-23       normal  Yes    Bitweaver overlay_type Directory Traversal
   489   scanner/http/blind_sql_query                                                    normal  Yes    HTTP Blind SQL Injection Scanner
   490   scanner/http/bmc_trackit_passwd_reset                          2014-12-09       normal  Yes    BMC TrackIt! Unauthenticated Arbitrary User Password Change
   491   scanner/http/brute_dirs                                                         normal  Yes    HTTP Directory Brute Force Scanner
   492   scanner/http/buffalo_login                                                      normal  Yes    Buffalo NAS Login Utility
   493   scanner/http/buildmaster_login                                                  normal  Yes    Inedo BuildMaster Login Scanner
   494   scanner/http/caidao_bruteforce_login                                            normal  Yes    Chinese Caidao Backdoor Bruteforce
   495   scanner/http/canon_wireless                                    2013-06-18       normal  Yes    Canon Printer Wireless Configuration Disclosure
   496   scanner/http/cert                                                               normal  Yes    HTTP SSL Certificate Checker
   497   scanner/http/cgit_traversal                                    2018-08-03       normal  Yes    cgit Directory Traversal
   498   scanner/http/chef_webui_login                                                   normal  Yes    Chef Web UI Brute Force Utility
   499   scanner/http/chromecast_webserver                                               normal  Yes    Chromecast Web Server Scanner
   500   scanner/http/chromecast_wifi                                                    normal  Yes    Chromecast Wifi Enumeration
   501   scanner/http/cisco_asa_asdm                                                     normal  Yes    Cisco ASA ASDM Bruteforce Login Utility
   502   scanner/http/cisco_device_manager                              2000-10-26       normal  Yes    Cisco Device HTTP Device Manager Access
   503   scanner/http/cisco_directory_traversal                         2018-06-06       normal  No     Cisco ASA Directory Traversal
   504   scanner/http/cisco_firepower_download                          2016-10-10       normal  Yes    Cisco Firepower Management Console 6.0 Post Auth Report Download Directory Traversal
   505   scanner/http/cisco_firepower_login                                              normal  Yes    Cisco Firepower Management Console 6.0 Login
   506   scanner/http/cisco_ios_auth_bypass                             2001-06-27       normal  Yes    Cisco IOS HTTP Unauthorized Administrative Access
   507   scanner/http/cisco_ironport_enum                                                normal  Yes    Cisco Ironport Bruteforce Login Utility
   508   scanner/http/cisco_nac_manager_traversal                                        normal  Yes    Cisco Network Access Manager Directory Traversal Vulnerability
   509   scanner/http/cisco_ssl_vpn                                                      normal  Yes    Cisco SSL VPN Bruteforce Login Utility
   510   scanner/http/cisco_ssl_vpn_priv_esc                            2014-04-09       normal  Yes    Cisco ASA SSL VPN Privilege Escalation Vulnerability
   511   scanner/http/clansphere_traversal                              2012-10-23       normal  Yes    ClanSphere 2011.3 Local File Inclusion Vulnerability
   512   scanner/http/cnpilot_r_web_login_loot                                           normal  Yes    Cambium cnPilot r200/r201 Login Scanner and Config Dump
   513   scanner/http/coldfusion_locale_traversal                                        normal  Yes    ColdFusion Server Check
   514   scanner/http/coldfusion_version                                                 normal  Yes    ColdFusion Version Scanner
   515   scanner/http/concrete5_member_list                                              normal  Yes    Concrete5 Member List Enumeration
   516   scanner/http/copy_of_file                                                       normal  Yes    HTTP Copy File Scanner
   517   scanner/http/crawler                                                            normal  No     Web Site Crawler
   518   scanner/http/dell_idrac                                                         normal  Yes    Dell iDRAC Default Login
   519   scanner/http/dicoogle_traversal                                2018-07-11       normal  Yes    Dicoogle PACS Web Server Directory Traversal
   520   scanner/http/dir_listing                                                        normal  Yes    HTTP Directory Listing Scanner
   521   scanner/http/dir_scanner                                                        normal  Yes    HTTP Directory Scanner
   522   scanner/http/dir_webdav_unicode_bypass                                          normal  Yes    MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   523   scanner/http/directadmin_login                                                  normal  Yes    DirectAdmin Web Control Panel Login Utility
   524   scanner/http/dlink_dir_300_615_http_login                                       normal  Yes    D-Link DIR-300A / DIR-320 / DIR-615D HTTP Login Utility
   525   scanner/http/dlink_dir_615h_http_login                                          normal  Yes    D-Link DIR-615H HTTP Login Utility
   526   scanner/http/dlink_dir_session_cgi_http_login                                   normal  Yes    D-Link DIR-300B / DIR-600B / DIR-815 / DIR-645 HTTP Login Utility
   527   scanner/http/dlink_user_agent_backdoor                         2013-10-12       normal  Yes    D-Link User-Agent Backdoor Scanner
   528   scanner/http/dnalims_file_retrieve                             2017-03-08       normal  Yes    DnaLIMS Directory Traversal
   529   scanner/http/docker_version                                                     normal  Yes    Docker Server Version Scanner
   530   scanner/http/dolibarr_login                                                     normal  Yes    Dolibarr ERP/CRM Login Utility
   531   scanner/http/drupal_views_user_enum                            2010-07-02       normal  Yes    Drupal Views Module Users Enumeration
   532   scanner/http/ektron_cms400net                                                   normal  Yes    Ektron CMS400.NET Default Password Scanner
   533   scanner/http/elasticsearch_traversal                                            normal  Yes    ElasticSearch Snapshot API Directory Traversal
   534   scanner/http/enum_wayback                                                       normal  No     Archive.org Stored Domain URLs
   535   scanner/http/epmp1000_dump_config                                               normal  Yes    Cambium ePMP 1000 Dump Device Config
   536   scanner/http/epmp1000_dump_hashes                                               normal  Yes    Cambium ePMP 1000 'ping' Password Hash Extractor (up to v2.5)
   537   scanner/http/epmp1000_get_chart_cmd_exec                                        normal  Yes    Cambium ePMP 1000 'get_chart' Command Injection (v3.1-3.5-RC7)
   538   scanner/http/epmp1000_ping_cmd_exec                                             normal  Yes    Cambium ePMP 1000 'ping' Command Injection (up to v2.5)
   539   scanner/http/epmp1000_reset_pass                                                normal  Yes    Cambium ePMP 1000 Account Password Reset
   540   scanner/http/epmp1000_web_login                                                 normal  Yes    Cambium ePMP 1000 Login Scanner
   541   scanner/http/error_sql_injection                                                normal  Yes    HTTP Error Based SQL Injection Scanner
   542   scanner/http/es_file_explorer_open_port                        2019-01-16       normal  Yes    ES File Explorer Open Port
   543   scanner/http/etherpad_duo_login                                                 normal  Yes    EtherPAD Duo Login Bruteforce Utility
   544   scanner/http/f5_bigip_virtual_server                                            normal  Yes    F5 BigIP HTTP Virtual Server Scanner
   545   scanner/http/f5_mgmt_scanner                                                    normal  Yes    F5 Networks Devices Management Interface Scanner
   546   scanner/http/file_same_name_dir                                                 normal  Yes    HTTP File Same Name Directory Scanner
   547   scanner/http/files_dir                                                          normal  Yes    HTTP Interesting File Scanner
   548   scanner/http/fortinet_ssl_vpn                                                   normal  Yes    Fortinet SSL VPN Bruteforce Login Utility
   549   scanner/http/frontpage_credential_dump                                          normal  Yes    FrontPage .pwd File Credential Dump
   550   scanner/http/frontpage_login                                                    normal  Yes    FrontPage Server Extensions Anonymous Login Scanner
   551   scanner/http/gavazzi_em_login_loot                                              normal  Yes    Carlo Gavazzi Energy Meters - Login Brute Force, Extract Info and Dump Plant Database
   552   scanner/http/git_scanner                                                        normal  Yes    HTTP Git Scanner
   553   scanner/http/gitlab_login                                                       normal  Yes    GitLab Login Utility
   554   scanner/http/gitlab_user_enum                                  2014-11-21       normal  Yes    GitLab User Enumeration
   555   scanner/http/glassfish_login                                                    normal  Yes    GlassFish Brute Force Utility
   556   scanner/http/glassfish_traversal                               2015-08-08       normal  Yes    Path Traversal in Oracle GlassFish Server Open Source Edition
   557   scanner/http/goahead_traversal                                                  normal  Yes    Embedthis GoAhead Embedded Web Server Directory Traversal
   558   scanner/http/groupwise_agents_http_traversal                                    normal  Yes    Novell Groupwise Agents HTTP Directory Traversal
   559   scanner/http/host_header_injection                                              normal  Yes    HTTP Host Header Injection Detection
   560   scanner/http/hp_imc_bims_downloadservlet_traversal                              normal  Yes    HP Intelligent Management BIMS DownloadServlet Directory Traversal
   561   scanner/http/hp_imc_faultdownloadservlet_traversal                              normal  Yes    HP Intelligent Management FaultDownloadServlet Directory Traversal
   562   scanner/http/hp_imc_ictdownloadservlet_traversal                                normal  Yes    HP Intelligent Management IctDownloadServlet Directory Traversal
   563   scanner/http/hp_imc_reportimgservlt_traversal                                   normal  Yes    HP Intelligent Management ReportImgServlt Directory Traversal
   564   scanner/http/hp_imc_som_file_download                                           normal  Yes    HP Intelligent Management SOM FileDownloadServlet Arbitrary Download
   565   scanner/http/hp_sitescope_getfileinternal_fileaccess                            normal  Yes    HP SiteScope SOAP Call getFileInternal Remote File Access
   566   scanner/http/hp_sitescope_getsitescopeconfiguration                             normal  Yes    HP SiteScope SOAP Call getSiteScopeConfiguration Configuration Access
   567   scanner/http/hp_sitescope_loadfilecontent_fileaccess                            normal  Yes    HP SiteScope SOAP Call loadFileContent Remote File Access
   568   scanner/http/hp_sys_mgmt_login                                                  normal  Yes    HP System Management Homepage Login Utility
   569   scanner/http/http_header                                                        normal  Yes    HTTP Header Detection
   570   scanner/http/http_hsts                                                          normal  Yes    HTTP Strict Transport Security (HSTS) Detection
   571   scanner/http/http_login                                                         normal  Yes    HTTP Login Utility
   572   scanner/http/http_put                                                           normal  Yes    HTTP Writable Path PUT/DELETE File Access
   573   scanner/http/http_sickrage_password_leak                       2018-03-08       normal  No     HTTP SickRage Password Leak
   574   scanner/http/http_traversal                                                     normal  Yes    Generic HTTP Directory Traversal Utility
   575   scanner/http/http_version                                                       normal  Yes    HTTP Version Detection
   576   scanner/http/httpbl_lookup                                                      normal  Yes    Http:BL Lookup
   577   scanner/http/httpdasm_directory_traversal                                       normal  No     Httpdasm Directory Traversal
   578   scanner/http/iis_internal_ip                                                    normal  Yes    Microsoft IIS HTTP Internal IP Disclosure
   579   scanner/http/iis_shortname_scanner                                              normal  Yes    Microsoft IIS shortname vulnerability scanner
   580   scanner/http/influxdb_enum                                                      normal  No     InfluxDB Enum Utility
   581   scanner/http/infovista_enum                                                     normal  Yes    InfoVista VistaPortal Application Bruteforce Login Utility
   582   scanner/http/intel_amt_digest_bypass                           2017-05-05       normal  Yes    Intel AMT Digest Authentication Bypass Scanner
   583   scanner/http/ipboard_login                                                      normal  Yes    IP Board Login Auxiliary Module
   584   scanner/http/jboss_status                                                       normal  Yes    JBoss Status Servlet Information Gathering
   585   scanner/http/jboss_vulnscan                                                     normal  Yes    JBoss Vulnerability Scanner
   586   scanner/http/jenkins_command                                                    normal  Yes    Jenkins-CI Unauthenticated Script-Console Scanner
   587   scanner/http/jenkins_enum                                                       normal  Yes    Jenkins-CI Enumeration
   588   scanner/http/jenkins_login                                                      normal  Yes    Jenkins-CI Login Utility
   589   scanner/http/joomla_bruteforce_login                                            normal  Yes    Joomla Bruteforce Login Utility
   590   scanner/http/joomla_ecommercewd_sqli_scanner                   2015-03-20       normal  Yes    Web-Dorado ECommerce WD for Joomla! search_category_id SQL Injection Scanner
   591   scanner/http/joomla_gallerywd_sqli_scanner                     2015-03-30       normal  Yes    Gallery WD for Joomla! Unauthenticated SQL Injection Scanner
   592   scanner/http/joomla_pages                                                       normal  Yes    Joomla Page Scanner
   593   scanner/http/joomla_plugins                                                     normal  Yes    Joomla Plugins Scanner
   594   scanner/http/joomla_version                                                     normal  Yes    Joomla Version Scanner
   595   scanner/http/kodi_traversal                                    2017-02-12       normal  Yes    Kodi 17.0 Local File Inclusion Vulnerability
   596   scanner/http/linknat_vos_traversal                                              normal  Yes    Linknat Vos Manager Traversal
   597   scanner/http/linksys_e1500_traversal                                            normal  Yes    Linksys E1500 Directory Traversal Vulnerability
   598   scanner/http/litespeed_source_disclosure                                        normal  Yes    LiteSpeed Source Code Disclosure/Download
   599   scanner/http/lucky_punch                                                        normal  Yes    HTTP Microsoft SQL Injection Table XSS Infection
   600   scanner/http/majordomo2_directory_traversal                    2011-03-08       normal  Yes    Majordomo2 _list_file_get() Directory Traversal
   601   scanner/http/manageengine_desktop_central_login                                 normal  Yes    ManageEngine Desktop Central Login Utility
   602   scanner/http/manageengine_deviceexpert_traversal               2012-03-18       normal  Yes    ManageEngine DeviceExpert 5.6 ScheduleResultViewer FileName Traversal
   603   scanner/http/manageengine_deviceexpert_user_creds              2014-08-28       normal  Yes    ManageEngine DeviceExpert User Credentials
   604   scanner/http/manageengine_securitymanager_traversal            2012-10-19       normal  Yes    ManageEngine SecurityManager Plus 5.5 Directory Traversal
   605   scanner/http/mediawiki_svg_fileaccess                                           normal  Yes    MediaWiki SVG XML Entity Expansion Remote File Access
   606   scanner/http/meteocontrol_weblog_extractadmin                                   normal  Yes    Meteocontrol WEBlog Password Extractor
   607   scanner/http/mod_negotiation_brute                                              normal  Yes    Apache HTTPD mod_negotiation Filename Bruter
   608   scanner/http/mod_negotiation_scanner                                            normal  Yes    Apache HTTPD mod_negotiation Scanner
   609   scanner/http/ms09_020_webdav_unicode_bypass                                     normal  Yes    MS09-020 IIS6 WebDAV Unicode Authentication Bypass
   610   scanner/http/ms15_034_http_sys_memory_dump                                      normal  Yes    MS15-034 HTTP Protocol Stack Request Handling HTTP.SYS Memory Information Disclosure
   611   scanner/http/mybook_live_login                                                  normal  Yes    Western Digital MyBook Live Login Utility
   612   scanner/http/netdecision_traversal                             2012-03-07       normal  Yes    NetDecision NOCVision Server Directory Traversal
   613   scanner/http/netgear_sph200d_traversal                                          normal  Yes    Netgear SPH200D Directory Traversal Vulnerability
   614   scanner/http/nginx_source_disclosure                                            normal  Yes    Nginx Source Code Disclosure/Download
   615   scanner/http/novell_file_reporter_fsfui_fileaccess             2012-11-16       normal  Yes    NFR Agent FSFUI Record Arbitrary Remote File Access
   616   scanner/http/novell_file_reporter_srs_fileaccess               2012-11-16       normal  Yes    NFR Agent SRS Record Arbitrary Remote File Access
   617   scanner/http/novell_mdm_creds                                                   normal  Yes    Novell Zenworks Mobile Device Managment Admin Credentials
   618   scanner/http/ntlm_info_enumeration                                              normal  Yes    Host Information Enumeration via NTLM Authentication
   619   scanner/http/octopusdeploy_login                                                normal  Yes    Octopus Deploy Login Utility
   620   scanner/http/onion_omega2_login                                2019-03-27       normal  Yes    Onion Omega2 Login Brute-Force
   621   scanner/http/open_proxy                                                         normal  Yes    HTTP Open Proxy Detection
   622   scanner/http/openmind_messageos_login                                           normal  Yes    OpenMind Message-OS Portal Login Brute Force Utility
   623   scanner/http/options                                                            normal  Yes    HTTP Options Detection
   624   scanner/http/oracle_demantra_database_credentials_leak         2014-02-28       normal  Yes    Oracle Demantra Database Credentials Leak
   625   scanner/http/oracle_demantra_file_retrieval                    2014-02-28       normal  Yes    Oracle Demantra Arbitrary File Retrieval with Authentication Bypass
   626   scanner/http/oracle_ilom_login                                                  normal  Yes    Oracle ILO Manager Login Brute Force Utility
   627   scanner/http/owa_ews_login                                                      normal  Yes    OWA Exchange Web Services (EWS) Login Scanner
   628   scanner/http/owa_iis_internal_ip                               2012-12-17       normal  Yes    Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure
   629   scanner/http/owa_login                                                          normal  Yes    Outlook Web App (OWA) Brute Force Utility
   630   scanner/http/phpmyadmin_login                                                   normal  Yes    PhpMyAdmin Login Scanner
   631   scanner/http/pocketpad_login                                                    normal  Yes    PocketPAD Login Bruteforce Force Utility
   632   scanner/http/prev_dir_same_name_file                                            normal  Yes    HTTP Previous Directory File Scanner
   633   scanner/http/radware_appdirector_enum                                           normal  Yes    Radware AppDirector Bruteforce Login Utility
   634   scanner/http/rails_json_yaml_scanner                                            normal  Yes    Ruby on Rails JSON Processor YAML Deserialization Scanner
   635   scanner/http/rails_mass_assignment                                              normal  Yes    Ruby On Rails Attributes Mass Assignment Scanner
   636   scanner/http/rails_xml_yaml_scanner                                             normal  Yes    Ruby on Rails XML Processor YAML Deserialization Scanner
   637   scanner/http/replace_ext                                                        normal  Yes    HTTP File Extension Scanner
   638   scanner/http/rewrite_proxy_bypass                                               normal  Yes    Apache Reverse Proxy Bypass Vulnerability Scanner
   639   scanner/http/rfcode_reader_enum                                                 normal  Yes    RFCode Reader Web Interface Login / Bruteforce Utility
   640   scanner/http/rips_traversal                                                     normal  Yes    RIPS Scanner Directory Traversal
   641   scanner/http/riverbed_steelhead_vcx_file_read                  2017-06-01       normal  Yes    Riverbed SteelHead VCX File Read
   642   scanner/http/robots_txt                                                         normal  Yes    HTTP Robots.txt Content Scanner
   643   scanner/http/s40_traversal                                     2011-04-07       normal  Yes    S40 0.4.2 CMS Directory Traversal Vulnerability
   644   scanner/http/sap_businessobjects_user_brute                                     normal  Yes    SAP BusinessObjects User Bruteforcer
   645   scanner/http/sap_businessobjects_user_brute_web                                 normal  Yes    SAP BusinessObjects Web User Bruteforcer
   646   scanner/http/sap_businessobjects_user_enum                                      normal  Yes    SAP BusinessObjects User Enumeration
   647   scanner/http/sap_businessobjects_version_enum                                   normal  Yes    SAP BusinessObjects Version Detection
   648   scanner/http/scraper                                                            normal  Yes    HTTP Page Scraper
   649   scanner/http/sentry_cdu_enum                                                    normal  Yes    Sentry Switched CDU Bruteforce Login Utility
   650   scanner/http/servicedesk_plus_traversal                        2015-10-03       normal  Yes    ManageEngine ServiceDesk Plus Path Traversal
   651   scanner/http/sevone_enum                                       2013-06-07       normal  Yes    SevOne Network Performance Management Application Brute Force Login Utility
   652   scanner/http/simple_webserver_traversal                        2013-01-03       normal  Yes    Simple Web Server 2.3-RC1 Directory Traversal
   653   scanner/http/smt_ipmi_49152_exposure                           2014-06-19       normal  Yes    Supermicro Onboard IPMI Port 49152 Sensitive File Exposure
   654   scanner/http/smt_ipmi_cgi_scanner                              2013-11-06       normal  Yes    Supermicro Onboard IPMI CGI Vulnerability Scanner
   655   scanner/http/smt_ipmi_static_cert_scanner                      2013-11-06       normal  Yes    Supermicro Onboard IPMI Static SSL Certificate Scanner
   656   scanner/http/smt_ipmi_url_redirect_traversal                   2013-11-06       normal  Yes    Supermicro Onboard IPMI url_redirect.cgi Authenticated Directory Traversal
   657   scanner/http/soap_xml                                                           normal  Yes    HTTP SOAP Verb/Noun Brute Force Scanner
   658   scanner/http/sockso_traversal                                  2012-03-14       normal  Yes    Sockso Music Host Server 1.5 Directory Traversal
   659   scanner/http/splunk_web_login                                                   normal  Yes    Splunk Web Interface Login Utility
   660   scanner/http/springcloud_traversal                             2019-04-17       normal  Yes    Spring Cloud Config Server Directory Traversal
   661   scanner/http/squid_pivot_scanning                                               normal  Yes    Squid Proxy Port Scanner
   662   scanner/http/squiz_matrix_user_enum                            2011-11-08       normal  Yes    Squiz Matrix User Enumeration Scanner
   663   scanner/http/ssl                                                                normal  Yes    HTTP SSL Certificate Information
   664   scanner/http/ssl_version                                       2014-10-14       normal  Yes    HTTP SSL/TLS Version Detection (POODLE scanner)
   665   scanner/http/support_center_plus_directory_traversal           2014-01-28       normal  Yes    ManageEngine Support Center Plus Directory Traversal
   666   scanner/http/surgenews_user_creds                              2017-06-16       normal  Yes    SurgeNews User Credentials
   667   scanner/http/svn_scanner                                                        normal  Yes    HTTP Subversion Scanner
   668   scanner/http/svn_wcdb_scanner                                                   normal  Yes    SVN wc.db Scanner
   669   scanner/http/sybase_easerver_traversal                         2011-05-25       normal  Yes    Sybase Easerver 6.3 Directory Traversal
   670   scanner/http/symantec_brightmail_ldapcreds                     2015-12-17       normal  Yes    Symantec Messaging Gateway 10 Exposure of Stored AD Password Vulnerability
   671   scanner/http/symantec_brightmail_logfile                       2012-11-30       normal  Yes    Symantec Messaging Gateway 9.5 Log File Download Vulnerability
   672   scanner/http/symantec_web_gateway_login                                         normal  Yes    Symantec Web Gateway Login Utility
   673   scanner/http/titan_ftp_admin_pwd                                                normal  Yes    Titan FTP Administrative Password Disclosure
   674   scanner/http/title                                                              normal  Yes    HTTP HTML Title Tag Content Grabber
   675   scanner/http/tomcat_enum                                                        normal  Yes    Apache Tomcat User Enumeration
   676   scanner/http/tomcat_mgr_login                                                   normal  Yes    Tomcat Application Manager Login Utility
   677   scanner/http/totaljs_traversal                                 2019-02-18       normal  Yes    Total.js prior to 3.2.4 Directory Traversal
   678   scanner/http/tplink_traversal_noauth                                            normal  Yes    TP-Link Wireless Lite N Access Point Directory Traversal Vulnerability
   679   scanner/http/trace                                                              normal  Yes    HTTP Cross-Site Tracing Detection
   680   scanner/http/trace_axd                                                          normal  Yes    HTTP trace.axd Content Scanner
   681   scanner/http/typo3_bruteforce                                                   normal  Yes    Typo3 Login Bruteforcer
   682   scanner/http/vcms_login                                                         normal  Yes    V-CMS Login Utility
   683   scanner/http/verb_auth_bypass                                                   normal  Yes    HTTP Verb Authentication Bypass Scanner
   684   scanner/http/vhost_scanner                                                      normal  Yes    HTTP Virtual Host Brute Force Scanner
   685   scanner/http/wangkongbao_traversal                                              normal  Yes    WANGKONGBAO CNS-1000 and 1100 UTM Directory Traversal
   686   scanner/http/web_vulndb                                                         normal  Yes    HTTP Vuln Scanner
   687   scanner/http/webdav_internal_ip                                                 normal  Yes    HTTP WebDAV Internal IP Scanner
   688   scanner/http/webdav_scanner                                                     normal  Yes    HTTP WebDAV Scanner
   689   scanner/http/webdav_website_content                                             normal  Yes    HTTP WebDAV Website Content Scanner
   690   scanner/http/webpagetest_traversal                             2012-07-13       normal  Yes    WebPageTest Directory Traversal
   691   scanner/http/wildfly_traversal                                 2014-10-22       normal  Yes    WildFly Directory Traversal
   692   scanner/http/wordpress_content_injection                       2017-02-01       normal  Yes    WordPress REST API Content Injection
   693   scanner/http/wordpress_cp_calendar_sqli                        2015-03-03       normal  Yes    WordPress CP Multi-View Calendar Unauthenticated SQL Injection Scanner
   694   scanner/http/wordpress_ghost_scanner                                            normal  Yes    WordPress XMLRPC GHOST Vulnerability Scanner
   695   scanner/http/wordpress_login_enum                                               normal  Yes    WordPress Brute Force and User Enumeration Utility
   696   scanner/http/wordpress_multicall_creds                                          normal  Yes    Wordpress XML-RPC system.multicall Credential Collector
   697   scanner/http/wordpress_pingback_access                                          normal  Yes    Wordpress Pingback Locator
   698   scanner/http/wordpress_scanner                                                  normal  Yes    Wordpress Scanner
   699   scanner/http/wordpress_xmlrpc_login                                             normal  Yes    Wordpress XML-RPC Username/Password Login Scanner
   700   scanner/http/wp_arbitrary_file_deletion                        2018-06-26       normal  No     Wordpress Arbitrary File Deletion
   701   scanner/http/wp_contus_video_gallery_sqli                      2015-02-24       normal  Yes    WordPress Contus Video Gallery Unauthenticated SQL Injection Scanner
   702   scanner/http/wp_dukapress_file_read                                             normal  Yes    WordPress DukaPress Plugin File Read Vulnerability
   703   scanner/http/wp_gimedia_library_file_read                                       normal  Yes    WordPress GI-Media Library Plugin Directory Traversal Vulnerability
   704   scanner/http/wp_mobile_pack_info_disclosure                                     normal  Yes    WordPress Mobile Pack Information Disclosure Vulnerability
   705   scanner/http/wp_mobileedition_file_read                                         normal  Yes    WordPress Mobile Edition File Read Vulnerability
   706   scanner/http/wp_nextgen_galley_file_read                                        normal  Yes    WordPress NextGEN Gallery Directory Read Vulnerability
   707   scanner/http/wp_simple_backup_file_read                                         normal  Yes    WordPress Simple Backup File Read Vulnerability
   708   scanner/http/wp_subscribe_comments_file_read                                    normal  Yes    WordPress Subscribe Comments File Read Vulnerability
   709   scanner/http/xpath                                                              normal  Yes    HTTP Blind XPATH 1.0 Injector
   710   scanner/http/yaws_traversal                                    2011-11-25       normal  Yes    Yaws Web Server Directory Traversal
   711   scanner/http/zabbix_login                                                       normal  Yes    Zabbix Server Brute Force Utility
   712   scanner/http/zenworks_assetmanagement_fileaccess                                normal  Yes    Novell ZENworks Asset Management 7.5 Remote File Access
   713   scanner/http/zenworks_assetmanagement_getconfig                                 normal  Yes    Novell ZENworks Asset Management 7.5 Configuration Access
   714   scanner/ike/cisco_ike_benigncertain                            2016-09-29       normal  Yes    Cisco IKE Information Disclosure
   715   scanner/imap/imap_version                                                       normal  Yes    IMAP4 Banner Grabber
   716   scanner/ip/ipidseq                                                              normal  Yes    IPID Sequence Scanner
   717   scanner/ipmi/ipmi_cipher_zero                                  2013-06-20       normal  Yes    IPMI 2.0 Cipher Zero Authentication Bypass Scanner
   718   scanner/ipmi/ipmi_dumphashes                                   2013-06-20       normal  Yes    IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval
   719   scanner/ipmi/ipmi_version                                                       normal  Yes    IPMI Information Discovery
   720   scanner/jenkins/jenkins_udp_broadcast_enum                                      normal  No     Jenkins Server Broadcast Enumeration
   721   scanner/kademlia/server_info                                                    normal  Yes    Gather Kademlia Server Information
   722   scanner/llmnr/query                                                             normal  Yes    LLMNR Query
   723   scanner/lotus/lotus_domino_hashes                                               normal  Yes    Lotus Domino Password Hash Collector
   724   scanner/lotus/lotus_domino_login                                                normal  Yes    Lotus Domino Brute Force Utility
   725   scanner/lotus/lotus_domino_version                                              normal  Yes    Lotus Domino Version
   726   scanner/mdns/query                                                              normal  Yes    mDNS Query
   727   scanner/memcached/memcached_amp                                2018-02-27       normal  Yes    Memcached Stats Amplification Scanner
   728   scanner/memcached/memcached_udp_version                        2003-07-23       normal  Yes    Memcached UDP Version Scanner
   729   scanner/misc/cctv_dvr_login                                                     normal  Yes    CCTV DVR Login Scanning Utility
   730   scanner/misc/cisco_smart_install                                                normal  Yes    Identify Cisco Smart Install endpoints
   731   scanner/misc/clamav_control                                    2016-06-08       normal  Yes    ClamAV Remote Command Transmitter
   732   scanner/misc/dahua_dvr_auth_bypass                                              normal  Yes    Dahua DVR Auth Bypass Scanner
   733   scanner/misc/dvr_config_disclosure                                              normal  Yes    Multiple DVR Manufacturers Configuration Disclosure
   734   scanner/misc/easycafe_server_fileaccess                                         normal  Yes    EasyCafe Server Remote File Access
   735   scanner/misc/ib_service_mgr_info                                                normal  Yes    Borland InterBase Services Manager Information
   736   scanner/misc/ibm_mq_channel_brute                                               normal  Yes    IBM WebSphere MQ Channel Name Bruteforce
   737   scanner/misc/ibm_mq_enum                                                        normal  Yes    Identify Queue Manager Name and MQ Version
   738   scanner/misc/ibm_mq_login                                                       normal  Yes    IBM WebSphere MQ Login Check
   739   scanner/misc/java_jmx_server                                   2013-05-22       normal  Yes    Java JMX Server Insecure Endpoint Code Execution Scanner
   740   scanner/misc/java_rmi_server                                   2011-10-15       normal  Yes    Java RMI Server Insecure Endpoint Code Execution Scanner
   741   scanner/misc/oki_scanner                                                        normal  Yes    OKI Printer Default Login Credential Scanner
   742   scanner/misc/poisonivy_control_scanner                                          normal  Yes    Poison Ivy Command and Control Scanner
   743   scanner/misc/raysharp_dvr_passwords                                             normal  Yes    Ray Sharp DVR Password Retriever
   744   scanner/misc/rosewill_rxs3211_passwords                                         normal  Yes    Rosewill RXS-3211 IP Camera Password Retriever
   745   scanner/misc/sercomm_backdoor_scanner                          2013-12-31       normal  Yes    SerComm Network Device Backdoor Detection
   746   scanner/misc/sunrpc_portmapper                                                  normal  Yes    SunRPC Portmap Program Enumerator
   747   scanner/misc/zenworks_preboot_fileaccess                                        normal  Yes    Novell ZENworks Configuration Management Preboot Service Remote File Access
   748   scanner/mongodb/mongodb_login                                                   normal  Yes    MongoDB Login Utility
   749   scanner/motorola/timbuktu_udp                                  2009-09-25       normal  Yes    Motorola Timbuktu Service Detection
   750   scanner/mqtt/connect                                                            normal  Yes    MQTT Authentication Scanner
   751   scanner/msf/msf_rpc_login                                                       normal  Yes    Metasploit RPC Interface Login Utility
   752   scanner/msf/msf_web_login                                                       normal  Yes    Metasploit Web Interface Login Utility
   753   scanner/mssql/mssql_hashdump                                                    normal  Yes    MSSQL Password Hashdump
   754   scanner/mssql/mssql_login                                                       normal  Yes    MSSQL Login Utility
   755   scanner/mssql/mssql_ping                                                        normal  Yes    MSSQL Ping Utility
   756   scanner/mssql/mssql_schemadump                                                  normal  Yes    MSSQL Schema Dump
   757   scanner/mysql/mysql_authbypass_hashdump                        2012-06-09       normal  Yes    MySQL Authentication Bypass Password Dump
   758   scanner/mysql/mysql_file_enum                                                   normal  Yes    MYSQL File/Directory Enumerator
   759   scanner/mysql/mysql_hashdump                                                    normal  Yes    MYSQL Password Hashdump
   760   scanner/mysql/mysql_login                                                       normal  Yes    MySQL Login Utility
   761   scanner/mysql/mysql_schemadump                                                  normal  Yes    MYSQL Schema Dump
   762   scanner/mysql/mysql_version                                                     normal  Yes    MySQL Server Version Enumeration
   763   scanner/mysql/mysql_writable_dirs                                               normal  Yes    MYSQL Directory Write Test
   764   scanner/natpmp/natpmp_portscan                                                  normal  Yes    NAT-PMP External Port Scanner
   765   scanner/nessus/nessus_ntp_login                                                 normal  Yes    Nessus NTP Login Utility
   766   scanner/nessus/nessus_rest_login                                                normal  Yes    Nessus RPC Interface Login Utility
   767   scanner/nessus/nessus_xmlrpc_login                                              normal  Yes    Nessus XMLRPC Interface Login Utility
   768   scanner/nessus/nessus_xmlrpc_ping                                               normal  Yes    Nessus XMLRPC Interface Ping Utility
   769   scanner/netbios/nbname                                                          normal  Yes    NetBIOS Information Discovery
   770   scanner/nexpose/nexpose_api_login                                               normal  Yes    NeXpose API Interface Login Utility
   771   scanner/nfs/nfsmount                                                            normal  Yes    NFS Mount Scanner
   772   scanner/nntp/nntp_login                                                         normal  Yes    NNTP Login Utility
   773   scanner/ntp/ntp_monlist                                                         normal  Yes    NTP Monitor List Scanner
   774   scanner/ntp/ntp_nak_to_the_future                                               normal  Yes    NTP "NAK to the Future"
   775   scanner/ntp/ntp_peer_list_dos                                  2014-08-25       normal  Yes    NTP Mode 7 PEER_LIST DoS Scanner
   776   scanner/ntp/ntp_peer_list_sum_dos                              2014-08-25       normal  Yes    NTP Mode 7 PEER_LIST_SUM DoS Scanner
   777   scanner/ntp/ntp_readvar                                                         normal  Yes    NTP Clock Variables Disclosure
   778   scanner/ntp/ntp_req_nonce_dos                                  2014-08-25       normal  Yes    NTP Mode 6 REQ_NONCE DRDoS Scanner
   779   scanner/ntp/ntp_reslist_dos                                    2014-08-25       normal  Yes    NTP Mode 7 GET_RESTRICT DRDoS Scanner
   780   scanner/ntp/ntp_unsettrap_dos                                  2014-08-25       normal  Yes    NTP Mode 6 UNSETTRAP DRDoS Scanner
   781   scanner/openvas/openvas_gsad_login                                              normal  Yes    OpenVAS gsad Web Interface Login Utility
   782   scanner/openvas/openvas_omp_login                                               normal  Yes    OpenVAS OMP Login Utility
   783   scanner/openvas/openvas_otp_login                                               normal  Yes    OpenVAS OTP Login Utility
   784   scanner/oracle/emc_sid                                                          normal  Yes    Oracle Enterprise Manager Control SID Discovery
   785   scanner/oracle/isqlplus_login                                                   normal  Yes    Oracle iSQL*Plus Login Utility
   786   scanner/oracle/isqlplus_sidbrute                                                normal  Yes    Oracle iSQLPlus SID Check
   787   scanner/oracle/oracle_hashdump                                                  normal  Yes    Oracle Password Hashdump
   788   scanner/oracle/oracle_login                                                     normal  Yes    Oracle RDBMS Login Utility
   789   scanner/oracle/sid_brute                                                        normal  Yes    Oracle TNS Listener SID Bruteforce
   790   scanner/oracle/sid_enum                                        2009-01-07       normal  Yes    Oracle TNS Listener SID Enumeration
   791   scanner/oracle/spy_sid                                                          normal  Yes    Oracle Application Server Spy Servlet SID Enumeration
   792   scanner/oracle/tnslsnr_version                                 2009-01-07       normal  Yes    Oracle TNS Listener Service Version Query
   793   scanner/oracle/tnspoison_checker                               2012-04-18       normal  Yes    Oracle TNS Listener Checker
   794   scanner/oracle/xdb_sid                                                          normal  Yes    Oracle XML DB SID Discovery
   795   scanner/oracle/xdb_sid_brute                                                    normal  Yes    Oracle XML DB SID Discovery via Brute Force
   796   scanner/pcanywhere/pcanywhere_login                                             normal  Yes    PcAnywhere Login Scanner
   797   scanner/pcanywhere/pcanywhere_tcp                                               normal  Yes    PcAnywhere TCP Service Discovery
   798   scanner/pcanywhere/pcanywhere_udp                                               normal  Yes    PcAnywhere UDP Service Discovery
   799   scanner/pop3/pop3_login                                                         normal  Yes    POP3 Login Utility
   800   scanner/pop3/pop3_version                                                       normal  Yes    POP3 Banner Grabber
   801   scanner/portmap/portmap_amp                                                     normal  Yes    Portmapper Amplification Scanner
   802   scanner/portscan/ack                                                            normal  Yes    TCP ACK Firewall Scanner
   803   scanner/portscan/ftpbounce                                                      normal  Yes    FTP Bounce Port Scanner
   804   scanner/portscan/syn                                                            normal  Yes    TCP SYN Port Scanner
   805   scanner/portscan/tcp                                                            normal  Yes    TCP Port Scanner
   806   scanner/portscan/xmas                                                           normal  Yes    TCP "XMas" Port Scanner
   807   scanner/postgres/postgres_dbname_flag_injection                                 normal  Yes    PostgreSQL Database Name Command Line Flag Injection
   808   scanner/postgres/postgres_hashdump                                              normal  Yes    Postgres Password Hashdump
   809   scanner/postgres/postgres_login                                                 normal  Yes    PostgreSQL Login Utility
   810   scanner/postgres/postgres_schemadump                                            normal  Yes    Postgres Schema Dump
   811   scanner/postgres/postgres_version                                               normal  Yes    PostgreSQL Version Probe
   812   scanner/printer/canon_iradv_pwd_extract                                         normal  Yes    Canon IR-Adv Password Extractor
   813   scanner/printer/printer_delete_file                                             normal  Yes    Printer File Deletion Scanner
   814   scanner/printer/printer_download_file                                           normal  Yes    Printer File Download Scanner
   815   scanner/printer/printer_env_vars                                                normal  Yes    Printer Environment Variables Scanner
   816   scanner/printer/printer_list_dir                                                normal  Yes    Printer Directory Listing Scanner
   817   scanner/printer/printer_list_volumes                                            normal  Yes    Printer Volume Listing Scanner
   818   scanner/printer/printer_ready_message                                           normal  Yes    Printer Ready Message Scanner
   819   scanner/printer/printer_upload_file                                             normal  Yes    Printer File Upload Scanner
   820   scanner/printer/printer_version_info                                            normal  Yes    Printer Version Information Scanner
   821   scanner/quake/server_info                                                       normal  Yes    Gather Quake Server Information
   822   scanner/rdp/cve_2019_0708_bluekeep                             2019-05-14       normal  Yes    CVE-2019-0708 BlueKeep Microsoft Remote Desktop RCE Check
   823   scanner/rdp/ms12_020_check                                                      normal  Yes    MS12-020 Microsoft Remote Desktop Checker
   824   scanner/rdp/rdp_scanner                                                         normal  Yes    Identify endpoints speaking the Remote Desktop Protocol (RDP)
   825   scanner/redis/file_upload                                      2015-11-11       normal  Yes    Redis File Upload
   826   scanner/redis/redis_login                                                       normal  Yes    Redis Login Utility
   827   scanner/redis/redis_server                                                      normal  Yes    Redis Command Execute Scanner
   828   scanner/rogue/rogue_recv                                                        normal  No     Rogue Gateway Detection: Receiver
   829   scanner/rogue/rogue_send                                                        normal  Yes    Rogue Gateway Detection: Sender
   830   scanner/rservices/rexec_login                                                   normal  Yes    rexec Authentication Scanner
   831   scanner/rservices/rlogin_login                                                  normal  Yes    rlogin Authentication Scanner
   832   scanner/rservices/rsh_login                                                     normal  Yes    rsh Authentication Scanner
   833   scanner/rsync/modules_list                                                      normal  Yes    List Rsync Modules
   834   scanner/sap/sap_ctc_verb_tampering_user_mgmt                                    normal  Yes    SAP CTC Service Verb Tampering User Management
   835   scanner/sap/sap_hostctrl_getcomputersystem                                      normal  Yes    SAP Host Agent Information Disclosure
   836   scanner/sap/sap_icf_public_info                                                 normal  Yes    SAP ICF /sap/public/info Service Sensitive Information Gathering
   837   scanner/sap/sap_icm_urlscan                                                     normal  Yes    SAP URL Scanner
   838   scanner/sap/sap_mgmt_con_abaplog                                                normal  Yes    SAP Management Console ABAP Syslog Disclosure
   839   scanner/sap/sap_mgmt_con_brute_login                                            normal  Yes    SAP Management Console Brute Force
   840   scanner/sap/sap_mgmt_con_extractusers                                           normal  Yes    SAP Management Console Extract Users
   841   scanner/sap/sap_mgmt_con_getaccesspoints                                        normal  Yes    SAP Management Console Get Access Points
   842   scanner/sap/sap_mgmt_con_getenv                                                 normal  Yes    SAP Management Console getEnvironment
   843   scanner/sap/sap_mgmt_con_getlogfiles                                            normal  Yes    SAP Management Console Get Logfile
   844   scanner/sap/sap_mgmt_con_getprocesslist                                         normal  Yes    SAP Management Console GetProcessList
   845   scanner/sap/sap_mgmt_con_getprocessparameter                                    normal  Yes    SAP Management Console Get Process Parameters
   846   scanner/sap/sap_mgmt_con_instanceproperties                                     normal  Yes    SAP Management Console Instance Properties
   847   scanner/sap/sap_mgmt_con_listconfigfiles                                        normal  Yes    SAP Management Console List Config Files
   848   scanner/sap/sap_mgmt_con_listlogfiles                                           normal  Yes    SAP Management Console List Logfiles
   849   scanner/sap/sap_mgmt_con_startprofile                                           normal  Yes    SAP Management Console getStartProfile
   850   scanner/sap/sap_mgmt_con_version                                                normal  Yes    SAP Management Console Version Detection
   851   scanner/sap/sap_router_info_request                                             normal  Yes    SAPRouter Admin Request
   852   scanner/sap/sap_router_portscanner                                              normal  No     SAPRouter Port Scanner
   853   scanner/sap/sap_service_discovery                                               normal  Yes    SAP Service Discovery
   854   scanner/sap/sap_smb_relay                                                       normal  Yes    SAP SMB Relay Abuse
   855   scanner/sap/sap_soap_bapi_user_create1                                          normal  Yes    SAP /sap/bc/soap/rfc SOAP Service BAPI_USER_CREATE1 Function User Creation
   856   scanner/sap/sap_soap_rfc_brute_login                                            normal  Yes    SAP SOAP Service RFC_PING Login Brute Forcer
   857   scanner/sap/sap_soap_rfc_dbmcli_sxpg_call_system_command_exec                   normal  Yes    SAP /sap/bc/soap/rfc SOAP Service SXPG_CALL_SYSTEM Function Command Injection
   858   scanner/sap/sap_soap_rfc_dbmcli_sxpg_command_exec                               normal  Yes    SAP /sap/bc/soap/rfc SOAP Service SXPG_COMMAND_EXEC Function Command Injection
   859   scanner/sap/sap_soap_rfc_eps_get_directory_listing                              normal  Yes    SAP SOAP RFC EPS_GET_DIRECTORY_LISTING Directories Information Disclosure
   860   scanner/sap/sap_soap_rfc_pfl_check_os_file_existence                            normal  Yes    SAP SOAP RFC PFL_CHECK_OS_FILE_EXISTENCE File Existence Check
   861   scanner/sap/sap_soap_rfc_ping                                                   normal  Yes    SAP /sap/bc/soap/rfc SOAP Service RFC_PING Function Service Discovery
   862   scanner/sap/sap_soap_rfc_read_table                                             normal  Yes    SAP /sap/bc/soap/rfc SOAP Service RFC_READ_TABLE Function Dump Data
   863   scanner/sap/sap_soap_rfc_rzl_read_dir                                           normal  Yes    SAP SOAP RFC RZL_READ_DIR_LOCAL Directory Contents Listing
   864   scanner/sap/sap_soap_rfc_susr_rfc_user_interface                                normal  Yes    SAP /sap/bc/soap/rfc SOAP Service SUSR_RFC_USER_INTERFACE Function User Creation
   865   scanner/sap/sap_soap_rfc_sxpg_call_system_exec                                  normal  Yes    SAP /sap/bc/soap/rfc SOAP Service SXPG_CALL_SYSTEM Function Command Execution
   866   scanner/sap/sap_soap_rfc_sxpg_command_exec                                      normal  Yes    SAP SOAP RFC SXPG_COMMAND_EXECUTE
   867   scanner/sap/sap_soap_rfc_system_info                                            normal  Yes    SAP /sap/bc/soap/rfc SOAP Service RFC_SYSTEM_INFO Function Sensitive Information Gathering
   868   scanner/sap/sap_soap_th_saprel_disclosure                                       normal  Yes    SAP /sap/bc/soap/rfc SOAP Service TH_SAPREL Function Information Disclosure
   869   scanner/sap/sap_web_gui_brute_login                                             normal  Yes    SAP Web GUI Login Brute Forcer
   870   scanner/scada/digi_addp_reboot                                                  normal  Yes    Digi ADDP Remote Reboot Initiator
   871   scanner/scada/digi_addp_version                                                 normal  Yes    Digi ADDP Information Discovery
   872   scanner/scada/digi_realport_serialport_scan                                     normal  Yes    Digi RealPort Serial Server Port Scanner
   873   scanner/scada/digi_realport_version                                             normal  Yes    Digi RealPort Serial Server Version
   874   scanner/scada/indusoft_ntwebserver_fileaccess                                   normal  Yes    Indusoft WebStudio NTWebServer Remote File Access
   875   scanner/scada/koyo_login                                       2012-01-19       normal  Yes    Koyo DirectLogic PLC Password Brute Force Utility
   876   scanner/scada/modbus_findunitid                                2012-10-28       normal  No     Modbus Unit ID and Station ID Enumerator
   877   scanner/scada/modbusclient                                                      normal  No     Modbus Client Utility
   878   scanner/scada/modbusdetect                                     2011-11-01       normal  Yes    Modbus Version Scanner
   879   scanner/scada/moxa_discover                                                     normal  Yes    Moxa UDP Device Discovery
   880   scanner/scada/pcomclient                                                        normal  No     Unitronics PCOM Client
   881   scanner/scada/profinet_siemens                                                  normal  No     Siemens Profinet Scanner
   882   scanner/scada/sielco_winlog_fileaccess                                          normal  Yes    Sielco Sistemi Winlog Remote File Access
   883   scanner/sip/enumerator                                                          normal  Yes    SIP Username Enumerator (UDP)
   884   scanner/sip/enumerator_tcp                                                      normal  Yes    SIP Username Enumerator (TCP)
   885   scanner/sip/options                                                             normal  Yes    SIP Endpoint Scanner (UDP)
   886   scanner/sip/options_tcp                                                         normal  Yes    SIP Endpoint Scanner (TCP)
   887   scanner/sip/sipdroid_ext_enum                                                   normal  No     SIPDroid Extension Grabber
   888   scanner/smb/impacket/dcomexec                                  2018-03-19       normal  Yes    DCOM Exec
   889   scanner/smb/impacket/secretsdump                                                normal  Yes    DCOM Exec
   890   scanner/smb/impacket/wmiexec                                   2018-03-19       normal  Yes    WMI Exec
   891   scanner/smb/pipe_auditor                                                        normal  Yes    SMB Session Pipe Auditor
   892   scanner/smb/pipe_dcerpc_auditor                                                 normal  Yes    SMB Session Pipe DCERPC Auditor
   893   scanner/smb/psexec_loggedin_users                                               normal  Yes    Microsoft Windows Authenticated Logged In Users Enumeration
   894   scanner/smb/smb1                                                                normal  Yes    SMBv1 Protocol Detection
   895   scanner/smb/smb2                                                                normal  Yes    SMB 2.0 Protocol Detection
   896   scanner/smb/smb_enum_gpp                                                        normal  Yes    SMB Group Policy Preference Saved Passwords Enumeration
   897   scanner/smb/smb_enumshares                                                      normal  Yes    SMB Share Enumeration
   898   scanner/smb/smb_enumusers                                                       normal  Yes    SMB User Enumeration (SAM EnumUsers)
   899   scanner/smb/smb_enumusers_domain                                                normal  Yes    SMB Domain User Enumeration
   900   scanner/smb/smb_login                                                           normal  Yes    SMB Login Check Scanner
   901   scanner/smb/smb_lookupsid                                                       normal  Yes    SMB SID User Enumeration (LookupSid)
   902   scanner/smb/smb_ms17_010                                                        normal  Yes    MS17-010 SMB RCE Detection
   903   scanner/smb/smb_uninit_cred                                                     normal  Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   904   scanner/smb/smb_version                                                         normal  Yes    SMB Version Detection
   905   scanner/smtp/smtp_enum                                                          normal  Yes    SMTP User Enumeration Utility
   906   scanner/smtp/smtp_ntlm_domain                                                   normal  Yes    SMTP NTLM Domain Extraction
   907   scanner/smtp/smtp_relay                                                         normal  Yes    SMTP Open Relay Detection
   908   scanner/smtp/smtp_version                                                       normal  Yes    SMTP Banner Grabber
   909   scanner/snmp/aix_version                                                        normal  Yes    AIX SNMP Scanner Auxiliary Module
   910   scanner/snmp/arris_dg950                                                        normal  Yes    Arris DG950A Cable Modem Wifi Enumeration
   911   scanner/snmp/brocade_enumhash                                                   normal  Yes    Brocade Password Hash Enumeration
   912   scanner/snmp/cisco_config_tftp                                                  normal  Yes    Cisco IOS SNMP Configuration Grabber (TFTP)
   913   scanner/snmp/cisco_upload_file                                                  normal  Yes    Cisco IOS SNMP File Upload (TFTP)
   914   scanner/snmp/cnpilot_r_snmp_loot                                                normal  Yes    Cambium cnPilot r200/r201 SNMP Enumeration
   915   scanner/snmp/epmp1000_snmp_loot                                                 normal  Yes    Cambium ePMP 1000 SNMP Enumeration
   916   scanner/snmp/netopia_enum                                                       normal  Yes    Netopia 3347 Cable Modem Wifi Enumeration
   917   scanner/snmp/sbg6580_enum                                                       normal  Yes    ARRIS / Motorola SBG6580 Cable Modem SNMP Enumeration Module
   918   scanner/snmp/snmp_enum                                                          normal  Yes    SNMP Enumeration Module
   919   scanner/snmp/snmp_enum_hp_laserjet                                              normal  Yes    HP LaserJet Printer SNMP Enumeration
   920   scanner/snmp/snmp_enumshares                                                    normal  Yes    SNMP Windows SMB Share Enumeration
   921   scanner/snmp/snmp_enumusers                                                     normal  Yes    SNMP Windows Username Enumeration
   922   scanner/snmp/snmp_login                                                         normal  Yes    SNMP Community Login Scanner
   923   scanner/snmp/snmp_set                                                           normal  Yes    SNMP Set Module
   924   scanner/snmp/ubee_ddw3611                                                       normal  Yes    Ubee DDW3611b Cable Modem Wifi Enumeration
   925   scanner/snmp/xerox_workcentre_enumusers                                         normal  Yes    Xerox WorkCentre User Enumeration (SNMP)
   926   scanner/ssh/apache_karaf_command_execution                     2016-02-09       normal  Yes    Apache Karaf Default Credentials Command Execution
   927   scanner/ssh/cerberus_sftp_enumusers                            2014-05-27       normal  Yes    Cerberus FTP Server SFTP Username Enumeration
   928   scanner/ssh/detect_kippo                                                        normal  Yes    Kippo SSH Honeypot Detector
   929   scanner/ssh/eaton_xpert_backdoor                               2018-07-18       normal  Yes    Eaton Xpert Meter SSH Private Key Exposure Scanner
   930   scanner/ssh/fortinet_backdoor                                  2016-01-09       normal  Yes    Fortinet SSH Backdoor Scanner
   931   scanner/ssh/juniper_backdoor                                   2015-12-20       normal  Yes    Juniper SSH Backdoor Scanner
   932   scanner/ssh/karaf_login                                                         normal  Yes    Apache Karaf Login Utility
   933   scanner/ssh/libssh_auth_bypass                                 2018-10-16       normal  Yes    libssh Authentication Bypass Scanner
   934   scanner/ssh/ssh_enumusers                                                       normal  Yes    SSH Username Enumeration
   935   scanner/ssh/ssh_identify_pubkeys                                                normal  Yes    SSH Public Key Acceptance Scanner
   936   scanner/ssh/ssh_login                                                           normal  Yes    SSH Login Check Scanner
   937   scanner/ssh/ssh_login_pubkey                                                    normal  Yes    SSH Public Key Login Scanner
   938   scanner/ssh/ssh_version                                                         normal  Yes    SSH Version Scanner
   939   scanner/ssl/bleichenbacher_oracle                              2009-06-17       normal  Yes    Scanner for Bleichenbacher Oracle in RSA PKCS #1 v1.5
   940   scanner/ssl/openssl_ccs                                        2014-06-05       normal  Yes    OpenSSL Server-Side ChangeCipherSpec Injection Scanner
   941   scanner/ssl/openssl_heartbleed                                 2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak
   942   scanner/steam/server_info                                                       normal  Yes    Gather Steam Server Information
   943   scanner/telephony/wardial                                                       normal  Yes    Wardialer
   944   scanner/telnet/brocade_enable_login                                             normal  Yes    Brocade Enable Login Check Scanner
   945   scanner/telnet/lantronix_telnet_password                                        normal  Yes    Lantronix Telnet Password Recovery
   946   scanner/telnet/lantronix_telnet_version                                         normal  Yes    Lantronix Telnet Service Banner Detection
   947   scanner/telnet/satel_cmd_exec                                  2017-04-07       normal  Yes    Satel Iberia SenNet Data Logger and Electricity Meters Command Injection Vulnerability
   948   scanner/telnet/telnet_encrypt_overflow                                          normal  Yes    Telnet Service Encryption Key ID Overflow Detection
   949   scanner/telnet/telnet_login                                                     normal  Yes    Telnet Login Check Scanner
   950   scanner/telnet/telnet_ruggedcom                                                 normal  Yes    RuggedCom Telnet Password Generator
   951   scanner/telnet/telnet_version                                                   normal  Yes    Telnet Service Banner Detection
   952   scanner/teradata/teradata_odbc_login                           2018-03-30       normal  Yes    Teradata ODBC Login Scanner Module
   953   scanner/tftp/ipswitch_whatsupgold_tftp                         2011-12-12       normal  Yes    IpSwitch WhatsUp Gold TFTP Directory Traversal
   954   scanner/tftp/netdecision_tftp                                  2009-05-16       normal  Yes    NetDecision 4.2 TFTP Directory Traversal
   955   scanner/tftp/tftpbrute                                                          normal  Yes    TFTP Brute Forcer
   956   scanner/ubiquiti/ubiquiti_discover                                              normal  Yes    Ubiquiti Discovery Scanner
   957   scanner/udp/udp_amplification                                                   normal  Yes    UDP Amplification Scanner
   958   scanner/upnp/ssdp_amp                                                           normal  Yes    SSDP ssdp:all M-SEARCH Amplification Scanner
   959   scanner/upnp/ssdp_msearch                                                       normal  Yes    UPnP SSDP M-SEARCH Information Discovery
   960   scanner/varnish/varnish_cli_file_read                                           normal  Yes    Varnish Cache CLI File Read
   961   scanner/varnish/varnish_cli_login                                               normal  Yes    Varnish Cache CLI Login Utility
   962   scanner/vmware/esx_fingerprint                                                  normal  Yes    VMWare ESX/ESXi Fingerprint Scanner
   963   scanner/vmware/vmauthd_login                                                    normal  Yes    VMWare Authentication Daemon Login Scanner
   964   scanner/vmware/vmauthd_version                                                  normal  Yes    VMWare Authentication Daemon Version Scanner
   965   scanner/vmware/vmware_enum_permissions                                          normal  Yes    VMWare Enumerate Permissions
   966   scanner/vmware/vmware_enum_sessions                                             normal  Yes    VMWare Enumerate Active Sessions
   967   scanner/vmware/vmware_enum_users                                                normal  Yes    VMWare Enumerate User Accounts
   968   scanner/vmware/vmware_enum_vms                                                  normal  Yes    VMWare Enumerate Virtual Machines
   969   scanner/vmware/vmware_host_details                                              normal  Yes    VMWare Enumerate Host Details
   970   scanner/vmware/vmware_http_login                                                normal  Yes    VMWare Web Login Scanner
   971   scanner/vmware/vmware_screenshot_stealer                                        normal  Yes    VMWare Screenshot Stealer
   972   scanner/vmware/vmware_server_dir_trav                                           normal  Yes    VMware Server Directory Traversal Vulnerability
   973   scanner/vmware/vmware_update_manager_traversal                 2011-11-21       normal  Yes    VMWare Update Manager 4 Directory Traversal
   974   scanner/vnc/ard_root_pw                                                         normal  Yes    Apple Remote Desktop Root Vulnerability
   975   scanner/vnc/vnc_login                                                           normal  Yes    VNC Authentication Scanner
   976   scanner/vnc/vnc_none_auth                                                       normal  Yes    VNC Authentication None Detection
   977   scanner/voice/recorder                                                          normal  No     Telephone Line Voice Scanner
   978   scanner/vxworks/wdbrpc_bootline                                                 normal  Yes    VxWorks WDB Agent Boot Parameter Scanner
   979   scanner/vxworks/wdbrpc_version                                                  normal  Yes    VxWorks WDB Agent Version Scanner
   980   scanner/winrm/winrm_auth_methods                                                normal  Yes    WinRM Authentication Method Detection
   981   scanner/winrm/winrm_cmd                                                         normal  Yes    WinRM Command Runner
   982   scanner/winrm/winrm_login                                                       normal  Yes    WinRM Login Utility
   983   scanner/winrm/winrm_wql                                                         normal  Yes    WinRM WQL Query Runner
   984   scanner/wproxy/att_open_proxy                                  2017-08-31       normal  Yes    Open WAN-to-LAN proxy on AT&T routers
   985   scanner/wsdd/wsdd_query                                                         normal  Yes    WS-Discovery Information Discovery
   986   scanner/x11/open_x11                                                            normal  Yes    X11 No-Auth Scanner
   987   server/android_browsable_msf_launch                                             normal  No     Android Meterpreter Browsable Launcher
   988   server/android_mercury_parseuri                                                 normal  No     Android Mercury Browser Intent URI Scheme and Directory Traversal Vulnerability
   989   server/browser_autopwn                                                          normal  No     HTTP Client Automatic Exploiter
   990   server/browser_autopwn2                                        2015-07-05       normal  No     HTTP Client Automatic Exploiter 2 (Browser Autopwn)
   991   server/capture/drda                                                             normal  No     Authentication Capture: DRDA (DB2, Informix, Derby)
   992   server/capture/ftp                                                              normal  No     Authentication Capture: FTP
   993   server/capture/http                                                             normal  No     Authentication Capture: HTTP
   994   server/capture/http_basic                                                       normal  No     HTTP Client Basic Authentication Credential Collector
   995   server/capture/http_javascript_keylogger                                        normal  No     Capture: HTTP JavaScript Keylogger
   996   server/capture/http_ntlm                                                        normal  No     HTTP Client MS Credential Catcher
   997   server/capture/imap                                                             normal  No     Authentication Capture: IMAP
   998   server/capture/mssql                                                            normal  No     Authentication Capture: MSSQL
   999   server/capture/mysql                                                            normal  No     Authentication Capture: MySQL
   1000  server/capture/pop3                                                             normal  No     Authentication Capture: POP3
   1001  server/capture/postgresql                                                       normal  No     Authentication Capture: PostgreSQL
   1002  server/capture/printjob_capture                                                 normal  No     Printjob Capture Service
   1003  server/capture/sip                                                              normal  No     Authentication Capture: SIP
   1004  server/capture/smb                                                              normal  No     Authentication Capture: SMB
   1005  server/capture/smtp                                                             normal  No     Authentication Capture: SMTP
   1006  server/capture/telnet                                                           normal  No     Authentication Capture: Telnet
   1007  server/capture/vnc                                                              normal  No     Authentication Capture: VNC
   1008  server/dhclient_bash_env                                       2014-09-24       normal  No     DHCP Client Bash Environment Variable Code Injection (Shellshock)
   1009  server/dhcp                                                                     normal  No     DHCP Server
   1010  server/dns/native_server                                                        normal  No     Native DNS Server (Example)
   1011  server/dns/spoofhelper                                                          normal  No     DNS Spoofing Helper Service
   1012  server/fakedns                                                                  normal  No     Fake DNS Service
   1013  server/ftp                                                                      normal  No     FTP File Server
   1014  server/http_ntlmrelay                                                           normal  No     HTTP Client MS Credential Relayer
   1015  server/icmp_exfil                                                               normal  No     ICMP Exfiltration Service
   1016  server/jsse_skiptls_mitm_proxy                                 2015-01-20       normal  No     Java Secure Socket Extension (JSSE) SKIP-TLS MITM Proxy
   1017  server/local_hwbridge                                                           normal  No     Hardware Bridge Server
   1018  server/ms15_134_mcl_leak                                       2015-12-08       normal  No     MS15-134 Microsoft Windows Media Center MCL Information Disclosure
   1019  server/netbios_spoof_nat                                       2016-06-14       normal  No     NetBIOS Response "BadTunnel" Brute Force Spoof (NAT Tunnel)
   1020  server/openssl_altchainsforgery_mitm_proxy                     2015-07-09       normal  No     OpenSSL Alternative Chains Certificate Forgery MITM Proxy
   1021  server/openssl_heartbeat_client_memory                         2014-04-07       normal  No     OpenSSL Heartbeat (Heartbleed) Client Memory Exposure
   1022  server/pxeexploit                                                               normal  No     PXE Boot Exploit Server
   1023  server/regsvr32_command_delivery_server                                         normal  No     Regsvr32.exe (.sct) Command Delivery Server
   1024  server/socks4a                                                                  normal  No     Socks4a Proxy Server
   1025  server/socks5                                                                   normal  No     Socks5 Proxy Server
   1026  server/socks_unc                                                                normal  No     SOCKS Proxy UNC Path Redirection
   1027  server/tftp                                                                     normal  No     TFTP File Server
   1028  server/webkit_xslt_dropper                                                      normal  No     Cross Platform Webkit File Dropper
   1029  server/wget_symlink_file_write                                 2014-10-27       normal  No     GNU Wget FTP Symlink Arbitrary Filesystem Access
   1030  server/wpad                                                                     normal  No     WPAD.dat File Server
   1031  sniffer/psnuffle                                                                normal  No     pSnuffle Packet Sniffer
   1032  spoof/arp/arp_poisoning                                        1999-12-22       normal  No     ARP Spoof
   1033  spoof/cisco/cdp                                                                 normal  No     Send Cisco Discovery Protocol (CDP) Packets
   1034  spoof/cisco/dtp                                                                 normal  No     Forge Cisco DTP Packets
   1035  spoof/dns/bailiwicked_domain                                   2008-07-21       normal  Yes    DNS BailiWicked Domain Attack
   1036  spoof/dns/bailiwicked_host                                     2008-07-21       normal  Yes    DNS BailiWicked Host Attack
   1037  spoof/dns/compare_results                                      2008-07-21       normal  No     DNS Lookup Result Comparison
   1038  spoof/dns/native_spoofer                                                        normal  No     Native DNS Spoofer (Example)
   1039  spoof/llmnr/llmnr_response                                                      normal  No     LLMNR Spoofer
   1040  spoof/mdns/mdns_response                                                        normal  No     mDNS Spoofer
   1041  spoof/nbns/nbns_response                                                        normal  No     NetBIOS Name Service Spoofer
   1042  spoof/replay/pcap_replay                                                        normal  No     Pcap Replay Utility
   1043  sqli/oracle/dbms_cdc_ipublish                                  2008-10-22       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_IPUBLISH.ALTER_HOTLOG_INTERNAL_CSOURCE
   1044  sqli/oracle/dbms_cdc_publish                                   2008-10-22       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.ALTER_AUTOLOG_CHANGE_SOURCE
   1045  sqli/oracle/dbms_cdc_publish2                                  2010-04-26       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE
   1046  sqli/oracle/dbms_cdc_publish3                                  2010-10-13       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_PUBLISH.CREATE_CHANGE_SET
   1047  sqli/oracle/dbms_cdc_subscribe_activate_subscription           2005-04-18       normal  No     Oracle DB SQL Injection via SYS.DBMS_CDC_SUBSCRIBE.ACTIVATE_SUBSCRIPTION
   1048  sqli/oracle/dbms_export_extension                              2006-04-26       normal  No     Oracle DB SQL Injection via DBMS_EXPORT_EXTENSION
   1049  sqli/oracle/dbms_metadata_get_granted_xml                      2008-01-05       normal  No     Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_GRANTED_XML
   1050  sqli/oracle/dbms_metadata_get_xml                              2008-01-05       normal  No     Oracle DB SQL Injection via SYS.DBMS_METADATA.GET_XML
   1051  sqli/oracle/dbms_metadata_open                                 2008-01-05       normal  No     Oracle DB SQL Injection via SYS.DBMS_METADATA.OPEN
   1052  sqli/oracle/droptable_trigger                                  2009-01-13       normal  No     Oracle DB SQL Injection in MDSYS.SDO_TOPO_DROP_FTBL Trigger
   1053  sqli/oracle/jvm_os_code_10g                                    2010-02-01       normal  No     Oracle DB 10gR2, 11gR1/R2 DBMS_JVM_EXP_PERMS OS Command Execution
   1054  sqli/oracle/jvm_os_code_11g                                    2010-02-01       normal  No     Oracle DB 11g R1/R2 DBMS_JVM_EXP_PERMS OS Code Execution
   1055  sqli/oracle/lt_compressworkspace                               2008-10-13       normal  No     Oracle DB SQL Injection via SYS.LT.COMPRESSWORKSPACE
   1056  sqli/oracle/lt_findricset_cursor                               2007-10-17       normal  No     Oracle DB SQL Injection via SYS.LT.FINDRICSET Evil Cursor Method
   1057  sqli/oracle/lt_mergeworkspace                                  2008-10-22       normal  No     Oracle DB SQL Injection via SYS.LT.MERGEWORKSPACE
   1058  sqli/oracle/lt_removeworkspace                                 2008-10-13       normal  No     Oracle DB SQL Injection via SYS.LT.REMOVEWORKSPACE
   1059  sqli/oracle/lt_rollbackworkspace                               2009-05-04       normal  No     Oracle DB SQL Injection via SYS.LT.ROLLBACKWORKSPACE
   1060  voip/asterisk_login                                                             normal  Yes    Asterisk Manager Login Utility
   1061  voip/cisco_cucdm_call_forward                                                   normal  No     Viproy CUCDM IP Phone XML Services - Call Forwarding Tool
   1062  voip/cisco_cucdm_speed_dials                                                    normal  No     Viproy CUCDM IP Phone XML Services - Speed Dial Attack Tool
   1063  voip/sip_deregister                                                             normal  Yes    SIP Deregister Extension
   1064  voip/sip_invite_spoof                                                           normal  Yes    SIP Invite Spoof
   1065  voip/telisca_ips_lock_control                                  2015-12-17       normal  No     Telisca IPS Lock Cisco IP Phone Control
   1066  vsploit/malware/dns/dns_mariposa                                                normal  No     VSploit Mariposa DNS Query Module
   1067  vsploit/malware/dns/dns_query                                                   normal  No     VSploit DNS Beaconing Emulation
   1068  vsploit/malware/dns/dns_zeus                                                    normal  No     VSploit Zeus DNS Query Module
   1069  vsploit/pii/email_pii                                                           normal  No     VSploit Email PII
   1070  vsploit/pii/web_pii                                                             normal  No     VSploit Web PII
"""
    msfpost="""
Post
====

   #    Name                                               Disclosure Date  Rank       Check  Description
   -    ----                                               ---------------  ----       -----  -----------
   0    aix/hashdump                                                        normal     No     AIX Gather Dump Password Hashes
   1    android/capture/screen                                              normal     No     Android Screen Capture
   2    android/gather/sub_info                                             normal     No     extracts subscriber info from target device
   3    android/gather/wireless_ap                                          normal     No     Displays wireless SSIDs and PSKs
   4    android/manage/remove_lock                         2013-10-11       normal     No     Android Settings Remove Device Locks (4.0-4.3)
   5    android/manage/remove_lock_root                                     normal     No     Android Root Remove Device Locks (root)
   6    apple_ios/gather/ios_image_gather                                   normal     No     iOS Image Gatherer
   7    apple_ios/gather/ios_text_gather                                    normal     No     iOS Text Gatherer
   8    cisco/gather/enum_cisco                                             normal     No     Cisco Gather Device General Information
   9    firefox/gather/cookies                             2014-03-26       normal     No     Firefox Gather Cookies from Privileged Javascript Shell
   10   firefox/gather/history                             2014-04-11       normal     No     Firefox Gather History from Privileged Javascript Shell
   11   firefox/gather/passwords                           2014-04-11       normal     No     Firefox Gather Passwords from Privileged Javascript Shell
   12   firefox/gather/xss                                                  normal     No     Firefox XSS
   13   firefox/manage/webcam_chat                         2014-05-13       normal     No     Firefox Webcam Chat on Privileged Javascript Shell
   14   hardware/automotive/can_flood                                       normal     No     CAN Flood
   15   hardware/automotive/canprobe                                        normal     No     Module to Probe Different Data Points in a CAN Packet
   16   hardware/automotive/getvinfo                                        normal     No     Get the Vehicle Information Such as the VIN from the Target Module
   17   hardware/automotive/identifymodules                                 normal     No     Scan CAN Bus for Diagnostic Modules
   18   hardware/automotive/malibu_overheat                                 normal     No     Sample Module to Flood Temp Gauge on 2006 Malibu
   19   hardware/automotive/pdt                                             normal     No     Check For and Prep the Pyrotechnic Devices (Airbags, Battery Clamps, etc.)
   20   hardware/rftransceiver/rfpwnon                                      normal     No     Brute Force AM/OOK (ie: Garage Doors)
   21   hardware/rftransceiver/transmitter                                  normal     No     RF Transceiver Transmitter
   22   hardware/zigbee/zstumbler                                           normal     No     Sends Beacons to Scan for Active ZigBee Networks
   23   juniper/gather/enum_juniper                                         normal     No     Juniper Gather Device General Information
   24   linux/busybox/enum_connections                                      normal     No     BusyBox Enumerate Connections
   25   linux/busybox/enum_hosts                                            normal     No     BusyBox Enumerate Host Names
   26   linux/busybox/jailbreak                                             normal     No     BusyBox Jailbreak 
   27   linux/busybox/ping_net                                              normal     No     BusyBox Ping Network Enumeration
   28   linux/busybox/set_dmz                                               normal     No     BusyBox DMZ Configuration
   29   linux/busybox/set_dns                                               normal     No     BusyBox DNS Configuration
   30   linux/busybox/smb_share_root                                        normal     No     BusyBox SMB Sharing
   31   linux/busybox/wget_exec                                             normal     No     BusyBox Download and Execute
   32   linux/dos/xen_420_dos                                               normal     No     Linux DoS Xen 4.2.0 2012-5525
   33   linux/gather/checkcontainer                                         normal     No     Linux Gather Container Detection
   34   linux/gather/checkvm                                                normal     No     Linux Gather Virtual Environment Detection
   35   linux/gather/ecryptfs_creds                                         normal     No     Gather eCryptfs Metadata
   36   linux/gather/enum_commands                                          normal     No     Testing commands needed in a function
   37   linux/gather/enum_configs                                           normal     No     Linux Gather Configurations
   38   linux/gather/enum_network                                           normal     No     Linux Gather Network Information
   39   linux/gather/enum_protections                                       normal     No     Linux Gather Protection Enumeration
   40   linux/gather/enum_psk                                               normal     No     Linux Gather 802-11-Wireless-Security Credentials
   41   linux/gather/enum_system                                            normal     No     Linux Gather System and User Information
   42   linux/gather/enum_users_history                                     normal     No     Linux Gather User History
   43   linux/gather/enum_xchat                                             normal     No     Linux Gather XChat Enumeration
   44   linux/gather/gnome_commander_creds                                  normal     No     Linux Gather Gnome-Commander Creds
   45   linux/gather/gnome_keyring_dump                                     normal     No     Gnome-Keyring Dump
   46   linux/gather/hashdump                                               normal     No     Linux Gather Dump Password Hashes for Linux Systems
   47   linux/gather/mount_cifs_creds                                       normal     No     Linux Gather Saved mount.cifs/mount.smbfs Credentials
   48   linux/gather/openvpn_credentials                                    normal     No     OpenVPN Gather Credentials
   49   linux/gather/phpmyadmin_credsteal                                   normal     No     Phpmyadmin credentials stealer
   50   linux/gather/pptpd_chap_secrets                                     normal     No     Linux Gather PPTP VPN chap-secrets Credentials
   51   linux/gather/tor_hiddenservices                                     normal     No     Linux Gather TOR Hidden Services
   52   linux/manage/dns_spoofing                                           normal     No     Native DNS Spoofing module
   53   linux/manage/download_exec                                          normal     No     Linux Manage Download and Execute
   54   linux/manage/iptables_removal                                       normal     No     IPTABLES rules removal
   55   linux/manage/pseudo_shell                                           normal     No     Pseudo-Shell Post-Exploitation Module
   56   linux/manage/sshkey_persistence                                     excellent  No     SSH Key Persistence
   57   multi/escalate/aws_create_iam_user                                  normal     No     Create an AWS IAM User
   58   multi/escalate/cups_root_file_read                 2012-11-20       normal     No     CUPS 1.6.1 Root File Read
   59   multi/escalate/metasploit_pcaplog                  2012-07-16       manual     No     Multi Escalate Metasploit pcap_log Local Privilege Escalation
   60   multi/gather/apple_ios_backup                                       normal     No     Windows Gather Apple iOS MobileSync Backup File Collection
   61   multi/gather/aws_ec2_instance_metadata                              normal     No     Gather AWS EC2 Instance Metadata
   62   multi/gather/aws_keys                                               normal     No     UNIX Gather AWS Keys
   63   multi/gather/check_malware                                          normal     No     Multi Gather Malware Verifier
   64   multi/gather/chrome_cookies                                         normal     No     Chrome Gather Cookies
   65   multi/gather/dbvis_enum                                             normal     No     Multi Gather DbVisualizer Connections Settings
   66   multi/gather/dns_bruteforce                                         normal     No     Multi Gather DNS Forward Lookup Bruteforce
   67   multi/gather/dns_reverse_lookup                                     normal     No     Multi Gather DNS Reverse Lookup Scan
   68   multi/gather/dns_srv_lookup                                         normal     No     Multi Gather DNS Service Record Lookup Scan
   69   multi/gather/docker_creds                                           normal     No     Multi Gather Docker Credentials Collection
   70   multi/gather/enum_vbox                                              normal     No     Multi Gather VirtualBox VM Enumeration
   71   multi/gather/env                                                    normal     No     Multi Gather Generic Operating System Environment Settings
   72   multi/gather/fetchmailrc_creds                                      normal     No     UNIX Gather .fetchmailrc Credentials
   73   multi/gather/filezilla_client_cred                                  normal     No     Multi Gather FileZilla FTP Client Credential Collection
   74   multi/gather/find_vmx                                               normal     No     Multi Gather VMWare VM Identification
   75   multi/gather/firefox_creds                                          normal     No     Multi Gather Firefox Signon Credential Collection
   76   multi/gather/gpg_creds                                              normal     No     Multi Gather GnuPG Credentials Collection
   77   multi/gather/irssi_creds                                            normal     No     Multi Gather IRSSI IRC Password(s)
   78   multi/gather/jboss_gather                                           normal     No     Jboss Credential Collector
   79   multi/gather/jenkins_gather                                         normal     No     Jenkins Credential Collector
   80   multi/gather/lastpass_creds                                         normal     No     LastPass Vault Decryptor
   81   multi/gather/maven_creds                                            normal     No     Multi Gather Maven Credentials Collection
   82   multi/gather/multi_command                                          normal     No     Multi Gather Run Shell Command Resource File
   83   multi/gather/netrc_creds                                            normal     No     UNIX Gather .netrc Credentials
   84   multi/gather/pgpass_creds                                           normal     No     Multi Gather pgpass Credentials
   85   multi/gather/pidgin_cred                                            normal     No     Multi Gather Pidgin Instant Messenger Credential Collection
   86   multi/gather/ping_sweep                                             normal     No     Multi Gather Ping Sweep
   87   multi/gather/remmina_creds                                          normal     No     UNIX Gather Remmina Credentials
   88   multi/gather/resolve_hosts                                          normal     No     Multi Gather Resolve Hosts
   89   multi/gather/rsyncd_creds                                           normal     No     UNIX Gather RSYNC Credentials
   90   multi/gather/rubygems_api_key                                       normal     No     Multi Gather RubyGems API Key
   91   multi/gather/run_console_rc_file                                    normal     No     Multi Gather Run Console Resource File
   92   multi/gather/skype_enum                                             normal     No     Multi Gather Skype User Data Enumeration
   93   multi/gather/ssh_creds                                              normal     No     Multi Gather OpenSSH PKI Credentials Collection
   94   multi/gather/thunderbird_creds                                      normal     No     Multi Gather Mozilla Thunderbird Signon Credential Collection
   95   multi/gather/tomcat_gather                                          normal     No     Gather Tomcat Credentials
   96   multi/gather/ubiquiti_unifi_backup                                  normal     No     Multi Gather Ubiquiti UniFi Controller Backup
   97   multi/gather/wlan_geolocate                                         normal     No     Multiplatform WLAN Enumeration and Geolocation
   98   multi/general/close                                                 normal     No     Multi Generic Operating System Session Close
   99   multi/general/execute                                               normal     No     Multi Generic Operating System Session Command Execution
   100  multi/general/wall                                                  normal     No     Write Messages to Users
   101  multi/manage/autoroute                                              normal     No     Multi Manage Network Route via Meterpreter Session
   102  multi/manage/dbvis_add_db_admin                                     normal     No     Multi Manage DbVisualizer Add Db Admin
   103  multi/manage/dbvis_query                                            normal     No     Multi Manage DbVisualizer Query
   104  multi/manage/hsts_eraser                                            normal     No     Web browsers HSTS entries eraser
   105  multi/manage/multi_post                                             normal     No     Multi Manage Post Module Macro Execution
   106  multi/manage/open                                                   normal     No     Open a file or URL on the target computer
   107  multi/manage/play_youtube                                           normal     No     Multi Manage YouTube Broadcast
   108  multi/manage/record_mic                                             normal     No     Multi Manage Record Microphone
   109  multi/manage/screensaver                                            normal     No     Multi Manage the screensaver of the target computer
   110  multi/manage/set_wallpaper                                          normal     No     Multi Manage Set Wallpaper
   111  multi/manage/shell_to_meterpreter                                   normal     No     Shell to Meterpreter Upgrade
   112  multi/manage/sudo                                                   normal     No     Multiple Linux / Unix Post Sudo Upgrade Shell
   113  multi/manage/system_session                                         normal     No     Multi Manage System Remote TCP Shell Session
   114  multi/manage/upload_exec                                            normal     No     Upload and Execute
   115  multi/manage/zip                                                    normal     No     Multi Manage File Compressor
   116  multi/recon/local_exploit_suggester                                 normal     No     Multi Recon Local Exploit Suggester
   117  multi/recon/multiport_egress_traffic                                normal     No     Generate TCP/UDP Outbound Traffic On Multiple Ports
   118  multi/recon/sudo_commands                                           normal     No     Sudo Commands
   119  osx/admin/say                                                       normal     No     OS X Text to Speech Utility
   120  osx/capture/keylog_recorder                                         normal     No     OSX Capture Userspace Keylogger
   121  osx/capture/screen                                                  normal     No     OSX Screen Capture
   122  osx/gather/apfs_encrypted_volume_passwd            2018-03-21       normal     Yes    Mac OS X APFS Encrypted Volume Password Disclosure
   123  osx/gather/autologin_password                                       normal     No     OSX Gather Autologin Password as Root
   124  osx/gather/enum_adium                                               normal     No     OS X Gather Adium Enumeration
   125  osx/gather/enum_airport                                             normal     No     OS X Gather Airport Wireless Preferences
   126  osx/gather/enum_chicken_vnc_profile                                 normal     No     OS X Gather Chicken of the VNC Profile
   127  osx/gather/enum_colloquy                                            normal     No     OS X Gather Colloquy Enumeration
   128  osx/gather/enum_keychain                                            normal     No     OS X Gather Keychain Enumeration
   129  osx/gather/enum_messages                                            normal     No     OS X Gather Messages
   130  osx/gather/enum_osx                                                 normal     No     OS X Gather Mac OS X System Information Enumeration
   131  osx/gather/hashdump                                                 normal     No     OS X Gather Mac OS X Password Hash Collector
   132  osx/gather/password_prompt_spoof                                    normal     No     OSX Password Prompt Spoof
   133  osx/gather/safari_lastsession                                       normal     No     OSX Gather Safari LastSession.plist
   134  osx/gather/vnc_password_osx                                         normal     No     OS X Display Apple VNC Password
   135  osx/manage/mount_share                                              normal     No     OSX Network Share Mounter
   136  osx/manage/record_mic                                               normal     No     OSX Manage Record Microphone
   137  osx/manage/sonic_pi                                                 normal     No     OS X Manage Sonic Pi
   138  osx/manage/vpn                                                      normal     No     OSX VPN Manager
   139  osx/manage/webcam                                                   normal     No     OSX Manage Webcam
   140  solaris/escalate/pfexec                                             normal     No     Solaris pfexec Upgrade Shell
   141  solaris/escalate/srsexec_readline                  2007-05-07       normal     Yes    Solaris srsexec Arbitrary File Reader
   142  solaris/gather/checkvm                                              normal     No     Solaris Gather Virtual Environment Detection
   143  solaris/gather/enum_packages                                        normal     No     Solaris Gather Installed Packages
   144  solaris/gather/enum_services                                        normal     No     Solaris Gather Configured Services
   145  solaris/gather/hashdump                                             normal     No     Solaris Gather Dump Password Hashes for Solaris Systems
   146  windows/capture/keylog_recorder                                     normal     No     Windows Capture Keystroke Recorder
   147  windows/capture/lockout_keylogger                                   normal     No     Windows Capture Winlogon Lockout Credential Keylogger
   148  windows/escalate/droplnk                                            normal     No     Windows Escalate SMB Icon LNK Dropper
   149  windows/escalate/getsystem                                          normal     No     Windows Escalate Get System via Administrator
   150  windows/escalate/golden_ticket                                      normal     No     Windows Escalate Golden Ticket
   151  windows/escalate/ms10_073_kbdlayout                2010-10-12       normal     No     Windows Escalate NtUserLoadKeyboardLayoutEx Privilege Escalation
   152  windows/escalate/screen_unlock                                      normal     No     Windows Escalate Locked Desktop Unlocker
   153  windows/escalate/unmarshal_cmd_exec                2018-08-05       normal     No     Windows unmarshal post exploitation
   154  windows/gather/ad_to_sqlite                                         normal     No     AD Computer, Group and Recursive User Membership to Local SQLite DB
   155  windows/gather/arp_scanner                                          normal     No     Windows Gather ARP Scanner
   156  windows/gather/bitcoin_jacker                                       normal     No     Windows Gather Bitcoin Wallet
   157  windows/gather/bitlocker_fvek                                       normal     No     Bitlocker Master Key (FVEK) Extraction
   158  windows/gather/cachedump                                            normal     No     Windows Gather Credential Cache Dump
   159  windows/gather/checkvm                                              normal     No     Windows Gather Virtual Environment Detection
   160  windows/gather/credentials/avira_password                           normal     No     Windows Gather Avira Password Extraction
   161  windows/gather/credentials/bulletproof_ftp                          normal     No     Windows Gather BulletProof FTP Client Saved Password Extraction
   162  windows/gather/credentials/coreftp                                  normal     No     Windows Gather CoreFTP Saved Password Extraction
   163  windows/gather/credentials/credential_collector                     normal     No     Windows Gather Credential Collector
   164  windows/gather/credentials/domain_hashdump                          normal     No     Windows Domain Controller Hashdump
   165  windows/gather/credentials/dynazip_log             2001-03-27       normal     No     Windows Gather DynaZIP Saved Password Extraction
   166  windows/gather/credentials/dyndns                                   normal     No     Windows Gather DynDNS Client Password Extractor
   167  windows/gather/credentials/enum_cred_store                          normal     No     Windows Gather Credential Store Enumeration and Decryption Module
   168  windows/gather/credentials/enum_laps                                normal     No     Windows Gather Credentials Local Administrator Password Solution
   169  windows/gather/credentials/enum_picasa_pwds                         normal     No     Windows Gather Google Picasa Password Extractor
   170  windows/gather/credentials/epo_sql                                  normal     No     Windows Gather McAfee ePO 4.6 Config SQL Credentials
   171  windows/gather/credentials/filezilla_server                         normal     No     Windows Gather FileZilla FTP Server Credential Collection
   172  windows/gather/credentials/flashfxp                                 normal     No     Windows Gather FlashFXP Saved Password Extraction
   173  windows/gather/credentials/ftpnavigator                             normal     No     Windows Gather FTP Navigator Saved Password Extraction
   174  windows/gather/credentials/ftpx                                     normal     No     Windows Gather FTP Explorer (FTPX) Credential Extraction
   175  windows/gather/credentials/gpp                                      normal     No     Windows Gather Group Policy Preference Saved Passwords
   176  windows/gather/credentials/heidisql                                 normal     No     Windows Gather HeidiSQL Saved Password Extraction
   177  windows/gather/credentials/idm                                      normal     No     Windows Gather Internet Download Manager (IDM) Password Extractor
   178  windows/gather/credentials/imail                                    normal     No     Windows Gather IPSwitch iMail User Data Enumeration
   179  windows/gather/credentials/imvu                                     normal     No     Windows Gather Credentials IMVU Game Client
   180  windows/gather/credentials/mcafee_vse_hashdump                      normal     No     McAfee Virus Scan Enterprise Password Hashes Dump
   181  windows/gather/credentials/mdaemon_cred_collector                   excellent  No     Windows Gather MDaemonEmailServer Credential Cracking
   182  windows/gather/credentials/meebo                                    normal     No     Windows Gather Meebo Password Extractor
   183  windows/gather/credentials/mremote                                  normal     No     Windows Gather mRemote Saved Password Extraction
   184  windows/gather/credentials/mssql_local_hashdump                     normal     No     Windows Gather Local SQL Server Hash Dump
   185  windows/gather/credentials/nimbuzz                                  normal     No     Windows Gather Nimbuzz Instant Messenger Password Extractor
   186  windows/gather/credentials/outlook                                  normal     No     Windows Gather Microsoft Outlook Saved Password Extraction
   187  windows/gather/credentials/purevpn_cred_collector                   normal     No     Windows Gather PureVPN Client Credential Collector
   188  windows/gather/credentials/razer_synapse                            normal     No     Windows Gather Razer Synapse Password Extraction
   189  windows/gather/credentials/razorsql                                 normal     No     Windows Gather RazorSQL Credentials
   190  windows/gather/credentials/rdc_manager_creds                        normal     No     Windows Gather Remote Desktop Connection Manager Saved Password Extraction
   191  windows/gather/credentials/skype                                    normal     No     Windows Gather Skype Saved Password Hash Extraction
   192  windows/gather/credentials/smartermail                              normal     No     Windows Gather SmarterMail Password Extraction
   193  windows/gather/credentials/smartftp                                 normal     No     Windows Gather SmartFTP Saved Password Extraction
   194  windows/gather/credentials/spark_im                                 normal     No     Windows Gather Spark IM Password Extraction
   195  windows/gather/credentials/sso                                      normal     No     Windows Single Sign On Credential Collector (Mimikatz)
   196  windows/gather/credentials/steam                                    normal     No     Windows Gather Steam Client Session Collector.
   197  windows/gather/credentials/tortoisesvn                              normal     No     Windows Gather TortoiseSVN Saved Password Extraction
   198  windows/gather/credentials/total_commander                          normal     No     Windows Gather Total Commander Saved Password Extraction
   199  windows/gather/credentials/trillian                                 normal     No     Windows Gather Trillian Password Extractor
   200  windows/gather/credentials/vnc                                      normal     No     Windows Gather VNC Password Extraction
   201  windows/gather/credentials/windows_autologin                        normal     No     Windows Gather AutoLogin User Credential Extractor
   202  windows/gather/credentials/winscp                                   normal     No     Windows Gather WinSCP Saved Password Extraction
   203  windows/gather/credentials/wsftp_client                             normal     No     Windows Gather WS_FTP Saved Password Extraction
   204  windows/gather/dnscache_dump                                        normal     No     Windows Gather DNS Cache
   205  windows/gather/dumplinks                                            normal     No     Windows Gather Dump Recent Files lnk Info
   206  windows/gather/enum_ad_bitlocker                                    normal     No     Windows Gather Active Directory BitLocker Recovery
   207  windows/gather/enum_ad_computers                                    normal     No     Windows Gather Active Directory Computers
   208  windows/gather/enum_ad_groups                                       normal     No     Windows Gather Active Directory Groups
   209  windows/gather/enum_ad_managedby_groups                             normal     No     Windows Gather Active Directory Managed Groups
   210  windows/gather/enum_ad_service_principal_names                      normal     No     Windows Gather Active Directory Service Principal Names
   211  windows/gather/enum_ad_to_wordlist                                  normal     No     Windows Active Directory Wordlist Builder
   212  windows/gather/enum_ad_user_comments                                normal     No     Windows Gather Active Directory User Comments
   213  windows/gather/enum_ad_users                                        normal     No     Windows Gather Active Directory Users
   214  windows/gather/enum_applications                                    normal     No     Windows Gather Installed Application Enumeration
   215  windows/gather/enum_artifacts                                       normal     No     Windows Gather File and Registry Artifacts Enumeration
   216  windows/gather/enum_av_excluded                                     normal     No     Windows Antivirus Exclusions Enumeration
   217  windows/gather/enum_chrome                                          normal     No     Windows Gather Google Chrome User Data Enumeration
   218  windows/gather/enum_computers                                       normal     No     Windows Gather Enumerate Computers
   219  windows/gather/enum_db                                              normal     No     Windows Gather Database Instance Enumeration
   220  windows/gather/enum_devices                                         normal     No     Windows Gather Hardware Enumeration
   221  windows/gather/enum_dirperms                                        normal     No     Windows Gather Directory Permissions Enumeration
   222  windows/gather/enum_domain                                          normal     No     Windows Gather Enumerate Domain
   223  windows/gather/enum_domain_group_users                              normal     No     Windows Gather Enumerate Domain Group
   224  windows/gather/enum_domain_tokens                                   normal     No     Windows Gather Enumerate Domain Tokens
   225  windows/gather/enum_domain_users                                    normal     No     Windows Gather Enumerate Active Domain Users
   226  windows/gather/enum_domains                                         normal     No     Windows Gather Domain Enumeration
   227  windows/gather/enum_emet                                            normal     No     Windows Gather EMET Protected Paths
   228  windows/gather/enum_files                                           normal     No     Windows Gather Generic File Collection
   229  windows/gather/enum_hostfile                                        normal     No     Windows Gather Windows Host File Enumeration
   230  windows/gather/enum_ie                                              normal     No     Windows Gather Internet Explorer User Data Enumeration
   231  windows/gather/enum_logged_on_users                                 normal     No     Windows Gather Logged On User Enumeration (Registry)
   232  windows/gather/enum_ms_product_keys                                 normal     No     Windows Gather Product Key
   233  windows/gather/enum_muicache                                        normal     No     Windows Gather Enum User MUICache
   234  windows/gather/enum_patches                                         normal     No     Windows Gather Applied Patches
   235  windows/gather/enum_powershell_env                                  normal     No     Windows Gather Powershell Environment Setting Enumeration
   236  windows/gather/enum_prefetch                                        normal     No     Windows Gather Prefetch File Information
   237  windows/gather/enum_proxy                                           normal     No     Windows Gather Proxy Setting
   238  windows/gather/enum_putty_saved_sessions                            normal     No     PuTTY Saved Sessions Enumeration Module
   239  windows/gather/enum_services                                        normal     No     Windows Gather Service Info Enumeration
   240  windows/gather/enum_shares                                          normal     No     Windows Gather SMB Share Enumeration via Registry
   241  windows/gather/enum_snmp                                            normal     No     Windows Gather SNMP Settings Enumeration (Registry)
   242  windows/gather/enum_termserv                                        normal     No     Windows Gather Terminal Server Client Connection Information Dumper
   243  windows/gather/enum_tokens                                          normal     No     Windows Gather Enumerate Domain Admin Tokens (Token Hunter)
   244  windows/gather/enum_tomcat                                          normal     No     Windows Gather Apache Tomcat Enumeration
   245  windows/gather/enum_trusted_locations                               normal     No     Windows Gather Microsoft Office Trusted Locations
   246  windows/gather/enum_unattend                                        normal     No     Windows Gather Unattended Answer File Enumeration
   247  windows/gather/file_from_raw_ntfs                                   normal     No     Windows File Gather File from Raw NTFS
   248  windows/gather/forensics/browser_history                            normal     No     Windows Gather Skype, Firefox, and Chrome Artifacts
   249  windows/gather/forensics/duqu_check                                 normal     No     Windows Gather Forensics Duqu Registry Check
   250  windows/gather/forensics/enum_drives                                normal     No     Windows Gather Physical Drives and Logical Volumes
   251  windows/gather/forensics/imager                                     normal     No     Windows Gather Forensic Imaging
   252  windows/gather/forensics/nbd_server                                 normal     No     Windows Gather Local NBD Server
   253  windows/gather/forensics/recovery_files                             normal     No     Windows Gather Deleted Files Enumeration and Recovering
   254  windows/gather/hashdump                                             normal     No     Windows Gather Local User Account Password Hashes (Registry)
   255  windows/gather/local_admin_search_enum                              normal     Yes    Windows Gather Local Admin Search
   256  windows/gather/lsa_secrets                                          normal     No     Windows Enumerate LSA Secrets
   257  windows/gather/make_csv_orgchart                                    normal     No     Generate CSV Organizational Chart Data Using Manager Information
   258  windows/gather/memory_grep                                          normal     No     Windows Gather Process Memory Grep
   259  windows/gather/netlm_downgrade                                      normal     No     Windows NetLM Downgrade Attack
   260  windows/gather/ntds_grabber                                         normal     No     NTDS Grabber
   261  windows/gather/ntds_location                                        normal     No     Post Windows Gather NTDS.DIT Location
   262  windows/gather/outlook                                              normal     No     Windows Gather Outlook Email Messages
   263  windows/gather/phish_windows_credentials                            normal     No     Windows Gather User Credentials (phishing)
   264  windows/gather/psreadline_history                                   normal     No     Windows Gather PSReadline History
   265  windows/gather/resolve_sid                                          normal     No     Windows Gather Local User Account SID Lookup
   266  windows/gather/reverse_lookup                                       normal     No     Windows Gather IP Range Reverse Lookup
   267  windows/gather/screen_spy                                           normal     No     Windows Gather Screen Spy
   268  windows/gather/smart_hashdump                                       normal     No     Windows Gather Local and Domain Controller Account Password Hashes
   269  windows/gather/tcpnetstat                                           normal     No     Windows Gather TCP Netstat
   270  windows/gather/usb_history                                          normal     No     Windows Gather USB Drive History
   271  windows/gather/win_privs                                            normal     No     Windows Gather Privileges Enumeration
   272  windows/gather/wmic_command                                         normal     No     Windows Gather Run Specified WMIC Command
   273  windows/gather/word_unc_injector                                    normal     No     Windows Gather Microsoft Office Word UNC Path Injector
   274  windows/manage/add_user_domain                                      normal     No     Windows Manage Add User to the Domain and/or to a Domain Group
   275  windows/manage/archmigrate                                          normal     No     Architecture Migrate
   276  windows/manage/change_password                                      normal     No     Windows Manage Change Password
   277  windows/manage/clone_proxy_settings                                 normal     No     Windows Manage Proxy Setting Cloner
   278  windows/manage/delete_user                                          normal     No     Windows Manage Local User Account Deletion
   279  windows/manage/download_exec                                        normal     No     Windows Manage Download and/or Execute
   280  windows/manage/driver_loader                                        normal     No     Windows Manage Driver Loader
   281  windows/manage/enable_rdp                                           normal     No     Windows Manage Enable Remote Desktop
   282  windows/manage/enable_support_account                               normal     No     Windows Manage Trojanize Support Account
   283  windows/manage/exec_powershell                                      normal     No     Windows Powershell Execution Post Module
   284  windows/manage/forward_pageant                                      normal     No     Forward SSH Agent Requests To Remote Pageant
   285  windows/manage/hashcarve                                            normal     No     Windows Local User Account Hash Carver
   286  windows/manage/ie_proxypac                                          normal     No     Windows Manage Proxy PAC File
   287  windows/manage/inject_ca                                            normal     No     Windows Manage Certificate Authority Injection
   288  windows/manage/inject_host                                          normal     No     Windows Manage Hosts File Injection
   289  windows/manage/killav                                               normal     No     Windows Post Kill Antivirus and Hips
   290  windows/manage/migrate                                              normal     No     Windows Manage Process Migration
   291  windows/manage/mssql_local_auth_bypass                              normal     No     Windows Manage Local Microsoft SQL Server Authorization Bypass
   292  windows/manage/multi_meterpreter_inject                             normal     No     Windows Manage Inject in Memory Multiple Payloads
   293  windows/manage/nbd_server                                           normal     No     Windows Manage Local NBD Server for Remote Disks
   294  windows/manage/payload_inject                                       normal     No     Windows Manage Memory Payload Injection Module
   295  windows/manage/peinjector                                           normal     No     Peinjector
   296  windows/manage/persistence_exe                                      normal     No     Windows Manage Persistent EXE Payload Installer
   297  windows/manage/portproxy                                            normal     No     Windows Manage Set Port Forwarding With PortProxy
   298  windows/manage/powershell/build_net_code           2012-08-14       excellent  No     Powershell .NET Compiler
   299  windows/manage/powershell/exec_powershell                           normal     No     Windows Manage PowerShell Download and/or Execute
   300  windows/manage/powershell/load_script                               normal     No     Load Scripts Into PowerShell Session
   301  windows/manage/pptp_tunnel                                          normal     No     Windows Manage Remote Point-to-Point Tunneling Protocol
   302  windows/manage/priv_migrate                                         normal     No     Windows Manage Privilege Based Process Migration 
   303  windows/manage/pxeexploit                                           normal     No     Windows Manage PXE Exploit Server
   304  windows/manage/reflective_dll_inject                                normal     No     Windows Manage Reflective DLL Injection Module
   305  windows/manage/remove_ca                                            normal     No     Windows Manage Certificate Authority Removal
   306  windows/manage/remove_host                                          normal     No     Windows Manage Host File Entry Removal
   307  windows/manage/rid_hijack                                           normal     No     Windows Manage RID Hijacking
   308  windows/manage/rollback_defender_signatures                         normal     No     Disable Windows Defender Signatures
   309  windows/manage/rpcapd_start                                         normal     No     Windows Manage Remote Packet Capture Service Starter
   310  windows/manage/run_as                                               normal     No     Windows Manage Run Command As User
   311  windows/manage/run_as_psh                                           normal     No     Windows 'Run As' Using Powershell
   312  windows/manage/sdel                                                 normal     No     Windows Manage Safe Delete
   313  windows/manage/sticky_keys                                          normal     No     Sticky Keys Persistance Module
   314  windows/manage/vmdk_mount                                           normal     No     Windows Manage VMDK Mount Drive
   315  windows/manage/vss_create                                           normal     No     Windows Manage Create Shadow Copy
   316  windows/manage/vss_list                                             normal     No     Windows Manage List Shadow Copies
   317  windows/manage/vss_mount                                            normal     No     Windows Manage Mount Shadow Copy
   318  windows/manage/vss_set_storage                                      normal     No     Windows Manage Set Shadow Copy Storage Space
   319  windows/manage/vss_storage                                          normal     No     Windows Manage Get Shadow Copy Storage Info
   320  windows/manage/wdigest_caching                                      normal     No     Windows Post Manage WDigest Credential Caching
   321  windows/manage/webcam                                               normal     No     Windows Manage Webcam
   322  windows/recon/computer_browser_discovery                            normal     No     Windows Recon Computer Browser Discovery
   323  windows/recon/outbound_ports                                        normal     No     Windows Outbound-Filtering Rules
   324  windows/recon/resolve_ip                                            normal     No     Windows Recon Resolve IP
   325  windows/wlan/wlan_bss_list                                          normal     No     Windows Gather Wireless BSS Info
   326  windows/wlan/wlan_current_connection                                normal     No     Windows Gather Wireless Current Connection Info
   327  windows/wlan/wlan_disconnect                                        normal     No     Windows Disconnect Wireless Connection
   328  windows/wlan/wlan_probe_request                                     normal     No     Windows Send Probe Request Packets
   329  windows/wlan/wlan_profile                                           normal     No     Windows Gather Wireless Profile
"""
    msfpluguins="""
[*] Available Framework plugins:
    * token_adduser
    * wiki
    * ffautoregen
    * nessus
    * lab
    * request
    * event_tester
    * msfd
    * sounds
    * rssfeed
    * pcap_log
    * token_hunter
    * nexpose
    * libnotify
    * socket_logger
    * openvas
    * db_credcollect
    * sample
    * ips_filter
    * session_tagger
    * db_tracker
    * session_notifier
    * thread
    * alias
    * msgrpc
    * sqlmap
    * aggregator
    * auto_add_route
    * wmap
    * beholder
    * komand
"""
    time.sleep(1)
    random.shuffle(banners)
    msfcomando = input("msf5 > ")
    msfcomando = msfcomando.upper()
    msfcomando = msfcomando.split()
    if msfcomando[0] in msflista:
      gga ="EXIT"
    elif msfcomando[0] == "BANNER":
      os.system('cls')
      random.shuffle(banners)
      print(banners[0])
    elif msfcomando[0] == "HELP":
      print('hello')
    elif msfcomando[0] =="SHOW":
      if msfcomando[1] =="ALL":
        print(msfencoder)
        print(msfnopgen)
        print(msfexploits)
        print(msfpayloads)
        print(msfauxiliary)
        print(msfpost)
        print(msfpluguins)
      elif msfcomando[1] =="EXPLOITS":
        print(msfexploits)
      elif msfcomando[1] =="PAYLOADS":
        print(msfpayloads)
      elif msfcomando[1] =="AUXILIARY":
        print(msfauxiliary)
      elif msfcomando[1] =="ACTIONS":
        print('a')
      elif msfcomando[1] =="ENCODERS":
        print(msfencoder)
      elif msfcomando[1] =="NOPS":
        print(msfnopgen)
      elif msfcomando[1] =="POST":
        print(msfpost)
      elif msfcomando[1] =="PLUGINS":
        print(msfpluguins)
      elif msfcomando[1] =="INFO":
        print('a')
      elif msfcomando[1] =="OPTIONS":
        print('a')
    elif msfcomando[0] =="USE":
      print('use')
    else:
      print('elsee')
"""
Tabla 1. Comandos de metasploit'
Help  Muestra una lista de los comandos disponibles
Show[options, exploits, payloads...]  Muestra una lista del argumento seleccionado, p. e. los exploits disponibles con show exploits
use <exploit> Seleccionamos un exploit a usar
Show options  Muestra los argumentos del exploit seleccionado
set <parámetro> <exploit> Configura los parámetros del exploit
exploit Lanza el exploit ya configurado
"""
