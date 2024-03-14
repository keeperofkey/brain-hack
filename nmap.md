# OS and Services

## nmap -A -T4 172.18.0.3

Nmap scan report for metasploitable2.pentest (172.18.0.3)
Host is up (0.00014s latency).
Not shown: 980 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
21/tcp   open     ftp         vsftpd 2.3.4
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 172.18.0.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open     ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp   open     telnet      Linux telnetd
25/tcp   open     smtp        Postfix smtpd
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
|\_ssl-date: 2024-03-14T16:03:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|\_Not valid after:  2010-04-16T14:07:45
|\_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp   open     http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
|_http-title: Metasploitable2 - Linux
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open     netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
512/tcp  open     exec?
513/tcp  open     login
514/tcp  open     tcpwrapped
1099/tcp open     java-rmi    GNU Classpath grmiregistry
1524/tcp open     ingreslock?
| fingerprint-strings:
|   GenericLines:
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|   GetRequest:
|     \]0;@victim: /
|     root@victim:/# GET / HTTP/1.0
|     <HTML>
|     <HEAD>
|     <TITLE>Directory /</TITLE>
|     <BASE HREF="file:/">
|     </HEAD>
|     <BODY>
|     <H1>Directory listing of /</H1>
|     <UL>
|     <LI><A HREF="./">./</A>
|     <LI><A HREF="../">../</A>
|     <LI><A HREF=".dockerenv">.dockerenv</A>
|     <LI><A HREF="bin/">bin/</A>
|     <LI><A HREF="boot/">boot/</A>
|     <LI><A HREF="cdrom/">cdrom/</A>
|     <LI><A HREF="core">core</A>
|     <LI><A HREF="dev/">dev/</A>
|     <LI><A HREF="etc/">etc/</A>
|     <LI><A HREF="home/">home/</A>
|     <LI><A HREF="initrd/">initrd/</A>
|     <LI><A HREF="initrd.img">initrd.img</A>
|     <LI><A HREF="lib/">lib/</A>
|     <LI><A HREF="lost%2Bfound/">lost+found/</A>
|     <LI><A HREF="media/">media/</A>
|     <LI><A HREF="mnt/">mnt/</A>
|     <LI><A HREF="nohup.out">nohup.out</A>
|     <LI><A HREF="opt/">opt/</A>
|     <LI><A HREF="proc/">proc/</A>
|     <LI><A HREF="root/">root/</A>
|     <LI><A HREF="sbin/">sbin/</A>
|     <LI><A HREF="srv/">srv/</A>
|     <LI><A HREF="sys/">sys/</A>
|     <LI><A HREF="tmp/">tmp/</A>
|   HTTPOptions:
|     \]0;@victim: /
|     root@victim:/# OPTIONS / HTTP/1.0
|     bash: OPTIONS: command not found
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|   NULL:
|     \]0;@victim: /
|     root@victim:/#
|   RTSPRequest:
|     \]0;@victim: /
|     root@victim:/# OPTIONS / RTSP/1.0
|     bash: OPTIONS: command not found
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|     root@victim:/#
|     \]0;@victim: /
|_    root@victim:/#
2121/tcp open     ftp         ProFTPD 1.3.1
3306/tcp open     mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info:
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 110
|   Capabilities flags: 43564
|   Some Capabilities: LongColumnFlag, Support41Auth, SupportsTransactions, SwitchToSSLAfterHandshake, Speaks41ProtocolNew, ConnectWithDatabase, SupportsCompression
|   Status: Autocommit
|_  Salt: kkXT!AeYn@3}@cTX@tKW
5432/tcp open     postgresql  PostgreSQL DB 8.3.0 - 8.3.7
|\_ssl-date: 2024-03-14T16:03:45+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2010-03-17T14:07:45
|_Not valid after:  2010-04-16T14:07:45
5900/tcp open     vnc         VNC (protocol 3.3)
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    VNC Authentication (2)
6000/tcp open     X11         (access denied)
6667/tcp filtered irc
8009/tcp open     ajp13       Apache Jserv (Protocol v1.3)
|\_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp open     http        Apache Tomcat/Coyote JSP engine 1.1
|\_http-favicon: Apache Tomcat
|\_http-server-header: Apache-Coyote/1.1
|\_http-title: Apache Tomcat/5.5
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1524-TCP:V=7.94SVN%I=7%D=3/14%Time=65F31F3C%P=x86_64-pc-linux-gnu%r
SF:(NULL,1E,"\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20")%r(GenericLines,
SF:9A,"\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\
SF:x07root@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20\\n\\x1
SF:b\]0;@victim:\\x20/\\x07root@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\\x07root
SF:@victim:/#\\x20")%r(GetRequest,4CB,"\\x1b\]0;@victim:\\x20/\\x07root@victim
SF::/#\\x20GET\\x20/\\x20HTTP/1.0\\n<HTML>\\n<HEAD>\\n<TITLE>Directory\\x20/\</TI
SF:TLE>\\n\<BASE\\x20HREF="file:/">\\n</HEAD>\\n<BODY>\\n<H1>Directory\\x20list
SF:ing\\x20of\\x20/</H1>\\n<UL>\\n<LI>\<A\\x20HREF="./">./</A>\\n<LI>\<A\\x20HR
SF:EF="../">../</A>\\n<LI>\<A\\x20HREF=".dockerenv">.dockerenv</A>\
SF:n<LI>\<A\\x20HREF="bin/">bin/</A>\\n<LI>\<A\\x20HREF="boot/">boot/</A>\\n
SF:<LI>\<A\\x20HREF="cdrom/">cdrom/</A>\\n<LI>\<A\\x20HREF="core">core</A>\
SF:n<LI>\<A\\x20HREF="dev/">dev/</A>\\n<LI>\<A\\x20HREF="etc/">etc/</A>\\n<L
SF:I>\<A\\x20HREF="home/">home/</A>\\n<LI>\<A\\x20HREF="initrd/">initrd/\</A
SF:>\\n<LI>\<A\\x20HREF="initrd.img">initrd.img</A>\\n<LI>\<A\\x20HREF="lib
SF:/">lib/</A>\\n<LI>\<A\\x20HREF="lost%2Bfound/">lost+found/</A>\\n<LI>\<A
SF:\\x20HREF="media/">media/</A>\\n<LI>\<A\\x20HREF="mnt/">mnt/</A>\\n<LI>\<
SF:A\\x20HREF="nohup.out">nohup.out</A>\\n<LI>\<A\\x20HREF="opt/">opt/\</
SF:A>\\n<LI>\<A\\x20HREF="proc/">proc/</A>\\n<LI>\<A\\x20HREF="root/">root/\<
SF:/A>\\n<LI>\<A\\x20HREF="sbin/">sbin/</A>\\n<LI>\<A\\x20HREF="srv/">srv/\</
SF:A>\\n<LI>\<A\\x20HREF="sys/">sys/</A>\\n<LI>\<A\\x20HREF="tmp/">tmp/</A>\
SF:n\<")%r(HTTPOptions,CD,"\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20OPTIO
SF:NS\\x20/\\x20HTTP/1.0\\nbash:\\x20OPTIONS:\\x20command\\x20not\\x20found\\n\\x1
SF:b\]0;@victim:\\x20/\\x07root@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\\x07root
SF:@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20\\n\\x1b\]0;@v
SF:ictim:\\x20/\\x07root@victim:/#\\x20")%r(RTSPRequest,CD,"\\x1b\]0;@victim:\
SF:x20/\\x07root@victim:/#\\x20OPTIONS\\x20/\\x20RTSP/1.0\\nbash:\\x20OPTIONS:\
SF:x20command\\x20not\\x20found\\n\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20
SF:\\n\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\\x0
SF:7root@victim:/#\\x20\\n\\x1b\]0;@victim:\\x20/\\x07root@victim:/#\\x20");
MAC Address: 02:42:AC:12:00:03 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=3/14%OT=21%CT=1%CU=32122%PV=Y%DS=1%DC=D%G=Y%M=0242A
OS:C%TM=65F31FE1%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%I
OS:I=I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW
OS:7%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7C70%W2=7C70%W3=7C70%W4=7C70%W5=7C70
OS:%W6=7C70)ECN(R=Y%DF=Y%T=40%W=7D78%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%
OS:S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%
OS:RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W
OS:=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: Host:  metasploitable.localdomain; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: victim
|   NetBIOS computer name:
|   Domain name:
|   FQDN: victim
|_  System time: 2024-03-14T12:03:37-04:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|\_  message_signing: disabled (dangerous, but default)
|\_nbstat: NetBIOS name: VICTIM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|\_clock-skew: mean: 1h00m00s, deviation: 2h00m00s, median: 0s

TRACEROUTE
HOP RTT     ADDRESS
1   0.14 ms metasploitable2.pentest (172.18.0.3)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# CVSS Scan

## nmap -Pn --script 172.18.0.3

Not shown: 980 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
| ftp-vsftpd-backdoor:
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2011-2523  BID:48539
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
|     References:
|       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
|       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|\_      https://www.securityfocus.com/bid/48539
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
| ssl-poodle:
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|\_      https://www.securityfocus.com/bid/70574
|_sslv2-drown: ERROR: Script execution failed (use -d to debug)
| ssl-dh-params:
|   VULNERABLE:
|   Anonymous Diffie-Hellman Key Exchange MitM Vulnerability
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use anonymous
|       Diffie-Hellman key exchange only provide protection against passive
|       eavesdropping, and are vulnerable to active man-in-the-middle attacks
|       which could completely compromise the confidentiality and integrity
|       of any data exchanged over the resulting session.
|     Check results:
|       ANONYMOUS DH GROUP 1
|             Cipher Suite: TLS_DH_anon_WITH_DES_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: postfix builtin
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|       https://www.ietf.org/rfc/rfc2246.txt
|
|   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-4000  BID:74733
|       The Transport Layer Security (TLS) protocol contains a flaw that is
|       triggered when handling Diffie-Hellman key exchanges defined with
|       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
|       to downgrade the security of a TLS session to 512-bit export-grade
|       cryptography, which is significantly weaker, allowing the attacker
|       to more easily break the encryption and monitor or tamper with
|       the encrypted stream.
|     Disclosure date: 2015-5-19
|     Check results:
|       EXPORT-GRADE DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 512
|             Generator Length: 8
|             Public Key Length: 512
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
|       https://weakdh.org
|       https://www.securityfocus.com/bid/74733
|
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: postfix builtin
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| smtp-vuln-cve2010-4344:
|\_  The SMTP server is not Exim: NOT VULNERABLE
80/tcp   open  http
| http-sql-injection:
|   Possible sqli for queries:
|     http://metasploitable2.pentest:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=text-file-viewer.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=credits.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=login.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=view-someones-blog.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=captured-data.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=notes.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=credits.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=home.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=documentation%2Fvulnerabilities.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=show-log.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=home.php&do=toggle-hints%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=documentation%2Fhow-to-access-Mutillidae-over-Virtual-Box-network.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=browser-info.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=user-poll.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=php-errors.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=usage-instructions.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=installation.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=add-to-your-blog.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=secret-administrative-pages.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=html5-storage.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=change-log.htm%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=framing.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=site-footer-xss-discussion.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=source-viewer.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=show-log.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=add-to-your-blog.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=view-someones-blog.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=arbitrary-file-inclusion.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=source-viewer.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=login.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?username=anonymous&page=password-generator.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=set-background-color.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=user-info.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=dns-lookup.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=home.php&do=toggle-security%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=pen-test-tool-lookup.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=capture-data.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/?page=text-file-viewer.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=register.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/mutillidae/index.php?page=user-info.php%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=S%3BO%3DD%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=D%3BO%3DD%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=M%3BO%3DD%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/dav/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/view/TWiki/TWikiHistory?rev=1.7%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.7%27%20OR%20sqlspider&rev1=1.8
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.7&rev1=1.8%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/view/TWiki/TWikiHistory?rev=1.8%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.9%27%20OR%20sqlspider&rev1=1.10
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.9&rev1=1.10%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/view/TWiki/TWikiHistory?rev=1.9%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/oops/TWiki/TWikiHistory?template=oopsrev%27%20OR%20sqlspider&param1=1.10
|     http://metasploitable2.pentest:80/oops/TWiki/TWikiHistory?template=oopsrev&param1=1.10%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.8%27%20OR%20sqlspider&rev1=1.9
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.8&rev1=1.9%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/view/TWiki/TWikiHistory?rev=1.7%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.8%27%20OR%20sqlspider&rev1=1.9
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.8&rev1=1.9%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/view/TWiki/TWikiHistory?rev=1.8%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.9%27%20OR%20sqlspider&rev1=1.10
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.9&rev1=1.10%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.7%27%20OR%20sqlspider&rev1=1.8
|     http://metasploitable2.pentest:80/rdiff/TWiki/TWikiHistory?rev2=1.7&rev1=1.8%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/view/TWiki/TWikiHistory?rev=1.9%27%20OR%20sqlspider
|     http://metasploitable2.pentest:80/oops/TWiki/TWikiHistory?template=oopsrev%27%20OR%20sqlspider&param1=1.10
|\_    http://metasploitable2.pentest:80/oops/TWiki/TWikiHistory?template=oopsrev&param1=1.10%27%20OR%20sqlspider
|_http-trace: TRACE is enabled
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-fileupload-exploiter:
|
|_    Couldn't find a file-type field.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=metasploitable2.pentest
|   Found the following possible CSRF vulnerabilities:
|
|     Path: http://metasploitable2.pentest:80/dvwa/
|     Form id:
|     Form action: login.php
|
|     Path: http://metasploitable2.pentest:80/twiki/TWikiDocumentation.html
|     Form id:
|     Form action: http://TWiki.org/cgi-bin/passwd/TWiki/WebHome
|
|     Path: http://metasploitable2.pentest:80/twiki/TWikiDocumentation.html
|     Form id:
|     Form action: http://TWiki.org/cgi-bin/passwd/Main/WebHome
|
|     Path: http://metasploitable2.pentest:80/twiki/TWikiDocumentation.html
|     Form id:
|     Form action: http://TWiki.org/cgi-bin/edit/TWiki/
|
|     Path: http://metasploitable2.pentest:80/twiki/TWikiDocumentation.html
|     Form id:
|     Form action: http://TWiki.org/cgi-bin/view/TWiki/TWikiSkins
|
|     Path: http://metasploitable2.pentest:80/twiki/TWikiDocumentation.html
|     Form id:
|     Form action: http://TWiki.org/cgi-bin/manage/TWiki/ManagingWebs
|
|     Path: http://metasploitable2.pentest:80/dvwa/login.php
|     Form id:
|_    Form action: login.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum:
|   /tikiwiki/: Tikiwiki
|   /test/: Test page
|   /phpinfo.php: Possible information file
|   /phpMyAdmin/: phpMyAdmin
|   /doc/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) dav/2'
|   /icons/: Potentially interesting folder w/ directory listing
|_  /index/: Potentially interesting folder
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
| rmi-vuln-classloader:
|   VULNERABLE:
|   RMI registry default configuration remote code execution vulnerability
|     State: VULNERABLE
|       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
|
|     References:
|\_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
1524/tcp open  ingreslock
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5432/tcp open  postgresql
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle:
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://www.securityfocus.com/bid/70574
| ssl-ccs-injection:
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.cvedetails.com/cve/2014-0224
|\_      http://www.openssl.org/news/secadv_20140605.txt
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
|_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again).
8009/tcp open  ajp13
8180/tcp open  unknown
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| http-enum:
|   /admin/: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /admin/login.html: Possible admin folder
|   /admin/admin.html: Possible admin folder
|   /admin/account.html: Possible admin folder
|   /admin/admin_login.html: Possible admin folder
|   /admin/home.html: Possible admin folder
|   /admin/admin-login.html: Possible admin folder
|   /admin/adminLogin.html: Possible admin folder
|   /admin/controlpanel.html: Possible admin folder
|   /admin/cp.html: Possible admin folder
|   /admin/index.jsp: Possible admin folder
|   /admin/login.jsp: Possible admin folder
|   /admin/admin.jsp: Possible admin folder
|   /admin/home.jsp: Possible admin folder
|   /admin/controlpanel.jsp: Possible admin folder
|   /admin/admin-login.jsp: Possible admin folder
|   /admin/cp.jsp: Possible admin folder
|   /admin/account.jsp: Possible admin folder
|   /admin/admin_login.jsp: Possible admin folder
|   /admin/adminLogin.jsp: Possible admin folder
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload
|   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload
|   /admin/jscript/upload.html: Lizard Cart/Remote File upload
|\_  /webdav/: Potentially interesting folder
MAC Address: 02:42:AC:12:00:03 (Unknown)

Host script results:
|\_smb-vuln-ms10-061: false
|\_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
|\_smb-vuln-ms10-054: false
