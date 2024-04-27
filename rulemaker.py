import os
import time

print("[+] Welcome to the Booger Goblin. A rule generator for Snort")
print("The best Snort Booger \(Rule\) Flicker.")
time.sleep(2)
rulenumber = 1000000 # Snort wants you to place custom rules after this number.
if os.path.exists("rules.txt"):
    print("[+] Rules.txt Already found switching to append mode") 
else:
    rulefile = open("rules.txt", "x")
    rulefile.close()
    print("[-] Rules file not found building that funky file")

ipruleout = "alert ip any any <> {} any (msg:\"Bad Boy IP Detected\"; sid: {};)\n"
iprulein = "alert ip {} any <> any any (msg:\"Bad Boy IP Detected\"; sid: {};)\n"
# Below block handles the IP part of the script.
iprulenumber = 0 
iprulenumbertxt = "[#] I made {} Rules for IPs\n"
if os.path.exists("ips.txt"):
    print("[+] IP file found starting IP Rules Generation :) ")
    ipfile = open("ips.txt", "r")
    for iter in ipfile:
        iter = iter.strip("\n")
        ruleout = ipruleout.format(iter, rulenumber)
        rulenumber += 1
        iprulenumber += 1

        rulein = iprulein.format(iter, rulenumber)
        rulenumber += 1
        iprulenumber += 1

        with open("rules.txt", "a") as file:
            file.write(ruleout) # This is for Destination Traffic
            file.write(rulein) # This is for Source Traffic 
    else:
        print("[+] Finished with IP lists moving on to Domains")
        print(iprulenumbertxt.format(iprulenumber))
        time.sleep(2)
else:
    print("[-] IP's not found so bypassing this section and moving on to domains :( ")

# Below is the logic for Domain parsing

websiterule = "alert tcp any any -> any any (msg:\"Known Bad Domain\";{} sid: {};)\n"
domainruletcp = "alert tcp any any -> any any (msg:\"Known Bad Domain\";{} sid: {};)\n"
domainruleudp = "alert udp any any -> any any (msg:\"Known Bad Domain\";{} sid: {};)\n"
content = " content:\"{}\";"
conhost = " http_uri:host; content:\"{}\",fast_pattern,nocase;"
domainrulenumber = 0
websiterulenumber = 0
domainrulenumbertxt = "[#] I made {} rules for Domains\n" 
if os.path.exists("domains.txt"):
    print("[+] Domains file found beginning. :) ")
    domainfile = open("domains.txt","r")
    for iter in domainfile:
        iter = iter.strip("\n")
        iterblock = ""
        webiter = ""
        conhost = conhost.format(iter)
        webrule = websiterule.format(conhost, rulenumber)
        iter = iter.split(".")
        rulenumber += 1
        domainrulenumber += 1
        for i in iter:
            if i == "":
                continue
            else:
                iterblock = iterblock + content.format(i)
        

        ruletcp = domainruletcp.format(iterblock, rulenumber)
        rulenumber += 1
        domainrulenumber += 1
        ruleudp = domainruleudp.format(iterblock, rulenumber)
        rulenumber += 1
        domainrulenumber += 1

        with open("rules.txt", "a") as file:
            file.write(ruletcp) # This is the TCP Rules being written.
            file.write(ruleudp) # This is the UDP Rules being written.
            file.write(webrule) # This is the website Rule being written.

    else:
        print("[+] Domains is finished! :)")
        print(domainrulenumbertxt.format(domainrulenumber))
        time.sleep(2)
else:
    print("[-] Domains File not found :( ")

