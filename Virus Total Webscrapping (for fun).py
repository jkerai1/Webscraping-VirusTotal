import webbrowser
import re #Regex
import sys
import requests
from bs4 import BeautifulSoup
import pyclip

regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def CheckIP(Ip): 
    
    if(re.search(regex, Ip)):
        pass ##no need to do anything if IP is valid
    else:
        sys.exit() ##This is a cop-out but oh well
    
IP =(input("IP address? "))
##sanitize
IP = IP.replace("-", "")
IP = IP.replace(" ","")
CheckIP(IP)
    
page = requests.get("https://www.virustotal.com/gui/ip-address/" + IP + "/detection")
soup = BeautifulSoup(page.text, 'html.parser')
label = soup.find("script")
res = re.findall("wasClean...",str(label))
res =str(res).replace('\']',"").split(":")

if res[1].lower() == "f":
    VirusTotalOutcome = "Neutral"
else:
    VirusTotalOutcome = "Malicious" 

    
def GenerateTemplate():
    string1 = ("Source: " + IP + "\n")
    string2 = ("Rating On Virus Total: " + VirusTotalOutcome + "\n")
    string3 = ("VirusTotal Link" + "https://www.virustotal.com/gui/ip-address/" + IP + "/detection" + "\n") 
    string4 = ("Who Is " + "https://who.is/whois-ip/ip-address/" + IP + "\n")
    string5 = ("OTX" + "https://otx.alienvault.com/indicator/ip/" + ele + "\n")
    
    if VirusTotalOutcome == "Malicious":
        string6 = ("Blacklisting is Advised"+ "\n")
        FinalString = string1 + string2 + string3 + string4 + string5 + string6
        
    else: 
        FinalString = string1 + string2 + string3 + string4 + string5
    print(FinalString)
    pyclip.copy(FinalString)
    
print("\n\n")
GenerateTemplate()
