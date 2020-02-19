import os
from colorama import Fore,Back,Style
def extract_features(source, destination, victimIP):
	serverIP=list(set(source))
	if victimIP in serverIP:
		serverIP.remove(victimIP)
	AttackServers=[]
	for IP in serverIP:
		ratio=float(destination.count(IP))/source.count(IP)
		if ratio<=0.4:
			AttackServers.append(IP)
	print("[+]"+ Fore.RED+ Back.GREEN+" Attack Servers are ",AttackServers,Style.RESET_ALL) 

def main():
	t=10
	victimIP="10.0.2.9"
	while(1):		
		command1= "timeout "+ str(t)+" tcpdump -W 1 -w capture.pcap -i eth0 port 53 && host 08:00:27:d7:72:99"
		os.system(command1)
		os.system("tshark -r capture.pcap -T fields -e ip.src -e ip.dst > ip.txt")
		file1 = open('ip.txt', 'r') 
		Lines = file1.readlines() 
		source=[]
		destination=[]
		print("Total Packets ",len(Lines))
		if (len(Lines)<10):
			if t<10:
				t+=1
			print("No Attack.", "Time cycle for packet capture",t,"seconds")
			continue
		for line in Lines: 
			temp=line.split("\t")
			source.append(temp[0].strip())
			destination.append(temp[1].strip())

		requests=source.count(victimIP)
		responses=destination.count(victimIP)
		if responses==0:
			if t<10:
				t+=1
			print("No Attack.", "Time cycle for packet capture",t,"seconds")
			continue			
		OverallRatio=float(requests)/responses
		if (OverallRatio < 0.4):
			print("Tol Requests :", requests," Total Responses ", responses)
			print("Overall Ratio of requests to responses: ",OverallRatio)
			extract_features(source, destination,victimIP)
			t=3
		else:
			if t<10:
				t+=1
			print("No Attack", "time cycle for packet capture",t,"seconds")
			continue

main()

