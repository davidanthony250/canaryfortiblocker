#This program scans the opencanary log file for changes. When a change occurs, it graps the source IP in the log and creates a new address in the Fortigate. It then adds the address to the address group PYTHON_GROUP. If PYTHON_GROUP does not exist, the program will prompt the user to create it. However, in order for blocking to occur, the PYTHON_GROUP needs to be added to relevant block rules. I recommend running the program to create PYTHON_GROUP, and then adding the PYTHON_GROUP to the block rules manually. NOTE that PYTHON_GROUP will initally include a "throwaway" APIPA address, since groups cannot be empty in the Fortigate.

import getpass
import re
from pprint import pprint
from fortigate_api import FortigateAPI
import time
#import logging
#logging.getLogger().setLevel(logging.DEBUG)
current_time = time.time()

########################################################################################################
#Config values here:
check_duration = 60 #How often in seconds will the scanner check the canarylog for changes (default:60)
HOST = "###.###.###.###" #IP address to access Fortigate firewall
PORT = "###" #Management port for firewall
VDOM = "######" #VDOM to manage
########################################################################################################

#reads last line and establishes a baseline for last line
def read_last_line(file_path):
	with open(file_path, 'r') as f:
		last_line = ''
		for line in f:
			last_line = line
		return last_line
last_one_old = read_last_line("/var/tmp/opencanary.log")



while True:
	try:
		print("Please enter your Fortigate Username or q to quit")
		USERNAME = input()
		if USERNAME == "exit" or USERNAME == "q":
			exit()
		print("Please enter your password")
		PASSWORD = getpass.getpass()
		fgt = FortigateAPI(host=HOST, username=USERNAME, password=PASSWORD, port=PORT, vdom=VDOM)
		fgt.login()
		fgt.logout()
		break
	except ValueError:
		print("Invalid login credentials.")

while True:
	print("""Please enter a selection:
1. View blocked IPs.
2. Remove blocked IP.
3. Run auto-blocking program.
4. Quit""")
	selection = input()
	if selection == str("1"):
		fgt.login()
		address1 = 1
		while True: 
			#loops through all the "pythonadress" addresses
			addresses = str(fgt.address.get(uid="pythonaddress"+str(address1)))
			if addresses == "[]":
				print("Press any key to continue.")
				any_key = input()
				break 
				#ends the loop when it hits the last address
			addressname = re.search("pythonaddress(\S)?", addresses)
			addressip = re.search("\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?", addresses)
			print(str(address1)+") " + str(addressname.group()) + " " + str(addressip.group())) 
			#pprint(addresses) #rawdata
			address1 += 1
		print("")
		fgt.logout()
			
	elif selection == str("2"):
		fgt.login()
		address1 = 1
		address_ip_list = []
		address_name_list = []
		while True: 
			addresses = str(fgt.address.get(uid="pythonaddress"+str(address1)))
			if addresses == "[]":
				address1 -= 1
				break
			addressname = re.search("pythonaddress(\S)?", addresses)
			address_name_list.append(addressname.group())
			addressip = re.search("\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?", addresses)
			address_ip_list.append(addressip.group())
			print(str(address1) + ") " + str(addressname.group()) + " - " + str(addressip.group()))
			address1 += 1
		remove_ip=-2
		while True:
			print("\nWhich address would you like to remove? Type 0 for none.")
			while True: #Input validation to make sure it's a integer.
				try:
					remove_ip = int(input())
				except ValueError:
					print("You must enter a number.")
					continue
				else:
					break
			remove_ip -= 1 #because python lists begin at 0 rather than 1
			if remove_ip <-1 or remove_ip >= address1: #input validation to make sure selection is in range.
				print("Invalid selection.")
			else:
				break
		if remove_ip == -1: 
			print("\n") 
		else:
#clears PYTHON_GROUP, neccessary in order to delete pythonaddresses
			data = {"name": "tttemporaryaddress",
				"obj-type": "ip",
				"subnet": "169.254.0.5 255.255.255.255",
				"type": "ipmask"}
			response = fgt.address.create(data=data)
#			print("Created temporary address to add to PYTHON_GROUP " + str(response))
			data = {"name": "PYTHON_GROUP", "member": [{"name": "tttemporaryaddress"}]}
			response = fgt.address_group.update(data=data)
#			print("Added temporary address to PYTHON_GROUP, clearing other addresses " + str(response))	
			#delete all addresses in PYTHON_GROUP on fortigate, necessary so that they can be readded without conflicts
			for name in address_name_list:
				response = fgt.address.delete(filter="name=@"+str(name))
#				print("Cleared address " + str(name) + " " + str(response))
			#creates all addresses to be added to PYTHON_GROUP, including new address, necessary because single address cannot be added to group, all need to be readded each time
			address_ip_list.pop(remove_ip)
			address2 = 1
			data_member = []
			for address in address_ip_list:
				data = {"name": "pythonaddress" + str(address2),
					"obj-type": "ip",
					"subnet": str(address) + " 255.255.255.255",
					"type": "ipmask"}
				response = fgt.address.create(data=data)
				data_member.append({"name": "pythonaddress"+str(address2)})
#				print("Rebuilding blocklist! Address " + str(address2)  + str(response))
				address2 += 1	
			#write address_ip_list to PYTHON_GROUP to block it
			data_group = {"name": "PYTHON_GROUP", "member": ""}
			data_group["member"] = data_member
			response = fgt.address_group.update(data=data_group)
#			print("Blocklist rebuilt! PYTHON_GROUP rebuilt ", response)
			response = fgt.address.delete(uid="tttemporaryaddress")
#			print("Temporary address deleted! ", response)		
			print("\nAddress " + str(remove_ip + 1) + " removed successfully")
			print("Hit any key to continue.")
			any_key = input()
		fgt.logout()
		
	elif selection == str("3"):
		fgt.login()
		response = fgt.address_group.is_exist(uid="PYTHON_GROUP")
		if response == False:
			while True:
				print("\nPYTHON_GROUP does not exist in firewall. We can create PYTHON_GROUP for you now, but you must add PYTHON_GROUP to your firewall blocking policies for this scanner to be effective.")
				print("\nIf you continue, address \"tttemporaryaddress\" with ip 169.254.0.5 255.255.255.255 will be created as a placeholder for now, since Fortigate does not allow empty groups.\n\n Continue with creation?. Y/N \n")
				any_key = input()
				if any_key == "N" or any_key == "n":
					fgt.logout()
					print("Quitting!")
					raise SystemExit
				elif any_key == "Y" or any_key == "y":
					data = {"name": "tttemporaryaddress",
						"obj-type": "ip",
						"subnet": "169.254.0.5 255.255.255.255",
						"type": "ipmask"}
					response = fgt.address.create(data=data)
					print("Created temporary address to add to PYTHON_GROUP " + str(response))
					data = {"name": "PYTHON_GROUP", "member": [{"name": "tttemporaryaddress"}]}
					response = fgt.address_group.create(data=data)
					print("Added temporary address to PYTHON_GROUP." + str(response))
					break	
		fgt.logout()
		timer_s=0
		timer_m=0
		timer_h=0
		timer_d=0
		#print(address_ip_list) just testing this
		#reads the last line of logfile
		print("Scanner running! Checking every " + str(check_duration) +" seconds.")
		while True:
			try:
				last_one = read_last_line("/var/tmp/opencanary.log")
				if last_one_old == last_one:
					print("\rCurrent runtime " + str(timer_d) + "d " + str(timer_h) + "h " + str(timer_m) + "m " + str(timer_s) + "s Press ctrl+c to stop." , end="")
				else:
					#check to see if last line source IP is in address_ip_list, if not, add last line IP to address_ip_list
					log_ip_with_text_raw = re.search("\"src_host\":\s\"\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?", last_one)
					if log_ip_with_text_raw == None:
						print("New data in logfile! No source IP given, autoblocking impossible.") #handles error if there is no src_host IP in log
					else:
						#pulls the source host ip from the log file, includes "src_host:" tag.
						log_ip_with_text = log_ip_with_text_raw.group()
						# removes "src_host:" tag.
						log_ip_raw = re.search("\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?", log_ip_with_text)
						# removes src_host from varible, leaving bare ip
						log_ip = log_ip_raw.group()
						fgt.login()
						#get list of blocked IPs and assign it to a list - address_ip_list
						address1 = 1
						address_ip_list = []
						address_name_list = []
						while True: 
							#loops through all the "pythonaddress" addresses
							addresses = str(fgt.address.get(uid="pythonaddress"+str(address1)))
							if addresses == "[]":
								break
							addressname = re.search("pythonaddress(\S)?", addresses)
							address_name_list.append(addressname.group())
							addressip = re.search("\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?", addresses)
							address_ip_list.append(addressip.group())
							address1 += 1
						if log_ip in address_ip_list:
							print("IP detected, but already in ban list. Be sure to add PYTHON_GROUP to firewall ban rules!")
							break
						else:
							#clears PYTHON_GROUP, neccessary in order to delete pythonaddresses
							data = {"name": "tttemporaryaddress",
								"obj-type": "ip",
								"subnet": "169.254.0.5 255.255.255.255",
								"type": "ipmask"}
							response = fgt.address.create(data=data)
#							print("Created temporary address to add to PYTHON_GROUP " + str(response))
							data = {"name": "PYTHON_GROUP", "member": [{"name": "tttemporaryaddress"}]}
							response = fgt.address_group.update(data=data)
#							print("Added temporary address to PYTHON_GROUP, clearing other addresses " + str(response))	
							#delete all addresses in PYTHON_GROUP on fortigate, necessary so that they can be readded without conflicts
							for name in address_name_list:
								response = fgt.address.delete(filter="name=@"+str(name))
#								print("Cleared address " + str(name) + " " + str(response))
							#creates all addresses to be added to PYTHON_GROUP, including new address, necessary because single address cannot be added to group, all need to be readded each time
							address_ip_list.append(log_ip)
							address2 = 1
							data_member = []
							for address in address_ip_list:
								data = {"name": "pythonaddress" + str(address2),
								"obj-type": "ip",
								"subnet": str(address) + " 255.255.255.255",
								"type": "ipmask"}
								response = fgt.address.create(data=data)
								data_member.append({"name": "pythonaddress"+str(address2)})
#								print("Rebuilding blocklist! Address " + str(address2)  + str(response))
								address2 += 1	
							#write address_ip_list to PYTHON_GROUP to block it
							data_group = {"name": "PYTHON_GROUP", "member": ""}
							data_group["member"] = data_member
							response = fgt.address_group.update(data=data_group)
#							print("Blocklist rebuilt! PYTHON_GROUP rebuilt ", response)
							response = fgt.address.delete(uid="tttemporaryaddress")
#							print("Temporary address deleted! ", response)
							last_one_old = read_last_line("/var/tmp/opencanary.log")
							print("\nNew IP blocked - " + str(log_ip) + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
						fgt.logout
				time.sleep(check_duration)
						timer_s += check_duration
				if timer_s == 60:
					timer_m += 1
					timer_s = 0
				if timer_m == 60:
					timer_h += 1
					timer_m = 0
				if timer_h == 24:
					timer_d += 1
					timer_h =0
			except KeyboardInterrupt:
				break																	
			
			
	elif selection == str("4"):
		fgt.logout()
		exit()
	else:
		print("Invalid selection.")
	
##None of the below does anything right now, since the above loops will not break
print("\nCreates address and address-group in the Fortigate")
data = {"name": "pythonaddress1",
        "obj-type": "ip",
        "subnet": "190.2.142.25 255.255.255.255",
        "type": "ipmask"}
response = fgt.address.create(data=data)
print("address.create", response)  # address.create <Response [200]>

data = {"name": "PYTHON_GROUP", "member": [{"name": "pythonaddress1"}, {"name": "pythonaddress3"}, {"name": "pythonaddress2"}]}
response = fgt.address_group.update(data=data)
print("address_group.update", response)  # address_group.create <Response [200]>


fgt.logout()
