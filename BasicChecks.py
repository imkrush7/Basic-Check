import requests
import argparse
import re


if __name__ == "__main__":

	try:
		parser = argparse.ArgumentParser()
		parser.add_argument('--u', help='Add valid URL')
		args = parser.parse_args()
		url = args.u

		if url[-1] != '/':

			url += '/'


		if (url is not None):
			option = requests.options(url, allow_redirects=False)
			req = requests.get(url, allow_redirects=False)
			
			
			forOption = option.headers.get('allow') 
			forHSTS = req.headers.get('Strict-Transport-Security')
			forServerBanner = req.headers.get('Server')
			forAppBanner = req.headers.get('X-Powered-By')
			forCache = req.headers.get('Cache-Control')
			forCookie = req.headers.get('Set-Cookie')

			user_agent1 = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0'}
			Clickjacking1 = requests.get(url, headers = user_agent1)	
			forClickjacking1 = Clickjacking1.headers.get('X-Frame-Options')
			
			user_agent2 = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36'}
			Clickjacking2 = requests.get(url, headers = user_agent2)	
			forClickjacking2 = Clickjacking1.headers.get('X-Frame-Options')



# Option
			print("+++++++++++++++++++++++\n\n")
			if forOption is not None:
				print(">> "+forOption)
				print("[+] Vulernable to OPTION Method\n")
			else:
			 	print("Not Vulernable to OPTION Method\n")
# HSTS		
			if forHSTS is not None:
				print("Not Vulernable to HSTS\n")
			else:
				print(">> \"Strict-Transport-Security\" header is not present")
				print("[+] Vulnerable to HSTS\n")
# server banner
			if forServerBanner is not None:
				check = re.findall(r"[\w']+", forServerBanner)
				flag = 0;
				for x in check:
					if x.isdigit():
						flag = flag + 1
				if flag > 0:
					print(">> "+forServerBanner)
					print("[+] Vulernable to Server Banner\n")
				else:
					print(">> "+forServerBanner)
					print("Not Vulernable to Server Banner\n")
			else:
			 	print("Not Vulernable to Server Banner\n")


# app banner
			if forAppBanner is not None:
				print(">> "+forAppBanner)
				print("[+] Vulernable to Application Banner\n")
			else:
			 	print("Not Vulernable to Application Banner\n")
# clickjacking
			if forClickjacking1 is None:
				print(">> \"X-Frame-Options\" header is not present")
				print("[+] Vulernable to Clickjacking in Firefox\n")
			elif forClickjacking2 is None:
				print(">> \"X-Frame-Options\" header is not present")
				print("[+] Vulernable to Clickjacking in Chrome\n")
			else:
				print("Not Vulnerable to Clickjacking\n")


			
# HttpOnly & Secure			
			if forCookie is not None:
				cookie = forCookie.split("; ")
				c2 = "secure"
				c1 = "HttpOnly"
				flag2 = ""
				for x in cookie:
					if c1 == x:
						flag2 = flag2 + "h" 
				
				for x in cookie:
					if c2 == x:
						flag2 = flag2 + "s"

				if flag2 == "hs":
					print("Not Vulnerbale to HttpOnly & Secure flag\n")
				elif flag2 == "h":
					print(">> \"Secure\" header attribute is missing")
					print("[+] Vulnerbale to HttpOnly & Secure flag\n")	
				elif flag2 == "s":
					print(">> \"HttpOnly\" header attribute is missing")
					print("[+] Vulnerbale to HttpOnly & Secure flag\n")
				else:
					print(">> \"HttpOnly & secure\" header attribute is missing")
					print("[+] Vulnerbale to HttpOnly & Secure flag\n")
			else:
				print(">> \"Set-Cookie\" header is not present")
				print("Once Check Manualy\n")


# host Header
			request = requests.get(url, headers={'host': 'www.bing.com'})	
			
			#response = request.headers
			code = request.status_code
						
			if(code == 200):
				print("[+] Response Code: "+str(code))
				
				check = request.headers.get('Set-Cookie')
				list = re.findall(r"[\w']+", check)
				#print(list)
				searchFor1 = "domain"
				searchFor2 = "bing"
				
				flag = ""
				flag1 = searchFor1
				flag2 = searchFor2

				temp = 0
				for x in list:
					if temp == 0:
						if x == searchFor1:
							flag = flag + flag1 + " = "
							temp = temp + 1
					
					if temp == 1:
						if x == searchFor2:
							flag = flag + flag2 + ".com"	
							temp = temp + 1

				print(">>  "+flag)
				print("[+] Vulnrable to Host Header Injection\n\n")
			
			else:
				print(">> Response Code: "+str(code))
				print("Not vulnerable to Host Header Injection\n\n")


		else:

			print('Please provide valid URL !')

			print('For more help use -h option\n\n')	


	except requests.exceptions.MissingSchema:

		print('Please provide corrrect URL  (eg: http://example.com  or  https://example.com)\n')



	except requests.exceptions.ConnectionError:

		print("\n")


	except requests.exceptions.TooManyRedirects:
		print("\n")

	except KeyboardInterrupt:
		print("\nExit\n")
