import requests
import argparse
import datetime
from pathlib import Path
import re

###
#    Cookie Checker
#    Usage: python3 cookie_check.py
###

GRAY = '\033[0;97m'
BLUE = '\033[94m'
CYAN = '\033[96m'
GREEN = '\033[92m'
WARNING = '\033[0;93m'
FAIL = '\033[0;91m'
END = '\033[0;0m'

# Display banner
def banner():
    print()
    print(f"{BLUE}========================================================{END}")
    print(f"{CYAN} > cookie_checker.py .................................. {END}")
    print(f"{BLUE}--------------------------------------------------------{END}")
    print(f"{CYAN} Simple tool to check for insecure cookies on a website {END}")
    print(f"{BLUE}========================================================{END}")
    print()
# Check if the input is a valid domain format
def is_valid_domain(input_url):
    domain_pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$"
    return re.match(domain_pattern, input_url)
# Check if the input is a valid URL format
def is_valid_url(input_url):
    url_pattern = r"^(?:http(s)?://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!$&'()*+,;=]+$"
    return re.match(url_pattern, input_url)
# Check url or targets
def check_url(url, disable_ssl_verification, output_file):
    # Disable ssl verification
    if disable_ssl_verification:
        requests.packages.urllib3.disable_warnings()
    if not url.startswith('http://') and not url.startswith('https://'):
        http_url = f"http://{url}"
        https_url = f"https://{url}"
        check_cookie(http_url, disable_ssl_verification, output_file)
        check_cookie(https_url, disable_ssl_verification, output_file)
    else:
        check_cookie(url, disable_ssl_verification, output_file)
    print(f"\n{GRAY}Done.{END}\n\n")
# Check cookies
def check_cookie(url, disable_ssl_verification, output_file):
    try:
        print(f"\n{GRAY}[*] Checking for cookies...{END}")
        response = requests.get(url, verify=not disable_ssl_verification)
        cookies = response.cookies
        with open(output_file, 'a+') as file:
            if cookies:
                print(f"\n{GRAY}[*] Cookies found in {url}:{END}")
                file.write(f"\nCookies found in {url}:\n")
                for cookie in cookies:
                    # Check if there is an expiration date  
                    if cookie.expires is not None:    
                        expires_datetime = datetime.datetime.fromtimestamp(cookie.expires)
                        # Convert cookie.expires to readable format
                        expires_str = expires_datetime.strftime("%I:%M:%S %p %m/%d/%Y")
                        # Get the current date
                        current_date = datetime.datetime.now().date()
                        # Get the date part of the expiration datetime
                        expiration_date_only = expires_datetime.date()
                        expiration_date_value = expires_str
                    else:
                        expiration_date_value = "None"
                    # Check if cookie.expires > today
                    # Check if cookie.expires > today
                    if cookie.expires is not None and expiration_date_only > current_date:
                        expire_msg = "Persistent cookie found."
                        expire_alert = f"{WARNING}[-] {expire_msg}{END}"
                    else:
                        expire_msg = "No persistent cookie found."
                        expire_alert = f"{GREEN}[+] {expire_msg}{END}"
                    # Check httponly attribute
                    if cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'):
                        httponly_value = "True"
                        httponly_msg = "HttpOnly attribute found."
                        httponly_alert = f"{GREEN}[+] {httponly_msg}{END}"
                    else:
                        httponly_value = "False"
                        httponly_msg = "Missing HttpOnly attribute."
                        httponly_alert = f"{WARNING}[-] {httponly_msg}{END}"

                    # Check samesite attribute
                    if cookie.has_nonstandard_attr('SameSite') or cookie.has_nonstandard_attr('samesite'):
                        samesite_value = cookie.get_nonstandard_attr('SameSite') or cookie.get_nonstandard_attr('samesite')
                        samesite_value = samesite_value if samesite_value is not None else "None"
                        samesite_msg = "SameSite attribute found."
                        samesite_alert = f"{GREEN}[+] {samesite_msg}{END}"
                    else:
                        samesite_value = "False"
                        samesite_msg = "Missing SameSite attribute."
                        samesite_alert = f"{WARNING}[-] {samesite_msg}{END}"
                    # Check secure attribute
                    if not cookie.secure:
                        secure_value = "False"
                        secure_msg =  "Missing Secure attribute."
                        secure_alert = f"{WARNING}[-] {secure_msg}{END}"
                    else:
                        secure_value = "True"
                        secure_msg = "Secure attribute found."
                        secure_alert = f"{GREEN}[+] {secure_msg}{END}"
                    # Print cookie info
                    print(f"{GRAY}")
                    print(f"Name         : " + cookie.name)
                    print(f"Value        : " + cookie.value)
                    print(f"Path         : " + cookie.path)
                    print(f"Domain       : " + cookie.domain)
                    print(f"Expires      : " + expiration_date_value + "  " + expire_alert)
                    print(f"Secure       : " + secure_value + "  " + secure_alert)
                    print(f"SameSite     : " + samesite_value + "  " + samesite_alert)
                    print(f"HttpOnly     : " + httponly_value + "  " + httponly_alert)
                    print(f"{END}")
                    # Write cookie info to file
                    file.write("\n")
                    file.write(f"Name         : {cookie.name}\n")
                    file.write(f"Value        : {cookie.value}\n")
                    file.write(f"Path         : {cookie.path}\n")
                    file.write(f"Domain       : {cookie.domain}\n")
                    file.write(f"Expires      : {expiration_date_value}  {expire_msg}\n")
                    file.write(f"Secure       : {secure_value}  {secure_msg}\n")
                    file.write(f"SameSite     : {samesite_value}  {samesite_msg}\n")
                    file.write(f"HttpOnly     : {httponly_value}  {httponly_msg}\n")
                    file.write("\n")           
                # Collect insecure cookies found         
                insecure_cookies = [ cookie for cookie in cookies if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly') or not cookie.has_nonstandard_attr('SameSite') and not cookie.has_nonstandard_attr('samesite') or cookie.expires is not None and expiration_date_only > current_date ] 
                if insecure_cookies or url.startswith('http://'):
                    # Print if insecure cookies found
                    if url.startswith('http://'):
                        print(f"\n{WARNING}[!] Target is under HTTP connection. It's highly recommended to ensure that cookies are transmitted over HTTPS connection.{END}")
                        file.write(f"\nTarget is under HTTP connection. It's highly recommended to ensure that cookies are transmitted over HTTPS connection.\n")
                    print(f"\n{WARNING}[!] There are insecure cookies found in {url}{WARNING}.{END}")
                    file.write(f"\nThere are insecure cookies found in {url}.\n")
                else:
                    # Print message if no insecure cookies found 
                    print(f"\n{GREEN}[*] No insecure cookies found in {url}{GREEN}.{END}")       
                    file.write(f"\nNo insecure cookies found in {url}.\n")         
            else:
                # Print message if no cookies found
                print(f"\n{GRAY}[*] No cookies found in {url}.{END}")
                file.write(f"\nNo cookies found in {url}.\n")
        file.close()
        # Print link for reference
        print(f"\n{GRAY}Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies{END}\n")
        print(f"\n{GRAY}[*] Results saved to {output_file}.{END}\n")
    except requests.exceptions.SSLError as e:
        print(f"\n{FAIL}[!] Error: SSL certificate verification failed. To ignore this error, disable SSL certificate verification.{END}")
        return
    except requests.exceptions.RequestException as e:
#       print(f"\nError: {e}")
        print(f"\n{FAIL}[!] Error: Can't reach {url}{FAIL}. Connection timed out.{END}")
        return
def cookie_checker():
    banner()
    parser = argparse.ArgumentParser(description="Check for insecure cookies on target website(s).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", dest="url_target", help="Target URL.")
    group.add_argument("-f", "--file", dest="file_target", help="File path containing list of targets.")
    parser.add_argument("-d", "--disable-ssl-verification", action="store_true", help="Disable SSL certificate verification.")
    parser.add_argument("-o", "--output", dest="output_file", help="Output file to save the results.")
    args = parser.parse_args()
    try:
        if not args.output_file:
            # Create a default output file  
            output_file = "cookies_output.txt"
            print(f"{GRAY}[*] No output file was entered. Using default output file {output_file} to save results.{END}")
        else:
            # Create folders if they don't exist
            output_file = Path(args.output_file).expanduser()
            output_file.parent.mkdir(parents=True, exist_ok=True) 
        # --file target
        if args.file_target:
            with open(args.file_target) as f:
                targets = f.read().splitlines()
            for target in targets:
                check_url(target, args.disable_ssl_verification, output_file)
        # --url target
        else:
            if not is_valid_domain(args.url_target) and not is_valid_url(args.url_target):
                print(f"\n{FAIL}[!] Invalid URL format. Please enter a valid domain or URL.{END}\n")
                return
            else:
                check_url(args.url_target, args.disable_ssl_verification, output_file)
    except KeyboardInterrupt:
        print(f"{FAIL}\nExiting...\n{END}")

if __name__ == "__main__":
    cookie_checker()
    
