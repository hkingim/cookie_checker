import requests
import datetime
from pathlib import Path
import re
import time
from halo import Halo
import argparse

###
#    Cookie Checker
#    Usage: python3 cookie_check.py
###

CYAN = '\033[36m'
GRAY = '\033[0;37m'
BLUE = '\033[34m'
GREEN = '\033[32m'
WARNING = '\033[0;33m'
FAIL = '\033[0;31m'
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
def progress_load():
    duration = 3  # Duration of the animation in seconds
    spinner = Halo(text='Please wait...', spinner='dots')  # Choose the desired spinner style
    spinner.start()
    start_time = time.time()
    while time.time() - start_time < duration:
        time.sleep(0.1)  # Simulating some processing time
    spinner.stop()
# Save results to outfile file path
def save_output(output, output_file_path):
    # Accepts tilde (~)
    path = Path(output_file_path).expanduser()
    # Create directory if not existing
    path.parent.mkdir(parents=True, exist_ok=True)
    # Save file
    with path.open('a') as file:
        file.write(output)
# Check if the input is a valid domain format
def is_valid_domain(input_url):
    domain_pattern = r"^(?:[-A-Za-z0-9]+\.)+[A-Za-z]{2,6}$"
    return re.match(domain_pattern, input_url)
# Check if the input is a valid URL format
def is_valid_url(input_url):
    url_pattern = r"^(?:http(s)?://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!$&'()*+,;=]+$"
    return re.match(url_pattern, input_url)
# Check file extension if .txt
def validate_file_extension(file_path):
    valid_extensions = ['.txt']
    extension = Path(file_path).suffix.lower()
    return extension in valid_extensions
# Check url or targets
def check_url(url, disable_ssl_verification, output_file_path):
    # Disable ssl verification
    if disable_ssl_verification:
        requests.packages.urllib3.disable_warnings()
    if not url.startswith('http://') and not url.startswith('https://'):
        http_url = f"http://{url}"
        https_url = f"https://{url}"
        check_cookie(http_url, disable_ssl_verification, output_file_path)
        check_cookie(https_url, disable_ssl_verification, output_file_path)
    else:
        check_cookie(url, disable_ssl_verification, output_file_path)
    print(f"\n{GRAY}Done.{END}\n\n")
# Check cookies
def check_cookie(url, disable_ssl_verification, output_file_path):
    try:
        # username = input(f"{BLUE}Enter username: {END}")
        # password = getpass(f"{BLUE}Enter password: {END}")
        # session = requests.Session()
        # session.auth = (username, password)

        print(f"\n{GRAY}[*] Checking for cookies...{END}") 
        progress_load()
        session = requests.Session()
        response = session.get(url, verify=not disable_ssl_verification) or requests.get(url, verify=not disable_ssl_verification)
        cookies = session.cookies or response.cookies
        
        # # Check the response status code and content
        # print(f"{GRAY}[*] Response Status Code: {response.status_code}{END}")
     
        # # Handle authentication errors
        # if response.status_code == 401:
        #     print(f"{FAIL}[!] Invalid authentication credentials. Please check your username and password.{END}")
        # elif response.status_code == 403:
        #     print(f"{FAIL}[!] Access to the resource is forbidden. Please ensure you have the necessary permissions.{END}") 
        
        if cookies:
            print(f"\n{GRAY}[*] Cookies found in {url}:{END}")
            output = f"\nCookies found in {url}:\n"
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
                print(f"HttpOnly     : " + httponly_value + "  " + httponly_alert)
                print(f"{END}")
                # Write cookie info to file
                output += "\n"
                output += f"Name         : {cookie.name}\n"
                output += f"Value        : {cookie.value}\n"
                output += f"Path         : {cookie.path}\n"
                output += f"Domain       : {cookie.domain}\n"
                output += f"Expires      : {expiration_date_value}  {expire_msg}\n"
                output += f"Secure       : {secure_value}  {secure_msg}\n"
                output += f"SameSite     : {samesite_value}  {samesite_msg}\n"
                output += f"HttpOnly     : {httponly_value}  {httponly_msg}\n"
                output += "\n"
            # Collect insecure cookies found         
            insecure_cookies = [ cookie for cookie in cookies if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly') \
                                and not cookie.has_nonstandard_attr('httponly') or not cookie.has_nonstandard_attr('SameSite') \
                                and not cookie.has_nonstandard_attr('samesite') or cookie.expires is not None and expiration_date_only > current_date ] 
            if insecure_cookies or url.startswith('http://'):
                # Print if insecure cookies found
                if url.startswith('http://'):
                    print(f"\n{WARNING}[!] Target is under HTTP connection. It's highly recommended to ensure that cookies are transmitted over HTTPS connection.{END}")
                    output += f"\nTarget is under HTTP connection. It's highly recommended to ensure that cookies are transmitted over HTTPS connection.\n"
                print(f"\n{WARNING}[!] There are insecure cookies found in {url}{WARNING}.{END}")
                output += f"\nThere are insecure cookie(s) found in {url}.\n"
            else:
                # Print message if no insecure cookies found 
                print(f"\n{GREEN}[+] No insecure cookies found in {url}{GREEN}.{END}")
                output += f"\nNo insecure cookies found in {url}.\n"         
        else:
            # Print message if no cookies found
            print(f"\n{GRAY}[*] No cookies found in {url}.{END}")
            output += f"\nNo cookies found in {url}.\n"
        save_output(output, output_file_path)
        # Print link for reference
        print(f"\n{GRAY}[*] Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies{END}")
        print(f"\n{GRAY}[*] Results saved to {output_file_path}.{END}\n")
    except requests.exceptions.SSLError as e:
        print(f"\n{FAIL}[!] Error: SSL certificate verification failed. To ignore this error, disable SSL certificate verification.{END}")
        return
    except requests.exceptions.RequestException as e:
        # print(f"\nError: {e}")
        print(f"\n{FAIL}[!] Error: Can't reach {url}{FAIL}. Connection timed out.{END}")
        return    
def cookie_checker():
    banner()
    parser = argparse.ArgumentParser(description="Check for insecure cookies on target website(s).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", dest="url_target", help="Target URL.")
    group.add_argument("-f", "--file", dest="file_target", help="File path containing list of targets.")
    parser.add_argument("-d", "--disable-ssl-verification", action="store_true", help="Disable SSL certificate verification.")
    parser.add_argument("-o", "--output", dest="output_file_path", help="Output file to save the results.")
    args = parser.parse_args()
    try:
        if not args.output_file_path:
            # Create a default output file  
            output_file_path = "cookies_output.txt"
            print(f"{GRAY}[!] No output file was entered. Using default output file {output_file_path} to save results.{END}")
        elif not validate_file_extension(args.output_file_path):
            print(f"\n{FAIL}[!] The file must be a text file (.txt). Please try again.{END}\n")
            return
        else:
            # Create folders if they don't exist
            output_file_path = Path(args.output_file_path).expanduser()
            output_file_path.parent.mkdir(parents=True, exist_ok=True) 
        # --file target
        if args.file_target:
            with open(args.file_target) as f:
                targets = f.read().splitlines()
            for target in targets:
                check_url(target, args.disable_ssl_verification, output_file_path)
        # --url target
        else:
            if not is_valid_domain(args.url_target) and not is_valid_url(args.url_target):
                print(f"\n{FAIL}[!] Invalid URL format. Please enter a valid domain or URL.{END}\n")
                return
            else:
                check_url(args.url_target, args.disable_ssl_verification, output_file_path)
    except KeyboardInterrupt:
        print(f"{FAIL}\nExiting...\n{END}")

if __name__ == "__main__":
    cookie_checker()
    
