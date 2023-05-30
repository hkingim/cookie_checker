import requests
import argparse
import datetime

###
#    Cookie Checker
#    Usage: python3 cookie_check.py -u <url>
#    Use -h or --help for more options.
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

# Check url or targets
def check_url(url, disable_ssl_verification):
    # Disable ssl verification
    if disable_ssl_verification:
        requests.packages.urllib3.disable_warnings()
    if not url.startswith('http://') and not url.startswith('https://'):
        http_url = f"http://{url}"
        https_url = f"https://{url}"
        check_cookie(http_url, disable_ssl_verification)
        check_cookie(https_url, disable_ssl_verification)
    else:
        check_cookie(url, disable_ssl_verification)

# Check cookies
def check_cookie(url, disable_ssl_verification):
    try:
        print(f"{CYAN}\nChecking for cookies...{END}")
        response = requests.get(url, verify=not disable_ssl_verification)
        cookies = response.cookies
        if cookies:
            print(f"{GRAY}\nCookies found in {url}:{END}")
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
                if cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'):
                    httponly_value = "True"
                else:
                    httponly_value = "False"
                if cookie.has_nonstandard_attr('SameSite') or cookie.has_nonstandard_attr('samesite'):
                    samesite_value = "True"
                else:
                    samesite_value = "False"
                if not cookie.secure:
                    secure_value = "False"
                else:
                    secure_value = "True"
                

                # Print cookie info
                print(f"\n{GRAY}[*] {cookie.name}={cookie.value}; Expires={expiration_date_value}; Secure={secure_value}; SameSite={samesite_value}; HttpOnly={httponly_value}{END}")

                # Check if cookie.expires > today
                if cookie.expires is not None and expiration_date_only > current_date:
                    print(f"{WARNING}[!] Persistent cookie found.{END}")
                else:
                    print(f"{GREEN}[+] No persistent cookie found.{END}")
                # Check secure attribute
                if not cookie.secure:
                    print(f"{WARNING}[!] Missing Secure attribute.{END}")
                else:
                    print(f"{GREEN}[+] Secure attribute found.{END}")
                # Check httponly attribute
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly'):
                    print(f"{WARNING}[!] Missing HttpOnly attribute.{END}")
                else:
                    print(f"{GREEN}[+] HttpOnly attribute found.{END}")
                # Check samesite attribute
                if not cookie.has_nonstandard_attr('SameSite') and not cookie.has_nonstandard_attr('samesite'): 
                    print(f"{WARNING}[!] Missing SameSite attribute.{END}")
                else:
                    print(f"{GREEN}[+] SameSite attribute found.{END}")                 
            print()
               
            # Collect insecure cookies found         
            insecure_cookies = [ cookie for cookie in cookies if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly') and not cookie.has_nonstandard_attr('httponly') or not cookie.has_nonstandard_attr('SameSite') and not cookie.has_nonstandard_attr('samesite') or cookie.expires is not None and expiration_date_only > current_date ] 
            if insecure_cookies or url.startswith('http://'):
                # Print if insecure cookies found
                if url.startswith('http://'):
                    print(f"{WARNING}[!] Target is under HTTP connection. It's highly recommended to ensure that cookies are transmitted over HTTPS connection.{END}")
                print(f"{WARNING}[!] There are insecure cookies found in {url}{WARNING}.{END}")
            else:
                # Print message if no insecure cookies found 
                print(f"{GREEN}[*] No insecure cookies found in {url}{GREEN}.{END}")
            
        else:
            # Print message if no cookies found
            print(f"{GRAY}\n[*] No cookies found in {url}.{END}")
        print()
    except requests.exceptions.SSLError as e:
        print(f"{FAIL}\n[!] Error: SSL certificate verification failed. To ignore this error, disable SSL certificate verification.{END}")
        return
    except requests.exceptions.RequestException as e:
#       print(f"\nError: {e}")
        print(f"{FAIL}\n[!] Error: Can't reach {url}{FAIL}. Connection timed out.{END}")
        return
    # Print link for reference
    print(f'{GRAY}\nReference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies\n{END}')
    
    print(f"{GRAY}\nCompleted.\n\n{END}")

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Check for insecure cookies on target website(s).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", dest="url_target", help="Target URL.")
    group.add_argument("-f", "--file", dest="file_target", help="File path containing list of targets.")
    parser.add_argument("-d", "--disable-ssl-verification", action="store_true", help="Disable SSL certificate verification.")
    args = parser.parse_args()


    try:
        # --file target
        if args.file_target:
            with open(args.file_target) as f:
                targets = f.read().splitlines()
            for target in targets:
                check_url(target, args.disable_ssl_verification)
        # --url target
        else:
            check_url(args.url_target, args.disable_ssl_verification)
    except KeyboardInterrupt:
        print(f"{FAIL}\nExiting...\n{END}")
