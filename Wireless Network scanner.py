import sys
import scapy.all as scapy
import socket
import pandas as pd
import clipboard
import ipaddress
import netifaces
import threading
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import tkinter as tk
from PIL import Image, ImageTk

devices = []

def get_wifi_address():
    try:
        hostname = socket.gethostname()
        wifi_address = socket.gethostbyname(hostname)
        return wifi_address
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_local_ip_info(ip_prefix):
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            ipv4_info = addresses[netifaces.AF_INET][0]
            ip_address = ipv4_info.get('addr')
            netmask = ipv4_info.get('netmask')
            if ip_address and ip_address.startswith(ip_prefix) and netmask:
                return ip_address, netmask
    return None, None

def get_ip_range(ip_address):
    return f"{ip_address.rsplit('.', 1)[0]}.0/24"

def scan_ip(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        manufacturer = get_manufacturer(mac)
        try:
            name = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            name = "Unknown"
        
        devices.append({"IP": ip, "MAC": mac, "Manufacturer": manufacturer, "Name": name})

def scan_network(ip_range):
    network = ipaddress.IPv4Network(ip_range)
    threads = []
    
    for ip in network.hosts():
        thread = threading.Thread(target=scan_ip, args=(str(ip),))
        thread.start()
        threads.append(thread)

        if len(threads) >= 100:
            for thread in threads:
                thread.join()
            threads.clear()
    
    for thread in threads:
        thread.join()

def get_manufacturer(mac):
    return mac

def export_to_csv():
    df = pd.DataFrame(devices)
    df.to_csv('connected_devices.csv', index=False)
    print("CSV exported.")

def copy_to_clipboard():
    text = "\n".join([f"IP: {d['IP']}, MAC: {d['MAC']}, Manufacturer: {d['Manufacturer']}, Name: {d['Name']}" for d in devices])
    clipboard.copy(text)
    print("Copied to clipboard.")

def show_results_with_table():
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.axis('tight')
    ax.axis('off')

    table_data = [["IP", "MAC", "Manufacturer", "Name"]] + [[d['IP'], d['MAC'], d['Manufacturer'], d['Name']] for d in devices]
    table = ax.table(cellText=table_data, cellLoc='center', loc='center')

    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1.2, 1.2)

    wifi_address = get_wifi_address()
    local_ip, netmask = get_local_ip_info(wifi_address)
    ip_range = get_ip_range(local_ip) if local_ip else ""
    ax.set_title(f'Connected Devices\nWi-Fi Address: {wifi_address}\nLocal IP Address: {local_ip}\nNetmask: {netmask}\nScanning Range: {ip_range}', fontsize=14)

    plt.show()

def start_program():
    global devices
    devices = []
    ip_prefix = get_wifi_address()
    
    if ip_prefix:
        ip_address, netmask = get_local_ip_info(ip_prefix)
        if ip_address and netmask:
            ip_range = get_ip_range(ip_address)
            print(f"Wi-Fi Address: {ip_prefix}")
            print(f"Local IP Address: {ip_address}")
            print(f"Netmask: {netmask}")
            print(f"Scanning Range: {ip_range}")
            scan_network(ip_range)
            if devices:
                show_results_with_table()
                ask_export_to_csv()
            else:
                print("No devices found.")
        else:
            print("Could not determine the local IP range.")
    else:
        print("Could not determine the wireless network address.")

def ask_export_to_csv():
    csv_window = tk.Toplevel()
    csv_window.title("Export to CSV")
    csv_window.geometry("402x167")

    csv_background_image = Image.open("csvbackround.png")
    csv_bg = ImageTk.PhotoImage(csv_background_image)
    csv_background_label = tk.Label(csv_window, image=csv_bg)
    csv_background_label.place(relwidth=1, relheight=1)

    yes_button_image = Image.open("yespushbutton.png")
    yes_button = ImageTk.PhotoImage(yes_button_image)

    no_button_image = Image.open("nopushbutton.png")
    no_button = ImageTk.PhotoImage(no_button_image)

    def close_csv_and_open_clipboard(export=False):
        if export:
            export_to_csv()
        csv_window.destroy()
        ask_copy_to_clipboard()

    yes_push_button = tk.Button(csv_window, image=yes_button, command=lambda: close_csv_and_open_clipboard(export=True), borderwidth=0)
    yes_push_button.place(relx=0.2, rely=0.8, anchor=tk.SW)

    no_push_button = tk.Button(csv_window, image=no_button, command=lambda: close_csv_and_open_clipboard(export=False), borderwidth=0)
    no_push_button.place(relx=0.8, rely=0.8, anchor=tk.SE)

    csv_background_label.image = csv_bg
    yes_push_button.image = yes_button
    no_push_button.image = no_button

def ask_copy_to_clipboard():
    clipboard_window = tk.Toplevel()
    clipboard_window.title("Copy to Clipboard")
    clipboard_window.geometry("402x167")

    clipboard_background_image = Image.open("clipboredbackround.png")
    clipboard_bg = ImageTk.PhotoImage(clipboard_background_image)
    clipboard_background_label = tk.Label(clipboard_window, image=clipboard_bg)
    clipboard_background_label.place(relwidth=1, relheight=1)

    yes_button_image = Image.open("yespushbutton.png")
    yes_button = ImageTk.PhotoImage(yes_button_image)

    no_button_image = Image.open("nopushbutton.png")
    no_button = ImageTk.PhotoImage(no_button_image)

    yes_push_button = tk.Button(clipboard_window, image=yes_button, command=lambda: [copy_to_clipboard(), clipboard_window.destroy()], borderwidth=0)
    yes_push_button.place(relx=0.2, rely=0.8, anchor=tk.SW)

    no_push_button = tk.Button(clipboard_window, image=no_button, command=clipboard_window.destroy, borderwidth=0)
    no_push_button.place(relx=0.8, rely=0.8, anchor=tk.SE)

    clipboard_background_label.image = clipboard_bg
    yes_push_button.image = yes_button
    no_push_button.image = no_button

def create_gui():
    root = tk.Tk()
    root.title("Network Scanner")
    root.geometry("680x420")

    background_image = Image.open("background.png")
    bg = ImageTk.PhotoImage(background_image)
    background_label = tk.Label(root, image=bg)
    background_label.place(relwidth=1, relheight=1)
    
    button_image = Image.open("pushbutton.png")
    button = ImageTk.PhotoImage(button_image)

    push_button = tk.Button(root, image=button, command=start_program, borderwidth=0)
    push_button.place(relx=0.1, rely=0.9, anchor=tk.SW)

    background_label.image = bg
    push_button.image = button

    root.mainloop()

if __name__ == "__main__":
    create_gui()
