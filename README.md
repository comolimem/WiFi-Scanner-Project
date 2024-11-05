Project Overview:

This project involves a Python program designed to scan wireless networks and detect connected devices. The program utilizes several libraries, including Scapy for ARP requests, Socket for retrieving device information, and Pandas for handling data export. The GUI is crafted using Figma and implemented with Tkinter for a user-friendly interface.

Key Libraries Used

Scapy: For crafting and sending ARP packets to discover devices on the network.

Socket: To obtain the local machine's IP address and perform hostname lookups.

Pandas: For data manipulation and exporting the results to CSV format.

Clipboard: To copy device information directly to the clipboard.

Ipaddress: For handling IP address manipulations and network calculations.

Netifaces: To retrieve network interface information and IP addresses.

Matplotlib: For visual representation of scanned device data in table format.

Tkinter: For creating the GUI components of the application.

PIL (Pillow): For handling image assets used in the GUI.

Script Structure and Functionality:

Global Variables:

devices: A list to store detected device information.

Function Definitions:

get_wifi_address(): Retrieves the Wi-Fi address of the host.

get_local_ip_info(ip_prefix): Fetches the local IP and netmask based on a given prefix.

get_ip_range(ip_address): Generates the IP range for the network.

scan_ip(ip): Sends ARP requests to a specified IP and collects device information.

scan_network(ip_range): Initiates scanning for all hosts in the given IP range using threading to optimize speed.

get_manufacturer(mac): Placeholder function for determining the manufacturer based on MAC address (currently returns the MAC as-is).

export_to_csv(): Exports the collected device information to a CSV file.

copy_to_clipboard(): Copies the formatted device information to the clipboard.

show_results_with_table(): Displays the results in a table using Matplotlib.

start_program(): Main function to initiate the scanning process and gather device data.

ask_export_to_csv() and ask_copy_to_clipboard(): Functions to prompt the user for exporting data or copying to the clipboard, displaying corresponding confirmation dialogs.

GUI Implementation:

create_gui(): Sets up the main window and layout using Tkinter, including buttons for starting the scan and a background image designed in Figma. Additional dialogs are created for user prompts regarding data export and clipboard actions.

Assets Used

Background images for the main window and prompts, designed in Figma to enhance user experience.

Button images for user interaction, also designed in Figma for a cohesive visual style.

How It Works

When the program starts, it initializes the GUI. Upon clicking the scan button, it retrieves the local Wi-Fi address and corresponding IP information. The program then scans the network for connected devices using ARP requests in parallel threads. Detected devices' details, including IP, MAC address, manufacturer, and hostname, are collected and displayed in a table format. Users can export this information to a CSV file or copy it to the clipboard using the provided prompts
