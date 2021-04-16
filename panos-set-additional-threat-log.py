"""
Palo Alto Set Additional Threat Logging

In PAN-OS 8.1.2 and higher, Palo Alto introduced additional threat logging that is enabled with an OP/CLI command.

Enable the firewall to generate Threat logs for a teardrop attack and a DoS attack using ping of death,
and also generate Threat logs for the types of packets listed above if you enable the corresponding packet-based attack
protection (in Step 1). For example, if you enable packet-based attack protection for Spoofed IP address,
using the following OP/CLI causes the firewall to generate a Threat log when the firewall receives and drops a packet
with a spoofed IP address.

    set system setting additional-threat-log on

For more information on this function visit the following link:

    https://live.paloaltonetworks.com/t5/blogs/pan-os-8-1-2-introduces-new-log-options/ba-p/217858

usage: panos-set-additional-threat-log.py [-h] {panorama_all,firewall_list,panorama_list,firewall_file,panorama_file} ..

Palo Alto Set Additional Threat Log Tool

optional arguments:
    -h, --help            show this help message and exit

subcommands:
    For a list of arguments for each command, type panos-set-additional-threat-log.py <command> -h

    {panorama_all,firewall_list,panorama_list,firewall_file,panorama_file}
        panorama_all        Run on all devices connected to Panorama
        firewall_list       Run direct on list of firewalls by FQDN or IP
        panorama_list       Run through Panorama on list of firewalls by Serial, Name, or Management IP
        firewall_file       Run direct on list of firewalls from a file
        panorama_file       Run on list of firewalls from a file through Panorama

Examples:

python panos-set-additional-threat-log.py firewall_file -u admin -v -f firewall_list.txt
python panos-set-additional-threat-log.py panorama_list -u admin -v -l 015351000011111 PA-VM-50-A -m 192.168.100.100

To see the help specific to a subcommand:

python panos-set-additional-threat-log.py panorama_file -h

usage: panos-set-additional-threat-log.py panorama_file [-h] [-u USERNAME] [-m PANORAMA] [-p PASSWORD] [-v] [-f FILENAME]

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for login
  -m PANORAMA, --panorama PANORAMA
                        Panorama IP address
  -p PASSWORD, --password PASSWORD
                        Password for login - recommend not using this on command line
  -v, --verbose         Print responses to console
  -f FILENAME, --filename FILENAME
                        File containing firewall FQDN's and IP's one per line

Requirements:

pip install pan-os-python

Verification:

Run the following operational command to verify if the setting is enabled:

firewall> show system state filter cfg.general.additional-threat-log

If it is already enabled on the firewall, the command will return the following:

cfg.general.additional-threat-log: True

If the response is empty or if the setting is False, then the additional threat logs are disabled

Author: Bill Sucevic
Email: bsucevic@paloaltonetworks.com

More Information

Please see http://github.com/PaloAltoNetworks/panos-set-additional-threat-log for more information

Contributing

Feel free to open issues, offer feedback, and send Pull Requests to our Github repository where this code is hosted.

Disclaimer

This software is provided without support, warranty, or guarantee.
Use at your own risk.

"""

from panos import base
from panos import firewall
from panos import panorama
from getpass import getpass
import argparse
import sys


def panorama_connected_firewalls(args):
    # Function to get the serial, hostname, and ip-address for all connected devices in Panorama
    root = args.pan_device.op('show devices connected')
    firewalls = root.findall("./result/devices/entry")
    # Loop through the XML response for "show devices connected" and write fields to devices dictionary
    for entry in firewalls:
        fw_serial = entry.attrib["name"]
        if fw_serial != "vsys1":
            args.devices[fw_serial] = {}
            args.devices[fw_serial]["hostname"] = entry.find("hostname").text
            args.devices[fw_serial]["ip-address"] = entry.find("ip-address").text


def panorama_op(args):
    # Function to execute the operational command through Panorama on all firewalls
    for current in args.list:
        # Loop for each item in the list
        for key, value in args.devices.items():
            # Loop through each device and check for a match on the items in the list
            if (current == key) or (current == value["hostname"]) or (current == value["ip-address"]) or\
               (current == "ALL_CONNECTED_FIREWALLS"):
                try:
                    # Create a firewall object for the current serial (key)
                    temp_fw_object = firewall.Firewall(serial=key)
                    # Attach the firewall object to panorama object for the proxy connection
                    args.pan_device.add(temp_fw_object)
                    # Send the op command to each firewall through Panorama
                    temp_fw_object.op(args.op_command)
                    if args.verbose:
                        print(value["hostname"] + " complete")
                except Exception as ex:
                    if args.verbose:
                        template = key + " An exception of type {0} occurred. ERROR:\n{1!r}"
                        message = template.format(type(ex).__name__, ex.args)
                        print(message)
            else:
                if args.verbose:
                    print(current + " not found")


def panorama_run(args):
    # Function to run the operational commands on Panorama based on the current function
    try:
        # Connect to Panorama and create a new pan-os-python device
        args.pan_device = base.PanDevice.create_from_device(args.panorama, api_username=args.username,
                                                            api_password=args.password)
        # Verify the device is a Panorama instance, and exit if any other device type
        if not isinstance(args.pan_device, panorama.Panorama):
            print("ERROR: panorama_all requires a valid Panorama IP or FQDN")
            sys.exit(1)
        # Create a dictionary to hold the firewall devices connected to Panorama
        args.devices = {}
        # Get the devices connected to Panorama
        panorama_connected_firewalls(args)
        # Call the panorama_op function to execute the command on all firewalls
        panorama_op(args)
    except Exception as ex:
        if args.verbose:
            template = args.panorama + " An exception of type {0} occurred. ERROR:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            print(message)


def firewall_run(args):
    # Function to run the operational commands on a list of firewalls
    for current_firewall in args.list:
        # Loop through the list of firewalls
        try:
            # Connect to firewall and create a firewall object
            pan_device = base.PanDevice.create_from_device(current_firewall, api_username=args.username,
                                                           api_password=args.password)
            # Verify the device is a Firewall instance and skip to the next entry if it is not
            if not isinstance(pan_device, firewall.Firewall) and args.verbose:
                print(current_firewall + " is not a firewall")
                continue
            # Call the panorama_op function to execute the command on the current firewall
            pan_device.op(args.op_command)
            if args.verbose:
                print(current_firewall + " complete")
        except Exception as ex:
            if args.verbose:
                template = current_firewall + " An exception of type {0} occurred. ERROR:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                print(message)


def panorama_all(args):
    # Function to run the operational command on all connected firewalls
    if not args.panorama:
        args.panorama = str(input("Panorama IP or FQDN: "))
    # This args.list is a flag used in panorama_op to run the command on all connected firewalls
    args.list = ["ALL_CONNECTED_FIREWALLS"]
    # Call the function to execute the operational commands through Panorama
    panorama_run(args)


def firewall_list(args):
    # Function to run the operational command on a list of firewalls
    if not args.list:
        args.list = str(input("Space Separated List of Firewall IP's or FQDN's: ")).split()
    # Call the function to execute the operational commands on a list of firewalls
    firewall_run(args)


def panorama_list(args):
    # Function to run the operational command on a list of firewalls through Panorama
    if not args.panorama:
        args.panorama = str(input("Panorama IP or FQDN: "))
    if not args.list:
        args.list = str(input("Space Separated List of Serial, Management IP, or Device Name: ")).split()
    # Call the function to execute the operational commands through Panorama
    panorama_run(args)


def firewall_file(args):
    # Function to run the operational command on a list of firewalls from a file
    if not args.filename:
        args.filename = str(input("Filename (text file list of firewall IP's and/or FQDN's): "))
    # Create an empty list to populate from a file
    args.list = []
    try:
        # Read the list of firewalls from a file
        with open(args.filename) as file:
            for line in file.readlines():
                args.list.extend(line.split())
    except Exception as ex:
        if args.verbose:
            template = "File Error:" + " An exception of type {0} occurred. ERROR:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            print(message)
            sys.exit(1)
    # Call the function to execute the operational commands on a list of firewalls
    firewall_run(args)


def panorama_file(args):
    # Function to run the operational command on a list of firewalls from a file through Panorama
    if not args.panorama:
        args.panorama = str(input("Panorama IP or FQDN: "))

    if not args.filename:
        args.filename = str(input("Filename (text file list of firewall IP's and/or FQDN's): "))
    # Create an empty list to populate from a file
    args.list = []
    try:
        # Read the list of firewalls from a file
        with open(args.filename) as file:
            for line in file.readlines():
                args.list.extend(line.split())
    except Exception as ex:
        if args.verbose:
            template = "File Error:" + " An exception of type {0} occurred. ERROR:\n{1!r}"
            message = template.format(type(ex).__name__, ex.args)
            print(message)
            sys.exit(1)
    # Call the function to execute the operational commands through Panorama
    panorama_run(args)


def main():
    # Build the command line parser
    parser = argparse.ArgumentParser(description="Palo Alto Set Additional Threat Log Tool")

    subparsers = parser.add_subparsers(description="For a list of arguments for each command, type " +
                                                   sys.argv[0] + " <command> -h")
    # Build the sub parser for panorama_all
    parser_pan_all = subparsers.add_parser("panorama_all", help="Run on all devices connected to Panorama")
    parser_pan_all.add_argument("-u", "--username", help="Username for login", type=str)
    parser_pan_all.add_argument("-m", "--panorama", help="Panorama FQDN or IP address", type=str)
    parser_pan_all.add_argument("-p", "--password",
                                help="Password for login - recommend not using this on command line", type=str)
    parser_pan_all.add_argument("-v", "--verbose", help="Print responses to console", action='store_true')
    parser_pan_all.set_defaults(func=panorama_all)
    # Build the sub parser for firewall_list
    parser_fw_list = subparsers.add_parser("firewall_list", help="Run direct on list of firewalls by FQDN or IP")
    parser_fw_list.add_argument("-u", "--username", help="Username for login", type=str)
    parser_fw_list.add_argument("-p", "--password",
                                help="Password for login - recommend not using this on command line", type=str)
    parser_fw_list.add_argument("-v", "--verbose", help="Print responses to console", action='store_true')
    parser_fw_list.add_argument("-l", "--list", help="List of Firewall FQDN's and IP's "
                                                     "- separate entries with spaces", type=str, nargs='+')
    parser_fw_list.set_defaults(func=firewall_list)
    # Build the sub parser for panorama_list
    parser_pan_list = subparsers.add_parser("panorama_list", help="Run through Panorama on list of firewalls "
                                                                  "by Serial, Name, or Management IP")
    parser_pan_list.add_argument("-u", "--username", help="Username for login", type=str)
    parser_pan_list.add_argument("-m", "--panorama", help="Panorama FQDN or IP address", type=str)
    parser_pan_list.add_argument("-p", "--password",
                                 help="Password for login - recommend not using this on command line", type=str)
    parser_pan_list.add_argument("-v", "--verbose", help="Print responses to console", action='store_true')
    parser_pan_list.add_argument("-l", "--list", help="List of Serial, FW Names, or Management IP's "
                                                      "- separate entries with spaces", type=str, nargs='+')
    parser_pan_list.set_defaults(func=panorama_list)
    # Build the sub parser for firewall_file
    parser_fw_file = subparsers.add_parser("firewall_file", help="Run direct on list of firewalls from a file")
    parser_fw_file.add_argument("-u", "--username", help="Username for login", type=str)
    parser_fw_file.add_argument("-p", "--password",
                                help="Password for login - recommend not using this on command line", type=str)
    parser_fw_file.add_argument("-v", "--verbose", help="Print responses to console", action='store_true')
    parser_fw_file.add_argument("-f", "--filename", help="File containing firewall FQDN's and IP's one per line",
                                type=str)
    parser_fw_file.set_defaults(func=firewall_file)
    # Build the sub parser for panorama_file
    parser_pan_file = subparsers.add_parser("panorama_file", help="Run on list of firewalls from a file through"
                                                                  " Panorama")
    parser_pan_file.add_argument("-u", "--username", help="Username for login", type=str)
    parser_pan_file.add_argument("-m", "--panorama", help="Panorama IP address", type=str)
    parser_pan_file.add_argument("-p", "--password",
                                 help="Password for login - recommend not using this on command line", type=str)
    parser_pan_file.add_argument("-v", "--verbose", help="Print responses to console", action='store_true')
    parser_pan_file.add_argument("-f", "--filename", help="File containing firewall FQDN's and IP's one per line",
                                 type=str)
    parser_pan_file.set_defaults(func=panorama_file)

    # Create the args object and parse the args
    args = parser.parse_args()
    # Add the operational command to args for execution within functions
    args.op_command = 'set system setting additional-threat-log on'
    # If the username was not entered on the command line, prompt the user
    if not args.username:
        args.username = str(input("Username: "))
    # If the password was not entered on command line, prompt the user using getpass for no echo
    if not args.password:
        args.password = getpass(prompt="Password: ")
    # Execute the sub parser function specified in the command line
    args.func(args)


# Main function
if __name__ == "__main__":
    main()
