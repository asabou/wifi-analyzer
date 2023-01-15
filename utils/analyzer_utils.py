import os
import time
import xml.etree.ElementTree as etree

import scapy.all
from pylibpcap import rpcap


def change_mode(mode):
    if mode == "Monitor":
        print("change mode to Monitor")
        os.system("airmon-ng start wlp2s0")
    else:
        print("Change mode to Managed")
        os.system("airmon-ng stop wlp2s0mon")


def is_monitor_mode():
    os.system("iwconfig > ./os/iwconfig")
    with open("./os/iwconfig", "r") as f:
        text = f.read()
    return True if "Mode:Monitor" in text else False


def get_beacons_frame():
    os.system("rm -rf ./os/capture*")
    os.system("cd ./os && timeout 15s airodump-ng --write capture wlp2s0mon > capture &")
    time.sleep(15)


def get_channels_frequency():
    command = "iwlist " + ("wlp2s0mon" if is_monitor_mode() else "wlp2s0") + " frequency > ./os/channels_frequency"
    os.system(command)
    file = open("./os/channels_frequency", "r")
    channels_frequency = {}
    for line in file:
        line = line.strip()
        if line != "":
            records = line.split(":")
            channels_frequency[records[0].strip()] = records[1].strip()
    return channels_frequency


def get_access_points_details():
    if not is_monitor_mode():
        change_mode("Monitor")
    get_beacons_frame()
    access_points = []
    tree = etree.parse("./os/capture-01.kismet.netxml")
    root = tree.getroot()
    for child in root:
        if child.tag == "wireless-network":
            access_point = init_access_point_details()
            for element in child:
                if element.tag == "SSID":
                    for sub_element in element:
                        if sub_element.tag == "encryption":
                            access_point["encryption"] = access_point["encryption"] + str(sub_element.text) + str(";")
                        if sub_element.tag == "essid":
                            access_point["essid"] = str(sub_element.text)
                if element.tag == "BSSID":
                    access_point["bssid"] = str(element.text)
                    access_point["power"] = get_signal_power(str(element.text))
                if element.tag == "manuf":
                    access_point["manuf"] = str(element.text)
                if element.tag == "channel":
                    access_point["channel"] = str(element.text)
                if element.tag == "freqmhz":
                    access_point["freq"] = str(element.text)
                if element.tag == "carrier":
                    access_point["carrier"] = str(element.text)
                if element.tag == "encoding":
                    access_point["encoding"] = str(element.text)
            access_points.append(access_point)
    return access_points


def get_signal_power(mac):
    file = open("./os/capture-01.csv", "r")
    for line in file:
        line = line.strip()
        if line != "":
            if line.startswith(mac):
                parameters = line.split(",")
                if len(parameters) >= 9:
                    return parameters[8].strip()
    return ""


def convert_bytes_to_bits(bytes):
    all_bits = ""
    for byte in bytes:
        bits = str(bin(byte))[2:]
        while len(bits) != 8:
            bits = "0" + bits
        all_bits = all_bits + bits
    return all_bits


def extract_header_frame_control_details(bytes):
    bits = convert_bytes_to_bits(bytes)
    first_octet = bits[:8]
    second_octet = bits[8:]
    version = first_octet[6:]
    type = first_octet[4:6]
    subtype = first_octet[:4]
    to_ds = second_octet[7]
    from_ds = second_octet[6]
    more_frag = second_octet[5]
    retry = second_octet[4]
    power_mgmt = second_octet[3]
    more_data = second_octet[2]
    wep = second_octet[1]
    order = second_octet[0]
    return {"version": version, "type": type, "subtype": subtype, "to_ds": to_ds, "from_ds": from_ds,
            "more_frag": more_frag, "retry": retry, "power_mgmt": power_mgmt, "more_data": more_data,
            "wep": wep, "order": order}


def get_bytes_in_pretty_format(bytes, sep):
    return sep.join("%02x" % b for b in bytes).upper()


def convert_bytes_to_decimal(bytes):
    bytes_string = get_bytes_in_pretty_format(bytes, "")
    decimal = 0
    p = 0
    for i in range(len(bytes_string) - 1, -1, -1):
        decimal = decimal + map_base_16[bytes_string[i]] * pow(16, p)
        p = p + 1
    return decimal


def convert_bytes_to_readable_ipv4_address(bytes):
    bytes_string_array = get_bytes_in_pretty_format(bytes, ":").split(":")
    ip = []
    for byte_string in bytes_string_array:
        p = 0
        decimal = 0
        for i in range(len(byte_string) - 1, -1, -1):
            decimal = decimal + map_base_16[byte_string[i]] * pow(16, p)
            p = p + 1
        ip.append(decimal)
    return ".".join(str(x) for x in ip)


def convert_bytes_to_readable_ipv6_address(bytes):
    bytes_string_array = get_bytes_in_pretty_format(bytes, ":").split(":")
    ip = []
    for i in range(0, len(bytes_string_array) - 1, 2):
        ip.append(bytes_string_array[i] + "" + bytes_string_array[i + 1])
    return ":".join(x for x in ip)


map_base_16 = {
    "0": 0,
    "1": 1,
    "2": 2,
    "3": 3,
    "4": 4,
    "5": 5,
    "6": 6,
    "7": 7,
    "8": 8,
    "9": 9,
    "A": 10,
    "B": 11,
    "C": 12,
    "D": 13,
    "E": 14,
    "F": 15
}


def init_frame_details():
    frame_details = {}
    frame_details["type"] = ""
    frame_details["mac_source"] = ""
    frame_details["ip_source"] = ""
    frame_details["ip_dest"] = ""
    frame_details["mac_dest"] = ""
    frame_details["protocol"] = ""
    frame_details["port_source"] = ""
    frame_details["port_dest"] = ""
    frame_details["sequence_number"] = ""
    frame_details["ack_number"] = ""
    frame_details["window"] = ""
    frame_details["payload"] = ""
    return frame_details


def init_access_point_details():
    access_point = {}
    access_point["essid"] = ""
    access_point["bssid"] = ""
    access_point["manuf"] = ""
    access_point["channel"] = ""
    access_point["freq"] = ""
    access_point["carrier"] = ""
    access_point["encryption"] = ""
    access_point["encoding"] = ""
    return access_point


def get_ethernet_frame_details_from_buffer(buf):
    frame_details = init_frame_details()
    header_eth = buf[:15]
    header_eth_dest = header_eth[:6]
    header_eth_source = header_eth[6: 6 + 6]
    header_eth_type = header_eth[6 + 6: 6 + 6 + 2]
    frame_details["mac_source"] = get_bytes_in_pretty_format(header_eth_source, ":")
    frame_details["mac_dest"] = get_bytes_in_pretty_format(header_eth_dest, ":")
    header_ip = buf[6 + 6 + 2: 6 + 6 + 2 + 20]
    # IPv4
    if header_eth_type == b'\x08\x00':
        frame_details["type"] = "IPv4"
        header_ip_version = header_ip[0]
        header_ip_differentiated_services = header_ip[1]
        header_ip_total_length = header_ip[2: 2 + 2]
        header_ip_identification = header_ip[2 + 2: 2 + 2 + 2]
        header_ip_flags = header_ip[2 + 2 + 2: 2 + 2 + 2 + 2]
        header_ip_time_to_live = header_ip[2 + 2 + 2 + 2: 2 + 2 + 2 + 2 + 1]
        frame_details["protocol"] = convert_bytes_to_decimal(header_ip[2 + 2 + 2 + 2 + 1: 2 + 2 + 2 + 2 + 1 + 1])
        header_ip_checksum = header_ip[2 + 2 + 2 + 2 + 1 + 1: 2 + 2 + 2 + 2 + 1 + 1 + 2]
        frame_details["ip_source"] = convert_bytes_to_readable_ipv4_address(
            header_ip[2 + 2 + 2 + 2 + 1 + 1 + 2: 2 + 2 + 2 + 2 + 1 + 1 + 2 + 4])
        frame_details["ip_dest"] = convert_bytes_to_readable_ipv4_address(
            header_ip[2 + 2 + 2 + 2 + 1 + 1 + 2 + 4: 2 + 2 + 2 + 2 + 1 + 1 + 2 + 4 + 4])
        header_tcp = buf[6 + 6 + 2 + 20:]
        frame_details["port_source"] = convert_bytes_to_decimal(header_tcp[:2])
        frame_details["port_dest"] = convert_bytes_to_decimal(header_tcp[2: 2 + 2])
        frame_details["sequence_number"] = convert_bytes_to_decimal(header_tcp[2 + 2: 2 + 2 + 4])
        frame_details["ack_number"] = header_tcp[2 + 2 + 4: 2 + 2 + 4 + 4]
        header_tcp_segment_len = header_tcp[2 + 2 + 4 + 4: 2 + 2 + 4 + 4 + 1]
        header_tcp_flags = header_tcp[2 + 2 + 4 + 4: 2 + 2 + 4 + 4 + 2]
        frame_details["window"] = convert_bytes_to_decimal(header_tcp[2 + 2 + 4 + 4 + 2: 2 + 2 + 4 + 4 + 2 + 2])
        header_tcp_checksum = header_tcp[2 + 2 + 4 + 4 + 2 + 2: 2 + 2 + 4 + 4 + 2 + 2 + 2]
        header_tcp_urgent_pointer = header_tcp[2 + 2 + 4 + 4 + 2 + 2 + 2: 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2]
        header_tcp_options = header_tcp[2 + 2 + 4 + 4 + 2 + 2 + 2 + 2: 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2 + 12]
        frame_details["payload"] = ""
        if frame_details["port_dest"] == 80:
            frame_details["payload"] = header_tcp[2 + 2 + 4 + 4 + 2 + 2 + 2 + 2 + 12:]
    # ARP
    if header_eth_type == b'\x08\x06':
        frame_details["type"] = "ARP"
        header_arp = buf[6 + 6 + 2 + 20:]
        header_arp_hardware_type = header_arp[:2]
        frame_details["protocol"] = convert_bytes_to_decimal(header_arp[2: 4])
        header_arp_hardware_size = header_arp[4]
        header_arp_protocol_size = header_arp[5]
        header_arp_opcode = header_arp[6: 6 + 2]
        header_arp_sender_mac = header_arp[8: 8 + 6]
        frame_details["ip_source"] = convert_bytes_to_readable_ipv4_address(header_arp[8 + 6: 8 + 6 + 4])
        header_arp_target_mac = header_arp[8 + 6 + 4: 8 + 6 + 4 + 6]
        frame_details["ip_dest"] = convert_bytes_to_readable_ipv4_address(header_arp[8 + 6 + 4 + 6: 8 + 6 + 4 + 6 + 4])
    # IPv6
    if header_eth_type == b'\x86\xdd':
        frame_details["type"] = "IPv6"
        header_ip = buf[14: 14 + 40]
        header_ip_version = header_ip[:4]
        header_ip_payload_len = header_ip[4: 4 + 2]
        header_ip_next_header = header_ip[4 + 2: 4 + 2 + 1]
        frame_details["protocol"] = convert_bytes_to_decimal(header_ip_next_header)
        header_ip_hop_limit = header_ip[4 + 2 + 1: 4 + 2 + 1 + 1]
        frame_details["ip_source"] = convert_bytes_to_readable_ipv6_address(
            header_ip[4 + 2 + 1 + 1: 4 + 2 + 1 + 1 + 16])
        frame_details["ip_dest"] = convert_bytes_to_readable_ipv6_address(
            header_ip[4 + 2 + 1 + 1 + 16: 4 + 2 + 1 + 1 + 16 + 16])
        # UDP or TCP
        if header_ip_next_header == b'\x11' or header_ip_next_header == b'\x06':
            frame_details["type"] = "UDP" if header_ip_next_header == b'\x11' else "TCP"
            header_next_header = buf[14 + 40:]
            frame_details["port_source"] = convert_bytes_to_decimal(header_next_header[:2])
            frame_details["port_dest"] = convert_bytes_to_decimal(header_next_header[2: 2 + 2])
            frame_details["sequence_number"] = convert_bytes_to_decimal(header_next_header[2 + 2: 2 + 2 + 4])
            frame_details["ack_number"] = header_next_header[2 + 2 + 4: 2 + 2 + 4 + 4]
            header_tcp_segment_len = header_next_header[2 + 2 + 4 + 4: 2 + 2 + 4 + 4 + 1]
            header_flags = header_next_header[2 + 2 + 4 + 4: 2 + 2 + 4 + 4 + 2]
            frame_details["window"] = convert_bytes_to_decimal(
                header_next_header[2 + 2 + 4 + 4 + 2: 2 + 2 + 4 + 4 + 2 + 2])
            header_checksum = header_next_header[2 + 2 + 4 + 4 + 2 + 2: 2 + 2 + 4 + 4 + 2 + 2 + 2]
            header_urgent_pointer = header_next_header[2 + 2 + 4 + 4 + 2 + 2 + 2: 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2]
            header_options = header_next_header[2 + 2 + 4 + 4 + 2 + 2 + 2 + 2:]
    if frame_details["protocol"] == 6:
        frame_details["protocol"] = "TCP"
    if frame_details["protocol"] == 17:
        frame_details["protocol"] = "UDP"
    return frame_details


def convert_bits_to_decimal(bits):
    decimal = 0
    p = 0
    for i in range(len(bits) - 1, -1, -1):
        decimal = decimal + int(bits[i]) * pow(p, 2)
        p = p + 1
    return decimal


def get_mac_frame_details_from_buffer(buf):
    frame_details = init_frame_details()
    header_radiotap = buf[:56]
    header_frame_control = buf[56: 56 + 2]
    header_duration = buf[56 + 2: 56 + 2 + 2]
    type = header_frame_control[0]
    frame_details["type"] = type
    frame_details["frame_control"] = extract_header_frame_control_details(header_frame_control)
    # Probe Request or Authentication or Beacon Frame
    # if type == b'\x40' or type == b'\xb0' or type == b'\x80':
    if type == 64 or type == 176 or type == 128 or type == 212:
        frame_details["mac_dest"] = get_bytes_in_pretty_format(buf[56 + 2 + 2: 56 + 2 + 2 + 6], ":")
        frame_details["mac_source"] = get_bytes_in_pretty_format(buf[56 + 2 + 2 + 6: 56 + 2 + 2 + 6 + 6], ":")
        # BSSID
        frame_details["ip_source"] = get_bytes_in_pretty_format(buf[56 + 2 + 2 + 6 + 6: 56 + 2 + 2 + 6 + 6 + 6], ":")
        header_number_bits = convert_bytes_to_bits(buf[56 + 2 + 2 + 6 + 6 + 6: 56 + 2 + 2 + 6 + 6 + 6 + 2])
        fragment_number = convert_bits_to_decimal(header_number_bits[12:])
        frame_details["sequence_number"] = convert_bits_to_decimal(header_number_bits[:12])
        header_wireless_management = buf[56 + 2 + 2 + 6 + 6 + 6 + 2: -4]
        header_fixed_parameters = header_wireless_management[:12]
        header_tagged_parameters = header_wireless_management[12:]
        # frame check sequence
        frame_details["ack_number"] = buf[-4:]
    # Acknowledgement
    # if type == b'\xd4':
    if type == 224:
        frame_details["mac_dest"] = get_bytes_in_pretty_format(buf[56 + 2 + 2: 56 + 2 + 2 + 6], ":")
        # frame check sequence
        frame_details["ack_number"] = buf[-4:]
    if type == 64:
        frame_details["type"] = "Pr Req"
    if type == 176:
        frame_details["type"] = "Auth"
    if type == 128:
        frame_details["type"] = "Beacon"
    if type == 228:
        frame_details["type"] = "Ack"
    if type == 224:
        frame_details["type"] = "Action"
    if type == 212:
        frame_details["type"] = "Null"
    return frame_details


def get_all_frame_details():
    is_monitor = is_monitor_mode()
    frame_details = []
    for len, time, buf in rpcap("./os/pcap.pcap"):
        if is_monitor:
            frame_details.append(get_mac_frame_details_from_buffer(buf))
        else:
            frame_details.append(get_ethernet_frame_details_from_buffer(buf))
    return frame_details


def start_sniff():
    interface = "wlp2s0"
    is_monitor = is_monitor_mode()
    if is_monitor:
        interface = interface + "mon"
    print("Interface: ", interface)
    # sniffer = Sniff(interface, count=-1, out_file="./os/pcap.pcap")
    # for len, ts, buf in sniffer.capture():
    #     print(buf)
    scapy.all.sniff(iface=interface, prn=process_pack)


def process_pack(pack):
    get_mac_frame_details_from_buffer(bytes(pack))
    print("#######################################################################################3")
