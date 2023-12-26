import asyncio
from scapy.all import ARP, Ether, srp
import psutil
import csv
import time
from typing import Dict, Tuple

async def get_mac(ip: str) -> str:
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = await asyncio.get_event_loop().run_in_executor(None, srp, packet, None, 2, False)
    ans, _ = result[0]

    return ans[0][1].hwsrc

async def get_speed() -> Tuple[int, int]:
    interface = list(psutil.net_if_stats().keys())[0]

    stats = psutil.net_io_counters(pernic=True)[interface]
    upload_speed = stats.bytes_sent
    download_speed = stats.bytes_recv

    return upload_speed, download_speed

async def save_to_csv(data: Dict[str, Tuple[str, int, int]]) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    filename = "network_data.csv"

    fieldnames = ['Timestamp', 'IP', 'MAC', 'Upload Speed', 'Download Speed']

    with open(filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()

        for ip, (mac, upload_speed, download_speed) in data.items():
            writer.writerow({'Timestamp': timestamp, 'IP': ip, 'MAC': mac, 'Upload Speed': upload_speed, 'Download Speed': download_speed})

    print(f"Data appended to {filename}")

async def scan_network(ip_range: str) -> Dict[str, Tuple[str, int, int]]:
    devices: Dict[str, Tuple[str, int, int]] = {}

    try:
        result = await asyncio.get_event_loop().run_in_executor(None, srp, Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), None, 2, False)
        ans, _ = result[0]

        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            upload_speed, download_speed = await get_speed()
            devices[ip] = (mac, upload_speed, download_speed)
    
    except Exception as e:
        print(f"An error occurred: {e}")

    return devices

async def main() -> None:
    ip_range = input("Enter the IP range of your network (e.g., 192.168.1.0/24): ")

    while True:
        devices = await scan_network(ip_range)

        for ip, (mac, upload_speed, download_speed) in devices.items():
            print(f"Device: {ip} ({mac})")
            print(f"Upload speed: {upload_speed} bytes/sec")
            print(f"Download speed: {download_speed} bytes/sec")
            print()

        await save_to_csv(devices)

        await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(main())