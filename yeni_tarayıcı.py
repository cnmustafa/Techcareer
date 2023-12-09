import scapy.all as scapy
import argparse
import socket

scapy.conf.use_pcap = True

def tarayici(ip, port):
    arp_req = scapy.ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
    ether_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    birlesim = ether_req / arp_req
    gönderim_alım = scapy.srp(birlesim, timeout=1)

    # ARP isteğini gönderip göndermediğini kontrol et
    print("[+] ARP Request Sent: {}".format(gönderim_alım[0].summary()))

    for paket in gönderim_alım[0]:
        # ARP cevaplarını kontrol et
        print("[+] ARP Response Received: {}".format(paket.summary()))

    for port_num in range(1, port):
        tara = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #socket.socket : soket modülündeki socket sınıfının bir örneğini oluşturur.
        #AF_INET : soketin bir IPv4 adresi ve port numarası ile ilişkilendirileceğini belirtir
        #SOCK_STREAM : soketin bir TCP bağlantısı için kullanılacağını belirtir
        try:
            tara.connect((ip, port_num))
            print("[+] {} portu açık".format(port_num))
            cevap = tara.recv(512)
            print("[+] Received response: {}".format(cevap))
            tara.close()
        except socket.error:
            pass

def main():
    tanım = argparse.ArgumentParser(description="Ağ taraması yapmak için şöyle kullanabilirsiniz: python yeni_tarayıcı.py --ip [IP Adresi] --port [Port Numarası]")
    tanım.add_argument("--ip", dest="ip", help="IP adresi girin.")
    tanım.add_argument("--port", dest="port", type=int, help="Port numarası girin.")
    args = tanım.parse_args()
    ip = args.ip
    port = args.port

    if not ip:
        print("Lütfen IP adresi giriniz.")
    elif not port:
        tarayici(ip, 1024)
    else:
        tarayici(ip, port)

if __name__ == "__main__":
    main()
