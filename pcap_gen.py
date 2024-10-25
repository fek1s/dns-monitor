from scapy.all import *

# Cesty pro uložení PCAP souborů
pcap_ipv4_filename = "dns_test_data_ipv4.pcap"
pcap_ipv6_filename = "dns_test_data_ipv6.pcap"

# Definice cílů a testovaných domén
dns_server_ipv4 = "8.8.8.8"
dns_server_ipv6 = "2001:4860:4860::8888"
src_ipv4 = "192.168.1.5"  # Libovolná IPv4 pro testování
src_ipv6 = "2001:db8::1"   # Libovolná IPv6 pro testování
test_domain = "example.com"

# Seznam typů DNS záznamů pro generování
query_types = ["A", "AAAA", "NS", "MX", "SOA", "CNAME", "SRV"]

# Vytváření DNS dotazů a odpovědí pro IPv4
packets_ipv4 = []
for qtype in query_types:
    # DNS Query IPv4
    query_packet_ipv4 = IP(src=src_ipv4, dst=dns_server_ipv4) / UDP(sport=53, dport=53) / DNS(rd=1, qd=DNSQR(qname=test_domain, qtype=qtype))
    packets_ipv4.append(query_packet_ipv4)

    # DNS Response IPv4
    response_packet_ipv4 = IP(src=dns_server_ipv4, dst=src_ipv4) / UDP(sport=53, dport=53) / DNS(
        id=query_packet_ipv4[DNS].id,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=query_packet_ipv4[DNS].qd,
        an=DNSRR(rrname=test_domain, type=qtype, rdata="93.184.216.34" if qtype == "A" else "2606:2800:220:1:248:1893:25c8:1946" if qtype == "AAAA" else dns_server_ipv4)
    )
    packets_ipv4.append(response_packet_ipv4)

# Vytváření DNS dotazů a odpovědí pro IPv6
packets_ipv6 = []
for qtype in query_types:
    # DNS Query IPv6
    query_packet_ipv6 = IPv6(src=src_ipv6, dst=dns_server_ipv6) / UDP(sport=53, dport=53) / DNS(rd=1, qd=DNSQR(qname=test_domain, qtype=qtype))
    packets_ipv6.append(query_packet_ipv6)

    # DNS Response IPv6
    response_packet_ipv6 = IPv6(src=dns_server_ipv6, dst=src_ipv6) / UDP(sport=53, dport=53) / DNS(
        id=query_packet_ipv6[DNS].id,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=query_packet_ipv6[DNS].qd,
        an=DNSRR(rrname=test_domain, type=qtype, rdata="93.184.216.34" if qtype == "A" else "2606:2800:220:1:248:1893:25c8:1946" if qtype == "AAAA" else dns_server_ipv6)
    )
    packets_ipv6.append(response_packet_ipv6)

# Uložení do oddělených PCAP souborů
wrpcap(pcap_ipv4_filename, packets_ipv4)
wrpcap(pcap_ipv6_filename, packets_ipv6)
print(f"PCAP soubory '{pcap_ipv4_filename}' a '{pcap_ipv6_filename}' byly úspěšně vytvořeny pro IPv4 a IPv6 DNS dotazy a odpovědi.")
