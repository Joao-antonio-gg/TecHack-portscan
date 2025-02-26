import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Dicionário com portas conhecidas e seus serviços
well_known_ports = {
    port: service for service, ports in {
        "echo": [7], "discard": [9], "systat": [11], "daytime": [13], "qotd": [17],
        "chargen": [19], "ftp-data": [20], "ftp": [21], "ssh": [22], "telnet": [23],
        "smtp": [25], "time": [37], "rlp": [39], "nameserver": [42], "nicname": [43],
        "domain": [53], "bootps": [67], "bootpc": [68], "tftp": [69], "gopher": [70],
        "finger": [79], "http": [80], "hosts2-ns": [81], "kerberos": [88], "hostname": [101],
        "iso-tsap": [102], "rtelnet": [107], "pop2": [109], "pop3": [110], "sunrpc": [111],
        "auth": [113], "uucp-path": [117], "sqlserv": [118], "nntp": [119], "ntp": [123],
        "epmap": [135], "netbios-ns": [137], "netbios-dgm": [138], "netbios-ssn": [139],
        "imap": [143], "sql-net": [150], "sqlsrv": [156], "pcmail-srv": [158], "snmp": [161],
        "snmptrap": [162], "print-srv": [170], "bgp": [179], "irc": [194], "ipx": [213],
        "rtsps": [322], "mftp": [349], "ldap": [389], "https": [443], "microsoft-ds": [445],
        "kpasswd": [464], "isakmp": [500]
    }.items() for port in ports
}

def get_banner(s):
    """Tenta capturar o banner do serviço na porta aberta."""
    try:
        s.settimeout(2)
        return s.recv(1024).decode().strip()
    except:
        return None

def identify_os(banner):
    """Identifica o sistema operacional a partir do banner."""
    if not banner:
        return "Não identificado"
    banner_lower = banner.lower()
    if "linux" in banner_lower:
        return "Provável: Linux"
    if "windows" in banner_lower:
        return "Provável: Windows"
    if "mac" in banner_lower or "darwin" in banner_lower:
        return "Provável: macOS"
    if "freebsd" in banner_lower:
        return "Provável: FreeBSD"
    if "openbsd" in banner_lower:
        return "Provável: OpenBSD"
    return "Não identificado"

def scan_tcp_port(host, port):
    """Escaneia uma porta TCP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((host, port))
        service = well_known_ports.get(port, 'Desconhecido')
        
        if result == 0:
            banner = get_banner(s)
            os_detected = identify_os(banner)
            print(f"[ABERTA] Host: {host} | Porta {port} ({service}) | Banner: {banner} | SO: {os_detected}")
        elif result in [111, 10061, 10054]:  # Conexão recusada ou resetada
            print(f"[FECHADA] Host: {host} | Porta {port} ({service})")
        else:
            print(f"[FILTRADA] Host: {host} | Porta {port} ({service})")

def scan_udp_port(host, port):
    """Escaneia uma porta UDP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        service = well_known_ports.get(port, 'Desconhecido')
        try:
            s.sendto(b'\x00', (host, port))
            data, _ = s.recvfrom(1024)  # Tenta receber resposta
            print(f"[ABERTA] Host: {host} | Porta {port} (UDP - {service}) | Resposta: {data}")
        except socket.timeout:
            print(f"[FILTRADA] Host: {host} | Porta {port} (UDP - {service})")
        except:
            print(f"[FECHADA] Host: {host} | Porta {port} (UDP - {service})")

def scan_host(host, ports, protocol="tcp"):
    """Escaneia um host nas portas especificadas."""
    print(f'Escaneando host: {host}... ({protocol.upper()})')
    with ThreadPoolExecutor(max_workers=50) as executor:
        scan_func = scan_tcp_port if protocol == "tcp" else scan_udp_port
        executor.map(lambda port: scan_func(host, port), ports)

def scan_network(network, ports, protocol="tcp"):
    """Escaneia uma rede nas portas especificadas."""
    print(f'Escaneando rede: {network}... ({protocol.upper()})')
    for host in ipaddress.IPv4Network(network, strict=False):
        scan_host(str(host), ports, protocol)

if __name__ == '__main__':
    target = input('Digite o host ou rede (ex: 192.168.1.1 ou 192.168.1.0/24): ')
    print("\nEscolha o tipo de escaneamento:")
    print("1 - Apenas as well-known ports")
    print("2 - Todas as portas (1-65535)")
    print("3 - Intervalo personalizado")
    choice = input("Opção: ").strip()

    if choice == '1':
        ports = list(well_known_ports.keys())
    elif choice == '2':
        ports = list(range(1, 65536))
    elif choice == '3':
        start_port = int(input('Digite a porta inicial: '))
        end_port = int(input('Digite a porta final: '))
        ports = list(range(start_port, end_port + 1))
    else:
        print("Opção inválida! Encerrando o programa.")
        exit()

    protocol = input("Escolha o protocolo (tcp/udp): ").strip().lower()
    if protocol not in ["tcp", "udp"]:
        print("Protocolo inválido! Encerrando o programa.")
        exit()

    try:
        if '/' in target:
            scan_network(target, ports, protocol)
        else:
            scan_host(target, ports, protocol)
    except ValueError:
        print('Erro: Entrada inválida! Certifique-se de digitar um endereço IP ou rede válida.')
