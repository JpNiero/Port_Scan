from scapy.all import *
import socket, logging, pyfiglet, re, argparse
from colorama import init, Fore

init(autoreset=True)
banner_text = pyfiglet.figlet_format("Port Scan", font="mono9")
colored_banner = f"{Fore.GREEN}{banner_text}"

print(colored_banner)

# Configuração para ocultar mensagens de erro do Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Service:
    @staticmethod
    def get_service_name(port, proto):
        try:
            return socket.getservbyport(port, proto) # Consulta um arquivo de configuração do sistema operacional
        except:
            return "unknown"

class Packet:
    def __init__(self, src_ip, target_ip):
        self.src_ip = src_ip
        self.target_ip = target_ip

    def create_syn_packet(self, port):
        return IP(src=self.src_ip, dst=self.target_ip)/TCP(dport=port, flags='S')

class Scanner:
    def __init__(self, src_ip, target_ip):
        self.src_ip = src_ip
        self.target_ip = target_ip
        self.packet_creator = Packet(src_ip, target_ip)
        self.service_name_resolver = Service()

    @staticmethod
    def validate_ip(ip):
        ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_regex, ip):
            return True
        else:
            return False

    @staticmethod
    def validate_port_range(port_range):
        # Verifica se o formato é de dois números separados por hífen
        port_range_regex = r'^(\d+)-(\d+)$'
        match = re.match(port_range_regex, port_range)
        if match:
            # Extrai os números do intervalo
            start_port, end_port = map(int, match.groups())
            # Verifica se ambos os números estão no intervalo de portas válidas e se o intervalo é válido
            if 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port:
                return True
        return False

    def analyze_response(response, port):
        if response is not None and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN-ACK flags
                return "open"
            elif tcp_layer.flags == 0x14:  # RST-ACK flags
                return "closed"
        else:
            return "filtered"

    def port_scan(self, port_range):
        open_ports, closed_ports, filtered_ports = [], [], []
        start_port, end_port = map(int, port_range.split('-'))

        for port in range(start_port, end_port + 1):
            sys.stdout.write(f"\rEscaneando a porta: {port}")
            sys.stdout.flush()
            packet = self.packet_creator.create_syn_packet(port)
            response = sr1(packet, timeout=6, verbose=0) # Envia o pacote e espera pela resposta
            port_status = Scanner.analyze_response(response, port)

            if port_status == "open":
                open_ports.append(port)
            elif port_status == "closed":
                closed_ports.append(port)
            elif port_status == "filtered":
                filtered_ports.append(port)

        print()

        return open_ports, closed_ports, filtered_ports

    def print_scan_results(self, port_range):
        open_ports, closed_ports, filtered_ports = self.port_scan(port_range)

        if open_ports:
            print("\nPortas abertas encontradas:")
            for port in open_ports:
                service = self.service_name_resolver.get_service_name(port, 'tcp')
                print(f"Porta {port}/tcp - Servico: {service}")

        if filtered_ports:
            print("\nPortas filtradas (sem resposta):")
            for port in filtered_ports:
                service = self.service_name_resolver.get_service_name(port, 'tcp')
                print(f"Porta {port}/tcp - Servico: {service}")

        if not (open_ports or filtered_ports):
            print("\nNenhuma porta aberta ou filtrada encontrada.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("src_ip", help="IP de origem")
    parser.add_argument("target_ip", help="IP de destino")
    parser.add_argument("port_range", help="Faixa de portas para o scan (ex: 20-80)")
    args = parser.parse_args()

    if not Scanner.validate_ip(args.src_ip):
        print("Erro: O endereço IP de origem foi digitado incorretamente.")
    elif not Scanner.validate_ip(args.target_ip):
        print("Erro: O endereço IP de destino foi digitado incorretamente.")
    elif not Scanner.validate_port_range(args.port_range):
        print("Erro: O intervalo de portas foi digitado incorretamente.")
    else:
        print("Resultados do Scan:")
        scanner = Scanner(args.src_ip, args.target_ip)
        scanner.print_scan_results(args.port_range)





