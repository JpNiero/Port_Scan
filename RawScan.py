import socket, struct, sys, random, re, pyfiglet, argparse
from colorama import init, Fore

init(autoreset=True)
banner_text = pyfiglet.figlet_format("Port Scan", font="mono9")
colored_banner = f"{Fore.GREEN}{banner_text}"

print(colored_banner)

class Service:
    @staticmethod
    def get_service_name(port, proto):
        try:
            return socket.getservbyport(port, proto) # Consulta um arquivo de configuração do sistema operacional
        except:
            return "unknown"

class IPHeader:
    def __init__(self, src_ip, dest_ip):
        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def create(self):
        source_ip = socket.inet_aton(self.src_ip) # Converte para binário
        dest_ip = socket.inet_aton(self.dest_ip) 

        version_ihl = (4 << 4) + 5 # Ipv4 e tamanho do cabeçalho igual a 5
        tos = 0 # 0 para uso padrão
        total_length = 20 + 20  # IP header + TCP header
        packet_id = 54321  # Identificador do pacote (arbitrário)
        fragment_offset = 0
        ttl = 255
        protocol = socket.IPPROTO_TCP
        checksum = 0  # Inicialmente zero antes do cálculo

        # Empacotar o cabeçalho IP (bytes)
        ip_header = struct.pack('!BBHHHBBH4s4s', 
                                version_ihl, tos, total_length, packet_id, 
                                fragment_offset, ttl, protocol, checksum, 
                                source_ip, dest_ip)

        return ip_header

class TCPHeader:
    def __init__(self, src_ip, dest_ip, dest_port):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    @staticmethod
    def checksum(msg):
        s = 0

        for i in range(0, len(msg), 2): # Percorre a mensagem em incremento de 2 bytes
            w = (msg[i] << 8) + (msg[i+1]) # Combina dois bytes adjacentes em um bloco de 16 bits
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s

    def create(self):
        
        src_port = random.randint(1024, 65535)
        seq_number = 0 # 0 pois a conexão ainda não foi estabelecida
        ack_number = 0 # 0 pois a conexão ainda não foi estabelecida
        offset_res = (5 << 4) + 0 # Cabeçalho de tamanho 5
        tcp_flags = 2  # SYN Flag
        window = socket.htons(5840) # Converte o número 5840 em ordem de byte de rede
        tcp_checksum = 0
        urg_ptr = 0  

        # Empacotar o cabeçalho TCP (bytes)
        tcp_header = struct.pack('!HHLLBBHHH', 
                                src_port, self.dest_port, seq_number, ack_number, 
                                offset_res, tcp_flags, window, tcp_checksum, urg_ptr)

        source_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = struct.pack('!4s4sBBH', 
                        source_address, dest_address, placeholder, protocol, tcp_length)
        psh = psh + tcp_header

        tcp_checksum = TCPHeader.checksum(psh)
        
        tcp_header = struct.pack('!HHLLBBHHH', 
                                src_port, self.dest_port, seq_number, ack_number, 
                                offset_res, tcp_flags, window, tcp_checksum, urg_ptr)

        return tcp_header

class Socket:
    def __init__(self):
        self.send_socket = None
        self.recv_socket = None

    # Inicializa e configura os sockets para envio e recebimento dos pacotes
    def open_sockets(self):
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) # Indica que o socket receberá pacotes TCP
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Configuração do socket de recebimento
        self.send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Configuração do socket de envio
        self.recv_socket.settimeout(6) # Se nenhum dado for recebido dentro de 5 segundos, uma exceção de timeout será lançada

    def close_sockets(self):
        if self.send_socket:
            self.send_socket.close()
        if self.recv_socket:
            self.recv_socket.close()

    def send_packet(self, packet, target_ip):
        self.send_socket.sendto(packet, (target_ip, 0)) # A porta é 0 pois já está especificada no cabeçalho

    # Define um método para receber uma resposta no socket de recebimento
    def receive_response(self):
        return self.recv_socket.recvfrom(65535)[0] # Bloqueia a execução até que algum dado seja recebido

class Scanner:
    def __init__(self, src_ip, target_ip):
        self.src_ip = src_ip
        self.target_ip = target_ip
        self.socket_manager = Socket()

    def validate_ip(ip):
        ip_regex = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_regex, ip):
            return True
        else:
            return False

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

    def port_scan(self, target_port):
        self.socket_manager.open_sockets()

        ip_header = IPHeader(self.src_ip, self.target_ip).create()
        tcp_header = TCPHeader(self.src_ip, self.target_ip, target_port).create()
        packet = ip_header + tcp_header

        self.socket_manager.send_packet(packet, self.target_ip)

        open_ports = []
        closed_ports = []
        filtered_ports = []

        try:
            while True:
                data = self.socket_manager.receive_response() # Captura a resposta
                if data:
                    ip_header_len = (data[0] & 0x0F) * 4 # Verifica o tamanho do cabeçalho IP
                    tcp_header_data = data[ip_header_len:ip_header_len+20] # Extrai apenas a parte do cabeçalho TCP do total recebido
                    
                    # Desempacotar o cabeçalho TCP
                    tcp_header = struct.unpack('!HHLLBBHHH', tcp_header_data)
                    
                    # Extrair campos relevantes do cabeçalho TCP
                    src_port, dest_port, seq, ack_seq, doff_reserved, flags, window, checksum, urg_ptr = tcp_header

                    # Calcular o tamanho do cabeçalho TCP (doff é o número de palavras de 32 bits no cabeçalho)
                    doff = (doff_reserved >> 4) * 4

                    # As flags estão no 13º byte (indexado de zero), então precisamos deslocar o byte
                    flags = flags & 0x3F  # Os últimos 6 bits contêm as flags
                    
                    # Verifique se a porta de destino no cabeçalho TCP corresponde à porta que estamos escaneando
                    if src_port == target_port:
                        if flags == 0x12:  # Verificar flags SYN
                            open_ports.append(target_port)
                        elif flags == 0x14:  # Verificar flags RST
                            closed_ports.append(target_port)
                        break
        except socket.timeout:
            filtered_ports.append(target_port)

        self.socket_manager.close_sockets()

        sys.stdout.write(f"\rEscaneando a porta: {target_port}")
        sys.stdout.flush()
        
        if open_ports:
            return {"port": target_port, "state": "open"}
        elif closed_ports:
            return {"port": target_port, "state": "closed"}
        elif filtered_ports:
            return {"port": target_port, "state": "filtered"}
        else:
            return {"port": target_port, "state": "unknown"}

    def scan_range(self, port_range):
        open_ports = []
        closed_ports = []
        filtered_ports = []
        unknown_ports = []

        start_port, end_port = map(int, port_range.split('-'))
        for port in range(start_port, end_port + 1):
            result = self.port_scan(port)
            if result["state"] == "open":
                open_ports.append(result["port"])
            elif result["state"] == "closed":
                closed_ports.append(result["port"])
            elif result["state"] == "filtered":
                filtered_ports.append(result["port"])
            else:
                unknown_ports.append(result["port"])

        return open_ports, closed_ports, filtered_ports, unknown_ports

# Exemplo de uso
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

        open_ports, closed_ports, filtered_ports, unknown_ports = scanner.scan_range(args.port_range)
        service_name = Service()

        print()
        if open_ports:
            print("\nPortas abertas encontradas:")
            for port in open_ports:
                service = service_name.get_service_name(port, 'tcp')
                print(f"Porta {port}/tcp - Servico: {service}")
        if filtered_ports:
            print("\nPortas filtradas (sem resposta):")
            for port in filtered_ports:
                service = service_name.get_service_name(port, 'tcp')
                print(f"Porta {port}/tcp - Servico: {service}")
        if not (open_ports or filtered_ports or unknown_ports):
            print("\nNenhuma porta aberta ou filtrada encontrada.")


