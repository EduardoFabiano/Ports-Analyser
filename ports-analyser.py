import socket
import sys
import subprocess
import os
def escanear_porta(ip, porta):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    resultado = sock.connect_ex((ip, porta))
    sock.close()
    return resultado == 0
def obter_servico(porta):
    servicos_comuns = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 3306: "MySQL", 3389: "RDP"
    }
    return servicos_comuns.get(porta, "Serviço Desconhecido")
def obter_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"
def escanear_rede_local():
    ip_local = obter_ip_local()
    if ip_local == "127.0.0.1":
        print("Erro: Não foi possível identificar sua rede local. Verifique o Wi-Fi.")
        return []
    partes = ip_local.split('.')
    base_rede = f"{partes[0]}.{partes[1]}.{partes[2]}."
    print(f"\n[+] Seu IP local: {ip_local}")
    print(f"[+] Escaneando a rede {base_rede}0/24... Por favor, aguarde.")
    ips_ativos = []
    fnull = open(os.devnull, 'w')
    for i in range(1, 255):
        ip_alvo = base_rede + str(i)
        comando = ["ping", "-c", "1", "-W", "1", ip_alvo]
        resultado = subprocess.call(comando, stdout=fnull, stderr=fnull)
        if resultado == 0:
            print(f"[ ATIVO ] -> {ip_alvo}")
            ips_ativos.append(ip_alvo)
    fnull.close()
    print(f"\n[+] Varredura concluída. {len(ips_ativos)} dispositivos encontrados.")
    return ips_ativos
def analisar_protocolos_frageis(ip):
    protocolos_inseguros = {
        21: "FTP (Credenciais e arquivos transmitidos em texto puro)",
        23: "Telnet (Totalmente inseguro, comandos enviados sem criptografia)",
        69: "TFTP (Sem autenticação, usado para transferir arquivos de configs)",
        80: "HTTP (Tráfego web sem criptografia, sujeito a interceptação)",
        139: "NetBIOS (Antigo protocolo Windows, frequentemente visado)",
        445: "SMBv1/v2 (Porta vulnerável a exploits críticos como EternalBlue)"
    }
    print(f"\nProcurando serviços frágeis em {ip}...")
    encontrados = 0
    for porta, motivo in protocolos_inseguros.items():
        if escanear_porta(ip, porta):
            print(f"[ ALERTA ] Porta {porta} aberta: {motivo}")
            encontrados += 1
    if encontrados == 0:
        print("[+] Nenhum protocolo visivelmente frágil foi detectado nesta análise básica.")
def menu():
    while True:
        print("         ANALISADOR DE PORTAS & REDE")
        print("1. Escanear portas principais (Apenas ABERTAS)")
        print("2. Escanear uma porta específica")
        print("3. Descobrir dispositivos no Wi-Fi (Scanner de Rede)")
        print("4. Analisar protocolos frágeis/inseguros no alvo")
        print("5. Sair")
        opcao = input("Escolha uma opção (1-5): ").strip()
        if opcao == "5":
            print("\nSaindo do programa. Até logo!")
            sys.exit()
        elif opcao in ("1", "2", "4"):
            alvo = input("\nDigite o IP ou domínio do alvo: ").strip()
            try:
                ip_alvo = socket.gethostbyname(alvo)
                print(f"Analisando o alvo: {alvo} [{ip_alvo}]")
            except socket.gaierror:
                print("Erro: Não foi possível resolver o host.")
                continue
            if opcao == "1":
                portas_principais = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]
                print("\nIniciando varredura silenciosa...")
                portas_abertas = 0
                for porta in portas_principais:
                    if escanear_porta(ip_alvo, porta):
                        servico = obter_servico(porta)
                        print(f"[ ABERTA ] Porta {porta} ({servico})")
                        portas_abertas += 1
                print(f"\nVarredura concluída. {portas_abertas} portas abertas.")
            elif opcao == "2":
                try:
                    porta = int(input("Digite o número da porta: "))
                    if porta < 1 or porta > 65535: continue
                except ValueError: continue
                if escanear_porta(ip_alvo, porta):
                    print(f"Resultado: A porta {porta} está [ ABERTA ].")
                else:
                    print(f"Resultado: A porta {porta} está [ FECHADA ].")
            elif opcao == "4":
                analisar_protocolos_frageis(ip_alvo)
        elif opcao == "3":
            escanear_rede_local()
        else:
            print("Opção inválida. Tente novamente.")
if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\nPrograma interrompido. Saindo...")
        sys.exit()
