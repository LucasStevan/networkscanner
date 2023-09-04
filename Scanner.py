import pyshark
from collections import defaultdict

#Aqui está o dicionário para rastrear o número de pacotes por IP
packet_count = defaultdict(int)

#Limiar de pacotes por segundo para detectar um ataque de flood 
#Deve ser estabelecido pelo time de segurança
threshold = 100

#Essa função verifica o tráfego e detecta atividades suspeitas (Com base na predefinição anterior)
def check_traffic(packet):
    # IP de origem do pacote
    attacker_ip = packet.ip.src

    #Atualize o contador de pacotes para o IP de origem (Cada IP poderá fazer "x" requisições como preestabelecido pelo time de segurança)
    packet_count[attacker_ip] += 1

    #Essa parte verifica se o IP está enviando pacotes acima do limite
    if packet_count[attacker_ip] > threshold:
        print("Ataque detectado do IP:", attacker_ip)
        block_ip(attacker_ip)

#Essa parte tem uma função fictícia para bloquear o IP(Mas não bloqueia realmente, para realizar o Drop consulte o final do código)
def block_ip(ip):
    #Exibirá uma mensagem indicando que o IP foi bloqueado
    print("IP {} bloqueado.".format(ip))

#Agora você deve escolher a interface de rede para capturar o tráfego (A que eu apresento aqui é da VM que estou utilizando)
interface = r"\Device\NPF_{1FE57E6A-E0AB-4A6B-8EEC-5F9D656562E6}" 

#Comece a captura e processe os pacotes
capture = pyshark.LiveCapture(interface=interface)
print("Capturando pacotes na interface {}...".format(interface))

for packet in capture.sniff_continuously():
    try:
        check_traffic(packet)
    except KeyboardInterrupt:
        break


#Para encerrar o processo use CTRL+C



#aqui está o DROP para linux : 

# sudo iptables -A INPUT -s <IP_DO_ATACANTE> -j DROP