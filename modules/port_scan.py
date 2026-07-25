import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_WORKERS = 10

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


def _is_safe_public_ip(ip):
    """
    Bloquea IPs privadas, loopback, link-local y multicast para evitar
    que el portscan se use como SSRF hacia la propia infraestructura.
    """
    addr = ipaddress.ip_address(ip)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _check_single_port(ip, port, service, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
    finally:
        sock.close()
    return {"port": port, "service": service} if result == 0 else None


def scan_ports(hostname, timeout=1):
    """
    Escanea puertos comunes contra un hostname, en paralelo.
    Rechaza hostnames que resuelvan a IPs privadas/internas (protección SSRF).
    """
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": f"No se pudo resolver {hostname}"}

    if not _is_safe_public_ip(ip):
        return {"error": "No se permite escanear direcciones IP privadas, loopback o internas"}

    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(_check_single_port, ip, port, service, timeout)
            for port, service in COMMON_PORTS.items()
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda p: p["port"])

    return {"hostname": hostname, "ip": ip, "open_ports": open_ports}
