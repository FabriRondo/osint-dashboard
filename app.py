from flask import Flask, request, jsonify
import requests
import whois
import socket

app = Flask(__name__)


def _query_crtsh(domain):
    """Intenta crt.sh. Devuelve set de subdominios o None si falla."""
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            subdomains.add(name.strip().lower())
    return subdomains


def _query_certspotter(domain):
    """Intenta Certspotter como respaldo. Devuelve set de subdominios o None si falla."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    subdomains = set()
    for entry in data:
        for name in entry.get("dns_names", []):
            subdomains.add(name.strip().lower())
    return subdomains


def get_subdomains(domain):
    """
    Busca subdominios usando crt.sh como fuente principal.
    Si crt.sh falla (timeout, 502, etc.), intenta con Certspotter.
    Si ambas fallan, devuelve un error claro.
    """
    subdomains = _query_crtsh(domain)
    source = "crt.sh"

    if subdomains is None:
        subdomains = _query_certspotter(domain)
        source = "certspotter"

    if subdomains is None:
        return {"error": "No se pudo consultar ni crt.sh ni Certspotter. Ambos servicios fallaron."}

    return {"domain": domain, "source": source, "subdomains": sorted(subdomains)}


def get_whois_info(domain):
    """
    Consulta WHOIS del dominio y devuelve datos clave:
    fecha de registro, expiración, y servidores DNS.
    """
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": f"Error consultando WHOIS: {e}"}

    if w.domain_name is None:
        return {"error": "No se encontraron datos WHOIS para este dominio"}

    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    expiration_date = w.expiration_date
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    return {
        "registrar": w.registrar,
        "creation_date": str(creation_date) if creation_date else None,
        "expiration_date": str(expiration_date) if expiration_date else None,
        "name_servers": w.name_servers,
    }
def calculate_risk_score(subdomains_data, alive_data=None):
    """
    Calcula un score de riesgo basado en:
    - Palabras sensibles en los nombres de subdominios
    - Cantidad total de subdominios expuestos
    - Si un subdominio sensible está realmente vivo y responde con
      401/403 (existe y está protegido, o sea, hay algo real ahí)
    """
    if "error" in subdomains_data:
        return {"score": 0, "level": "N/A", "findings": ["No se pudo calcular: faltan datos de subdominios"]}

    subdomains = subdomains_data.get("subdomains", [])
    findings = []
    score = 0

    sensitive_keywords = ["dev", "staging", "test", "old", "admin", "vpn",
                           "backup", "uat", "traefik", "jenkins", "gitlab",
                           "portainer", "kibana", "grafana"]

    # armamos un diccionario rápido de subdominio -> status_code si tenemos alive_check
    alive_lookup = {}
    if alive_data and "details" in alive_data:
        for entry in alive_data["details"]:
            if entry.get("alive"):
                alive_lookup[entry["subdomain"]] = entry.get("status_code")

    for sub in subdomains:
        matched_keyword = None
        for keyword in sensitive_keywords:
            if keyword in sub.lower():
                matched_keyword = keyword
                break

        if matched_keyword:
            status_code = alive_lookup.get(sub)

            if status_code in (401, 403):
                # está vivo, protegido, y es un nombre sensible = riesgo alto real
                score += 25
                findings.append(
                    f"Panel/servicio sensible EXPUESTO Y VIVO: {sub} "
                    f"(contiene '{matched_keyword}', responde {status_code})"
                )
            elif status_code == 200:
                # vivo y accesible sin login = riesgo aún mayor
                score += 30
                findings.append(
                    f"Panel/servicio sensible EXPUESTO SIN AUTENTICACIÓN: {sub} "
                    f"(contiene '{matched_keyword}', responde 200)"
                )
            else:
                # solo aparece en certificados, no confirmamos que esté vivo
                score += 10
                findings.append(f"Subdominio con palabra sensible (no verificado si está vivo): {sub}")

    total = len(subdomains)
    if total > 30:
        score += 20
        findings.append(f"Superficie grande: {total} subdominios expuestos")
    elif total > 15:
        score += 10
        findings.append(f"Superficie moderada: {total} subdominios expuestos")

    if score <= 20:
        level = "BAJO"
    elif score <= 50:
        level = "MEDIO"
    else:
        level = "ALTO"

    return {"score": score, "level": level, "findings": findings}

    return {"score": score, "level": level, "findings": findings}

def check_alive_subdomains(subdomains_data, limit=20):
    """
    Para cada subdominio (sin contar wildcards), verifica si responde
    por HTTPS o HTTP. Limita la cantidad para no demorar demasiado.
    """
    if "error" in subdomains_data:
        return {"error": "No hay subdominios para verificar"}

    subdomains = subdomains_data.get("subdomains", [])

    # sacamos los wildcards (*.algo.com) porque no son URLs reales
    real_subdomains = [s for s in subdomains if not s.startswith("*.")]

    # limitamos la cantidad para que la demo no tarde una eternidad
    to_check = real_subdomains[:limit]

    results = []
    for sub in to_check:
        status = _check_single_subdomain(sub)
        results.append(status)

    alive_count = sum(1 for r in results if r["alive"])

    return {
        "checked": len(to_check),
        "total_found": len(real_subdomains),
        "alive_count": alive_count,
        "details": results
    }

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


def scan_ports(hostname, timeout=1):
    """
    Escanea un set de puertos comunes contra un hostname.
    Devuelve la lista de puertos abiertos encontrados.
    """
    open_ports = []

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": f"No se pudo resolver {hostname}"}

    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            open_ports.append({"port": port, "service": service})

    return {"hostname": hostname, "ip": ip, "open_ports": open_ports}

def _check_single_subdomain(subdomain):
    """Intenta HTTPS primero, si falla intenta HTTP. Devuelve estado."""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            response = requests.get(url, timeout=4, allow_redirects=True)
            return {
                "subdomain": subdomain,
                "alive": True,
                "scheme": scheme,
                "status_code": response.status_code,
                "final_url": response.url
            }
        except requests.exceptions.RequestException:
            continue

    return {"subdomain": subdomain, "alive": False}



@app.route("/scan")
def scan():
    domain = request.args.get("domain")

    if not domain:
        return jsonify({"error": "Falta el parámetro ?domain=ejemplo.com"}), 400

    subdomains_result = get_subdomains(domain)
    whois_result = get_whois_info(domain)
    alive_result = check_alive_subdomains(subdomains_result)
    risk_result = calculate_risk_score(subdomains_result, alive_result)

    return jsonify({
        "domain": domain,
        "subdomains": subdomains_result,
        "whois": whois_result,
        "risk": risk_result,
        "alive_check": alive_result
    })

@app.route("/portscan")
def portscan():
    hostname = request.args.get("host")

    if not hostname:
        return jsonify({"error": "Falta el parámetro ?host=ejemplo.com"}), 400

    result = scan_ports(hostname)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)