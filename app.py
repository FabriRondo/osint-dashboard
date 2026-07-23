from flask import Flask, request, jsonify
import requests
import whois

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


@app.route("/scan")
def scan():
    domain = request.args.get("domain")

    if not domain:
        return jsonify({"error": "Falta el parámetro ?domain=ejemplo.com"}), 400

    subdomains_result = get_subdomains(domain)
    whois_result = get_whois_info(domain)

    return jsonify({
        "domain": domain,
        "subdomains": subdomains_result,
        "whois": whois_result
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)