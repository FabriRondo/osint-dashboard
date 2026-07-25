import requests


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
