import requests


def _query_crtsh(domain):
    """
    Intenta crt.sh. Devuelve (set_de_subdominios, None) si funciona,
    o (None, motivo_legible) si falla, para poder mostrar la causa real
    en vez de un error genérico.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.Timeout:
        return None, "timeout (no respondió en 10s)"
    except requests.exceptions.RequestException as e:
        return None, f"error de conexión ({type(e).__name__})"

    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"

    try:
        data = response.json()
    except ValueError:
        return None, "respuesta no era JSON válido"

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            subdomains.add(name.strip().lower())
    return subdomains, None


def _query_certspotter(domain):
    """
    Intenta Certspotter como respaldo. Devuelve (set_de_subdominios, None)
    si funciona, o (None, motivo_legible) si falla.
    """
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.Timeout:
        return None, "timeout (no respondió en 10s)"
    except requests.exceptions.RequestException as e:
        return None, f"error de conexión ({type(e).__name__})"

    if response.status_code == 503:
        return None, "servicio no disponible (free tier caído por alta carga)"
    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"

    try:
        data = response.json()
    except ValueError:
        return None, "respuesta no era JSON válido"

    subdomains = set()
    for entry in data:
        for name in entry.get("dns_names", []):
            subdomains.add(name.strip().lower())
    return subdomains, None

def _query_hackertarget(domain):
    """
    Intenta HackerTarget como tercer respaldo. A diferencia de las otras
    dos fuentes, esta devuelve texto plano (no JSON): una línea por
    resultado, formato "subdominio,ip". Devuelve (set_de_subdominios, None)
    si funciona, o (None, motivo_legible) si falla.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.Timeout:
        return None, "timeout (no respondió en 10s)"
    except requests.exceptions.RequestException as e:
        return None, f"error de conexión ({type(e).__name__})"

    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"

    text = response.text.strip()

    # HackerTarget devuelve mensajes de error como texto plano con 200 OK
    # (no como código de error HTTP), hay que detectarlos a mano
    if "error" in text.lower() or "API count exceeded" in text:
        return None, f"servicio devolvió error: {text[:100]}"

    subdomains = set()
    for line in text.split("\n"):
        if "," in line:
            subdomain = line.split(",")[0].strip().lower()
            if subdomain:
                subdomains.add(subdomain)

    if not subdomains:
        return None, "no devolvió resultados"

    return subdomains, None

    
def get_subdomains(domain):
    """
    Busca subdominios usando crt.sh como fuente principal.
    Si falla, intenta con Certspotter, y si también falla,
    intenta con HackerTarget como último recurso.
    """
    subdomains, crtsh_reason = _query_crtsh(domain)
    source = "crt.sh"

    certspotter_reason = None
    hackertarget_reason = None

    if subdomains is None:
        subdomains, certspotter_reason = _query_certspotter(domain)
        source = "certspotter"

    if subdomains is None:
        subdomains, hackertarget_reason = _query_hackertarget(domain)
        source = "hackertarget"

    if subdomains is None:
        return {
            "error": (
                f"No se pudo consultar ninguna fuente. "
                f"crt.sh: {crtsh_reason}. "
                f"Certspotter: {certspotter_reason}. "
                f"HackerTarget: {hackertarget_reason}. "
                f"Probablemente estén caídos o saturados, probá de nuevo en unos minutos."
            )
        }

    return {"domain": domain, "source": source, "subdomains": sorted(subdomains)}