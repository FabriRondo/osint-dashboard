import threading

import whois


def get_whois_info(domain, timeout=8):
    """
    Consulta WHOIS del dominio y devuelve datos clave: fecha de registro,
    expiración, y servidores DNS.

    OJO: la librería python-whois no tiene forma nativa de limitar cuánto
    tarda — si el servidor WHOIS no responde, puede colgarse indefinidamente
    sin lanzar ninguna excepción. Por eso la corremos en un hilo aparte y le
    ponemos un timeout externo con thread.join(timeout): si no terminó a
    tiempo, abandonamos y devolvemos error, en vez de dejar la request de
    Flask esperando para siempre.
    """
    result_holder = {}

    def _run():
        try:
            result_holder["w"] = whois.whois(domain)
        except Exception as e:
            result_holder["error"] = f"{type(e).__name__}: {e}"

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        return {"error": f"WHOIS no respondió en {timeout}s (timeout)"}

    if "error" in result_holder:
        return {"error": f"Error consultando WHOIS: {result_holder['error']}"}

    w = result_holder.get("w")
    if w is None or w.domain_name is None:
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

