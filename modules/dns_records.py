import dns.resolver


def get_dns_records(domain, timeout=8):
    """
    Resuelve los registros DNS más relevantes del dominio (A, AAAA, MX, TXT, NS)
    y evalúa la postura de seguridad de email a partir de SPF (TXT del dominio)
    y DMARC (TXT de _dmarc.<domain>, que es donde realmente vive ese registro).

    Usa el resolver del sistema primero; si falla por timeout u otro error de
    red (no si es NoAnswer/NXDOMAIN, que son respuestas legítimas), reintenta
    contra resolvers públicos (Google 8.8.8.8, Cloudflare 1.1.1.1) antes de
    darse por vencido.
    """
    resolvers_to_try = [
        None,  # None = resolver del sistema (default)
        ["8.8.8.8", "8.8.4.4"],
        ["1.1.1.1", "1.0.0.1"],
    ]

    def _resolve_with_fallback(name, rtype):
        """Intenta resolver contra el sistema y, si falla por red, contra públicos.
        Para cada resolver, prueba UDP y después TCP antes de pasar al siguiente."""
        last_nxdomain = False
        for nameservers in resolvers_to_try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            if nameservers:
                resolver.nameservers = nameservers

            for use_tcp in (False, True):
                try:
                    answers = resolver.resolve(name, rtype, tcp=use_tcp)
                    return [str(r) for r in answers], None
                except dns.resolver.NoAnswer:
                    return [], None  # respuesta legítima: el registro no existe
                except dns.resolver.NXDOMAIN:
                    last_nxdomain = True
                    break
                except (dns.exception.Timeout, Exception):
                    continue

        if last_nxdomain:
            return None, "NXDOMAIN"
        return [], "no_answer_from_any_resolver"

    records = {}
    resolution_errors = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
        result, error = _resolve_with_fallback(domain, rtype)
        if error == "NXDOMAIN":
            return {"error": f"El dominio {domain} no existe (NXDOMAIN)"}
        records[rtype] = result if result is not None else []
        if error:
            resolution_errors[rtype] = error

    # DMARC no vive en el TXT del dominio raíz, sino en _dmarc.<domain>.
    # NXDOMAIN acá es normal (significa "no configuraron DMARC"), no un
    # error real de resolución, así que no lo sumamos a resolution_errors.
    dmarc_txt, dmarc_error = _resolve_with_fallback(f"_dmarc.{domain}", "TXT")
    dmarc_txt = dmarc_txt or []
    if dmarc_error and dmarc_error != "NXDOMAIN":
        resolution_errors["DMARC"] = dmarc_error

    email_security = _check_email_security(records.get("TXT", []), dmarc_txt)

    result = {"records": records, "email_security": email_security}
    if resolution_errors:
        result["resolution_warnings"] = resolution_errors
    return result


def _check_email_security(spf_txt_records, dmarc_txt_records):
    """
    Evalúa SPF (en el TXT del dominio) y DMARC (en _dmarc.<domain>).
    """
    result = {"spf": False, "dmarc": False, "issues": []}

    for txt in spf_txt_records:
        txt_lower = txt.lower()
        if "v=spf1" in txt_lower:
            result["spf"] = True
            if "-all" not in txt_lower and "~all" not in txt_lower:
                result["issues"].append("SPF configurado sin hard/soft fail (falta -all o ~all)")
            break

    for txt in dmarc_txt_records:
        txt_lower = txt.lower()
        if "v=dmarc1" in txt_lower:
            result["dmarc"] = True
            if "p=none" in txt_lower:
                result["issues"].append("DMARC en modo 'p=none' (solo monitorea, no bloquea spoofing)")
            break

    if not result["spf"]:
        result["issues"].append("No se encontró registro SPF")
    if not result["dmarc"]:
        result["issues"].append("No se encontró registro DMARC")

    return result

