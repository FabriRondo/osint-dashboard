def calculate_risk_score(subdomains_data, alive_data=None, dns_data=None):
    """
    Calcula un score de riesgo basado en:
    - Palabras sensibles en los nombres de subdominios
    - Cantidad total de subdominios expuestos
    - Si un subdominio sensible está realmente vivo y con qué status code
    - Archivos/rutas sensibles confirmados expuestos (deep scan)
    - Postura de seguridad de email (SPF/DMARC)
    """
    if "error" in subdomains_data:
        return {"score": 0, "level": "N/A", "findings": ["No se pudo calcular: faltan datos de subdominios"]}

    subdomains = subdomains_data.get("subdomains", [])
    findings = []
    score = 0

    sensitive_keywords = ["dev", "staging", "test", "old", "admin", "vpn",
                           "backup", "uat", "traefik", "jenkins", "gitlab",
                           "portainer", "kibana", "grafana"]

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
                score += 25
                findings.append(
                    f"Panel/servicio sensible EXPUESTO Y VIVO: {sub} "
                    f"(contiene '{matched_keyword}', responde {status_code})"
                )
            elif status_code == 200:
                score += 30
                findings.append(
                    f"Panel/servicio sensible EXPUESTO SIN AUTENTICACIÓN: {sub} "
                    f"(contiene '{matched_keyword}', responde 200)"
                )
            else:
                score += 10
                findings.append(f"Subdominio con palabra sensible (no verificado si está vivo): {sub}")

    total = len(subdomains)
    if total > 30:
        score += 20
        findings.append(f"Superficie grande: {total} subdominios expuestos")
    elif total > 15:
        score += 10
        findings.append(f"Superficie moderada: {total} subdominios expuestos")

    if alive_data and "details" in alive_data:
        for entry in alive_data["details"]:
            if not entry.get("alive"):
                continue
            for path in entry.get("exposed_paths", []):
                score += 35
                findings.append(
                    f"Archivo/ruta sensible EXPUESTO en {entry['subdomain']}: {path}"
                )

    if dns_data and "email_security" in dns_data:
        email_sec = dns_data["email_security"]
        if not email_sec.get("spf"):
            score += 10
            findings.append("Dominio sin SPF configurado (facilita email spoofing)")
        if not email_sec.get("dmarc"):
            score += 10
            findings.append("Dominio sin DMARC configurado (facilita email spoofing)")
        elif "DMARC en modo 'p=none' (solo monitorea, no bloquea spoofing)" in email_sec.get("issues", []):
            score += 5
            findings.append("DMARC configurado pero en modo 'p=none' (no bloquea spoofing)")

    if score <= 20:
        level = "BAJO"
    elif score <= 50:
        level = "MEDIO"
    else:
        level = "ALTO"

    return {"score": score, "level": level, "findings": findings}
