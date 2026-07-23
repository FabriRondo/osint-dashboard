# OSINT Domain Intelligence Dashboard

Herramienta en Python/Flask que centraliza reconocimiento pasivo (OSINT) sobre un dominio: enumera subdominios, verifica cuáles están activos, consulta WHOIS, y calcula un score de riesgo basado en reglas propias.

## Qué hace

- **Enumeración de subdominios**: consulta Certificate Transparency logs vía crt.sh, con fallback automático a Certspotter si crt.sh falla (es un servicio comunitario con uptime inconsistente).
- **Verificación de vida**: para cada subdominio encontrado, chequea si responde por HTTP/HTTPS y con qué código de estado.
- **WHOIS lookup**: fecha de registro, expiración, name servers, registrador.
- **Risk scoring**: heurística propia que cruza nombres sensibles (dev, staging, admin, vpn, traefik, etc.) con si el subdominio está realmente vivo, para distinguir ruido de hallazgos reales.

## Ejemplo de uso

```bash
curl "http://127.0.0.1:5000/scan?domain=ejemplo.com"
```

## Stack

Python, Flask, requests, python-whois

## Limitaciones conocidas

- WHOIS no funciona con dominios `.ar` (NIC Argentina usa un protocolo distinto al estándar).
- crt.sh puede estar caído (es común); por eso el fallback a Certspotter.
- El alive-check está limitado a los primeros 20 subdominios para no demorar la respuesta.

## Por qué lo hice

Portfolio para roles de SOC Analyst / Blue Team. El objetivo es mostrar herramientas de reconocimiento y triage propias, no solo consumo de APIs de terceros.
