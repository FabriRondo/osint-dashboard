# OSINT Domain Intelligence Dashboard

Herramienta en Python/Flask que centraliza reconocimiento (OSINT) sobre un dominio: enumera subdominios, verifica cuáles están activos, consulta WHOIS y DNS, evalúa postura de seguridad de email (SPF/DMARC), y calcula un score de riesgo basado en reglas propias.

## ⚠️ Uso responsable

Esta herramienta realiza reconocimiento activo (no solo pasivo): verifica si subdominios responden, hace fingerprinting de tecnologías, y prueba rutas conocidas como sensibles (`.git/config`, `.env`, backups, etc).

**Usar únicamente contra:**
- Dominios propios
- `example.com` (dominio reservado por IANA para pruebas)
- Programas de bug bounty que autoricen explícitamente ese scope (HackerOne, Bugcrowd)

No usar contra dominios de terceros sin autorización explícita. El escaneo de rutas sensibles y el fingerprinting activo generan tráfico identificable en los logs del servidor objetivo, y hacerlo sin permiso puede constituir acceso no autorizado según la legislación aplicable (en Argentina, Ley 26.388).

## Por qué

Automatiza varias tareas de reconocimiento que un analista SOC / pentester junior suele hacer manualmente y por separado (buscar subdominios, verificar cuáles responden, chequear configuración DNS/email, WHOIS), centralizando todo en un solo reporte con un score de riesgo.

## Cómo funciona

1. **Enumeración de subdominios** — consulta tres fuentes en cascada: crt.sh (certificados TLS) como principal, con fallback automático a Certspotter y luego a HackerTarget si las anteriores fallan. Filtra resultados inválidos (direcciones de email o dominios ajenos que a veces se cuelan en los certificados).
2. **Verificación de vida** — chequea en paralelo (ThreadPoolExecutor) cuáles subdominios responden por HTTP/HTTPS.
3. **Deep scan** — sobre una muestra de subdominios activos, hace fingerprinting de tecnología (headers, patrones HTML) y prueba rutas sensibles conocidas.
4. **DNS y seguridad de email** — resuelve registros A/AAAA/MX/TXT/NS y evalúa configuración de SPF y DMARC.
5. **WHOIS** — datos de registro del dominio, con timeout controlado (la librería `python-whois` puede colgarse sin esto).
6. **Port scan** — escaneo de puertos comunes, con protección anti-SSRF (rechaza IPs privadas/internas).
7. **Risk score** — combina todos los hallazgos en un score (BAJO/MEDIO/ALTO). Las coincidencias de "palabra sensible en el nombre" tienen un techo máximo de puntos (para no inflar el score en dominios grandes con muchos ambientes dev/test legítimos), mientras que hallazgos graves confirmados (archivos sensibles expuestos) no tienen límite.

## Requisitos

- Python 3.10+
- Flask, requests, dnspython, python-whois

## Instalación

```bash
git clone https://github.com/FabriRondo/osint-dashboard.git
cd osint-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
python3 app.py
```

Abrir `http://127.0.0.1:5000` en el navegador, o consultar directamente:

```bash
curl "http://127.0.0.1:5000/scan?domain=example.com"
curl "http://127.0.0.1:5000/portscan?host=example.com"
```

## Estructura del proyecto

```
osint-dashboard/
├── app.py                  # Rutas Flask
├── modules/
│   ├── subdomains.py       # Enumeración de subdominios (crt.sh / Certspotter)
│   ├── whois_lookup.py     # Consulta WHOIS con timeout
│   ├── dns_records.py      # Registros DNS + SPF/DMARC
│   ├── fingerprint.py      # Fingerprinting de tecnología + rutas sensibles
│   ├── alive_check.py      # Verificación de subdominios activos (paralelo)
│   ├── port_scan.py        # Escaneo de puertos con protección SSRF
│   └── risk_score.py       # Cálculo de score de riesgo
├── templates/
└── requirements.txt
```

## Limitaciones

- El deep scan (fingerprinting + rutas sensibles) se aplica solo a una muestra de subdominios activos, elegidos según orden de respuesta de red — no es determinístico entre corridas.
- La detección de rutas sensibles se basa en status code 200; puede haber falsos positivos por páginas de error personalizadas (soft-404) no estándar.
- Sujeto a los límites de cuota de crt.sh / Certspotter.
- No reemplaza un análisis manual: los findings de "riesgo" son heurísticas propias, no un veredicto definitivo.

## Próximas mejoras

- Exportar historial a CSV.
- Rate limiting configurable para reducir el volumen de requests contra el objetivo.
- Modo "solo pasivo" que desactive fingerprinting y chequeo de rutas sensibles.
