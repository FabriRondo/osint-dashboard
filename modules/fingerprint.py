import requests

# Rutas comunes que no deberían estar accesibles públicamente
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.sql",
    "/wp-config.php.bak",
    "/.htaccess",
    "/config.json",
    "/config.php.bak",
    "/.aws/credentials",
    "/docker-compose.yml",
]

# Patrones simples para identificar tecnologías a partir del HTML devuelto
TECH_HTML_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla": ["/media/jui/", "joomla"],
    "Drupal": ["sites/default/files", "drupal.js"],
    "phpMyAdmin": ["phpmyadmin"],
    "Swagger / OpenAPI": ["swagger-ui", "swagger-ui.html"],
    "Grafana": ["grafana"],
    "Kibana": ["kbn-injected-metadata"],
    "Jenkins": ["jenkins", "Dashboard [Jenkins]"],
    "GitLab": ["gitlab"],
}

FINGERPRINT_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def _fingerprint_from_response(response):
    """
    Extrae tecnologías detectadas a partir de headers HTTP y del cuerpo HTML.
    Devuelve una lista de strings, ej: ["nginx/1.18.0", "WordPress"].
    """
    detected = set()

    for header in FINGERPRINT_HEADERS:
        value = response.headers.get(header)
        if value:
            detected.add(value.strip())

    content_type = response.headers.get("Content-Type", "")
    if "html" in content_type.lower():
        body_sample = response.text[:20000].lower()
        for tech, patterns in TECH_HTML_SIGNATURES.items():
            if any(pattern.lower() in body_sample for pattern in patterns):
                detected.add(tech)

    return sorted(detected)


def _check_sensitive_paths(base_url, timeout=1.5):
    """
    Prueba rutas sensibles conocidas contra el subdominio. Solo cuenta
    como "expuesto" un 200 real (compara antes con una ruta que casi
    seguro no existe, para descartar servidores que devuelven 200 para todo).
    """
    exposed = []

    probe_path = "/__nonexistent_probe_check__"
    try:
        probe = requests.get(base_url + probe_path, timeout=timeout, allow_redirects=False)
        soft_404 = probe.status_code == 200
    except requests.exceptions.RequestException:
        soft_404 = False

    if soft_404:
        return exposed

    for path in SENSITIVE_PATHS:
        try:
            resp = requests.get(base_url + path, timeout=timeout, allow_redirects=False)
            if resp.status_code == 200:
                exposed.append(path)
        except requests.exceptions.RequestException:
            continue

    return exposed
