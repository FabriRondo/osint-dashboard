from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from modules.fingerprint import _fingerprint_from_response, _check_sensitive_paths

# Cuántos hilos usar para chequeos concurrentes
MAX_WORKERS = 10


def _check_single_subdomain(subdomain, deep_scan=False):
    """
    Intenta HTTPS primero, si falla intenta HTTP. Si deep_scan=True,
    además hace fingerprinting de tecnología y chequea rutas sensibles.
    """
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            response = requests.get(url, timeout=4, allow_redirects=True)
            result = {
                "subdomain": subdomain,
                "alive": True,
                "scheme": scheme,
                "status_code": response.status_code,
                "final_url": response.url,
                "technologies": [],
                "exposed_paths": [],
            }

            if deep_scan:
                result["technologies"] = _fingerprint_from_response(response)
                result["exposed_paths"] = _check_sensitive_paths(url)

            return result
        except requests.exceptions.RequestException:
            continue

    return {"subdomain": subdomain, "alive": False}


def check_alive_subdomains(subdomains_data, limit=15, deep_scan_limit=3):
    """
    Verifica cuáles subdominios responden. Corre todo en paralelo con
    ThreadPoolExecutor porque son operaciones de red (I/O-bound): el
    cuello de botella es esperar la respuesta, no la CPU, así que los
    hilos aceleran esto sin problemas de GIL.
    """
    if "error" in subdomains_data:
        return {"error": "No hay subdominios para verificar"}

    subdomains = subdomains_data.get("subdomains", [])
    real_subdomains = [s for s in subdomains if not s.startswith("*.")]
    to_check = real_subdomains[:limit]

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_sub = {executor.submit(_check_single_subdomain, sub): sub for sub in to_check}
        for future in as_completed(future_to_sub):
            results.append(future.result())

    alive_count = sum(1 for r in results if r["alive"])

    alive_subs = [r["subdomain"] for r in results if r["alive"]][:deep_scan_limit]
    if alive_subs:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_sub = {
                executor.submit(_check_single_subdomain, sub, True): sub for sub in alive_subs
            }
            deep_results = {}
            for future in as_completed(future_to_sub):
                deep_results[future_to_sub[future]] = future.result()

        for r in results:
            if r["subdomain"] in deep_results:
                deep = deep_results[r["subdomain"]]
                r["technologies"] = deep.get("technologies", [])
                r["exposed_paths"] = deep.get("exposed_paths", [])

    return {
        "checked": len(to_check),
        "total_found": len(real_subdomains),
        "alive_count": alive_count,
        "deep_scanned": len(alive_subs),
        "details": results
    }

