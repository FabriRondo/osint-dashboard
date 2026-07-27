import os

from flask import Flask, request, jsonify, render_template

from modules.subdomains import get_subdomains
from modules.whois_lookup import get_whois_info
from modules.dns_records import get_dns_records
from modules.alive_check import check_alive_subdomains
from modules.risk_score import calculate_risk_score
from modules.port_scan import scan_ports

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan")
def scan():
    domain = request.args.get("domain")

    if not domain:
        return jsonify({"error": "Falta el parámetro ?domain=ejemplo.com"}), 400

    subdomains_result = get_subdomains(domain)
    whois_result = get_whois_info(domain)
    dns_result = get_dns_records(domain)
    alive_result = check_alive_subdomains(subdomains_result)
    risk_result = calculate_risk_score(subdomains_result, alive_result, dns_result)

    return jsonify({
        "domain": domain,
        "subdomains": subdomains_result,
        "whois": whois_result,
        "dns": dns_result,
        "risk": risk_result,
        "alive_check": alive_result
    })


@app.route("/portscan")
def portscan():
    hostname = request.args.get("host")

    if not hostname:
        return jsonify({"error": "Falta el parámetro ?host=ejemplo.com"}), 400

    result = scan_ports(hostname)
    return jsonify(result)


if __name__ == "__main__":
    # DEBUG solo si se define explícitamente FLASK_DEBUG=1
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)