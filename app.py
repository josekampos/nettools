from flask import Flask, render_template, request, jsonify
import ipaddress
import dns.resolver
import whois

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/subnet_calculator', methods=['POST'])
def subnet_calculator():
    data = request.json.get('ip')
    try:
        network = ipaddress.ip_network(data, strict=False)
        return jsonify({
            "network": str(network.network_address),
            "netmask": str(network.netmask),
            "broadcast": str(network.broadcast_address),
            "hosts": list(map(str, network.hosts()))
        })
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

@app.route('/dns_lookup', methods=['POST'])
def dns_lookup():
    domain = request.json.get('domain')
    try:
        result = {record_type: [str(record) for record in dns.resolver.resolve(domain, record_type)]
                  for record_type in ['A', 'MX', 'CNAME', 'TXT']}
        return jsonify(result)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return jsonify({"error": "Domain not found"}), 400

@app.route('/whois_lookup', methods=['POST'])
def whois_lookup():
    domain = request.json.get('domain')
    try:
        domain_info = whois.whois(domain)
        return jsonify(domain_info)
    except Exception:
        return jsonify({"error": "WHOIS lookup failed"}), 400

if __name__ == '__main__':
    app.run(debug=True)
