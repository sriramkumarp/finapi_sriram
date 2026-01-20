from flask import Flask, request, jsonify
import os
from azure.storage.blob import BlobServiceClient
from datetime import timezone
import time
app = Flask(__name__)

# ----------- Root Route for Azure ----------
@app.route("/")
def home():
    return "Hello! Flask API running on Azure."

# ----------- Price Endpoints -----------

@app.route("/api/retrieve-price", methods=["GET"])
def retrieve_price():
    symbol = request.args.get("symbol", "").upper()
    if not symbol:
        return jsonify({"error": "Symbol parameter is required"}), 400
    return jsonify({
        "symbol": symbol,
        "price": 123.45,
        "name": f"Sample Name for {symbol}"
    })

@app.route("/api/update-price", methods=["PUT"])
def update_price():
    data = request.json
    symbol = request.args.get("symbol", "").upper()
    if not symbol or "price" not in data:
        return jsonify({"error": "Symbol and price required"}), 400
    return jsonify({"status": "success", "message": f"Price for {symbol} updated to {data['price']}."})

@app.route("/api/delete-price", methods=["DELETE"])
def delete_price():
    symbol = request.args.get("symbol", "").upper()
    if not symbol:
        return jsonify({"error": "Symbol parameter is required"}), 400
    return jsonify({"status": "success", "message": f"Price for {symbol} deleted."})

# ----------- Client Valuation -----------

@app.route("/api/client-valuation", methods=["GET"])
def client_valuation():
    valuations = [
        {"ClientCode": "C001", "ClientName": "John Doe", "TotalValuation": 100000.00},
        {"ClientCode": "C002", "ClientName": "Jane Smith", "TotalValuation": 150000.00}
    ]
    return jsonify(valuations)

# ----------- Portfolio CRUD -----------

@app.route("/api/portfolio", methods=["POST"])
def create_portfolio():
    data = request.json
    portfolio_id = data.get("PortfolioID")
    client_code = data.get("ClientCode")
    industry_type = data.get("IndustryType")
    if not (portfolio_id and client_code and industry_type):
        return jsonify({"error": "Missing PortfolioID, ClientCode or IndustryType"}), 400
    return jsonify({"status": "success", "message": f"Portfolio {portfolio_id} created."})

@app.route("/api/portfolio/<portfolio_id>", methods=["GET"])
def get_portfolio(portfolio_id):
    portfolio = {
        "PortfolioID": portfolio_id,
        "ClientCode": "C001",
        "IndustryType": "Technology",
        "Positions": [
            {"PositionID": f"{portfolio_id}_POS001", "Ticker": "AAPL", "Quantity": 50},
            {"PositionID": f"{portfolio_id}_POS002", "Ticker": "MSFT", "Quantity": 30}
        ]
    }
    return jsonify(portfolio)

@app.route("/api/portfolio/<portfolio_id>", methods=["PUT"])
def update_portfolio(portfolio_id):
    data = request.json
    return jsonify({"status": "success", "message": f"Portfolio {portfolio_id} updated with new data."})

@app.route("/api/portfolio/<portfolio_id>", methods=["DELETE"])
def delete_portfolio(portfolio_id):
    return jsonify({"status": "success", "message": f"Portfolio {portfolio_id} deleted."})

@app.route("/api/list-reports", methods=["GET"])
def list_csv_reports():
    try:
        connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", 'https://storage-fallback-if-not-set')
        container_name = "reports"

        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client(container_name)

        reports = []
        for blob in container_client.list_blobs():
            if blob.name.lower().endswith(".csv"):
                reports.append({
                    "report_title": blob.name,
                    "upload_date": blob.last_modified.astimezone(timezone.utc).isoformat()
                })

        return jsonify({"reports": reports})

    except KeyError as e:
        return jsonify({"error": f"Missing environment variable: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/api/slow-endpoint')
def slow_endpoint():
    time.sleep(5)
    return "This was a slow response after 5 seconds"
@app.route('/high-cpu')
def high_cpu():
    import math
    # Simulate CPU load by calculating primes
    n = 50000
    primes = []
    for num in range(2, n):
        is_prime = True
        for i in range(2, int(math.sqrt(num)) + 1):
            if num % i == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
    return f"Calculated {len(primes)} prime numbers."

@app.route('/high-memory')
def high_memory():
    # Simulate memory load
    data = ['x' * 1024 * 1024] * 500  # ~500MB in-memory array
    time.sleep(5)
    return f"Allocated {len(data)} MB of memory temporarily."
# IMPORTANT: No app.run() when deploying to Azure Linux App Service
