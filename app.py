from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from scanner import WiFiScanner
import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure Gemini
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-2.5-flash')

scanner = WiFiScanner()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Scan for Wi-Fi networks"""
    data = request.json
    trusted_ssids = data.get('trusted_ssids', [])
    
    # Scan networks
    networks = scanner.scan_networks()
    
    # Check for errors
    if networks and isinstance(networks[0], dict) and 'error' in networks[0]:
        return jsonify({
            'success': False,
            'error': networks[0]['error']
        })
    
    # Identify rogue APs
    rogue_aps = scanner.identify_rogue_aps(networks, trusted_ssids)
    
    # Security statistics
    encryption_counts = {
        'Open': 0,
        'WEP': 0,
        'WPA': 0,
        'WPA2': 0,
        'WPA3': 0
    }
    
    for network in networks:
        security = network.get('security', 'Unknown')
        for enc in encryption_counts:
            if enc.lower() in security.lower():
                encryption_counts[enc] += 1
                break
    
    # Get AI insights
    ai_insights = get_ai_insights(networks, rogue_aps)
    
    return jsonify({
        'success': True,
        'networks': networks,
        'count': len(networks),
        'rogue_aps': rogue_aps,
        'rogue_count': len(rogue_aps),
        'encryption_stats': encryption_counts,
        'ai_insights': ai_insights
    })

def get_ai_insights(networks, rogue_aps):
    """Get AI-powered security insights"""
    if not networks:
        return "No networks found. Make sure Wi-Fi is enabled and try again."
    
    # Summarize for AI (avoid sending too much data)
    summary = []
    for net in networks[:15]:
        summary.append(f"{net.get('ssid', 'Hidden')} - {net.get('security', 'Unknown')}")
    
    prompt = f"""
Wi-Fi Scan Results:
- Total networks: {len(networks)}
- Rogue APs detected: {len(rogue_aps)}
- Sample networks: {', '.join(summary)}

Provide a brief security analysis (2-3 sentences) about:
1. Overall security posture
2. Key risks detected
3. Quick recommendations
"""
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"AI error: {e}")
        return f"Found {len(networks)} networks, {len(rogue_aps)} potential rogue APs detected. Consider securing your Wi-Fi with WPA2/WPA3 encryption."

if __name__ == '__main__':
    print("\n" + "="*50)
    print("📡 Wi-Fi Security Scanner")
    print("="*50)
    print("📍 Running on: http://localhost:5005")
    print("="*50 + "\n")
    app.run(debug=True, port=5005)