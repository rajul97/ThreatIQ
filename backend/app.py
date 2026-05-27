import os
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from dotenv import load_dotenv

from analyzer import analyze_threat
from validator import validate_ioc
from pdf_generator import generate_pdf
from sigma_generator import generate_sigma
from ioc_extractor import extract_iocs
from database import Database
from auth import auth_bp
from logger import setup_logger, log_request, log_request_start

load_dotenv()

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'frontend')

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
CORS(app, origins='*')

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'threatiq-secret-key-change-in-production-32chars')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)   # FIX: was int 86400, must be timedelta

jwt = JWTManager(app)
db = Database()
logger = setup_logger()

app.before_request(log_request_start)
app.after_request(log_request)

app.register_blueprint(auth_bp, url_prefix='/api')


@app.route('/')
def serve_login():
    return send_from_directory(FRONTEND_DIR, 'login.html')


@app.route('/dashboard')
def serve_dashboard():
    return send_from_directory(FRONTEND_DIR, 'index.html')


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'online',
        'tool': 'ThreatIQ',
        'version': '1.0.0',
        'timestamp': datetime.now(timezone.utc).isoformat()   # FIX: utcnow() deprecated
    }), 200


@app.route('/api/analyze', methods=['POST'])
@jwt_required()
def analyze():
    try:
        user_id = int(get_jwt_identity())   # FIX: JWT returns string, DB needs int
        data = request.get_json()

        if not data or 'input' not in data:
            return jsonify({'error': 'No input provided'}), 400

        raw_input = data.get('input', '').strip()
        input_type = data.get('input_type', 'auto')

        if not raw_input:
            return jsonify({'error': 'Input cannot be empty'}), 400

        # FIX: input length guard
        if len(raw_input) > 50000:
            return jsonify({'error': 'Input too large (max 50,000 characters)'}), 400

        logger.info(f"Analysis started | user={user_id} | type={input_type}")

        iocs = extract_iocs(raw_input)
        validation_results = validate_ioc(iocs)
        analysis = analyze_threat(raw_input, input_type, iocs, validation_results)

        # FIX: set ioc_validation BEFORE save so it gets stored in the iocs table
        analysis['ioc_validation'] = validation_results

        analysis_id = db.save_analysis(
            user_id=user_id,
            input_data=raw_input,
            input_type=input_type,
            result=analysis
        )

        analysis['analysis_id'] = analysis_id
        analysis['timestamp'] = datetime.now(timezone.utc).isoformat()

        logger.info(f"Analysis complete | id={analysis_id} | threat={analysis.get('threat_level')}")

        return jsonify(analysis), 200

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Analysis failed', 'detail': str(e)}), 500


@app.route('/api/generate-pdf', methods=['POST'])
@jwt_required()
def generate_pdf_report():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # generate_pdf() returns raw bytes — wrap in BytesIO for send_file
        pdf_bytes  = generate_pdf(data)
        pdf_buffer = io.BytesIO(pdf_bytes)
        pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"ThreatIQ_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}", exc_info=True)
        return jsonify({'error': 'PDF generation failed', 'detail': str(e)}), 500


@app.route('/api/generate-sigma', methods=['POST'])
@jwt_required()
def generate_sigma_rules():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        ttps = data.get('ttps', [])

        if not ttps:
            return jsonify({'error': 'No TTPs provided'}), 400

        sigma_rules = generate_sigma(ttps)

        return jsonify({
            'sigma_rules': sigma_rules,
            'count': len(sigma_rules),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.error(f"SIGMA generation error: {str(e)}", exc_info=True)
        return jsonify({'error': 'SIGMA generation failed', 'detail': str(e)}), 500


@app.route('/api/validate-ioc', methods=['GET'])
@jwt_required()
def validate_single_ioc():
    try:
        ioc_value = request.args.get('value', '').strip()

        if not ioc_value:
            return jsonify({'error': 'IOC value required'}), 400

        # FIX: was {ioc_type: [ioc_value]} which broke with type=auto
        iocs = extract_iocs(ioc_value)
        result = validate_ioc(iocs)

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"IOC validation error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Validation failed', 'detail': str(e)}), 500


@app.route('/api/history', methods=['GET'])
@jwt_required()
def get_history():
    try:
        user_id = int(get_jwt_identity())   # FIX: cast to int
        limit = min(request.args.get('limit', 20, type=int), 100)  # FIX: cap at 100
        history = db.get_history(user_id, limit=limit)

        return jsonify({
            'history': history,
            'count': len(history)
        }), 200

    except Exception as e:
        logger.error(f"History fetch error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch history'}), 500


@app.route('/api/history/<int:analysis_id>', methods=['GET'])
@jwt_required()
def get_analysis(analysis_id):
    try:
        user_id = int(get_jwt_identity())   # FIX: cast to int
        analysis = db.get_analysis(analysis_id, user_id)

        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404

        return jsonify(analysis), 200

    except Exception as e:
        logger.error(f"Analysis fetch error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch analysis'}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Route not found'}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    logger.info(f"ThreatIQ starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
