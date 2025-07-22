import os
import secrets
import requests
import jwt
from urllib.parse import urlencode, urlparse, parse_qs
from flask import Flask, request, redirect, session, jsonify, Response
import json
import time

app = Flask(__name__)
app.secret_key = os.getenv('PEP_SECRET_KEY', 'oauth2-pep-secret-key-2024')

# OAuth2 Configuration
DEX_ISSUER = os.getenv('DEX_ISSUER', 'http://dex:5556')
DEX_CLIENT_ID = os.getenv('DEX_CLIENT_ID', 'flask-app')
DEX_CLIENT_SECRET = os.getenv('DEX_CLIENT_SECRET', 'flask-app-secret')
BACKEND_URL = os.getenv('BACKEND_URL', 'http://flask-app:8080')

# OAuth2 endpoints
DEX_AUTH_URL = f'{DEX_ISSUER}/auth'
DEX_TOKEN_URL = f'{DEX_ISSUER}/token'
DEX_USERINFO_URL = f'{DEX_ISSUER}/userinfo'

# PEP redirect URI (where DEX will callback)
PEP_REDIRECT_URI = 'http://localhost:5000/oauth2/callback'

def is_authenticated():
    """Check if user has valid OAuth2 session"""
    return 'access_token' in session and 'user_info' in session

def get_user_info():
    """Get user info from session"""
    return session.get('user_info', {})

def validate_token(access_token):
    """Validate access token with DEX userinfo endpoint"""
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(DEX_USERINFO_URL, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Token validation error: {e}")
        return None

def proxy_to_backend(path, user_info):
    """Proxy request to backend Flask app with user headers"""
    backend_url = f"{BACKEND_URL}{path}"
    
    # Add user information as headers
    headers = dict(request.headers)
    headers['X-User-ID'] = user_info.get('preferred_username', 'unknown')
    headers['X-User-Name'] = user_info.get('name', user_info.get('preferred_username', 'Unknown'))
    headers['X-User-Email'] = user_info.get('email', '')
    headers['X-User-Groups'] = ','.join(user_info.get('groups', []))
    headers['X-Authenticated'] = 'true'
    
    # Remove host header to avoid conflicts
    headers.pop('Host', None)
    
    try:
        # Forward request to backend
        if request.method == 'GET':
            resp = requests.get(backend_url, headers=headers, params=request.args, timeout=10)
        elif request.method == 'POST':
            resp = requests.post(backend_url, headers=headers, data=request.get_data(), 
                               params=request.args, timeout=10)
        else:
            resp = requests.request(request.method, backend_url, headers=headers, 
                                  data=request.get_data(), params=request.args, timeout=10)
        
        # Return response from backend
        response = Response(resp.content, status=resp.status_code)
        for key, value in resp.headers.items():
            if key.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']:
                response.headers[key] = value
        
        return response
        
    except requests.exceptions.RequestException as e:
        print(f"Backend proxy error: {e}")
        return f"Backend service unavailable: {e}", 502

@app.route('/oauth2/login')
def oauth2_login():
    """Initiate OAuth2 login flow"""
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    params = {
        'response_type': 'code',
        'client_id': DEX_CLIENT_ID,
        'redirect_uri': PEP_REDIRECT_URI,
        'scope': 'openid email profile groups',
        'state': state
    }
    
    auth_url = f"{DEX_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/oauth2/callback')
def oauth2_callback():
    """Handle OAuth2 callback from DEX"""
    try:
        # Verify state parameter
        if request.args.get('state') != session.get('oauth_state'):
            return 'Invalid state parameter', 400
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            return 'Authorization code not received', 400
        
        # Exchange code for token
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': PEP_REDIRECT_URI,
            'client_id': DEX_CLIENT_ID,
            'client_secret': DEX_CLIENT_SECRET
        }
        
        token_response = requests.post(DEX_TOKEN_URL, data=token_data)
        if token_response.status_code != 200:
            return f'Token exchange failed: {token_response.text}', 400
        
        tokens = token_response.json()
        access_token = tokens.get('access_token')
        
        if not access_token:
            return 'No access token received', 400
        
        # Get user info
        user_info = validate_token(access_token)
        if not user_info:
            return 'Failed to get user information', 400
        
        # Store in session
        session['access_token'] = access_token
        session['user_info'] = user_info
        session['token_expires'] = time.time() + tokens.get('expires_in', 3600)
        
        # Clean up
        session.pop('oauth_state', None)
        
        # Redirect to original requested path or root
        original_path = session.pop('original_path', '/')
        return redirect(original_path)
        
    except Exception as e:
        return f'OAuth2 callback failed: {str(e)}', 400

@app.route('/oauth2/logout')
def oauth2_logout():
    """Logout user"""
    session.clear()
    return redirect('/')

@app.route('/oauth2/userinfo')
def oauth2_userinfo():
    """Get current user info (for debugging)"""
    if not is_authenticated():
        return {'error': 'Not authenticated'}, 401
    return jsonify(get_user_info())

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy_handler(path):
    """Main proxy handler - authenticate and forward to backend"""
    
    # Skip authentication for OAuth2 endpoints
    if request.path.startswith('/oauth2/'):
        return f"OAuth2 endpoint accessed directly", 404
    
    # Check if user is authenticated
    if not is_authenticated():
        # Store original path for redirect after login
        session['original_path'] = request.path
        return redirect('/oauth2/login')
    
    # Check if token is still valid
    if time.time() > session.get('token_expires', 0):
        # Token expired, re-authenticate
        session.clear()
        session['original_path'] = request.path
        return redirect('/oauth2/login')
    
    # Validate token is still good
    access_token = session.get('access_token')
    user_info = validate_token(access_token)
    if not user_info:
        # Token invalid, re-authenticate
        session.clear()
        session['original_path'] = request.path
        return redirect('/oauth2/login')
    
    # Update user info in session (in case it changed)
    session['user_info'] = user_info
    
    # Proxy to backend with user headers
    return proxy_to_backend('/' + path, user_info)

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'service': 'oauth2-pep'}, 200

if __name__ == '__main__':
    print(f"OAuth2 PEP starting on port 5000")
    print(f"DEX Issuer: {DEX_ISSUER}")
    print(f"Backend URL: {BACKEND_URL}")
    print(f"Client ID: {DEX_CLIENT_ID}")
    app.run(host='0.0.0.0', port=5000, debug=True) 