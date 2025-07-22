import os
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Flask backend configuration
FLASK_PORT = int(os.getenv('FLASK_PORT', 8080))

# HTML templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Flask OAuth2 Protected Application</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 50px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        .welcome { 
            color: #2c3e50; 
            text-align: center; 
        }
        .user-info { 
            background-color: #ecf0f1; 
            padding: 15px; 
            border-radius: 5px; 
            margin-top: 20px; 
        }
        .logout-btn { 
            display: inline-block; 
            background-color: #e74c3c; 
            color: white; 
            padding: 10px 20px; 
            text-decoration: none; 
            border-radius: 5px; 
            margin-top: 20px; 
        }
        .logout-btn:hover { 
            background-color: #c0392b; 
        }
        .debug-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="welcome">Hello {{ user_name }}!</h1>
        <div class="user-info">
            <p><strong>Username:</strong> {{ user_id }}</p>
            <p><strong>Email:</strong> {{ user_email }}</p>
            <p><strong>Groups:</strong> {{ user_groups }}</p>
            <p><strong>Protected by:</strong> OAuth2 PEP</p>
        </div>
        <a href="/oauth2/logout" class="logout-btn">Logout</a>
        
        {% if debug_headers %}
        <div class="debug-info">
            <strong>Debug - HTTP Headers from PEP:</strong><br>
            {% for header, value in debug_headers %}
            <strong>{{ header }}:</strong> {{ value }}<br>
            {% endfor %}
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

def get_user_from_headers():
    """Extract user information from HTTP headers set by OAuth2 PEP"""
    return {
        'id': request.headers.get('X-User-ID', 'unknown'),
        'name': request.headers.get('X-User-Name', 'Unknown User'),
        'email': request.headers.get('X-User-Email', ''),
        'groups': request.headers.get('X-User-Groups', ''),
        'authenticated': request.headers.get('X-Authenticated', 'false') == 'true'
    }

def get_debug_headers():
    """Get all X-User headers for debugging"""
    debug_headers = []
    for header, value in request.headers.items():
        if header.startswith('X-User') or header == 'X-Authenticated':
            debug_headers.append((header, value))
    return debug_headers

@app.route('/')
def home():
    """Protected home page - user info comes from PEP headers"""
    user = get_user_from_headers()
    
    # Check if request came through OAuth2 PEP
    if not user['authenticated']:
        return '''
        <html>
        <body>
            <h1>Access Denied</h1>
            <p>This application must be accessed through the OAuth2 PEP.</p>
            <p>Please access: <a href="http://localhost:5000">http://localhost:5000</a></p>
        </body>
        </html>
        ''', 403
    
    # Show debug headers in development
    debug_headers = get_debug_headers() if os.getenv('FLASK_DEBUG', 'false') == 'true' else None
    
    return render_template_string(
        HOME_TEMPLATE, 
        user_id=user['id'],
        user_name=user['name'],
        user_email=user['email'],
        user_groups=user['groups'],
        debug_headers=debug_headers
    )

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy'}, 200

if __name__ == '__main__':
    print(f"Flask backend starting on port {FLASK_PORT}")
    print("This backend is protected by OAuth2 PEP")
    print("Access the application via: http://localhost:5000")
    app.run(host='0.0.0.0', port=FLASK_PORT, debug=True) 