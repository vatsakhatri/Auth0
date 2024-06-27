from flask import Flask, redirect, request, session, url_for
from urllib.parse import urlencode, quote_plus
import requests
from jose import jwt
import config

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this to a random secret key in production
app.config['SESSION_TYPE'] = 'filesystem'

@app.route('/login')
def login():
    """Initiate login by redirecting to Auth0"""
    response_type = 'code'
    scope = 'openid profile email'

    auth_url = f"https://{config.AUTH0_DOMAIN}/authorize?" + urlencode({
        'response_type': response_type,
        'client_id': config.CLIENT_ID,
        'redirect_uri': config.REDIRECT_URI,
        'scope': scope,
        'audience': config.AUDIENCE,
        'prompt': 'login'  # This ensures the user is prompted to log in
    })

    print(auth_url)
    return redirect(auth_url)

@app.route('/signup')
def signup():
    """Initiate signup by redirecting to Auth0"""
    response_type = 'code'
    scope = 'openid profile email'

    signup_url = f"https://{config.AUTH0_DOMAIN}/authorize?" + urlencode({
        'response_type': response_type,
        'client_id': config.CLIENT_ID,
        'redirect_uri': config.REDIRECT_URI,
        'scope': scope,
        'audience': config.AUDIENCE,
        'screen_hint': 'signup'  # This hints Auth0 to show the signup screen
    })

    print(signup_url)
    return redirect(signup_url)

@app.route('/callback')
def callback():
    """Handle the callback from Auth0"""
    code = request.args.get('code')
    if not code:
        return "Error: No code provided"

    token_url = f"https://{config.AUTH0_DOMAIN}/oauth/token"
    token_payload = {
        'grant_type': 'authorization_code',
        'client_id': config.CLIENT_ID,
        'client_secret': config.CLIENT_SECRET,
        'code': code,
        'redirect_uri': config.REDIRECT_URI,
    }

    try:
        token_info = requests.post(token_url, json=token_payload).json()
        id_token = token_info.get('id_token')
        access_token = token_info.get('access_token')
        
        if not id_token:
            return "Error: No id_token in response"
        
        # Debugging: Print the tokens received
        print(f"ID Token: {id_token}")
        print(f"Access Token: {access_token}")

        # Verify the token
        user_info = verify_token(id_token)

        if user_info:
            # Perform login or create session
            session['user'] = user_info
            session.permanent = True  # Ensure the session is permanent (has a timeout)
            return redirect(url_for('index'))  # Redirect to the root URL
        else:
            return "Error: Token verification failed"
    except requests.RequestException as e:
        return f"Error: {e}"

def verify_token(token):
    """Verify the JWT token from Auth0"""
    jwks_url = f"https://{config.AUTH0_DOMAIN}/.well-known/jwks.json"
    jwks = requests.get(jwks_url).json()
    
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError as e:
        print(f"Error decoding token headers: {e}")
        return None

    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header.get('kid'):
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=['RS256'],
                audience=config.CLIENT_ID,
                issuer=f"https://{config.AUTH0_DOMAIN}/"
            )
            return payload
        except jwt.ExpiredSignatureError:
            print("Error: Token has expired")
            return None
        except jwt.JWTClaimsError:
            print("Error: Invalid token claims")
            return None
        except Exception as e:
            print(f"Error decoding token: {e}")
            return None
    return None

@app.route('/logout')
def logout():
    """Log the user out and clear the session"""
    session.clear()
    # return redirect(
    #     f"https://{config.AUTH0_DOMAIN}/v2/logout?" + urlencode({
    #         "returnTo": url_for('index', _external=True),
    #         "client_id": config.CLIENT_ID,
    #     }, quote_via=quote_plus)
    # )
    return redirect(url_for('index'))

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f'Hello, {user["name"]}! <a href="/logout">Logout</a>'
    return 'Welcome to the Flask App. <a href="/login">Login</a> or <a href="/signup">Sign Up</a>'


if __name__ == '__main__':
    app.run(debug=True)
