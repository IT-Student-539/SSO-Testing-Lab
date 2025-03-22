# ecommerce.py

from flask import Flask, redirect, request, session, url_for  
# ^ Import Flask functions for handling routing, sessions, etc.
import requests  
# ^ Import the requests library to perform HTTP requests to the IDP.

app = Flask(__name__)  
# ^ Create a new Flask application instance for the ecommerce app.
app.secret_key = 'ecommerce_secret_key'  
# ^ Set a secret key for securing the session data.

# Configure the session cookie settings for HTTPS and subdomain sharing.
app.config['SESSION_COOKIE_DOMAIN'] = '.localtest.me'  
# ^ Allow the cookie to be shared across subdomains (ecommerce.localtest.me, blog.localtest.me, etc.).
app.config['SESSION_COOKIE_PATH'] = '/'  
# ^ Set the cookie path to the root.
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  
# ^ Set SameSite to 'None' to allow cross-site usage.
app.config['SESSION_COOKIE_SECURE'] = True  
# ^ Ensure the cookie is only sent over HTTPS.
app.session_cookie_name = 'ecommerce_session'  
# ^ Use a unique session cookie name for the ecommerce app.

# OAuth client configuration for the ecommerce app.
CLIENT_ID = 'ecommerce_client_id'  
# ^ The client ID assigned by the IDP.
CLIENT_SECRET = 'ecommerce_client_secret'  
# ^ The client secret assigned by the IDP.
REDIRECT_URI = 'https://ecommerce.localtest.me:5001/callback'  
# ^ The redirect URI where the IDP will send the authorization code after login.
IDP_AUTHORIZE_URL = 'https://idp.localtest.me:5000/authorize'  
# ^ The IDP’s authorization endpoint.
IDP_TOKEN_URL = 'https://idp.localtest.me:5000/token'  
# ^ The IDP’s token endpoint for exchanging codes for tokens.
IDP_USERINFO_URL = 'https://idp.localtest.me:5000/userinfo'  
# ^ The IDP’s endpoint for retrieving user information.

@app.route('/')  
# ^ Define the home route for the ecommerce app.
def index():
    if 'user' in session:  
         # ^ If the user is logged in (exists in session), show a welcome page with logout and switch links.
         return f"""
         <h2>Welcome {session['user']} to the E-commerce Site</h2>
         <p><a href='/logout'>Logout</a></p>
         <p><a href='https://blog.localtest.me:5002/'>Switch to Blog</a></p>
         """
    # ^ If not logged in, display a page with a link labeled "SSO Login".
    return "<h2>Welcome to the E-commerce Site</h2><p><a href='/login'>SSO Login</a></p>"

@app.route('/login')  
# ^ Define the login route to start the OAuth flow.
def login():
    state = 'random_state_string'  
    # ^ A static state parameter; in production, generate this dynamically for CSRF protection.
    # Redirect the user to the IDP’s authorization endpoint with the required query parameters.
    return redirect(f"{IDP_AUTHORIZE_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}")

@app.route('/callback')  
# ^ Define the callback route that processes the response from the IDP.
def callback():
    code = request.args.get('code')  
    # ^ Retrieve the authorization code from the URL query parameters.
    data = {
         'grant_type': 'authorization_code',  
         # ^ Specify the OAuth grant type.
         'code': code,  
         # ^ Include the authorization code.
         'redirect_uri': REDIRECT_URI,  
         # ^ The redirect URI must match the registered URI.
         'client_id': CLIENT_ID,  
         # ^ Include the client ID.
         'client_secret': CLIENT_SECRET  
         # ^ Include the client secret.
    }
    # Exchange the authorization code for an access token by making a POST request to the IDP.
    response = requests.post(IDP_TOKEN_URL, data=data, verify='cert.pem')
    token_data = response.json()  
    # ^ Parse the JSON response.
    access_token = token_data.get('access_token')  
    # ^ Extract the access token.
    if not access_token:  
         # ^ If no access token is received, return an error.
         return "Error fetching access token", 400
    # Use the access token to fetch user info from the IDP.
    response = requests.get(IDP_USERINFO_URL, params={'access_token': access_token}, verify=False)
    user_info = response.json()  
    # ^ Parse the user information from the JSON response.
    session['user'] = user_info.get('user')  
    # ^ Store the username in the session.
    return redirect(url_for('index'))  
    # ^ Redirect the user back to the home page.

@app.route('/logout')  
# ^ Define the logout route to clear the session.
def logout():
    session.pop('user', None)  
    # ^ Remove the user information from the session.
    return redirect(url_for('index'))  
    # ^ Redirect the user to the home page after logout.

if __name__ == '__main__':  
    # ^ If this script is executed directly, start the server.
    app.run(port=5001, debug=True, ssl_context=('cert.pem', 'key.pem'))  
    # ^ Run the ecommerce app on port 5001 with HTTPS enabled using the provided certificate and key.


