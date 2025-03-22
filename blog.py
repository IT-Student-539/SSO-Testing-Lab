# blog.py

from flask import Flask, redirect, request, session, url_for  
# ^ Import Flask functions for routing, handling requests, and managing sessions.
import requests  
# ^ Import the requests library to perform HTTP calls to external services.

app = Flask(__name__)  
# ^ Create a new Flask application instance for the blog.
app.secret_key = 'blog_secret_key'  
# ^ Set a secret key for securing the blog app's session data.

# Configure the blog app's session cookie settings for HTTPS and subdomain sharing.
app.config['SESSION_COOKIE_DOMAIN'] = '.localtest.me'  
# ^ Allow the cookie to be shared across all subdomains (e.g., blog.localtest.me).
app.config['SESSION_COOKIE_PATH'] = '/'  
# ^ Set the cookie path to the root.
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  
# ^ Set SameSite to 'None' to allow cross-site cookie usage.
app.config['SESSION_COOKIE_SECURE'] = True  
# ^ Ensure the cookie is only sent over HTTPS.
app.session_cookie_name = 'blog_session'  
# ^ Set a unique session cookie name for the blog app.

# OAuth client configuration for the blog app.
CLIENT_ID = 'blog_client_id'  
# ^ The client ID provided by the IDP for the blog.
CLIENT_SECRET = 'blog_client_secret'  
# ^ The client secret provided by the IDP for the blog.
REDIRECT_URI = 'https://blog.localtest.me:5002/callback'  
# ^ The redirect URI for the blog app after authentication.
IDP_AUTHORIZE_URL = 'https://idp.localtest.me:5000/authorize'  
# ^ The IDP’s authorization endpoint.
IDP_TOKEN_URL = 'https://idp.localtest.me:5000/token'  
# ^ The IDP’s token endpoint.
IDP_USERINFO_URL = 'https://idp.localtest.me:5000/userinfo'  
# ^ The IDP’s user info endpoint.

@app.route('/')  
# ^ Define the home route for the blog app.
def index():
    if 'user' not in session:  
         # ^ If the user is not logged in, redirect to the login route.
         return redirect(url_for('login'))
    # If the user is logged in, display a welcome message with logout and switch links.
    return f"""
    <h2>Welcome {session['user']} to the Blog</h2>
    <p><a href='/logout'>Logout</a></p>
    <p><a href='https://ecommerce.localtest.me:5001/'>Switch to E-commerce Site</a></p>
    """

@app.route('/login')  
# ^ Define the login route for the blog app to start the OAuth flow.
def login():
    state = 'random_state_string'  
    # ^ A static state parameter; in production, generate this securely.
    # Redirect to the IDP’s authorization endpoint with the required parameters.
    return redirect(f"{IDP_AUTHORIZE_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state={state}")

@app.route('/callback')  
# ^ Define the callback route that processes the IDP’s response.
def callback():
    code = request.args.get('code')  
    # ^ Retrieve the authorization code from the URL query parameters.
    data = {
         'grant_type': 'authorization_code',  
         # ^ Specify the OAuth grant type.
         'code': code,  
         # ^ Include the received authorization code.
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
         # ^ If no access token is returned, return an error.
         return "Error fetching access token", 400
    # Use the access token to request user information from the IDP.
    response = requests.get(IDP_USERINFO_URL, params={'access_token': access_token}, verify=False)
    user_info = response.json()  
    # ^ Parse the JSON response to retrieve user details.
    session['user'] = user_info.get('user')  
    # ^ Store the user information in the session.
    return redirect(url_for('index'))  
    # ^ Redirect the user to the blog home page.

@app.route('/logout')  
# ^ Define the logout route for the blog app.
def logout():
    session.pop('user', None)  
    # ^ Remove the user from the session.
    return redirect(url_for('index'))  
    # ^ Redirect to the home page after logout.

if __name__ == '__main__':  
    # ^ If this script is executed directly, run the blog app.
    app.run(port=5002, debug=True, ssl_context=('cert.pem', 'key.pem'))  
    # ^ Run the blog app on port 5002 with HTTPS enabled using the provided certificate and key.


