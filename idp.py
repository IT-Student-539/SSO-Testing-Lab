# idp.py

from flask import Flask, request, redirect, session, url_for, jsonify  
# ^ Import Flask functions to create routes, manage sessions, handle redirects, etc.

import jwt  
# ^ Import the PyJWT library for encoding and decoding JSON Web Tokens (JWTs).

import datetime  
# ^ Import datetime module to manage token expiration times.

app = Flask(__name__)  
# ^ Create a new Flask application instance.

app.secret_key = 'idp_secret_key'  
# ^ Set a secret key for signing session cookies and JWTs.

# Configure session cookie settings for HTTPS and subdomain sharing.
app.config['SESSION_COOKIE_DOMAIN'] = '.localtest.me'  
# ^ This allows the cookie to be shared across all subdomains of localtest.me.
app.config['SESSION_COOKIE_PATH'] = '/'  
# ^ Set cookie path to root so that it is sent with all requests.
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  
# ^ Set SameSite to 'None' to allow cross-site cookies when using HTTPS.
app.config['SESSION_COOKIE_SECURE'] = True  
# ^ Ensure the cookie is only sent over HTTPS connections.
app.session_cookie_name = 'idp_session'  
# ^ Give the IDP a unique session cookie name.

# Define an in-memory user store (username: password)
users = {
    'alice': 'password123',  # Example user: alice with password 'password123'
    'bob': 'password456'     # Example user: bob with password 'password456'
}

# Define registered OAuth clients with their credentials and redirect URIs.
clients = {
    'ecommerce': {
         'client_id': 'ecommerce_client_id',             
         'client_secret': 'ecommerce_client_secret',       
         'redirect_uri': 'https://ecommerce.localtest.me:5001/callback'  
         # ^ The ecommerce app’s redirect URI.
    },
    'blog': {
         'client_id': 'blog_client_id',                   
         'client_secret': 'blog_client_secret',           
         'redirect_uri': 'https://blog.localtest.me:5002/callback'       
         # ^ The blog app’s redirect URI.
    }
}

@app.route('/login', methods=['GET', 'POST'])
# ^ Define a route for /login that accepts both GET (to display the form) and POST (to process the login).
def login():
    if request.method == 'GET':
         # Return a simple HTML login form for the user to enter credentials.
         return '''
         <h2>IDP Login</h2>
         <form method="post">
             Username: <input type="text" name="username"><br>
             Password: <input type="password" name="password"><br>
             <input type="submit" value="Login">
         </form>
         '''
    # Process the POST request.
    username = request.form.get('username')  
    # ^ Retrieve the username from the submitted form.
    password = request.form.get('password')  
    # ^ Retrieve the password from the submitted form.
    if username in users and users[username] == password:
         # If the username exists and the password matches, store the user in the session.
         session['user'] = username  
         next_url = request.args.get('next') or '/'  
         # ^ Retrieve the next URL from the query parameters (or default to '/').
         return redirect(next_url)  
         # ^ Redirect the user to the next URL.
    return 'Invalid credentials', 401  
    # ^ Return a 401 Unauthorized error if credentials do not match.

@app.route('/authorize')
# ^ Define the route that handles OAuth authorization requests.
def authorize():
    client_id = request.args.get('client_id')  
    # ^ Get the client ID from the URL query string.
    redirect_uri = request.args.get('redirect_uri')  
    # ^ Get the redirect URI provided by the client.
    state = request.args.get('state')  
    # ^ Retrieve the state parameter to maintain client state.
    if 'user' not in session:
         # ^ If the user is not logged in, redirect to the login page.
         return redirect(url_for('login', next=request.url))
    # Create an authorization code as a JWT with a short expiration (1 minute).
    code = jwt.encode({
         'user': session['user'],  # ^ Include the logged-in username.
         'client_id': client_id,     # ^ Include the client ID.
         'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  
         # ^ Set the token to expire in 1 minute.
    }, 'jwt_secret_key', algorithm='HS256')
    # Redirect back to the client's redirect_uri with the code and state as query parameters.
    return redirect(f"{redirect_uri}?code={code}&state={state}")

@app.route('/token', methods=['POST'])
# ^ Define the token endpoint to exchange the authorization code for an access token.
def token():
    code = request.form.get('code')  
    # ^ Retrieve the authorization code from the POST data.
    client_id = request.form.get('client_id')  
    # ^ Retrieve the client ID from the POST data.
    client_secret = request.form.get('client_secret')  
    # ^ Retrieve the client secret from the POST data.
    # Validate the provided client credentials.
    client = None
    for c in clients.values():
         if c['client_id'] == client_id and c['client_secret'] == client_secret:
             client = c
             break
    if client is None:
         # ^ Return an error if client credentials are invalid.
         return jsonify(error="Invalid client credentials"), 401
    try:
         # Decode the JWT authorization code using the secret key.
         data = jwt.decode(code, 'jwt_secret_key', algorithms=['HS256'])
    except Exception as e:
         # ^ If the code is invalid or expired, return an error.
         return jsonify(error="Invalid or expired code"), 400
    # Create an access token as a JWT, expiring in 10 minutes.
    access_token = jwt.encode({
         'user': data['user'],       
         'client_id': client_id,       
         'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }, 'jwt_secret_key', algorithm='HS256')
    # Return the access token as a JSON response.
    return jsonify(access_token=access_token)

@app.route('/userinfo')
# ^ Define an endpoint for clients to retrieve user information using an access token.
def userinfo():
    token = request.args.get('access_token')  
    # ^ Retrieve the access token from the query string.
    try:
         # Decode the access token.
         data = jwt.decode(token, 'jwt_secret_key', algorithms=['HS256'])
    except Exception as e:
         # ^ Return an error if the token is invalid or expired.
         return jsonify(error="Invalid or expired token"), 400
    # Return the user information in JSON format.
    return jsonify(user=data['user'])

if __name__ == '__main__':
    # Run the IDP server on port 5000 with HTTPS enabled using our self-signed certificate and key.
    app.run(port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))
