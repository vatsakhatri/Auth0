# Documentation for Auth0 integration in Flask
- Start Date: 27-06-2024
- Created by : Vatsa Khatri


## Introduction


In this documentation, we will understand the integration of auth0 into fask.


## ***Backend Configuration***


### Install dependencies


#### Adding the packages into the requirements file:


```
📁 requirements.txt -----

Flask
requests
python-jose
```


#### Executing the installation command again to install the modified libraries in the project


```pip3 install -r requirements.txt```


### To run
```
cd auth_flask
python3 main.py 
```

### Configuring the ```config.py``` file


- File path: ```auth_flask/config.py```


#### Creating a function to get the outh providers from github and google.


```
📁 config.py

AUTH0_DOMAIN = 'your-auth0-domain'
CLIENT_ID = 'your-client-id'
CLIENT_SECRET = 'your-client-secret'
REDIRECT_URI = 'http://localhost:5000/callback'
AUDIENCE = 'your-api-audience'

```
- ```REDIRECT_URI``` :  the url auth0 will redirect to after succesfully authnetication 
- ```AUTH0_DOMAIN``` : Your domain (can be found in your auth0 application)

## login/Signup routes



```
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
        'prompt': 'login'  
    })

    print(auth_url)
    return redirect(auth_url)
```

### Flow 
- When your login/singup endpoint is hit you redirect to the user to auth0 login with all detials like domain, client_id etc.
- ```response_type='code'``` : In response you want code(authorisation code which will be use later to retrieve user details).
- ```prompt``` : helps auth0 to identify what type of page you want  
  - ```'prompt': 'login'``` : This ensures the user is prompted to log in page.
  - ```'screen_hint': 'signup'``` : This hints Auth0 to show the signup screen.


## Callback URL

### Step 1:

``````
In your auth0 application register in the allowed callback url section the
'redirect_uri' you gave above
``````

 - ```Example: http://127.0.0.1:5000/callback```

### Step 2: 
```
on your server end you will recieve a

"GET /callback?code=abaababababbaa request from auth0

Use the authorisation code provide by auth0 to get the access_token and 
id_token.
```
* ####   Retrieve the code provided by Auth0
```
📁 main.py

@app.route('/callback')
def callback():
    """Handle the callback from Auth0"""
    code = request.args.get('code')
    if not code:
        return "Error: No code provided"
```

** **
* #### Hit the auth0 endpoint for token using code
```
    token_url = f"https://{config.AUTH0_DOMAIN}/oauth/token"
    token_payload = {
        'grant_type': 'authorization_code',
        'client_id': config.CLIENT_ID,
        'client_secret': config.CLIENT_SECRET,
        'code': code,
        'redirect_uri': config.REDIRECT_URI,
    }    
```
** **
* #### From the response extract the access_token and id_token
```
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

```
> (id_token and access_token are JWT token) 
** **
* #### Now we need to validate the id_token to get user details 

```
def verify_token(token):
```
** **
* #### store the user_detials in session
```
session['user'] = user_info
session.permanent = True
```

** **
* #### Once verified we direct to the Homepage

```
return redirect(url_for('index'))  
```

** **
* #### Payload of id_token(jwt)

```
{
  "given_name": "",
  "nickname": "",
  "name": "",
  "picture": "",
  "updated_at": "",
  "email": "",
  "email_verified": true,
  "iss": "",
  "aud": "",
  "iat": ,
  "exp": ,
  "sub": "",
  "auth_time": ,
  "sid": ""
}
```
## Homepage

* ### From session retrieve the data 
```
@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f'Hello, {user["name"]}! <a href="/logout">Logout</a>'
    return 'Welcome to the Flask App. <a href="/login">Login</a> or <a href="/signup">Sign Up</a>'

```




## Logout 

* ### Clear the sesssion and log user out from auth0 also

```
@app.route('/logout')
def logout():
    """Log the user out and clear the session"""
    session.clear()
    return redirect(
        f"https://{config.AUTH0_DOMAIN}/v2/logout?" + urlencode({
            "returnTo": url_for('index', _external=True),
            "client_id": config.CLIENT_ID,
        }, quote_via=quote_plus)
    )

```


## Addtional 

* #### You have the id _token and verfication is done now you can create  a jwt token 
 
```
def create_jwt(username):
    paylaod= {
      "name": "",
      "email": "",
      "exp": 
    }

    return jwt.encode(payload,SECRET_KEY,algorithm=ALGORITHM)

```
* #### Redirect to a temporary html where you just store the jwt token in local-storage 

* #### now all subsequent request can now have the jwt token 
