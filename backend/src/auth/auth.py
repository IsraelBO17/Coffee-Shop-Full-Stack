import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


'''
manager = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhrVXJrZE5yUDNEZ0Nmam5vOEx1SSJ9.eyJpc3MiOiJodHRwczovL3VkYWNpdHktZnNuZC1pc3JhZWwudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYzMmFmOTE2YWMxMmJiMTY4NjEyZWNlMyIsImF1ZCI6Imh0dHBzOi8vY29mZmVlLXNob3AiLCJpYXQiOjE2NjM4NDI4MjksImV4cCI6MTY2Mzg1MDAyOSwiYXpwIjoiSWJic002TjlJNWN5VVVqeGhseEJEaVNETTU4QjBCaTIiLCJzY29wZSI6IiIsInBlcm1pc3Npb25zIjpbImRlbGV0ZTpkcmlua3MiLCJnZXQ6ZHJpbmtzIiwicGF0Y2g6ZHJpbmtzIiwicG9zdDpkcmlua3MiXX0.iTJmSQCnt8TiGLI3Ax_1UN32a0-61dE1OYOYkMe_5x_Hb-b9ST3Gl2Bndabx1rf6FjmVBvVsyJ3NCcAzM6M5MqJuK6z5QvL3yi_n39h-fBqZE5w7RX18-qBwTciVN6ZP-bxAlSUjmvtB_ZJ1xcE6qiYHUoT0mTi1eLDgeBxe6NsZ6i4Ew85JOdIAwr-06FnIPg1caRvIts-iq4M8WnTBlOCtfv5L2iiGPuJVNlQKsemyXfQwR_ujEmGaVq9tzvVtEj5u7-wZmBhHvZz8beecvsK5vz9qwwDFSB6SeN5ZIYNgL-RlIP9wH7jW-oBu9_TL0ZwDgAhlPu7CYn8oSjW_xw
bar man = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhrVXJrZE5yUDNEZ0Nmam5vOEx1SSJ9.eyJpc3MiOiJodHRwczovL3VkYWNpdHktZnNuZC1pc3JhZWwudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYzMmFmOTgyNjg1YmU3YjczNmU4NDVmMiIsImF1ZCI6Imh0dHBzOi8vY29mZmVlLXNob3AiLCJpYXQiOjE2NjM4NDMyNTAsImV4cCI6MTY2Mzg1MDQ1MCwiYXpwIjoiSWJic002TjlJNWN5VVVqeGhseEJEaVNETTU4QjBCaTIiLCJzY29wZSI6IiIsInBlcm1pc3Npb25zIjpbImdldDpkcmlua3MiXX0.OpbDbW3EVG1yOEfzJQks6jNcldRB-ato95SSaQQky2Wqltu0AKqfZ0kcbCdLPjkIkYRCRv6OnrFIo_qCSM8B4R6ukgHRtDs7mNnycXjTuLnaBtvYeSO6XGOmIpMV7RSw2SG_yueNWmWjEUh3ODhVOHdyNbBl7JV-P_0m-hXEsWYV_5O014QTprx0C3du_dC1QG6TcpnTDVzwdXbAwKspeV8g1K5MqDgEXuFyWa5XQzJ2-pufKn4b2UrxANp2KYnqAyNNsWgApeSdUHbXP382XPmLHVmpz9J-DGH9AWcQEmxe86lXHxQ370ldjB0C-mXndUs5YUhG4eeG_k6U7rhKDg
'''

AUTH0_DOMAIN = 'udacity-fsnd-israel.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'https://coffee-shop'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''

def get_token_auth_header():
    if 'Authorization' not in request.headers:
        raise AuthError({
                'code': 'no_authorization',
                'description': 'No Authorization in header.'
            }, 401)
        
    auth_header = request.headers['Authorization']
    header_parts = auth_header.split(' ')
    
    if len(header_parts) != 2:
        raise AuthError({
                'code': 'header_malformed',
                'description': 'Authorization is malformed'
            }, 401)
    elif header_parts[0].lower() != 'bearer':
        raise AuthError({
                'code': 'header_malformed',
                'description': 'Authorization is malformed'
            }, 401) 
    return header_parts[1]

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''

def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'forbidden',
            'description': 'Permission not found.'
        }, 403)

    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''

def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    
    unverified_header = jwt.get_unverified_header(token)
    
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
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
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)

    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            
            return f(*args, **kwargs)
        return wrapper
    return requires_auth_decorator

