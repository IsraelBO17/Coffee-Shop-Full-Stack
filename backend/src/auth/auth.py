import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


'''
manager = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhrVXJrZE5yUDNEZ0Nmam5vOEx1SSJ9.eyJpc3MiOiJodHRwczovL3VkYWNpdHktZnNuZC1pc3JhZWwudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYzMmFmOTE2YWMxMmJiMTY4NjEyZWNlMyIsImF1ZCI6Imh0dHBzOi8vY29mZmVlLXNob3AiLCJpYXQiOjE2NjM4NjUwNjQsImV4cCI6MTY2Mzg3MjI2NCwiYXpwIjoiSWJic002TjlJNWN5VVVqeGhseEJEaVNETTU4QjBCaTIiLCJzY29wZSI6IiIsInBlcm1pc3Npb25zIjpbImRlbGV0ZTpkcmlua3MiLCJnZXQ6ZHJpbmtzIiwiZ2V0OmRyaW5rcy1kZXRhaWwiLCJwYXRjaDpkcmlua3MiLCJwb3N0OmRyaW5rcyJdfQ.RqvTEOjUdNNw0wbYnYMoi2guibM4rNu6OSFcYrS1jZYpfMx2tgMyxx0d3Cjw21N_44PkqU00p7h_bcMBJfflMbIUHqAG86LRHznWZVlGKte1Oh5yXCm1w8ZjX9ewAsetwbTqcxIyZ3UxqRh2u2umYFmMW4yRDXF20iRkuQ_EVC4hcDy0NsBmYoVzFoawJzmJSd4pLR75tKuNuTjPfFnvMqgTpkw9eDNRJh0KVDNU_1Sd6owNUPdJgcfrgQQnXd0EzJFSpMCqxkciyc0aaP7oUFEw3Lkmx9K7-SLuqTUV1GPSHjKmRD2DHGCZCuy0JlPUZh3w9zX8FNyGeDqZXdepYA
bar man = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhrVXJrZE5yUDNEZ0Nmam5vOEx1SSJ9.eyJpc3MiOiJodHRwczovL3VkYWNpdHktZnNuZC1pc3JhZWwudXMuYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDYzMmFmOTgyNjg1YmU3YjczNmU4NDVmMiIsImF1ZCI6Imh0dHBzOi8vY29mZmVlLXNob3AiLCJpYXQiOjE2NjM4NjUxNDAsImV4cCI6MTY2Mzg3MjM0MCwiYXpwIjoiSWJic002TjlJNWN5VVVqeGhseEJEaVNETTU4QjBCaTIiLCJzY29wZSI6IiIsInBlcm1pc3Npb25zIjpbImdldDpkcmlua3MiLCJnZXQ6ZHJpbmtzLWRldGFpbCJdfQ.I-jq_y8KQLTjJPnKN5IFYz_P9P5WX1BbCDmd5yjNs2shl06Z1ZmrNP1mlXtCdsLq-niIzXGvfGFD9j5oAc0LFU2GoaS8TIRRT1FkJCSimkSxIoaFp_PirgI_HtEBG_HejQVTkSsGLCi5UjHX-4z57lXddnY738d3wlSPMtBpKX2gDeimFB2nWGWTrni3E04G_XdQwRofgu21u5GM-MdQWuHIUMLnDGqJvm5RrTvyusXKRExgiwaMgf0kbPV_ID8RVpGv5ZKad7oD76lb2oT_zBIzU42qoz6WbAd74HYJwJGfAQd6InrAsNd9HTlZAwXkmKQfNRkcJOtqheLFZvuIAw
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

