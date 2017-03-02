"""Some functions for interacting with GBDX end points."""
from future import standard_library
standard_library.install_aliases()
import os
import base64
import json
from configparser import ConfigParser
from datetime import datetime

from oauthlib.oauth2 import LegacyApplicationClient
from requests_oauthlib import OAuth2Session

from auth0.v2 import authentication as auth0
import requests
import jwt
from calendar import timegm
from datetime import datetime

# default to GBDX production auth0 client ID
GBDX_AUTH0_CLIENT_ID = os.environ.get('GBDX_AUTH0_CLIENT_ID', "vhaNEJymL4m1UCo4TqXmuKtkn9JCYDkT")
GBDX_AUTH0_DOMAIN = os.environ.get('GBDX_AUTH0_DOMAIN', "digitalglobe-platform.auth0.com")

if not GBDX_AUTH0_CLIENT_ID:
    raise Exception("GBDX_AUTH0_CLIENT_ID must be defined. Value provided was '{}'".format(GBDX_AUTH0_CLIENT_ID) )

if not GBDX_AUTH0_DOMAIN:
    raise Exception("GBDX_AUTH0_DOMAIN must be defined. Value provided was '{}'".format(GBDX_AUTH0_DOMAIN) )

def setup_gbdx_request_session(access_token, refresh_token):

    if not access_token:
        raise Exception("access_token is a required parameter. Value provided was '{}'".format(access_token) )

    if not refresh_token:
        raise Exception("refresh_token is a required parameter. Value provided was '{}'".format(refresh_token) )

    s = requests.Session()
    headers = {"Authorization":"Bearer {}".format(access_token)}
    s.headers.update(headers)

    return s

def auth0_get_token_from_resource_owner_credentials(username=None, password=None):
    if not username:
        raise Exception('username is required')

    if not password:
        raise Exception('password is required')

    d = auth0.Database(domain=GBDX_AUTH0_DOMAIN)
    return d.login(client_id=GBDX_AUTH0_CLIENT_ID, username=username, password=password, connection='Username-Password-Authentication', device='scope=offline_access', scope='openid offline_access')


def auth0_get_token_from_refresh_token(refresh_token=None):
    if not refresh_token:
        raise Exception('refresh_token is required')

    d = auth0.Delegated(domain=GBDX_AUTH0_DOMAIN)
    return d.get_token(client_id=GBDX_AUTH0_CLIENT_ID, target=GBDX_AUTH0_CLIENT_ID, grant_type='urn:ietf:params:oauth:grant-type:jwt-bearer', refresh_token=refresh_token, scope='openid offline_access', api_type='app')

def auth0_is_access_token_expired(access_token):
    try:
        #
        # Check if the token is expired and try to refresh it.
        # NOTE signature is not validated here. We do not have access to the client_secret and
        #   are only concerned about expired tokens. Server side apis will validate the signature.
        #
        jwt.decode(access_token, audience=GBDX_AUTH0_CLIENT_ID, options={"verify_signature":False})
    except jwt.ExpiredSignatureError:
        # automatically refresh any tokens that expire in the future
        token = auth0_get_token_from_refresh_token(refresh_token)
        access_token = token['id_token']


def session_from_envvars(auth_url='https://geobigdata.io/auth/v1/oauth/token/',
                         environ_template=(('username', 'GBDX_USERNAME'),
                                           ('password', 'GBDX_PASSWORD'))):
    """Returns a session with the GBDX authorization token baked in,
    pulling the credentials from environment variables.

    There are two ways to create a GBDX session from environment variables:
    1. Set GBDX_ACCESS_TOKEN and GBDX_REFRESH_TOKEN
    2. Or, provide GBDX_USERNAME, GBDX_PASSWORD
    """

    if os.environ.get('GBDX_ACCESS_TOKEN', None) and os.environ.get('GBDX_REFRESH_TOKEN', None):
        s = setup_gbdx_request_session(access_token=os.environ.get('GBDX_ACCESS_TOKEN'), refresh_token=os.environ.get('GBDX_REFRESH_TOKEN'))

    elif os.environ.get('GBDX_USERNAME', None) and os.environ.get('GBDX_PASSWORD', None):
        token = auth0_get_token_from_resource_owner_credentials(username=os.environ.get('GBDX_USERNAME'), password=os.environ.get('GBDX_PASSWORD'))
        s = setup_gbdx_request_session(access_token=token['id_token'], refresh_token=token['refresh_token'])

    return s

def session_from_kwargs(**kwargs):
    token = auth0_get_token_from_resource_owner_credentials(username=kwargs.get('username'), password=kwargs.get('password'))
    s = setup_gbdx_request_session(access_token=token['id_token'], refresh_token=token['refresh_token'])
    return s


def session_from_config(config_file):
    """Returns a requests session object with oauth enabled for
    interacting with GBDX end points."""

    def save_token(token):
        """Save off the token back to the config file."""
        if not 'gbdx_token' in set(cfg.sections()):
            cfg.add_section('gbdx_token')

        # reformat token to match legacy gbdx token format
        auth0_id_token = jwt.decode(token['id_token'], audience=GBDX_AUTH0_CLIENT_ID, options={"verify_signature":False})
        token_to_save = {
            "token_type": "Bearer",
            "refresh_token": token['refresh_token'],
            "access_token": token['id_token'],
            "scope": ["read", "write"],
            "expires_in": timegm(datetime.utcnow().utctimetuple()) - auth0_id_token['exp'],
            "expires_at": auth0_id_token['exp']
        }

        cfg.set('gbdx_token', 'json', json.dumps(token_to_save))
        with open(config_file, 'w') as sink:
            cfg.write(sink)

    # Read the config file (ini format).
    cfg = ConfigParser()
    if not cfg.read(config_file):
        raise RuntimeError('No ini file found at {} to parse.'.format(config_file))

    # See if we have a token stored in the config, and if not, get one.
    if 'gbdx_token' in set(cfg.sections()):
        # Parse the token from the config.
        token = json.loads(cfg.get('gbdx_token','json'))

        # Update the token experation   with a little buffer room.
        token['expires_in'] = (datetime.utcfromtimestamp(token['expires_at']) -
                               datetime.utcnow()).total_seconds() - 600

        s = setup_gbdx_request_session(access_token=token['access_token'], refresh_token=token['refresh_token'])

    else:
        # No pre-existing token, so we request one from the API.
        token = auth0_get_token_from_resource_owner_credentials(username=cfg.get('gbdx','user_name'), password=cfg.get('gbdx','user_password'))
        s = setup_gbdx_request_session(access_token=token['access_token'], refresh_token=token['refresh_token'])

        save_token(token)

    return s

def get_session(config_file=None):
    """Returns a requests session with gbdx oauth2 baked in.

    If you provide a path to a config file, it will look there for the
    credentials.  If you don't it will try to pull the credentials
    from environment variables (GBDX_USERNAME, GBDX_PASSWORD,
    GBDX_CLIENT_ID, GBDX_CLIENT_SECRET).  If that fails and you have a
    '~/.gbdx-config' ini file, it will read from that.
    """
    # If not config file, try using environment variables.  If that
    # fails and their is a config in the default location, use that.
    if not config_file:
        try:
            return session_from_envvars()
        except Exception as e:
            config_file = os.path.expanduser('~/.gbdx-config')

    error_output = """[gbdx]
auth_url = https://geobigdata.io/auth/v1/oauth/token/
client_id = your_client_id
client_secret = your_client_secret
user_name = your_user_name
user_password = your_password"""

    if not os.path.isfile(config_file):
        raise Exception("Please create a GBDX credential file at ~/.gbdx-config with these contents:\n%s" % error_output)

    session = session_from_config(config_file)
    try:
      session = session_from_config(config_file)
    except:
      raise Exception("Invalid credentials or incorrectly formated config file at ~/.gbdx-config")

    return session
