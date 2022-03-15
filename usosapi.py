# coding=utf-8
"""
This package is part of the USOS API project.
https://apps.usos.edu.pl/developers/
"""
import hashlib
import os
import os.path
import tempfile
import urllib.request
import shutil
import rauth
import warnings
import re
import requests.exceptions
import logging
import time

VERSION = '1.0.0'

_REQUEST_TOKEN_SUFFIX = 'services/oauth/request_token'
_AUTHORIZE_SUFFIX = 'services/oauth/authorize'
_ACCESS_TOKEN_SUFFIX = 'services/oauth/access_token'

SCOPES = 'offline_access'

_LOGGER = logging.getLogger('USOSAPI')
_DOWNLOAD_LOGGER = logging.getLogger('USOSAPI.download')


class USOSAPIException(Exception):
    pass


def download_file(url: str) -> str:
    """
    This function is here for convenience. It's useful for downloading
    for eg. user photos. It blocks until the file is saved on the disk
    and then returns path of the file.
    If given url was already downloaded before, it won't be downloaded
    again (useful when you download user profile photos, most of them
    are blanks).
    """
    md5 = hashlib.md5()
    file_name, extension = os.path.splitext(url)
    md5.update(url.encode())
    file_name = md5.hexdigest() + extension
    file_dir = os.path.join(tempfile.gettempdir(), 'USOSAPI')

    if not os.path.exists(file_dir):
        os.mkdir(file_dir)
    else:
        if not os.path.isdir(file_dir):
            shutil.rmtree(file_dir)
            os.mkdir(file_dir)

    file_name = os.path.join(file_dir, file_name)

    if os.path.exists(file_name):
        if os.path.isfile(file_name):
            return file_name
        else:
            shutil.rmtree(file_name)

    with urllib.request.urlopen(url) as resp, open(file_name, 'wb') as out:
        shutil.copyfileobj(resp, out)

    _DOWNLOAD_LOGGER.info('File from {} saved as {}.'.format(url, file_name))

    return file_name


class USOSAPIConnection():
    """
    This class provides basic functionality required to work with
    USOS API server. To start communication you need to provide server
    address and your consumer key/secret pair to the constructor.

    After you create an USOSAPIConnection object with working parameters
    (check them with test_connection function), you may already use a subset
    of USOS API services that don't require a valid access key.

    To prevent the 'self signed certificate in certificate chain' error
    for development environments you can disable the certificate checking by 
    passing verify_certificate=False to the constructor.

    To log in as a specific user you need to get an URL address with
    get_authorization_url and somehow display it to the user (this module
    doesn't provide any UI). On the web page, after accepting
    scopes required by the module, user will receive a PIN code.
    This code should be passed to authorize_with_pin function to
    complete the authorization process. After successfully calling the
    authorize_with_pin function, you will have an authorized_session.
    """
    def __init__(self, api_base_address: str, consumer_key: str,
                 consumer_secret: str, verify_certificate: bool = True):
        self.base_address = str(api_base_address)
        if not self.base_address:
            raise ValueError('Empty USOS API address.')
        if not self.base_address.startswith('https'):
            warnings.warn('Insecure protocol in USOS API address. '
                          'The address should start with https.')
        if not self.base_address.endswith('/'):
            self.base_address += '/'

        self.consumer_key = str(consumer_key)
        self.consumer_secret = str(consumer_secret)

        req_token_url = self.base_address + _REQUEST_TOKEN_SUFFIX
        authorize_url = self.base_address + _AUTHORIZE_SUFFIX
        access_token_url = self.base_address + _ACCESS_TOKEN_SUFFIX

        self._service = rauth.OAuth1Service(consumer_key=consumer_key,
                                            consumer_secret=consumer_secret,
                                            name='USOSAPI',
                                            request_token_url=req_token_url,
                                            authorize_url=authorize_url,
                                            access_token_url=access_token_url,
                                            base_url=self.base_address)

        self._request_token_secret = ''
        self._request_token = ''

        self._authorized_session = None
        _LOGGER.info('New connection to {} created with key: {} '
                     'and secret: {}.'.format(api_base_address,
                                              consumer_key, consumer_secret))
        self.verify_certificate = verify_certificate

    def _generate_request_token(self):
        params = {'oauth_callback': 'oob', 'scopes': SCOPES}
        token_tuple = self._service.get_request_token(params=params, verify=self.verify_certificate)
        self._request_token, self._request_token_secret = token_tuple
        _LOGGER.info("New request token generated: {}".format(token_tuple[0]))
        return

    def is_anonymous(self) -> bool:
        """
        Checks if current USOS API session is anonymous.
        This function assumes that USOS API server connection data
        (server address, consumer key and consumer secret) are correct.
        """
        return self._authorized_session is None

    def is_authorized(self) -> bool:
        """
        Checks if current USOS API session is authorized (if you are logged in
        as specific user). This function assumes that USOS API server
        connection data (server address, consumer key and consumer secret)
        are correct.
        """
        if self._authorized_session is None:
            return False
        try:
            identity = self.get('services/users/user')
            return bool(identity['id'])
        except USOSAPIException:
            return False

    def test_connection(self) -> bool:
        """
        Checks if parameters passed for this object's constructor are correct
        and if it's possible to connect to the USOS API server.
        """
        time_re = '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$'
        try:
            anonymous_session = self._service.get_session()
            now = anonymous_session.get('services/apisrv/now', verify=self.verify_certificate)
            now = now.json()
            return bool(re.match(time_re, now))
        except Exception as e:
            _LOGGER.debug('Connection test failed: {}'.format(e))
            return False

    def get_authorization_url(self) -> str:
        """
        Returns an URL address that user has to visit using some
        internet browser to obtain a PIN code required for authorization.
        Every time you call this function, a new request token is generated,
        so only PIN code acquired with the last generated address will allow
        successful authorization.
        """
        self._generate_request_token()
        url = self._service.get_authorize_url(self._request_token, verify=self.verify_certificate)
        _LOGGER.info('New authorization URL generated: {}'.format(url))
        return url

    def authorize_with_pin(self, pin: str):
        """
        Call this function after user has obtained PIN code from website
        which address was generated by the set_authorization_url function.
        Remember that only PIN code from the last generated address will work.

        Will raise USOSAPIException if the PIN is incorrect.
        """
        if not(self._request_token and self._request_token_secret):
            raise USOSAPIException('Request token not initialized. '
                                   'Use get_authorization_url to generate '
                                   'the token.')

        rt = self._request_token
        rts = self._request_token_secret
        params = {'oauth_verifier': pin}

        _LOGGER.debug('Trying to authorize request token {} '
                      'with PIN code: {}'.format(self._request_token, pin))

        try:
            self._authorized_session = \
                self._service.get_auth_session(rt, rts, params=params)
        except KeyError:
            response = self._service.get_raw_access_token(rt, rts,
                                                          params=params)
            text = response.json()
            if isinstance(text, dict) and 'message' in text:
                text = text['message']
            _LOGGER.info('Authorization failed, response message: ' + text)
            raise USOSAPIException(text)
        at = self.get_access_data()[0]
        _LOGGER.info('Authorization successful, received access token: ' + at)

    def get_access_data(self) -> tuple:
        """
        Returns a tuple of access token and access token secret.
        You can save them somewhere and later use them to resume
        an authorized session.
        """
        if self.is_anonymous():
            raise USOSAPIException('Connection not yet authorized.')
        at = self._authorized_session.access_token
        ats = self._authorized_session.access_token_secret
        return at, ats

    def set_access_data(self, access_token: str,
                        access_token_secret: str) -> bool:
        """
        Using this function you can resume an authorized session.
        Although this module requires offline_access scope from users
        it is still possible, that the session won't be valid when it's
        resumed. Check return value to make sure if provided access
        pair was valid.
        """
        self._authorized_session = self._service.get_session()
        self._authorized_session.access_token = access_token
        self._authorized_session.access_token_secret = access_token_secret

        if not self.is_authorized():
            self._authorized_session = None
            _LOGGER.info("Access token {} is invalid.".format(access_token))
            return False

        _LOGGER.info('New access token ({}) and secret ({}) '
                     'set.'.format(access_token, access_token_secret))
        return True

    def get(self, service: str, **kwargs):
        """
        General use function to retrieve data from USOS API server.
        Although it is called 'get' it will issue a POST request.
        It's arguments are service name and an optional set of keyword
        arguments, that will be passed as parameters of the request.

        Return type depends on the called service. It will usually be
        a dictionary or a string.
        """
        session = self._service.get_session()
        if self._authorized_session is not None:
            session = self._authorized_session

        start = time.time()
        response = session.post(service, params=kwargs, data={}, verify=self.verify_certificate)
        ex_time = time.time() - start

        if not response.ok:
            try:
                _LOGGER.info('{} ({}) FAILED: [{}] {}'
                             ''.format(service, repr(kwargs),
                                       response.status_code, response.text))
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                if response.status_code == 401:
                    raise USOSAPIException('HTTP 401: Unauthorized. Your '
                                           'access key probably expired.')
                if response.status_code == 400:
                    msg = response.text
                    raise USOSAPIException('HTTP 400: Bad request: ' + msg)
                raise e

        _LOGGER.info("{} ({}) {:f}s".format(service, repr(kwargs),
                                            ex_time))
        _LOGGER.debug("{} ({}) -> {}".format(response.url, repr(kwargs),
                                             response.text))

        return response.json()

    def logout(self):
        """
        This function results in revoking currently used access key
        and closing the authenticated session.
        You can safely call this method multiple times.
        """
        if self._authorized_session is None:
            return

        at = self.get_access_data()[0]
        self.get('services/oauth/revoke_token')
        _LOGGER.debug('Access token {} revoked.'.format(at))
        self._authorized_session = None

    def current_identity(self):
        """
        Returns a dictionary containing following keys: first_name,
        last_name and id.

        If current session is anonymous it will raise USOSAPIException.
        """
        try:
            data = self.get('services/users/user', self.verify_certificate)
            return data
        except USOSAPIException:
            raise USOSAPIException('Trying to get identity of an unauthorized'
                                   ' session.')
