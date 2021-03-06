#!/usr/bin/env python3

"""check_shib_idp.py -- Monitor a Shibboleth IdP or Shibboleth-protected service with Nagios

(C) copyright 2021, University of Illinois Board of Trustees

This Nagios plugin can check either an IdP directly using IdP-initiated
SSO or a URL on an SP that's Shibboleth-protected using SP-initiated SSO.
See check_shib_idp.py --help for syntax.

Changelog:
4/8/2021 -- kwessel: Initial release
"""

from bs4 import BeautifulSoup
from urllib.parse import urlparse
import argparse
import requests
import base64
import sys
import binascii
import time

# For writing debug output
from http.client import HTTPConnection

# Global vars
debug = False
timeout = 15

# Exceptions to throw
class IdPException(Exception):
    pass

class SPException(Exception):
    pass

def print_response_body(text):
    """print_response_body() -- print response body on error when in debug mode

    Params:
    text -- resp.text from request object

    Throws:
    None

    Returns:
    None
    """

    print()
    print("BEGIN RESPONSE BODY:")
    print(text)
    print("END RESPONSE BODY:")
    print()

def do_idp_initiated(host, sp, user, password, attribute):
    """do_idp_initiated() -- check an IdP directly

    Params:
    host -- IdP hostname
    sp -- entity ID of the SP to identify ourselves as
    user -- username to use in authentication
    password: password to use in authentication
    attribute -- friendly name of SAML attribute that must be in response

    Throws:
    IdPException if interaction fails at any point

    Returns:
    None
    """

    # Set SP to use for authn request
    req_params = {"providerId": sp}

    # Create persistent session
    sess = requests.session()

    # Send initial IdP-initiated SSO request
    try:
        if debug:
            print("Sending initial request to IdP")
        resp = sess.get("https://{}/idp/profile/SAML2/Unsolicited/SSO".format(host),
                        params=req_params, timeout=timeout)
        if resp.status_code != 200:
            debug and print_response_body(resp.text)
            raise IdPException("Not redirected to login page - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise IdPException("Not redirected to login page - {}".format(e))

    debug and print_response_body(resp.text)

    resp = do_login(sess, resp, user, password)

    # Parse SAML response out of form
    soup = BeautifulSoup(resp.text, "html.parser")

    saml_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "SAMLResponse"}):
            saml_form = form
            break

    if not saml_form:
        raise IdPException("Invalid response from IdP after authentication")

    saml_resp = saml_form.find("input", {"name": "SAMLResponse"}).get("value")

    if debug:
        print("Base64-encoded SAML response")
        print(saml_resp)
        print()

    # Base64 decode response
    try:
        decoded_resp = base64.b64decode(saml_resp).decode()

    except binascii.Error:
        raise IdPException("Unable to base64 decode response from IdP")

    if debug:
        print("Base64-decoded SAML response")
        print(decoded_resp)
        print()

    if "urn:oasis:names:tc:SAML:2.0:status:Success" not in decoded_resp:
        raise IdPException("SAML success status not found in response")
    elif debug:
        print("SAML success status found in response")

    if 'FriendlyName="{}"'.format(attribute) not in decoded_resp:
        raise IdPException("Required attribute {} not found in response".format(attribute))
    elif debug:
        print("Required attribute {} found in response".format(attribute))

def do_sp_initiated(url, user, password, string, idp):
    """do_sp_initiated() -- Check an SP resource that's Shibboleth-protected

    Params:
    url -- URL of the protected page to check
    user -- username to use in authentication
    password -- password to use in authentication
    string -- text that must be present on the page after return from IdP
    idp -- optional entity ID of the IdP to choose if directed to a discovery page

    Throws:
    SPException if interaction fails with the SP or discovery service
    IdPException if interaction fails with the IdP

    Returns:
    None
    """

    # Create persistent session
    sess = requests.session()

    # Start at the specified URL
    try:
        if debug:
            print("Sending initial request to SP")
        resp = sess.get(url, timeout=timeout)
        if resp.status_code != 200:
            debug and print_response_body(resp.text)
            raise SPException("Not redirected to login page - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Not redirected to login page - {}".format(e))

    debug and print_response_body(resp.text)

    # Were we redirected to the campus selection page?
    soup = BeautifulSoup(resp.text, "html.parser")

    for form in soup.find_all("form"):
        if form.get("name") == "IdPList":
            if debug:
                print("IdP discovery page detected")

            resp = do_discovery_select(sess, resp, idp)
            break

    resp = do_login(sess, resp, user, password)

    # Get form to submit back to SP
    soup = BeautifulSoup(resp.text, "html.parser")

    saml_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "SAMLResponse"}):
            saml_form = form
            break

    if not saml_form:
        raise IdPException("Invalid response from IdP after authentication")

    action = saml_form.get("action")

    form_data = {}
    for input_tag in saml_form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        form_data[input_name] = input_value

    if not action or not form_data:
        raise SPException("Invalid response from IdP after authentication")

    try:
        if debug:
            print("Submitting IdP response back to SP")

        resp = sess.post(action, data=form_data, timeout=timeout)

        if resp.status_code != 200:
            debug and print_response_body(resp.text)
            raise SPException("Failed to return to SP after authentication - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Failed to return to SP after authentication - {}".format(e))

    debug and print_response_body(resp.text)

    if string not in resp.text:
        raise SPException("Expected output text not found after authentication")
    elif debug:
        print("Expected output text found after authentication")

def do_proxy_idp_initiated(host, sp, user, password, attribute, idp):
    """do_proxy_idp_initiated() -- check a proxy IdP directly

    Params:
    host -- IdP hostname
    sp -- entity ID of the SP to identify ourselves as
    user -- username to use in authentication
    password: password to use in authentication
    attribute -- SAML2 name of SAML attribute that must be in response
    idp -- optional entity ID of the IdP to choose if directed to a discovery page

    Throws:
    SPException if interaction fails with the embedded SP or discovery service
    IdPException if interaction fails with the real or proxy IdP

    Returns:
    None
    """

    # Set SP to use for authn request
    req_params = {"spentityid": sp}

    # Create persistent session
    sess = requests.session()

    # Send initial IdP-initiated SSO request
    try:
        if debug:
            print("Sending initial request to proxy IdP")
        resp = sess.get("https://{}/simplesaml/saml2/idp/SSOService.php".format(host),
                        params=req_params, timeout=timeout)
        if resp.status_code != 200:
            debug and print_response_body(resp.text)
            raise IdPException("Not redirected to proxy IdP - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise IdPException("Not redirected to proxy IdP - {}".format(e))

    debug and print_response_body(resp.text)

    # Were we redirected to the campus selection page?
    soup = BeautifulSoup(resp.text, "html.parser")

    for form in soup.find_all("form"):
        if form.get("name") == "IdPList":
            if debug:
                print("IdP discovery page detected")

            resp = do_discovery_select(sess, resp, idp)
            break

    resp = do_login(sess, resp, user, password)

    # Get form to submit back to embedded SP
    soup = BeautifulSoup(resp.text, "html.parser")

    saml_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "SAMLResponse"}):
            saml_form = form
            break

    if not saml_form:
        raise IdPException("Invalid response from real IdP after authentication")

    action = saml_form.get("action")

    form_data = {}
    for input_tag in saml_form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        form_data[input_name] = input_value

    if not action or not form_data:
        raise SPException("Invalid response from real IdP after authentication")

    try:
        if debug:
            print("Submitting IdP response back to embedded SP")

        resp = sess.post(action, data=form_data, timeout=timeout)

        if resp.status_code != 200:
            debug and print_response_body(resp.text)
            raise SPException("Failed to return to embedded SP after authentication - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Failed to return to embedded SP after authentication - {}".format(e))

    debug and print_response_body(resp.text)

    # Parse SAML response out of form
    soup = BeautifulSoup(resp.text, "html.parser")

    saml_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "SAMLResponse"}):
            saml_form = form
            break

    if not saml_form:
        raise IdPException("Invalid response from proxy IdP after authentication")

    saml_resp = saml_form.find("input", {"name": "SAMLResponse"}).get("value")

    if debug:
        print("Base64-encoded SAML response")
        print(saml_resp)
        print()

    # Base64 decode response
    try:
        decoded_resp = base64.b64decode(saml_resp).decode()

    except binascii.Error:
        raise IdPException("Unable to base64 decode response from proxy IdP")

    if debug:
        print("Base64-decoded SAML response")
        print(decoded_resp)
        print()

    if "urn:oasis:names:tc:SAML:2.0:status:Success" not in decoded_resp:
        raise IdPException("SAML success status not found in response from proxy IdP")
    elif debug:
        print("SAML success status found in response from proxy IdP")

    if 'Name="{}"'.format(attribute) not in decoded_resp:
        raise IdPException("Required attribute {} not found in response from proxy IdP".format(attribute))
    elif debug:
        print("Required attribute {} found in response from proxy IdP".format(attribute))

def do_discovery_select(sess, resp, idp):
    """do_discovery_select() -- Select an IdP from a discovery service

    Params:
    sess -- persistent request.session object
    resp -- request response object containing the discovery service form
    idp -- entity ID of IdP to select

    Throws:
    SPException if interaction fails at any point

    Returns:
    Response object containing the result of IdP selection
    """

    if not idp:
        raise IdPException("Redirected to discovery page, but no default IdP was specified on the command-line")
    soup = BeautifulSoup(resp.text, "html.parser")

    disco_form = None
    for form in soup.find_all("form"):
        if form.get("name") == "IdPList":
            disco_form = form
            break

    if not disco_form:
        raise IdPException("Unable to find form on IdP discovery page")

    # Get discovery service hostname from response
    host = urlparse(resp.url).netloc

    # Get form response URL to submit back to discovery service
    action = disco_form.get("action")

    if not host or not action:
        raise SPException("Error from discovery service")

    # Build form response
    disco_data = {"user_idp": idp, "Select": "Select"}

    # Select campus
    try:
        if debug:
            print("Selecting IdP from discovery page")

        resp = sess.post("https://{}{}".format(host, action), data=disco_data,
                         timeout=timeout)
        if resp.status_code != 200:
            debug and print_response_body(resp.text)

            raise SPException("Failed to return to SP after IdP selection - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Failed to return to SP after IdP selection - {}".format(e))

    debug and print_response_body(resp.text)

    return resp

def do_login(sess, resp, user, password):
    """do_login() -- authenticate to an IdP

    Params:
    sess -- persistent request.session object
    resp -- request response object containing the discovery service form
    user -- username to use in authentication
    password -- password to use in authentication

    Throws:
    IdPException if interaction fails at any point

    Returns:
    Response object containing the result of submitting the login form
    """

    # Is Shibboleth proxying to ADFS?
    proxy_to_adfs = False

    # IdP login form data to use for authentication
    login_data = {}

    # Get IdP hostname from response
    host = urlparse(resp.url).netloc

    # Make sure page contains a login form
    soup = BeautifulSoup(resp.text, "html.parser")

    login_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"name": "UserName"}):
            login_form = form
            proxy_to_adfs = True
            login_data = {'UserName': user, 'Password': password, 'AuthMethod': 'FormsAuthentication'}
            break

        elif form.find("input", {"name": "j_username"}):
            login_form = form
            login_data = {'_eventId_proceed': 'Login', 'j_username': user, 'j_password': password}
            break

    if not login_form:
        raise IdPException("Error displaying IdP login page")

    # Get form response URL
    action = login_form.get("action")

    if not host or not action:
        raise IdPException("Error displaying IdP login page")

    # Fill out and submit form -- log in
    try:
        if debug:
            print("Submitting IdP login form")

        resp = sess.post("https://{}{}".format(host, action), data=login_data,
                         timeout=timeout)

        if resp.status_code != 200:
            debug and print_response_body(resp.text)
            raise IdPException("Failed to submit login page to IdP - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise IdPException("Failed to submit login page to IdP - {}".format(e))

    debug and print_response_body(resp.text)

    # Make sure we didn't get the login form again
    soup = BeautifulSoup(resp.text, "html.parser")

    for form in soup.find_all("form"):
        if (proxy_to_adfs and form.find("input", {"name": "UserName"})) or (not proxy_to_adfs and form.find("input", {"name": "j_username"})):
            raise IdPException("IdP authentication failed")

    if proxy_to_adfs:
        # Get form to submit back to Shibboleth IdP
        soup = BeautifulSoup(resp.text, "html.parser")

        saml_form = None
        for form in soup.find_all("form"):
            if form.find("input", {"name": "SAMLResponse"}):
                saml_form = form
                break

        if not saml_form:
            raise IdPException("Invalid response from ADFS IdP after authentication")

        saml_resp = saml_form.find("input", {"name": "SAMLResponse"}).get("value")

        if debug:
            print("Base64-encoded SAML response")
            print(saml_resp)
            print()

        # Base64 decode response
        try:
            decoded_resp = base64.b64decode(saml_resp).decode()

        except binascii.Error:
            raise IdPException("Unable to base64 decode response from IdP")

        if debug:
            print("Base64-decoded SAML response")
            print(decoded_resp)
            print()

        action = saml_form.get("action")

        form_data = {}
        for input_tag in saml_form.find_all("input"):
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            form_data[input_name] = input_value

        if not action or not form_data:
            raise IdPException("Invalid response from ADFS IdP after authentication")

        try:
            if debug:
                print("Submitting IdP response back to Shibboleth IdP")

            resp = sess.post(action, data=form_data, timeout=timeout)

            if resp.status_code != 200:
                debug and print_response_body(resp.text)
                raise IdPException("Failed to return to Shibboleth IdP after authentication - HTTP status {}".format(resp.status_code))
        except requests.exceptions.RequestException as e:
            raise IdPException("Failed to return to Shibboleth IdP after authentication - {}".format(e))

        debug and print_response_body(resp.text)

    return resp

if __name__ == "__main__":
    # Parse command-line args
    parser = argparse.ArgumentParser(
        description="Monitor a Shibboleth IdP or Shibboleth-protected service with Nagios",
        )

    req_opts = parser.add_argument_group("Required options")
    idp_opts = parser.add_argument_group("IdP monitoring options")
    sp_opts = parser.add_argument_group("SP monitoring options")

    #-d / --debug
    parser.add_argument("-d", "--debug", dest="debug", default=False,
                        action="store_true", help="enable debugging outputs")

    #-w / --warn
    parser.add_argument("-w", "--warn", metavar="ms", dest="warn", type=float,
                        action="store",
                        help="warning when IDP processing time exceeds this time in milliseconds")

    #-c / --crit
    parser.add_argument("-c", "--crit", metavar="ms", dest="crit", type=float,
                        action="store",
                        help="critical when IDP processing time exceeds this time in milliseconds")

    #-t / --timeout
    parser.add_argument("-t", "--timeout", metavar="secs", dest="timeout",
                        type=float, default=15, action="store",
                        help="HTTP request timeout in seconds")

    #-U / --user
    req_opts.add_argument("-U", "--user", required=True, metavar="username",
                          dest="user", action="store",
                          help="User to authenticate as")

    #-P / --password
    req_opts.add_argument("-P", "--password", required=True, metavar="password",
                          dest="password", action="store",
                          help="Password for authentication user")

    #-H / --host
    idp_opts.add_argument("-H", "--host", metavar="hostname", dest="host",
                          action="store", help="IdP hostname when checking an IdP directly")

    #-e / --entitty-id
    idp_opts.add_argument("-e", "--entity-id", metavar="entityID",
                          dest="entityid", action="store",
                          default="urn:mace:incommon:uiuc.edu:healthcheck:nagios",
                          help="Entity ID to use in authn request")

    #-a / --attribute
    idp_opts.add_argument("-a", "--attribute", metavar="attribute",
                          dest="attribute", action="store", default="eduPersonPrincipalName",
                          help="Friendly name of SAML attribute that must be in a successful response")

    #-p / --proxy-idp
    idp_opts.add_argument("-p", "--proxy-idp", dest="checking_proxy", default=False,
                        action="store_true", help="Indicates that this IdP is a proxy IdP")

    #-u / --url
    sp_opts.add_argument("-u", "--url", metavar="URL", dest="url",
                         action="store",
                         help="URL of Shibboleth-protected resource when checking an SP")

    #-s / --output-string
    sp_opts.add_argument("-s", "--output-string", metavar="string",
                         dest="output_str", action="store",
                         help="Text to expect on final page after successful authentication")

    #-i / --idp-selection
    sp_opts.add_argument("-i", "--idp-selection", metavar="entityID",
                         dest="idp", action="store", default="urn:mace:incommon:uiuc.edu",
                         help="Entity of the IdP to choose if the service redirects to a discovery page")

    #parse arguments
    options = parser.parse_args()

    debug = options.debug

    if debug:
        print("Processed command-line arguments:")
        print(options)
        print()

        HTTPConnection.debuglevel = 1
        requests.logging.basicConfig(stream=sys.stdout, level=requests.logging.DEBUG)
        requests_log = requests.logging.getLogger("check_shib_idp")
        requests_log.propagate = True

    timeout = options.timeout

    if (options.host and options.url) or (not options.host and not options.url):
        parser.error("You must specify either an IdP hostname with -H or a service url with -u")

    if options.url and not options.output_str:
        parser.error("When checking a service provider, you must specify a string to look for on the final page with -s")

    if options.url and options.checking_proxy:
        parser.error("When checking a service provider, you cannot check a proxy IdP with -p")

    if options.host and options.output_str:
        parser.error("Output string not valid when checking an IdP")

    if options.url and not (urlparse(options.url).scheme and urlparse(options.url).netloc):
        parser.error("SP URL must be a valid URL")

    start_time = time.perf_counter()
    try:
        if options.host and not options.checking_proxy:
            if debug:
                print("Doing IdP-initiated check")

            do_idp_initiated(options.host, options.entityid,
                             options.user, options.password, options.attribute)
        elif options.host and options.checking_proxy:
            if debug:
                print("Doing IdP-initiated check against proxy IdP")

            do_proxy_idp_initiated(options.host, options.entityid,
                             options.user, options.password,
                             options.attribute, options.idp)
        elif options.url:
            if debug:
                print("Doing SP-initiated check")

            do_sp_initiated(options.url, options.user, options.password,
                            options.output_str, options.idp)
    except (SPException, IdPException) as e:
        runtime = round((time.perf_counter() - start_time) * 1000)
        print("IDP CRITICAL - {};|TIME={}\n".format(e, runtime))
        sys.exit(2)

    runtime = round((time.perf_counter() - start_time) * 1000)

    if options.crit and runtime > options.crit:
        print("IDP CRITICAL - TIME={} MS;|TIME={}\n".format(runtime, runtime))
        sys.exit(2)
    elif options.warn and runtime > options.warn:
        print("IDP WARN - TIME={} MS;|TIME={}\n".format(runtime, runtime))
        sys.exit(1)
    else:
        print("IDP OK - TIME={} MS;|TIME={}\n".format(runtime, runtime))
        sys.exit(0)
