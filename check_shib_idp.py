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
import argparse, requests, base64, sys, binascii, time

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

def doIdPInitiated(host, sp, user, password, attribute):
    """doIdPInitiated() -- check in IdP directly

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
    reqParams = {"providerId": sp}

    # Create persistent session
    sess = requests.session()

    # Send initial IdP-initiated SSO request
    try:
        if debug:
            print("Sending initial request to IdP")
        resp = sess.get("https://{}/idp/profile/SAML2/Unsolicited/SSO".format(host),
            params=reqParams, timeout=timeout)
        if resp.status_code != 200:
            if debug:
                print()
                print("BEGIN RESPONSE BODY:")
                print(resp.text)
                print("END RESPONSE BODY:")
                print()

            raise IdPException("Not redirected to login page - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise IdPException("Not redirected to login page - {}".format(e))

    if debug:
        print()
        print("BEGIN RESPONSE BODY:")
        print(resp.text)
        print("END RESPONSE BODY:")
        print()

    resp = doLogin(sess, resp, user, password)

    # Parse SAML response out of form
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        samlResp = soup.form.find("input", {"name": "SAMLResponse"}).get("value")

    except AttributeError:
        raise IdPException("Invalid response from IdP after authentication")

    if debug:
        print("Base64-encoded SAML response")
        print(samlResp)
        print()

    # Base64 decode response
    try:
        decodedResp = base64.b64decode(samlResp).decode()

    except binascii.Error:
        raise IdPException("Unable to base64 decode response from IdP")

    if debug:
        print("Base64-decoded SAML response")
        print(decodedResp)
        print()

    if "urn:oasis:names:tc:SAML:2.0:status:Success" not in decodedResp:
        raise IdPException("SAML success status not found in response")
    elif debug:
        print("SAML success status found in response")

    if 'FriendlyName="{}"'.format(attribute) not in decodedResp:
        raise IdPException("Required attribute {} not found in response".format(attribute))
    elif debug:
        print("Required attribute {} found in response".format(attribute))

def doSPInitiated(url, user, password, str, idp):
    """doSPInitiated() -- Check an SP resource that's Shibboleth-protected

    Params:
    url -- URL of the protected page to check
    user -- username to use in authentication
    password -- password to use in authentication
    str -- text that must be present on the page after return from IdP
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
            if debug:
                print()
                print("BEGIN RESPONSE BODY:")
                print(resp.text)
                print("END RESPONSE BODY:")
                print()

            raise SPException("Not redirected to login page - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Not redirected to login page - {}".format(e))

    if debug:
        print()
        print("BEGIN RESPONSE BODY:")
        print(resp.text)
        print("END RESPONSE BODY:")
        print()

    # Were we redirected to the campus selection page?
    soup = BeautifulSoup(resp.text, "html.parser")
    if soup.title.string == "Illinois Identity Provider Selection":
        if debug:
            print("IdP discovery page detected")

        resp = doDiscoverySelect(sess, resp, idp)

    resp = doLogin(sess, resp, user, password)

    # Get form to submit back to SP
    soup = BeautifulSoup(resp.text, "html.parser")
    action = soup.form.get("action")

    formData = {}
    for input_tag in soup.form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        input_value =input_tag.attrs.get("value", "")
        formData[input_name] = input_value

    if not action or not formData:
        raise SPException("Invalid response from IdP after authentication")

    try:
        if debug:
            print("Submitting IdP response back to SP")

        resp = sess.post(action, data=formData, timeout=timeout)

        if resp.status_code != 200:
            if debug:
                print()
                print("BEGIN RESPONSE BODY:")
                print(resp.text)
                print("END RESPONSE BODY:")
                print()

            raise SPException("Failed to return to SP after authentication - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Failed to return to SP after authentication - {}".format(e))

    if debug:
        print()
        print("BEGIN RESPONSE BODY:")
        print(resp.text)
        print("END RESPONSE BODY:")
        print()

    if resp.text.find(str) == -1:
        raise SPException("Expected output text not found after authentication")
    elif debug:
        print("Expected output text found after authentication")

def doDiscoverySelect(sess,resp,idp):
    """doDiscoverySelect() -- Select an IdP from a discovery service

    Params:
    sess -- persistent request.session object
    resp -- request response object containing the discovery service form
    idp -- entity ID of IdP to select

    Throws:
    SPException if interaction fails at any point

    Returns:
    Response object containing the result of IdP selection
    """

    soup = BeautifulSoup(resp.text, "html.parser")

    # Get IdP hostname from response
    host = urlparse(resp.url).netloc

    # Get form response URL to submit back to discovery service
    action = soup.form.get("action")

    if not host or not action:
        raise SPException("Error from discovery service")

    # Build form response
    discoData = {"user_idp": idp, "Select": "Select"}

    # Select campus
    try:
        if debug:
            print("Selecting IdP from discovery page")

        resp = sess.post("https://{}{}".format(host,action), data=discoData,
            timeout=timeout)
        if resp.status_code != 200:
            if debug:
                print()
                print("BEGIN RESPONSE BODY:")
                print(resp.text)
                print("END RESPONSE BODY:")
                print()

            raise SPException("Failed to return to SP after IdP selection - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise SPException("Failed to return to SP after IdP selection - {}".format(e))

    if debug:
        print()
        print("BEGIN RESPONSE BODY:")
        print(resp.text)
        print("END RESPONSE BODY:")
        print()

    return resp

def doLogin(sess,resp,user,password):
    """doLogin() -- authenticate to an IdP

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

    # IdP login form data to use for authentication
    loginData = {'_eventId_proceed': 'Login', 'j_username': user, 'j_password': password}

    # Get IdP hostname from response
    host = urlparse(resp.url).netloc

    # Get form response URL
    soup = BeautifulSoup(resp.text, "html.parser")
    action = soup.form.get("action")

    if not host or not action:
        raise IdPException("Error displaying IdP login page")

    # Fill out and submit form -- log in
    try:
        if debug:
            print("Submitting IdP login form")

        resp = sess.post("https://{}{}".format(host,action), data=loginData,
            timeout=timeout)

        if resp.status_code != 200:
            if debug:
                print()
                print("BEGIN RESPONSE BODY:")
                print(resp.text)
                print("END RESPONSE BODY:")
                print()

            raise IdPException("Failed to submit login page to IdP - HTTP status {}".format(resp.status_code))
    except requests.exceptions.RequestException as e:
        raise IdPException("Failed to submit login page to IdP - {}".format(e))

    if debug:
        print()
        print("BEGIN RESPONSE BODY:")
        print(resp.text)
        print("END RESPONSE BODY:")
        print()

    # Make sure we didn't get the login form again
    soup = BeautifulSoup(resp.text, "html.parser")
    if soup.form.find("input", {"name": "j_username"}):
        raise IdPException("IdP authentication failed")

    if debug:
        print()
        print("BEGIN RESPONSE BODY:")
        print(resp.text)
        print("END RESPONSE BODY:")
        print()

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

    #-u / --url
    sp_opts.add_argument("-u", "--url", metavar="URL", dest="url",
        action="store",
        help="URL of Shibboleth-protected resource when checking an SP")

    #-s / --output-string
    sp_opts.add_argument("-s", "--output-string", metavar="string",
        dest="outputStr", action="store",
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
        requests.logging.basicConfig(stream=sys.stdout,
            level=requests.logging.DEBUG)
        requests_log = requests.logging.getLogger("urllib3")
        requests_log.propagate = True

    timeout = options.timeout

    if (options.host and options.url) or (not options.host and not options.url):
        parser.error("You must specify either an IdP hostname with -H or a service url with -u")

    if options.url and not options.outputStr:
        parser.error("When checking a service provider, you must specify a string to look for on the final page with -s")

    if options.host and options.outputStr:
        parser.error("Output string not valid when checking an IdP")

    if options.url and not (urlparse(options.url).scheme and urlparse(options.url).netloc):
        parser.error("SP URL must be a valid URL")

    startTime = time.clock()
    try:
        if options.host:
            if debug:
                print("Doing IdP-initiated check")

            doIdPInitiated(options.host, options.entityid,
                options.user, options.password, options.attribute)
        elif options.url:
            if debug:
                print("Doing SP-initiated check")

            doSPInitiated(options.url, options.user, options.password,
                options.outputStr, options.idp)
    except (SPException,IdPException) as e:
        runTime = round((time.clock() - startTime) * 1000)
        print("IDP CRITICAL - {};|TIME={}\n".format(e,runTime))
        sys.exit(2)

    runTime = round((time.clock() - startTime) * 1000)

    if options.crit and runTime > options.crit:
        print("IDP CRITICAL - TIME={} MS;|TIME={}\n".format(runTime,runTime))
        sys.exit(2)
    elif options.warn and runTime > options.warn:
        print("IDP WARN - TIME={} MS;|TIME={}\n".format(runTime,runTime))
        sys.exit(1)
    else:
        print("IDP OK - TIME={} MS;|TIME={}\n".format(runTime,runTime))
        sys.exit(0)
