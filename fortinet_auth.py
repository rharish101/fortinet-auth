#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2020 Harish Rajagopal <harish.rajagopals@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Authentication script for FortiNet."""
import logging
import re
from argparse import ArgumentParser, Namespace
from getpass import getpass
from http.client import RemoteDisconnected
from signal import SIGTERM, signal
from socket import timeout
from time import sleep
from typing import Dict, Optional
from urllib.error import URLError
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

LOG_FMT = "%(asctime)s %(levelname)s %(message)s"  # Format for logging


class AuthenticationFailure(Exception):
    """Indicates a failure in authentication.

    This mostly occurs if the username and/or password is wrong.
    """


class Authenticator:
    """Class for authenticating to FortiNet."""

    # Using HTTP as redirection to gateway raises SSL errors with HTTPS.
    TEST_URL = "http://www.imdb.com"

    # All times are in seconds.
    TIMEOUT = 5  # Timeout for GET/POST requests
    RETRY_SLEEP = 20  # Pause before retrying login/keep-alive if they fail
    KEEPALIVE_SLEEP = 60  # Pause b/w two pings of the keep-alive URL

    # Errors indicating that the request failed
    HTTP_ERRORS = (
        timeout,
        URLError,
        RemoteDisconnected,
    )

    def __init__(
        self,
        username: str,
        password: str,
        logger: Optional[logging.Logger] = None,
    ):
        """Store user details.

        Args:
            username: The FortiNet username
            password: The FortiNet password
            logger: The logger to be used
        """
        self.username = username
        self.password = password

        if logger is None:
            self.logger = logging.getLogger()
        else:
            self.logger = logger

        # This will later store the keep-alive and logout URLs.
        self.urls: Dict[str, str] = {}

    def __del__(self) -> None:
        """Automatically logout on exit."""
        self.logout()

    def authenticate(self) -> None:
        """Try to authenticate.

        Raises:
            AuthenticationFailure: If the authentication fails
        """
        self.logger.info("Starting authentication...")

        with urlopen(self.TEST_URL, timeout=self.TIMEOUT) as resp:
            redir_url = resp.geturl()  # URL after redirection to FortiNet

        parsed = urlparse(redir_url)
        if parsed.path != "/fgtauth":
            # We weren't redirected to a FortiNet authentication page.
            self.logger.info("Seems already authenticated")
            return

        # Redirected to a FortiNet authentication page.
        params: Dict[str, str] = {
            "username": self.username,
            "password": self.password,
            "magic": parsed.query,
        }
        data = urlencode(params).encode("utf8")  # POST data must be bytes.

        # "Content-Type" headers are automatically added by Python.
        with urlopen(redir_url, data=data, timeout=self.TIMEOUT) as resp:
            content = resp.read().decode("utf8")  # Convert bytes to str.

        # List of all URLs in the HTML response that are of the form:
        # href="http://url.to/some/page.html"
        all_urls = re.findall(r'href="([^"]+)"', content)

        if len(all_urls) == 0:
            # This mostly means that the username and/or password wrong.
            raise AuthenticationFailure("Failed to authenticate")

        # If this assertion fails, then it means that FortiNet has
        # changed its HTML template for authentication pages. This
        # implies that this code has to be changed as well.
        assert len(all_urls) == 3, "FortiNet HTML template has changed"

        self.logger.info("Successfully authenticated")
        self.urls["keepAlive"] = all_urls[2]
        self.urls["logout"] = all_urls[1]

    def keep_alive(self) -> bool:
        """Ping the keep-alive URL.

        Returns:
            bool: True if keep-alive succeeds

        """
        assert "keepAlive" in self.urls, "No keep-alive URL is registered"
        self.logger.info("Pinging keep-alive")

        try:
            with urlopen(self.urls["keepAlive"], timeout=self.TIMEOUT) as resp:
                resp_url = resp.geturl()
            # Ensure that keep-alive succeeded.
            assert urlparse(resp_url).path == "/keepalive"

        except self.HTTP_ERRORS + (AssertionError,):
            self.logger.warning("Keep-alive failed")
            return False

        else:
            return True

    def logout(self) -> None:
        """Logout from FortiNet."""
        assert "logout" in self.urls, "No logout URL is registered"
        self.logger.info("Logging out")
        try:
            urlopen(self.urls["logout"], timeout=self.TIMEOUT)
        except self.HTTP_ERRORS:
            self.logger.warning("Failed to log out")

    def open_session(self) -> None:
        """Open an authentication session and keep it open until closed.

        This session can be closed by deleting an instance of this object. This
        can be done by sending a KeyboardInterrupt, which causes Python to
        delete the instance. For handling SIGTERM, `exit` can be registered as
        a handler.
        """
        # This while loop ensures that in case of errors, we keep trying. If
        # the login succeeds, then the execution breaks out of this loop. Also,
        # if the user is already logged in, we keep pinging, in case this login
        # times out.
        while True:
            try:
                self.authenticate()

            # NOTE: An `AuthenticationFailure` indicates that username and
            # password are wrong. We want to deliberately CRASH if that
            # happens; hence we're not handling it.
            except self.HTTP_ERRORS:
                self.logger.warning(
                    "Encountered error when logging in; "
                    "retrying in {} seconds".format(self.RETRY_SLEEP)
                )

            if (
                self.urls
            ):  # This will not be empty if authentication succeeded.
                break  # Login succeeded, so break out of the loop.
            else:
                sleep(self.RETRY_SLEEP)

        # Wait for some time before pinging keep-alive.
        sleep(self.KEEPALIVE_SLEEP)

        # Loop forever and keep the login alive.
        while True:
            if self.keep_alive():
                sleep(self.KEEPALIVE_SLEEP)  # Keep-alive succeeded.
            else:
                sleep(self.RETRY_SLEEP)  # Keep-alive failed.


def main(args: Namespace) -> None:
    """Run the main program.

    Arguments:
        args: The object containing the commandline arguments
    """
    username, password = args.username, args.password
    if username is None:
        username = input("Enter username: ")
    if password is None:
        password = getpass("Enter password: ")

    if args.quiet:  # Log everything with custom format.
        logging.basicConfig(format=LOG_FMT)
    else:  # Log everything with level >= INFO and with custom format.
        logging.basicConfig(format=LOG_FMT, level=logging.INFO)

    # Gracefully exit with a logout on SIGTERM.
    signal(SIGTERM, lambda _, __: exit())

    auth = Authenticator(username, password)
    auth.open_session()


if __name__ == "__main__":
    parser = ArgumentParser(description="Authentication script for FortiNet")
    parser.add_argument("-u", "--username", type=str, help="FortiNet username")
    parser.add_argument("-p", "--password", type=str, help="FortiNet password")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="disable verbose output"
    )
    main(parser.parse_args())
