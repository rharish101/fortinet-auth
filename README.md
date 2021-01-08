# Fortinet Firewall Authenticator

This is a script that logs in to a Fortinet firewall, such as one set up for public internet in colleges.
The script is written with Python 3.5+ support with NO dependencies, since one cannot access the internet to download Python packages unless one logs in to the Fortinet firewall.

## Usage
This script starts a session with the firewall and keeps running in the foreground.
To start it, run the script as follows:
```sh
./fortinet_auth.py
```

This will ask you to type your username and password in the terminal.
If you want to run this script as part of an automated process, you can specify the username and password as CLI arguments with the `--username` and `--password` flags respectively.
Then it tries to authenticate with these credentials.
If the username and password are incorrent, the script will raise an exception.
If there is a connection error, then it waits for some time before retrying.

Once authenticated, the script stays in the foreground and periodically pings the keep-alive URL so that you aren't logged out.
You can run this script under tmux or screen so that you don't have to keep an open SSH session or terminal.

To log out, simply terminate the script using a keyboard interrupt (Ctrl-C), or send a SIGTERM to the process.

For further information about available CLI arguments, run:
```sh
./fortinet_auth.py --help
```
