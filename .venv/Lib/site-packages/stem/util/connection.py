# Copyright 2012-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Connection and networking based utility functions.

**Module Overview:**

::

  download - download from a given url
  get_connections - quieries the connections belonging to a given process
  system_resolvers - provides connection resolution methods that are likely to be available
  port_usage - brief description of the common usage for a port

  is_valid_ipv4_address - checks if a string is a valid IPv4 address
  is_valid_ipv6_address - checks if a string is a valid IPv6 address
  is_valid_port - checks if something is a valid representation for a port
  is_private_address - checks if an IPv4 address belongs to a private range or not

  address_to_int - provides an integer representation of an IP address

  expand_ipv6_address - provides an IPv6 address with its collapsed portions expanded
  get_mask_ipv4 - provides the mask representation for a given number of bits
  get_mask_ipv6 - provides the IPv6 mask representation for a given number of bits

.. data:: Resolver (enum)

  Method for resolving a process' connections.

  .. versionadded:: 1.1.0

  .. versionchanged:: 1.4.0
     Added **NETSTAT_WINDOWS**.

  .. versionchanged:: 1.6.0
     Added **BSD_FSTAT**.

  .. deprecated:: 1.6.0
     The SOCKSTAT connection resolver is proving to be unreliable
     (:trac:`23057`), and will be dropped in the 2.0.0 release unless fixed.

  ====================  ===========
  Resolver              Description
  ====================  ===========
  **PROC**              /proc contents
  **NETSTAT**           netstat
  **NETSTAT_WINDOWS**   netstat command under Windows
  **SS**                ss command
  **LSOF**              lsof command
  **SOCKSTAT**          sockstat command under \\*nix
  **BSD_SOCKSTAT**      sockstat command under FreeBSD
  **BSD_PROCSTAT**      procstat command under FreeBSD
  **BSD_FSTAT**         fstat command under OpenBSD
  ====================  ===========
"""

import collections
import os
import platform
import re
import socket
import sys
import time

import stem
import stem.util
import stem.util.proc
import stem.util.system

from stem.util import conf, enum, log, str_tools

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

# Connection resolution is risky to log about since it's highly likely to
# contain sensitive information. That said, it's also difficult to get right in
# a platform independent fashion. To opt into the logging requried to
# troubleshoot connection resolution set the following...

LOG_CONNECTION_RESOLUTION = False

Resolver = enum.Enum(
  ('PROC', 'proc'),
  ('NETSTAT', 'netstat'),
  ('NETSTAT_WINDOWS', 'netstat (windows)'),
  ('SS', 'ss'),
  ('LSOF', 'lsof'),
  ('SOCKSTAT', 'sockstat'),
  ('BSD_SOCKSTAT', 'sockstat (bsd)'),
  ('BSD_PROCSTAT', 'procstat (bsd)'),
  ('BSD_FSTAT', 'fstat (bsd)')
)

FULL_IPv4_MASK = '255.255.255.255'
FULL_IPv6_MASK = 'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'

PORT_USES = None  # port number => description

RESOLVER_COMMAND = {
  Resolver.PROC: '',

  # -n = prevents dns lookups, -p = include process, -W = don't crop addresses (needed for ipv6)
  Resolver.NETSTAT: 'netstat -npW',

  # -a = show all TCP/UDP connections, -n = numeric addresses and ports, -o = include pid
  Resolver.NETSTAT_WINDOWS: 'netstat -ano',

  # -n = numeric ports, -p = include process, -t = tcp sockets, -u = udp sockets
  Resolver.SS: 'ss -nptu',

  # -n = prevent dns lookups, -P = show port numbers (not names), -i = ip only, -w = no warnings
  # (lsof provides a '-p <pid>' but oddly in practice it seems to be ~11-28% slower)
  Resolver.LSOF: 'lsof -wnPi',

  Resolver.SOCKSTAT: 'sockstat',

  # -4 = IPv4, -c = connected sockets
  Resolver.BSD_SOCKSTAT: 'sockstat -4c',

  # -f <pid> = process pid
  Resolver.BSD_PROCSTAT: 'procstat -f {pid}',

  # -p <pid> = process pid
  Resolver.BSD_FSTAT: 'fstat -p {pid}',
}

RESOLVER_FILTER = {
  Resolver.PROC: '',

  # tcp        0    586 192.168.0.1:44284       38.229.79.2:443         ESTABLISHED 15843/tor
  Resolver.NETSTAT: '^{protocol}\\s+.*\\s+{local}\\s+{remote}\\s+ESTABLISHED\\s+{pid}/{name}\\s*$',

  # tcp        586 192.168.0.1:44284       38.229.79.2:443         ESTABLISHED 15843
  Resolver.NETSTAT_WINDOWS: '^\\s*{protocol}\\s+{local}\\s+{remote}\\s+ESTABLISHED\\s+{pid}\\s*$',

  # tcp    ESTAB      0      0           192.168.0.20:44415       38.229.79.2:443    users:(("tor",15843,9))
  Resolver.SS: '^{protocol}\\s+ESTAB\\s+.*\\s+{local}\\s+{remote}\\s+users:\\(\\("{name}",(?:pid=)?{pid},(?:fd=)?[0-9]+\\)\\)$',

  # tor  3873  atagar  45u  IPv4  40994  0t0  TCP 10.243.55.20:45724->194.154.227.109:9001 (ESTABLISHED)
  Resolver.LSOF: '^{name}\\s+{pid}\\s+.*\\s+{protocol}\\s+{local}->{remote} \\(ESTABLISHED\\)$',

  # atagar   tor                  15843    tcp4   192.168.0.20:44092        68.169.35.102:443         ESTABLISHED
  Resolver.SOCKSTAT: '^\\S+\\s+{name}\\s+{pid}\\s+{protocol}4\\s+{local}\\s+{remote}\\s+ESTABLISHED$',

  # _tor     tor        4397  12 tcp4   172.27.72.202:54011   127.0.0.1:9001
  Resolver.BSD_SOCKSTAT: '^\\S+\\s+{name}\\s+{pid}\\s+\\S+\\s+{protocol}4\\s+{local}\\s+{remote}$',

  # 3561 tor                 4 s - rw---n--   2       0 TCP 10.0.0.2:9050 10.0.0.1:22370
  Resolver.BSD_PROCSTAT: '^\\s*{pid}\\s+{name}\\s+.*\\s+{protocol}\\s+{local}\\s+{remote}$',

  # _tor     tor        15843   20* internet stream tcp 0x0 192.168.1.100:36174 --> 4.3.2.1:443
  Resolver.BSD_FSTAT: '^\\S+\\s+{name}\\s+{pid}\\s+.*\\s+{protocol}\\s+\\S+\\s+{local}\\s+[-<]-[->]\\s+{remote}$',
}


class Connection(collections.namedtuple('Connection', ['local_address', 'local_port', 'remote_address', 'remote_port', 'protocol', 'is_ipv6'])):
  """
  Network connection information.

  .. versionchanged:: 1.5.0
     Added the **is_ipv6** attribute.

  :var str local_address: ip address the connection originates from
  :var int local_port: port the connection originates from
  :var str remote_address: destionation ip address
  :var int remote_port: destination port
  :var str protocol: protocol of the connection ('tcp', 'udp', etc)
  :var bool is_ipv6: addresses are ipv6 if true, and ipv4 otherwise
  """


def download(url, timeout = None, retries = None):
  """
  Download from the given url.

  .. versionadded:: 1.8.0

  :param str url: uncompressed url to download from
  :param int timeout: timeout when connection becomes idle, no timeout applied
    if **None**
  :param int retires: maximum attempts to impose

  :returns: **bytes** content of the given url

  :raises:
    * :class:`~stem.DownloadTimeout` if our request timed out
    * :class:`~stem.DownloadFailed` if our request fails
  """

  if retries is None:
    retries = 0

  start_time = time.time()

  try:
    return urllib.urlopen(url, timeout = timeout).read()
  except socket.timeout as exc:
    raise stem.DownloadTimeout(url, exc, sys.exc_info()[2], timeout)
  except:
    exc, stacktrace = sys.exc_info()[1:3]

    if timeout is not None:
      timeout -= time.time() - start_time

    if retries > 0 and (timeout is None or timeout > 0):
      log.debug('Failed to download from %s (%i retries remaining): %s' % (url, retries, exc))
      return download(url, timeout, retries - 1)
    else:
      log.debug('Failed to download from %s: %s' % (url, exc))
      raise stem.DownloadFailed(url, exc, stacktrace)


def get_connections(resolver = None, process_pid = None, process_name = None):
  """
  Retrieves a list of the current connections for a given process. This
  provides a list of :class:`~stem.util.connection.Connection`. Note that
  addresses may be IPv4 *or* IPv6 depending on what the platform supports.

  .. versionadded:: 1.1.0

  .. versionchanged:: 1.5.0
     Made our resolver argument optional.

  .. versionchanged:: 1.5.0
     IPv6 support when resolving via proc, netstat, lsof, or ss.

  :param Resolver resolver: method of connection resolution to use, if not
    provided then one is picked from among those that should likely be
    available for the system
  :param int process_pid: pid of the process to retrieve
  :param str process_name: name of the process to retrieve

  :returns: **list** of :class:`~stem.util.connection.Connection` instances

  :raises:
    * **ValueError** if neither a process_pid nor process_name is provided

    * **IOError** if no connections are available or resolution fails
      (generally they're indistinguishable). The common causes are the
      command being unavailable or permissions.
  """

  if not resolver:
    available_resolvers = system_resolvers()

    if available_resolvers:
      resolver = available_resolvers[0]
    else:
      raise IOError('Unable to determine a connection resolver')

  if not process_pid and not process_name:
    raise ValueError('You must provide a pid or process name to provide connections for')

  def _log(msg):
    if LOG_CONNECTION_RESOLUTION:
      log.debug(msg)

  _log('=' * 80)
  _log('Querying connections for resolver: %s, pid: %s, name: %s' % (resolver, process_pid, process_name))

  if isinstance(process_pid, str):
    try:
      process_pid = int(process_pid)
    except ValueError:
      raise ValueError('Process pid was non-numeric: %s' % process_pid)

  if process_pid is None:
    all_pids = stem.util.system.pid_by_name(process_name, True)

    if len(all_pids) == 0:
      if resolver in (Resolver.NETSTAT_WINDOWS, Resolver.PROC, Resolver.BSD_PROCSTAT):
        raise IOError("Unable to determine the pid of '%s'. %s requires the pid to provide the connections." % (process_name, resolver))
    elif len(all_pids) == 1:
      process_pid = all_pids[0]
    else:
      if resolver in (Resolver.NETSTAT_WINDOWS, Resolver.PROC, Resolver.BSD_PROCSTAT):
        raise IOError("There's multiple processes named '%s'. %s requires a single pid to provide the connections." % (process_name, resolver))

  if resolver == Resolver.PROC:
    return stem.util.proc.connections(pid = process_pid)

  resolver_command = RESOLVER_COMMAND[resolver].format(pid = process_pid)

  try:
    results = stem.util.system.call(resolver_command)
  except OSError as exc:
    raise IOError("Unable to query '%s': %s" % (resolver_command, exc))

  resolver_regex_str = RESOLVER_FILTER[resolver].format(
    protocol = '(?P<protocol>\\S+)',
    local = '(?P<local>[\\[\\]0-9a-f.:]+)',
    remote = '(?P<remote>[\\[\\]0-9a-f.:]+)',
    pid = process_pid if process_pid else '[0-9]*',
    name = process_name if process_name else '\\S*',
  )

  _log('Resolver regex: %s' % resolver_regex_str)
  _log('Resolver results:\n%s' % '\n'.join(results))

  connections = []
  resolver_regex = re.compile(resolver_regex_str)

  def _parse_address_str(addr_type, addr_str, line):
    addr, port = addr_str.rsplit(':', 1)

    if not is_valid_ipv4_address(addr) and not is_valid_ipv6_address(addr, allow_brackets = True):
      _log('Invalid %s address (%s): %s' % (addr_type, addr, line))
      return None, None
    elif not is_valid_port(port):
      _log('Invalid %s port (%s): %s' % (addr_type, port, line))
      return None, None
    else:
      _log('Valid %s:%s: %s' % (addr, port, line))
      return addr.lstrip('[').rstrip(']'), int(port)

  for line in results:
    match = resolver_regex.match(line)

    if match:
      attr = match.groupdict()

      local_addr, local_port = _parse_address_str('local', attr['local'], line)
      remote_addr, remote_port = _parse_address_str('remote', attr['remote'], line)

      if not (local_addr and local_port and remote_addr and remote_port):
        continue  # missing or malformed field

      protocol = attr['protocol'].lower()

      if protocol == 'tcp6':
        protocol = 'tcp'

      if protocol not in ('tcp', 'udp'):
        _log('Unrecognized protocol (%s): %s' % (protocol, line))
        continue

      conn = Connection(local_addr, local_port, remote_addr, remote_port, protocol, is_valid_ipv6_address(local_addr))
      connections.append(conn)
      _log(str(conn))

  _log('%i connections found' % len(connections))

  if not connections:
    raise IOError('No results found using: %s' % resolver_command)

  return connections


def system_resolvers(system = None):
  """
  Provides the types of connection resolvers likely to be available on this platform.

  .. versionadded:: 1.1.0

  .. versionchanged:: 1.3.0
     Renamed from get_system_resolvers() to system_resolvers(). The old name
     still works as an alias, but will be dropped in Stem version 2.0.0.

  :param str system: system to get resolvers for, this is determined by
    platform.system() if not provided

  :returns: **list** of :data:`~stem.util.connection.Resolver` instances available on this platform
  """

  if system is None:
    if stem.util.system.is_gentoo():
      system = 'Gentoo'
    else:
      system = platform.system()

  if system == 'Windows':
    resolvers = [Resolver.NETSTAT_WINDOWS]
  elif system == 'Darwin':
    resolvers = [Resolver.LSOF]
  elif system == 'OpenBSD':
    resolvers = [Resolver.BSD_FSTAT]
  elif system == 'FreeBSD':
    # Netstat is available, but lacks a '-p' equivalent so we can't associate
    # the results to processes. The platform also has a ss command, but it
    # belongs to a spreadsheet application.

    resolvers = [Resolver.BSD_SOCKSTAT, Resolver.BSD_PROCSTAT, Resolver.LSOF]
  else:
    # Sockstat isn't available by default on ubuntu.

    resolvers = [Resolver.NETSTAT, Resolver.SOCKSTAT, Resolver.LSOF, Resolver.SS]

  # remove any that aren't in the user's PATH

  resolvers = [r for r in resolvers if stem.util.system.is_available(RESOLVER_COMMAND[r])]

  # proc resolution, by far, outperforms the others so defaults to this is able

  if stem.util.proc.is_available() and os.access('/proc/net/tcp', os.R_OK) and os.access('/proc/net/udp', os.R_OK):
    resolvers = [Resolver.PROC] + resolvers

  return resolvers


def port_usage(port):
  """
  Provides the common use of a given port. For example, 'HTTP' for port 80 or
  'SSH' for 22.

  .. versionadded:: 1.2.0

  :param int port: port number to look up

  :returns: **str** with a description for the port, **None** if none is known
  """

  global PORT_USES

  if PORT_USES is None:
    config = conf.Config()
    config_path = os.path.join(os.path.dirname(__file__), 'ports.cfg')

    try:
      config.load(config_path)
      port_uses = {}

      for key, value in config.get('port', {}).items():
        if key.isdigit():
         port_uses[int(key)] = value
        elif '-' in key:
          min_port, max_port = key.split('-', 1)

          for port_entry in range(int(min_port), int(max_port) + 1):
            port_uses[port_entry] = value
        else:
          raise ValueError("'%s' is an invalid key" % key)

      PORT_USES = port_uses
    except Exception as exc:
      log.warn("BUG: stem failed to load its internal port descriptions from '%s': %s" % (config_path, exc))

  if not PORT_USES:
    return None

  if isinstance(port, str) and port.isdigit():
    port = int(port)

  return PORT_USES.get(port)


def is_valid_ipv4_address(address):
  """
  Checks if a string is a valid IPv4 address.

  :param str address: string to be checked

  :returns: **True** if input is a valid IPv4 address, **False** otherwise
  """

  if isinstance(address, bytes):
    address = str_tools._to_unicode(address)
  elif not stem.util._is_str(address):
    return False

  # checks if theres four period separated values

  if address.count('.') != 3:
     return False

  # checks that each value in the octet are decimal values between 0-255
  for entry in address.split('.'):
    if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
      return False
    elif entry[0] == '0' and len(entry) > 1:
      return False  # leading zeros, for instance in '1.2.3.001'

  return True


def is_valid_ipv6_address(address, allow_brackets = False):
  """
  Checks if a string is a valid IPv6 address.

  :param str address: string to be checked
  :param bool allow_brackets: ignore brackets which form '[address]'

  :returns: **True** if input is a valid IPv6 address, **False** otherwise
  """

  if isinstance(address, bytes):
    address = str_tools._to_unicode(address)
  elif not stem.util._is_str(address):
    return False

  if allow_brackets:
    if address.startswith('[') and address.endswith(']'):
      address = address[1:-1]

  if address.count('.') == 3:
    # Likely an ipv4-mapped portion. Check that its vaild, then replace with a
    # filler.

    ipv4_start = address.rfind(':', 0, address.find('.')) + 1
    ipv4_end = address.find(':', ipv4_start + 1)

    if ipv4_end == -1:
      ipv4_end = None  # don't crop the last character

    if not is_valid_ipv4_address(address[ipv4_start:ipv4_end]):
      return False

    addr_comp = [address[:ipv4_start - 1] if ipv4_start != 0 else None, 'ff:ff', address[ipv4_end + 1:] if ipv4_end else None]
    address = ':'.join(filter(None, addr_comp))

  # addresses are made up of eight colon separated groups of four hex digits
  # with leading zeros being optional
  # https://en.wikipedia.org/wiki/IPv6#Address_format

  colon_count = address.count(':')

  if colon_count > 7:
    return False  # too many groups
  elif colon_count != 7 and '::' not in address:
    return False  # not enough groups and none are collapsed
  elif address.count('::') > 1 or ':::' in address:
    return False  # multiple groupings of zeros can't be collapsed

  for entry in address.split(':'):
    if not re.match('^[0-9a-fA-f]{0,4}$', entry):
      return False

  return True


def is_valid_port(entry, allow_zero = False):
  """
  Checks if a string or int is a valid port number.

  :param list,str,int entry: string, integer or list to be checked
  :param bool allow_zero: accept port number of zero (reserved by definition)

  :returns: **True** if input is an integer and within the valid port range, **False** otherwise
  """

  try:
    value = int(entry)

    if str(value) != str(entry):
      return False  # invalid leading char, e.g. space or zero
    elif allow_zero and value == 0:
      return True
    else:
      return value > 0 and value < 65536
  except TypeError:
    if isinstance(entry, (tuple, list)):
      for port in entry:
        if not is_valid_port(port, allow_zero):
          return False

      return True
    else:
      return False
  except ValueError:
    return False


def is_private_address(address):
  """
  Checks if the IPv4 address is in a range belonging to the local network or
  loopback. These include:

    * Private ranges: 10.*, 172.16.* - 172.31.*, 192.168.*
    * Loopback: 127.*

  .. versionadded:: 1.1.0

  :param str address: string to be checked

  :returns: **True** if input is in a private range, **False** otherwise

  :raises: **ValueError** if the address isn't a valid IPv4 address
  """

  if not is_valid_ipv4_address(address):
    raise ValueError("'%s' isn't a valid IPv4 address" % address)

  # checks for any of the simple wildcard ranges

  if address.startswith('10.') or address.startswith('192.168.') or address.startswith('127.'):
    return True

  # checks for the 172.16.* - 172.31.* range

  if address.startswith('172.'):
    second_octet = int(address.split('.')[1])

    if second_octet >= 16 and second_octet <= 31:
      return True

  return False


def address_to_int(address):
  """
  Provides an integer representation of a IPv4 or IPv6 address that can be used
  for sorting.

  .. versionadded:: 1.5.0

  :param str address: IPv4 or IPv6 address

  :returns: **int** representation of the address
  """

  # TODO: Could be neat to also use this for serialization if we also had an
  # int_to_address() function.

  return int(_address_to_binary(address), 2)


def expand_ipv6_address(address):
  """
  Expands abbreviated IPv6 addresses to their full colon separated hex format.
  For instance...

  ::

    >>> expand_ipv6_address('2001:db8::ff00:42:8329')
    '2001:0db8:0000:0000:0000:ff00:0042:8329'

    >>> expand_ipv6_address('::')
    '0000:0000:0000:0000:0000:0000:0000:0000'

    >>> expand_ipv6_address('::ffff:5.9.158.75')
    '0000:0000:0000:0000:0000:ffff:0509:9e4b'

  :param str address: IPv6 address to be expanded

  :raises: **ValueError** if the address can't be expanded due to being malformed
  """

  if not is_valid_ipv6_address(address):
    raise ValueError("'%s' isn't a valid IPv6 address" % address)

  # expand ipv4-mapped portions of addresses
  if address.count('.') == 3:
    ipv4_start = address.rfind(':', 0, address.find('.')) + 1
    ipv4_end = address.find(':', ipv4_start + 1)

    if ipv4_end == -1:
      ipv4_end = None  # don't crop the last character

    # Converts ipv4 address to its hex ipv6 representation. For instance...
    #
    #   '5.9.158.75' => '0509:9e4b'

    ipv4_bin = _address_to_binary(address[ipv4_start:ipv4_end])
    groupings = [ipv4_bin[16 * i:16 * (i + 1)] for i in range(2)]
    ipv6_snippet = ':'.join(['%04x' % int(group, 2) for group in groupings])

    addr_comp = [address[:ipv4_start - 1] if ipv4_start != 0 else None, ipv6_snippet, address[ipv4_end + 1:] if ipv4_end else None]
    address = ':'.join(filter(None, addr_comp))

  # expands collapsed groupings, there can only be a single '::' in a valid
  # address
  if '::' in address:
    missing_groups = 7 - address.count(':')
    address = address.replace('::', '::' + ':' * missing_groups)

  # inserts missing zeros
  for index in range(8):
    start = index * 5
    end = address.index(':', start) if index != 7 else len(address)
    missing_zeros = 4 - (end - start)

    if missing_zeros > 0:
      address = address[:start] + '0' * missing_zeros + address[start:]

  return address


def get_mask_ipv4(bits):
  """
  Provides the IPv4 mask for a given number of bits, in the dotted-quad format.

  :param int bits: number of bits to be converted

  :returns: **str** with the subnet mask representation for this many bits

  :raises: **ValueError** if given a number of bits outside the range of 0-32
  """

  if bits > 32 or bits < 0:
    raise ValueError('A mask can only be 0-32 bits, got %i' % bits)
  elif bits == 32:
    return FULL_IPv4_MASK

  # get the binary representation of the mask
  mask_bin = _get_binary(2 ** bits - 1, 32)[::-1]

  # breaks it into eight character groupings
  octets = [mask_bin[8 * i:8 * (i + 1)] for i in range(4)]

  # converts each octet into its integer value
  return '.'.join([str(int(octet, 2)) for octet in octets])


def get_mask_ipv6(bits):
  """
  Provides the IPv6 mask for a given number of bits, in the hex colon-delimited
  format.

  :param int bits: number of bits to be converted

  :returns: **str** with the subnet mask representation for this many bits

  :raises: **ValueError** if given a number of bits outside the range of 0-128
  """

  if bits > 128 or bits < 0:
    raise ValueError('A mask can only be 0-128 bits, got %i' % bits)
  elif bits == 128:
    return FULL_IPv6_MASK

  # get the binary representation of the mask
  mask_bin = _get_binary(2 ** bits - 1, 128)[::-1]

  # breaks it into sixteen character groupings
  groupings = [mask_bin[16 * i:16 * (i + 1)] for i in range(8)]

  # converts each group into its hex value
  return ':'.join(['%04x' % int(group, 2) for group in groupings]).upper()


def _get_masked_bits(mask):
  """
  Provides the number of bits that an IPv4 subnet mask represents. Note that
  not all masks can be represented by a bit count.

  :param str mask: mask to be converted

  :returns: **int** with the number of bits represented by the mask

  :raises: **ValueError** if the mask is invalid or can't be converted
  """

  if not is_valid_ipv4_address(mask):
    raise ValueError("'%s' is an invalid subnet mask" % mask)

  # converts octets to binary representation
  mask_bin = _address_to_binary(mask)
  mask_match = re.match('^(1*)(0*)$', mask_bin)

  if mask_match:
    return 32 - len(mask_match.groups()[1])
  else:
    raise ValueError('Unable to convert mask to a bit count: %s' % mask)


def _get_binary(value, bits):
  """
  Provides the given value as a binary string, padded with zeros to the given
  number of bits.

  :param int value: value to be converted
  :param int bits: number of bits to pad to
  """

  # http://www.daniweb.com/code/snippet216539.html
  return ''.join([str((value >> y) & 1) for y in range(bits - 1, -1, -1)])


# TODO: In stem 2.x we should consider unifying this with
# stem.client.datatype's _unpack_ipv4_address() and _unpack_ipv6_address().

def _address_to_binary(address):
  """
  Provides the binary value for an IPv4 or IPv6 address.

  :returns: **str** with the binary representation of this address

  :raises: **ValueError** if address is neither an IPv4 nor IPv6 address
  """

  if is_valid_ipv4_address(address):
    return ''.join([_get_binary(int(octet), 8) for octet in address.split('.')])
  elif is_valid_ipv6_address(address):
    address = expand_ipv6_address(address)
    return ''.join([_get_binary(int(grouping, 16), 16) for grouping in address.split(':')])
  else:
    raise ValueError("'%s' is neither an IPv4 or IPv6 address" % address)


# TODO: drop with stem 2.x
# We renamed our methods to drop a redundant 'get_*' prefix, so alias the old
# names for backward compatability.

get_system_resolvers = system_resolvers
