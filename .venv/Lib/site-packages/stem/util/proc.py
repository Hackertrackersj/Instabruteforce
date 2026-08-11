# Copyright 2011-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for querying process and system information from the /proc
contents. Fetching information this way provides huge performance benefits
over lookups via system utilities (ps, netstat, etc). For instance, resolving
connections this way cuts the runtime by around 90% verses the alternatives.
These functions may not work on all platforms (only Linux?).

The method for reading these files (and a little code) are borrowed from
`psutil <https://code.google.com/p/psutil/>`_, which was written by Jay Loden,
Dave Daeschler, Giampaolo Rodola' and is under the BSD license.

**These functions are not being vended to stem users. They may change in the
future, use them at your own risk.**

.. versionchanged:: 1.3.0
   Dropped the get_* prefix from several function names. The old names still
   work, but are deprecated aliases.

**Module Overview:**

::

  is_available - checks if proc utilities can be used on this system
  system_start_time - unix timestamp for when the system started
  physical_memory - memory available on this system
  cwd - provides the current working directory for a process
  uid - provides the user id a process is running under
  memory_usage - provides the memory usage of a process
  stats - queries statistics about a process
  file_descriptors_used - number of file descriptors used by a process
  connections - provides the connections made by a process

.. data:: Stat (enum)

  Types of data available via the :func:`~stem.util.proc.stats` function.

  ============== ===========
  Stat           Description
  ============== ===========
  **COMMAND**    command name under which the process is running
  **CPU_UTIME**  total user time spent on the process
  **CPU_STIME**  total system time spent on the process
  **START_TIME** when this process began, in unix time
  ============== ===========
"""

import base64
import os
import platform
import socket
import sys
import time

import stem.prereq
import stem.util.connection
import stem.util.enum
import stem.util.str_tools

from stem.util import log

try:
  # unavailable on windows (#19823)
  import pwd
  IS_PWD_AVAILABLE = True
except ImportError:
  IS_PWD_AVAILABLE = False

if stem.prereq._is_lru_cache_available():
  from functools import lru_cache
else:
  from stem.util.lru_cache import lru_cache

# os.sysconf is only defined on unix
try:
  CLOCK_TICKS = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
except AttributeError:
  CLOCK_TICKS = None

IS_LITTLE_ENDIAN = sys.byteorder == 'little'
ENCODED_ADDR = {}  # cache of encoded ips to their decoded version

Stat = stem.util.enum.Enum(
  ('COMMAND', 'command'), ('CPU_UTIME', 'utime'),
  ('CPU_STIME', 'stime'), ('START_TIME', 'start time')
)


@lru_cache()
def is_available():
  """
  Checks if proc information is available on this platform.

  :returns: **True** if proc contents exist on this platform, **False** otherwise
  """

  if platform.system() != 'Linux':
    return False
  else:
    # list of process independent proc paths we use
    proc_paths = ('/proc/stat', '/proc/meminfo', '/proc/net/tcp', '/proc/net/udp')

    for path in proc_paths:
      if not os.path.exists(path):
        return False

    return True


@lru_cache()
def system_start_time():
  """
  Provides the unix time (seconds since epoch) when the system started.

  :returns: **float** for the unix time of when the system started

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'system start time'
  btime_line = _get_line('/proc/stat', 'btime', parameter)

  try:
    result = float(btime_line.strip().split()[1])
    _log_runtime(parameter, '/proc/stat[btime]', start_time)
    return result
  except:
    exc = IOError('unable to parse the /proc/stat btime entry: %s' % btime_line)
    _log_failure(parameter, exc)
    raise exc


@lru_cache()
def physical_memory():
  """
  Provides the total physical memory on the system in bytes.

  :returns: **int** for the bytes of physical memory this system has

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'system physical memory'
  mem_total_line = _get_line('/proc/meminfo', 'MemTotal:', parameter)

  try:
    result = int(mem_total_line.split()[1]) * 1024
    _log_runtime(parameter, '/proc/meminfo[MemTotal]', start_time)
    return result
  except:
    exc = IOError('unable to parse the /proc/meminfo MemTotal entry: %s' % mem_total_line)
    _log_failure(parameter, exc)
    raise exc


def cwd(pid):
  """
  Provides the current working directory for the given process.

  :param int pid: process id of the process to be queried

  :returns: **str** with the path of the working directory for the process

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'cwd'
  proc_cwd_link = '/proc/%s/cwd' % pid

  if pid == 0:
    cwd = ''
  else:
    try:
      cwd = os.readlink(proc_cwd_link)
    except OSError:
      exc = IOError('unable to read %s' % proc_cwd_link)
      _log_failure(parameter, exc)
      raise exc

  _log_runtime(parameter, proc_cwd_link, start_time)
  return cwd


def uid(pid):
  """
  Provides the user ID the given process is running under.

  :param int pid: process id of the process to be queried

  :returns: **int** with the user id for the owner of the process

  :raises: **IOError** if it can't be determined
  """

  start_time, parameter = time.time(), 'uid'
  status_path = '/proc/%s/status' % pid
  uid_line = _get_line(status_path, 'Uid:', parameter)

  try:
    result = int(uid_line.split()[1])
    _log_runtime(parameter, '%s[Uid]' % status_path, start_time)
    return result
  except:
    exc = IOError('unable to parse the %s Uid entry: %s' % (status_path, uid_line))
    _log_failure(parameter, exc)
    raise exc


def memory_usage(pid):
  """
  Provides the memory usage in bytes for the given process.

  :param int pid: process id of the process to be queried

  :returns: **tuple** of two ints with the memory usage of the process, of the
    form **(resident_size, virtual_size)**

  :raises: **IOError** if it can't be determined
  """

  # checks if this is the kernel process

  if pid == 0:
    return (0, 0)

  start_time, parameter = time.time(), 'memory usage'
  status_path = '/proc/%s/status' % pid
  mem_lines = _get_lines(status_path, ('VmRSS:', 'VmSize:'), parameter)

  try:
    residentSize = int(mem_lines['VmRSS:'].split()[1]) * 1024
    virtualSize = int(mem_lines['VmSize:'].split()[1]) * 1024

    _log_runtime(parameter, '%s[VmRSS|VmSize]' % status_path, start_time)
    return (residentSize, virtualSize)
  except:
    exc = IOError('unable to parse the %s VmRSS and VmSize entries: %s' % (status_path, ', '.join(mem_lines)))
    _log_failure(parameter, exc)
    raise exc


def stats(pid, *stat_types):
  """
  Provides process specific information. See the :data:`~stem.util.proc.Stat`
  enum for valid options.

  :param int pid: process id of the process to be queried
  :param Stat stat_types: information to be provided back

  :returns: **tuple** with all of the requested statistics as strings

  :raises: **IOError** if it can't be determined
  """

  if CLOCK_TICKS is None:
    raise IOError('Unable to look up SC_CLK_TCK')

  start_time, parameter = time.time(), 'process %s' % ', '.join(stat_types)

  # the stat file contains a single line, of the form...
  # 8438 (tor) S 8407 8438 8407 34818 8438 4202496...
  stat_path = '/proc/%s/stat' % pid
  stat_line = _get_line(stat_path, str(pid), parameter)

  # breaks line into component values
  stat_comp = []
  cmd_start, cmd_end = stat_line.find('('), stat_line.find(')')

  if cmd_start != -1 and cmd_end != -1:
    stat_comp.append(stat_line[:cmd_start])
    stat_comp.append(stat_line[cmd_start + 1:cmd_end])
    stat_comp += stat_line[cmd_end + 1:].split()

  if len(stat_comp) < 44 and _is_float(stat_comp[13], stat_comp[14], stat_comp[21]):
    exc = IOError('stat file had an unexpected format: %s' % stat_path)
    _log_failure(parameter, exc)
    raise exc

  results = []
  for stat_type in stat_types:
    if stat_type == Stat.COMMAND:
      if pid == 0:
        results.append('sched')
      else:
        results.append(stat_comp[1])
    elif stat_type == Stat.CPU_UTIME:
      if pid == 0:
        results.append('0')
      else:
        results.append(str(float(stat_comp[13]) / CLOCK_TICKS))
    elif stat_type == Stat.CPU_STIME:
      if pid == 0:
        results.append('0')
      else:
        results.append(str(float(stat_comp[14]) / CLOCK_TICKS))
    elif stat_type == Stat.START_TIME:
      if pid == 0:
        return system_start_time()
      else:
        # According to documentation, starttime is in field 21 and the unit is
        # jiffies (clock ticks). We divide it for clock ticks, then add the
        # uptime to get the seconds since the epoch.
        p_start_time = float(stat_comp[21]) / CLOCK_TICKS
        results.append(str(p_start_time + system_start_time()))

  _log_runtime(parameter, stat_path, start_time)
  return tuple(results)


def file_descriptors_used(pid):
  """
  Provides the number of file descriptors currently being used by a process.

  .. versionadded:: 1.3.0

  :param int pid: process id of the process to be queried

  :returns: **int** of the number of file descriptors used

  :raises: **IOError** if it can't be determined
  """

  try:
    pid = int(pid)

    if pid < 0:
      raise IOError("Process pids can't be negative: %s" % pid)
  except (ValueError, TypeError):
    raise IOError('Process pid was non-numeric: %s' % pid)

  try:
    return len(os.listdir('/proc/%i/fd' % pid))
  except Exception as exc:
    raise IOError('Unable to check number of file descriptors used: %s' % exc)


def connections(pid = None, user = None):
  """
  Queries connections from the proc contents. This matches netstat, lsof, and
  friends but is much faster. If no **pid** or **user** are provided this
  provides all present connections.

  :param int pid: pid to provide connections for
  :param str user: username to look up connections for

  :returns: **list** of :class:`~stem.util.connection.Connection` instances

  :raises: **IOError** if it can't be determined
  """

  start_time, conn = time.time(), []

  if pid:
    parameter = 'connections for pid %s' % pid

    try:
      pid = int(pid)

      if pid < 0:
        raise IOError("Process pids can't be negative: %s" % pid)
    except (ValueError, TypeError):
      raise IOError('Process pid was non-numeric: %s' % pid)
  elif user:
    parameter = 'connections for user %s' % user
  else:
    parameter = 'all connections'

  try:
    if not IS_PWD_AVAILABLE:
      raise IOError("This requires python's pwd module, which is unavailable on Windows.")

    inodes = _inodes_for_sockets(pid) if pid else set()
    process_uid = stem.util.str_tools._to_bytes(str(pwd.getpwnam(user).pw_uid)) if user else None

    for proc_file_path in ('/proc/net/tcp', '/proc/net/tcp6', '/proc/net/udp', '/proc/net/udp6'):
      if proc_file_path.endswith('6') and not os.path.exists(proc_file_path):
        continue  # ipv6 proc contents are optional

      protocol = proc_file_path[10:].rstrip('6')  # 'tcp' or 'udp'
      is_ipv6 = proc_file_path.endswith('6')

      try:
        with open(proc_file_path, 'rb') as proc_file:
          proc_file.readline()  # skip the first line

          for line in proc_file:
            _, l_dst, r_dst, status, _, _, _, uid, _, inode = line.split()[:10]

            if inodes and inode not in inodes:
              continue
            elif process_uid and uid != process_uid:
              continue
            elif protocol == 'tcp' and status != b'01':
              continue  # skip tcp connections that aren't yet established

            div = l_dst.find(b':')
            l_addr = _unpack_addr(l_dst[:div])
            l_port = int(l_dst[div + 1:], 16)

            div = r_dst.find(b':')
            r_addr = _unpack_addr(r_dst[:div])
            r_port = int(r_dst[div + 1:], 16)

            if r_addr == '0.0.0.0' or r_addr == '0000:0000:0000:0000:0000:0000':
              continue  # no address
            elif l_port == 0 or r_port == 0:
              continue  # no port

            conn.append(stem.util.connection.Connection(l_addr, l_port, r_addr, r_port, protocol, is_ipv6))
      except IOError as exc:
        raise IOError("unable to read '%s': %s" % (proc_file_path, exc))
      except Exception as exc:
        raise IOError("unable to parse '%s': %s" % (proc_file_path, exc))

    _log_runtime(parameter, '/proc/net/[tcp|udp]', start_time)
    return conn
  except IOError as exc:
    _log_failure(parameter, exc)
    raise


def _inodes_for_sockets(pid):
  """
  Provides inodes in use by a process for its sockets.

  :param int pid: process id of the process to be queried

  :returns: **set** with inodes for its sockets

  :raises: **IOError** if it can't be determined
  """

  inodes = set()

  try:
    fd_contents = os.listdir('/proc/%s/fd' % pid)
  except OSError as exc:
    raise IOError('Unable to read our file descriptors: %s' % exc)

  for fd in fd_contents:
    fd_path = '/proc/%s/fd/%s' % (pid, fd)

    try:
      # File descriptor link, such as 'socket:[30899]'

      fd_name = os.readlink(fd_path)

      if fd_name.startswith('socket:['):
        inodes.add(stem.util.str_tools._to_bytes(fd_name[8:-1]))
    except OSError as exc:
      if not os.path.exists(fd_path):
        continue  # descriptors may shift while we're in the middle of iterating over them

      # most likely couldn't be read due to permissions
      raise IOError('unable to determine file descriptor destination (%s): %s' % (exc, fd_path))

  return inodes


def _unpack_addr(addr):
  """
  Translates an address entry in the /proc/net/* contents to a human readable
  form (`reference <http://linuxdevcenter.com/pub/a/linux/2000/11/16/LinuxAdmin.html>`_,
  for instance:

  ::

    "0500000A" -> "10.0.0.5"
    "F804012A4A5190010000000002000000" -> "2a01:4f8:190:514a::2"

  :param str addr: proc address entry to be decoded

  :returns: **str** of the decoded address
  """

  if addr not in ENCODED_ADDR:
    if len(addr) == 8:
      # IPv4 address
      decoded = base64.b16decode(addr)[::-1] if IS_LITTLE_ENDIAN else base64.b16decode(addr)
      ENCODED_ADDR[addr] = socket.inet_ntop(socket.AF_INET, decoded)
    else:
      # IPv6 address

      if IS_LITTLE_ENDIAN:
        # Group into eight characters, then invert in pairs...
        #
        #   https://trac.torproject.org/projects/tor/ticket/18079#comment:24

        inverted = []

        for i in range(4):
          grouping = addr[8 * i:8 * (i + 1)]
          inverted += [grouping[2 * i:2 * (i + 1)] for i in range(4)][::-1]

        encoded = b''.join(inverted)
      else:
        encoded = addr

      ENCODED_ADDR[addr] = stem.util.connection.expand_ipv6_address(socket.inet_ntop(socket.AF_INET6, base64.b16decode(encoded)))

  return ENCODED_ADDR[addr]


def _is_float(*value):
  try:
    for v in value:
      float(v)

    return True
  except ValueError:
    return False


def _get_line(file_path, line_prefix, parameter):
  return _get_lines(file_path, (line_prefix, ), parameter)[line_prefix]


def _get_lines(file_path, line_prefixes, parameter):
  """
  Fetches lines with the given prefixes from a file. This only provides back
  the first instance of each prefix.

  :param str file_path: path of the file to read
  :param tuple line_prefixes: string prefixes of the lines to return
  :param str parameter: description of the proc attribute being fetch

  :returns: mapping of prefixes to the matching line

  :raises: **IOError** if unable to read the file or can't find all of the prefixes
  """

  try:
    remaining_prefixes = list(line_prefixes)
    proc_file, results = open(file_path), {}

    for line in proc_file:
      if not remaining_prefixes:
        break  # found everything we're looking for

      for prefix in remaining_prefixes:
        if line.startswith(prefix):
          results[prefix] = line
          remaining_prefixes.remove(prefix)
          break

    proc_file.close()

    if remaining_prefixes:
      if len(remaining_prefixes) == 1:
        msg = '%s did not contain a %s entry' % (file_path, remaining_prefixes[0])
      else:
        msg = '%s did not contain %s entries' % (file_path, ', '.join(remaining_prefixes))

      raise IOError(msg)
    else:
      return results
  except IOError as exc:
    _log_failure(parameter, exc)
    raise


def _log_runtime(parameter, proc_location, start_time):
  """
  Logs a message indicating a successful proc query.

  :param str parameter: description of the proc attribute being fetch
  :param str proc_location: proc files we were querying
  :param int start_time: unix time for when this query was started
  """

  runtime = time.time() - start_time
  log.debug('proc call (%s): %s (runtime: %0.4f)' % (parameter, proc_location, runtime))


def _log_failure(parameter, exc):
  """
  Logs a message indicating that the proc query failed.

  :param str parameter: description of the proc attribute being fetch
  :param Exception exc: exception that we're raising
  """

  log.debug('proc call failed (%s): %s' % (parameter, exc))


# TODO: drop with stem 2.x
# We renamed our methods to drop a redundant 'get_*' prefix, so alias the old
# names for backward compatability.

get_system_start_time = system_start_time
get_physical_memory = physical_memory
get_cwd = cwd
get_uid = uid
get_memory_usage = memory_usage
get_stats = stats
get_connections = connections
