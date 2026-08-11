# Copyright 2018-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Directories that provide `relay descriptor information
<../tutorials/mirror_mirror_on_the_wall.html>`_. At a very high level tor works
as follows...

1. Volunteer starts a new tor relay, during which it sends a `server
   descriptor <descriptor/server_descriptor.html>`_ to each of the directory
   authorities.

2. Each hour the directory authorities make a `vote
   <descriptor/networkstatus.html>`_  that says who they think the active
   relays are in the network and some attributes about them.

3. The directory authorities send each other their votes, and compile that
   into the `consensus <descriptor/networkstatus.html>`_. This document is very
   similar to the votes, the only difference being that the majority of the
   authorities agree upon and sign this document. The idividual relay entries
   in the vote or consensus is called `router status entries
   <descriptor/router_status_entry.html>`_.

4. Tor clients (people using the service) download the consensus from an
   authority, fallback, or other mirror to determine who the active relays in
   the network are. They then use this to construct circuits and use the
   network.

::

  Directory - Relay we can retrieve descriptor information from
    | |- from_cache - Provides cached information bundled with Stem.
    | +- from_remote - Downloads the latest directory information from tor.
    |
    |- Authority - Tor directory authority
    +- Fallback - Mirrors that can be used instead of the authorities

.. versionadded:: 1.7.0
"""

import os
import re
import sys

import stem
import stem.util
import stem.util.conf

from stem.util import connection, str_tools, tor_tools

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

GITWEB_AUTHORITY_URL = 'https://gitweb.torproject.org/tor.git/plain/src/app/config/auth_dirs.inc'
GITWEB_FALLBACK_URL = 'https://gitweb.torproject.org/tor.git/plain/src/app/config/fallback_dirs.inc'
FALLBACK_CACHE_PATH = os.path.join(os.path.dirname(__file__), 'cached_fallbacks.cfg')

AUTHORITY_NAME = re.compile('"(\\S+) orport=(\\d+) .*"')
AUTHORITY_V3IDENT = re.compile('"v3ident=([\\dA-F]{40}) "')
AUTHORITY_IPV6 = re.compile('"ipv6=\\[([\\da-f:]+)\\]:(\\d+) "')
AUTHORITY_ADDR = re.compile('"([\\d\\.]+):(\\d+) ([\\dA-F ]{49})",')

FALLBACK_DIV = '/* ===== */'
FALLBACK_MAPPING = re.compile('/\\*\\s+(\\S+)=(\\S*)\\s+\\*/')

FALLBACK_ADDR = re.compile('"([\\d\\.]+):(\\d+) orport=(\\d+) id=([\\dA-F]{40}).*')
FALLBACK_NICKNAME = re.compile('/\\* nickname=(\\S+) \\*/')
FALLBACK_EXTRAINFO = re.compile('/\\* extrainfo=([0-1]) \\*/')
FALLBACK_IPV6 = re.compile('" ipv6=\\[([\\da-f:]+)\\]:(\\d+)"')


def _match_with(lines, regexes, required = None):
  """
  Scans the given content against a series of regex matchers, providing back a
  mapping of regexes to their capture groups. This maping is with the value if
  the regex has just a single capture group, and a tuple otherwise.

  :param list lines: text to parse
  :param list regexes: regexes to match against
  :param list required: matches that must be in the content

  :returns: **dict** mapping matchers against their capture groups

  :raises: **ValueError** if a required match is not present
  """

  matches = {}

  for line in lines:
    for matcher in regexes:
      m = matcher.search(str_tools._to_unicode(line))

      if m:
        match_groups = m.groups()
        matches[matcher] = match_groups if len(match_groups) > 1 else match_groups[0]

  if required:
    for required_matcher in required:
      if required_matcher not in matches:
        raise ValueError('Failed to parse mandatory data from:\n\n%s' % '\n'.join(lines))

  return matches


def _directory_entries(lines, pop_section_func, regexes, required = None):
  next_section = pop_section_func(lines)

  while next_section:
    yield _match_with(next_section, regexes, required)
    next_section = pop_section_func(lines)


class Directory(object):
  """
  Relay we can contact for descriptor information.

  Our :func:`~stem.directory.Directory.from_cache` and
  :func:`~stem.directory.Directory.from_remote` functions key off a
  different identifier based on our subclass...

    * :class:`~stem.directory.Authority` keys off the nickname.
    * :class:`~stem.directory.Fallback` keys off fingerprints.

  This is because authorities are highly static and canonically known by their
  names, whereas fallbacks vary more and don't necessarily have a nickname to
  key off of.

  :var str address: IPv4 address of the directory
  :var int or_port: port on which the relay services relay traffic
  :var int dir_port: port on which directory information is available
  :var str fingerprint: relay fingerprint
  :var str nickname: relay nickname
  :var str orport_v6: **(address, port)** tuple for the directory's IPv6
    ORPort, or **None** if it doesn't have one
  """

  def __init__(self, address, or_port, dir_port, fingerprint, nickname, orport_v6):
    identifier = '%s (%s)' % (fingerprint, nickname) if nickname else fingerprint

    if not connection.is_valid_ipv4_address(address):
      raise ValueError('%s has an invalid IPv4 address: %s' % (identifier, address))
    elif not connection.is_valid_port(or_port):
      raise ValueError('%s has an invalid ORPort: %s' % (identifier, or_port))
    elif not connection.is_valid_port(dir_port):
      raise ValueError('%s has an invalid DirPort: %s' % (identifier, dir_port))
    elif not tor_tools.is_valid_fingerprint(fingerprint):
      raise ValueError('%s has an invalid fingerprint: %s' % (identifier, fingerprint))
    elif nickname and not tor_tools.is_valid_nickname(nickname):
      raise ValueError('%s has an invalid nickname: %s' % (fingerprint, nickname))

    if orport_v6:
      if not isinstance(orport_v6, tuple) or len(orport_v6) != 2:
        raise ValueError('%s orport_v6 should be a two value tuple: %s' % (identifier, str(orport_v6)))
      elif not connection.is_valid_ipv6_address(orport_v6[0]):
        raise ValueError('%s has an invalid IPv6 address: %s' % (identifier, orport_v6[0]))
      elif not connection.is_valid_port(orport_v6[1]):
        raise ValueError('%s has an invalid IPv6 port: %s' % (identifier, orport_v6[1]))

    self.address = address
    self.or_port = int(or_port)
    self.dir_port = int(dir_port)
    self.fingerprint = fingerprint
    self.nickname = nickname
    self.orport_v6 = (orport_v6[0], int(orport_v6[1])) if orport_v6 else None

  @staticmethod
  def from_cache():
    """
    Provides cached Tor directory information. This information is hardcoded
    into Tor and occasionally changes, so the information provided by this
    method may not necessarily match the latest version of tor.

    .. versionadded:: 1.5.0

    .. versionchanged:: 1.7.0
       Support added to the :class:`~stem.directory.Authority` class.

    :returns: **dict** of **str** identifiers to
      :class:`~stem.directory.Directory` instances
    """

    raise NotImplementedError('Unsupported Operation: this should be implemented by the Directory subclass')

  @staticmethod
  def from_remote(timeout = 60):
    """
    Reads and parses tor's directory data `from gitweb.torproject.org <https://gitweb.torproject.org/>`_.
    Note that while convenient, this reliance on GitWeb means you should alway
    call with a fallback, such as...

    ::

      try:
        authorities = stem.directory.Authority.from_remote()
      except IOError:
        authorities = stem.directory.Authority.from_cache()

    .. versionadded:: 1.5.0

    .. versionchanged:: 1.7.0
       Support added to the :class:`~stem.directory.Authority` class.

    :param int timeout: seconds to wait before timing out the request

    :returns: **dict** of **str** identifiers to their
      :class:`~stem.directory.Directory`

    :raises: **IOError** if unable to retrieve the fallback directories
    """

    raise NotImplementedError('Unsupported Operation: this should be implemented by the Directory subclass')

  def __hash__(self):
    return stem.util._hash_attr(self, 'address', 'or_port', 'dir_port', 'fingerprint', 'nickname', 'orport_v6')

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Directory) else False

  def __ne__(self, other):
    return not self == other


class Authority(Directory):
  """
  Tor directory authority, a special type of relay `hardcoded into tor
  <https://gitweb.torproject.org/tor.git/plain/src/or/auth_dirs.inc>`_
  to enumerate the relays in the network.

  .. versionchanged:: 1.3.0
     Added the is_bandwidth_authority attribute.

  .. versionchanged:: 1.7.0
     Added the orport_v6 attribute.

  .. deprecated:: 1.7.0
     The is_bandwidth_authority attribute is deprecated and will be removed in
     the future.

  :var str v3ident: identity key fingerprint used to sign votes and consensus
  """

  def __init__(self, address = None, or_port = None, dir_port = None, fingerprint = None, nickname = None, orport_v6 = None, v3ident = None, is_bandwidth_authority = False):
    super(Authority, self).__init__(address, or_port, dir_port, fingerprint, nickname, orport_v6)

    if v3ident and not tor_tools.is_valid_fingerprint(v3ident):
      identifier = '%s (%s)' % (fingerprint, nickname) if nickname else fingerprint
      raise ValueError('%s has an invalid v3ident: %s' % (identifier, v3ident))

    self.v3ident = v3ident
    self.is_bandwidth_authority = is_bandwidth_authority

  @staticmethod
  def from_cache():
    return dict(DIRECTORY_AUTHORITIES)

  @staticmethod
  def from_remote(timeout = 60):
    try:
      lines = str_tools._to_unicode(urllib.urlopen(GITWEB_AUTHORITY_URL, timeout = timeout).read()).splitlines()

      if not lines:
        raise IOError('no content')
    except:
      exc, stacktrace = sys.exc_info()[1:3]
      message = "Unable to download tor's directory authorities from %s: %s" % (GITWEB_AUTHORITY_URL, exc)
      raise stem.DownloadFailed(GITWEB_AUTHORITY_URL, exc, stacktrace, message)

    # Entries look like...
    #
    # "moria1 orport=9101 "
    #   "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 "
    #   "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",

    try:
      results = {}

      for matches in _directory_entries(lines, Authority._pop_section, (AUTHORITY_NAME, AUTHORITY_V3IDENT, AUTHORITY_IPV6, AUTHORITY_ADDR), required = (AUTHORITY_NAME, AUTHORITY_ADDR)):
        nickname, or_port = matches.get(AUTHORITY_NAME)
        address, dir_port, fingerprint = matches.get(AUTHORITY_ADDR)

        results[nickname] = Authority(
          address = address,
          or_port = or_port,
          dir_port = dir_port,
          fingerprint = fingerprint.replace(' ', ''),
          nickname = nickname,
          orport_v6 = matches.get(AUTHORITY_IPV6),
          v3ident = matches.get(AUTHORITY_V3IDENT),
        )
    except ValueError as exc:
      raise IOError(str(exc))

    return results

  @staticmethod
  def _pop_section(lines):
    """
    Provides the next authority entry.
    """

    section_lines = []

    if lines:
      section_lines.append(lines.pop(0))

      while lines and lines[0].startswith(' '):
        section_lines.append(lines.pop(0))

    return section_lines

  def __hash__(self):
    return stem.util._hash_attr(self, 'v3ident', 'is_bandwidth_authority', parent = Directory, cache = True)

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Authority) else False

  def __ne__(self, other):
    return not self == other


class Fallback(Directory):
  """
  Particularly stable relays tor can instead of authorities when
  bootstrapping. These relays are `hardcoded in tor
  <https://gitweb.torproject.org/tor.git/tree/src/or/fallback_dirs.inc>`_.

  For example, the following checks the performance of tor's fallback directories...

  ::

    import time
    from stem.descriptor.remote import get_consensus
    from stem.directory import Fallback

    for fallback in Fallback.from_cache().values():
      start = time.time()
      get_consensus(endpoints = [(fallback.address, fallback.dir_port)]).run()
      print('Downloading the consensus took %0.2f from %s' % (time.time() - start, fallback.fingerprint))

  ::

    % python example.py
    Downloading the consensus took 5.07 from 0AD3FA884D18F89EEA2D89C019379E0E7FD94417
    Downloading the consensus took 3.59 from C871C91489886D5E2E94C13EA1A5FDC4B6DC5204
    Downloading the consensus took 4.16 from 74A910646BCEEFBCD2E874FC1DC997430F968145
    ...

  .. versionadded:: 1.5.0

  .. versionchanged:: 1.7.0
     Added the has_extrainfo and header attributes which are part of
     the `second version of the fallback directories
     <https://lists.torproject.org/pipermail/tor-dev/2017-December/012721.html>`_.

  :var bool has_extrainfo: **True** if the relay should be able to provide
    extrainfo descriptors, **False** otherwise.
  :var collections.OrderedDict header: metadata about the fallback directory file this originated from
  """

  def __init__(self, address = None, or_port = None, dir_port = None, fingerprint = None, nickname = None, has_extrainfo = False, orport_v6 = None, header = None):
    super(Fallback, self).__init__(address, or_port, dir_port, fingerprint, nickname, orport_v6)
    self.has_extrainfo = has_extrainfo
    self.header = OrderedDict(header) if header else OrderedDict()

  @staticmethod
  def from_cache(path = None):
    if path is None:
        path = FALLBACK_CACHE_PATH
    conf = stem.util.conf.Config()
    conf.load(path)
    headers = OrderedDict([(k.split('.', 1)[1], conf.get(k)) for k in conf.keys() if k.startswith('header.')])

    results = {}

    for fingerprint in set([key.split('.')[0] for key in conf.keys()]):
      if fingerprint in ('tor_commit', 'stem_commit', 'header'):
        continue

      attr = {}

      for attr_name in ('address', 'or_port', 'dir_port', 'nickname', 'has_extrainfo', 'orport6_address', 'orport6_port'):
        key = '%s.%s' % (fingerprint, attr_name)
        attr[attr_name] = conf.get(key)

        if not attr[attr_name] and attr_name not in ('nickname', 'has_extrainfo', 'orport6_address', 'orport6_port'):
          raise IOError("'%s' is missing from %s" % (key, FALLBACK_CACHE_PATH))

      if attr['orport6_address'] and attr['orport6_port']:
        orport_v6 = (attr['orport6_address'], int(attr['orport6_port']))
      else:
        orport_v6 = None

      results[fingerprint] = Fallback(
        address = attr['address'],
        or_port = int(attr['or_port']),
        dir_port = int(attr['dir_port']),
        fingerprint = fingerprint,
        nickname = attr['nickname'],
        has_extrainfo = attr['has_extrainfo'] == 'true',
        orport_v6 = orport_v6,
        header = headers,
      )

    return results

  @staticmethod
  def from_remote(timeout = 60):
    try:
      lines = str_tools._to_unicode(urllib.urlopen(GITWEB_FALLBACK_URL, timeout = timeout).read()).splitlines()

      if not lines:
        raise IOError('no content')
    except:
      exc, stacktrace = sys.exc_info()[1:3]
      message = "Unable to download tor's fallback directories from %s: %s" % (GITWEB_FALLBACK_URL, exc)
      raise stem.DownloadFailed(GITWEB_FALLBACK_URL, exc, stacktrace, message)

    # header metadata

    if lines[0] != '/* type=fallback */':
      raise IOError('%s does not have a type field indicating it is fallback directory metadata' % GITWEB_FALLBACK_URL)

    header = {}

    for line in Fallback._pop_section(lines):
      mapping = FALLBACK_MAPPING.match(line)

      if mapping:
        header[mapping.group(1)] = mapping.group(2)
      else:
        raise IOError('Malformed fallback directory header line: %s' % line)

    Fallback._pop_section(lines)  # skip human readable comments

    # Entries look like...
    #
    # "5.9.110.236:9030 orport=9001 id=0756B7CD4DFC8182BE23143FAC0642F515182CEB"
    # " ipv6=[2a01:4f8:162:51e2::2]:9001"
    # /* nickname=rueckgrat */
    # /* extrainfo=1 */

    try:
      results = {}

      for matches in _directory_entries(lines, Fallback._pop_section, (FALLBACK_ADDR, FALLBACK_NICKNAME, FALLBACK_EXTRAINFO, FALLBACK_IPV6), required = (FALLBACK_ADDR,)):
        address, dir_port, or_port, fingerprint = matches[FALLBACK_ADDR]

        results[fingerprint] = Fallback(
          address = address,
          or_port = int(or_port),
          dir_port = int(dir_port),
          fingerprint = fingerprint,
          nickname = matches.get(FALLBACK_NICKNAME),
          has_extrainfo = matches.get(FALLBACK_EXTRAINFO) == '1',
          orport_v6 = matches.get(FALLBACK_IPV6),
          header = header,
        )
    except ValueError as exc:
      raise IOError(str(exc))

    return results

  @staticmethod
  def _pop_section(lines):
    """
    Provides lines up through the next divider. This excludes lines with just a
    comma since they're an artifact of these being C strings.
    """

    section_lines = []

    if lines:
      line = lines.pop(0)

      while lines and line != FALLBACK_DIV:
        if line.strip() != ',':
          section_lines.append(line)

        line = lines.pop(0)

    return section_lines

  @staticmethod
  def _write(fallbacks, tor_commit, stem_commit, headers, path = FALLBACK_CACHE_PATH):
    """
    Persists fallback directories to a location in a way that can be read by
    from_cache().

    :param dict fallbacks: mapping of fingerprints to their fallback directory
    :param str tor_commit: tor commit the fallbacks came from
    :param str stem_commit: stem commit the fallbacks came from
    :param dict headers: metadata about the file these came from
    :param str path: location fallbacks will be persisted to
    """

    conf = stem.util.conf.Config()
    conf.set('tor_commit', tor_commit)
    conf.set('stem_commit', stem_commit)

    for k, v in headers.items():
      conf.set('header.%s' % k, v)

    for directory in sorted(fallbacks.values(), key = lambda x: x.fingerprint):
      fingerprint = directory.fingerprint
      conf.set('%s.address' % fingerprint, directory.address)
      conf.set('%s.or_port' % fingerprint, str(directory.or_port))
      conf.set('%s.dir_port' % fingerprint, str(directory.dir_port))
      conf.set('%s.nickname' % fingerprint, directory.nickname)
      conf.set('%s.has_extrainfo' % fingerprint, 'true' if directory.has_extrainfo else 'false')

      if directory.orport_v6:
        conf.set('%s.orport6_address' % fingerprint, str(directory.orport_v6[0]))
        conf.set('%s.orport6_port' % fingerprint, str(directory.orport_v6[1]))

    conf.save(path)

  def __hash__(self):
    return stem.util._hash_attr(self, 'has_extrainfo', 'header', parent = Directory, cache = True)

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Fallback) else False

  def __ne__(self, other):
    return not self == other


def _fallback_directory_differences(previous_directories, new_directories):
  """
  Provides a description of how fallback directories differ.
  """

  lines = []

  added_fp = set(new_directories.keys()).difference(previous_directories.keys())
  removed_fp = set(previous_directories.keys()).difference(new_directories.keys())

  for fp in added_fp:
    directory = new_directories[fp]
    orport_v6 = '%s:%s' % directory.orport_v6 if directory.orport_v6 else '[none]'

    lines += [
      '* Added %s as a new fallback directory:' % directory.fingerprint,
      '  address: %s' % directory.address,
      '  or_port: %s' % directory.or_port,
      '  dir_port: %s' % directory.dir_port,
      '  nickname: %s' % directory.nickname,
      '  has_extrainfo: %s' % directory.has_extrainfo,
      '  orport_v6: %s' % orport_v6,
      '',
    ]

  for fp in removed_fp:
    lines.append('* Removed %s as a fallback directory' % fp)

  for fp in new_directories:
    if fp in added_fp or fp in removed_fp:
      continue  # already discussed these

    previous_directory = previous_directories[fp]
    new_directory = new_directories[fp]

    if previous_directory != new_directory:
      for attr in ('address', 'or_port', 'dir_port', 'fingerprint', 'orport_v6'):
        old_attr = getattr(previous_directory, attr)
        new_attr = getattr(new_directory, attr)

        if old_attr != new_attr:
          lines.append('* Changed the %s of %s from %s to %s' % (attr, fp, old_attr, new_attr))

  return '\n'.join(lines)


DIRECTORY_AUTHORITIES = {
  'moria1': Authority(
    nickname = 'moria1',
    address = '128.31.0.39',
    or_port = 9101,
    dir_port = 9131,
    fingerprint = '9695DFC35FFEB861329B9F1AB04C46397020CE31',
    v3ident = 'D586D18309DED4CD6D57C18FDB97EFA96D330566',
  ),
  'tor26': Authority(
    nickname = 'tor26',
    address = '86.59.21.38',
    or_port = 443,
    dir_port = 80,
    fingerprint = '847B1F850344D7876491A54892F904934E4EB85D',
    orport_v6 = ('2001:858:2:2:aabb:0:563b:1526', 443),
    v3ident = '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
  ),
  'dizum': Authority(
    nickname = 'dizum',
    address = '45.66.33.45',
    or_port = 443,
    dir_port = 80,
    fingerprint = '7EA6EAD6FD83083C538F44038BBFA077587DD755',
    v3ident = 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
  ),
  'gabelmoo': Authority(
    nickname = 'gabelmoo',
    address = '131.188.40.189',
    or_port = 443,
    dir_port = 80,
    fingerprint = 'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281',
    orport_v6 = ('2001:638:a000:4140::ffff:189', 443),
    v3ident = 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
  ),
  'dannenberg': Authority(
    nickname = 'dannenberg',
    address = '193.23.244.244',
    or_port = 443,
    dir_port = 80,
    orport_v6 = ('2001:678:558:1000::244', 443),
    fingerprint = '7BE683E65D48141321C5ED92F075C55364AC7123',
    v3ident = '0232AF901C31A04EE9848595AF9BB7620D4C5B2E',
  ),
  'maatuska': Authority(
    nickname = 'maatuska',
    address = '171.25.193.9',
    or_port = 80,
    dir_port = 443,
    fingerprint = 'BD6A829255CB08E66FBE7D3748363586E46B3810',
    orport_v6 = ('2001:67c:289c::9', 80),
    v3ident = '49015F787433103580E3B66A1707A00E60F2D15B',
  ),
  'Faravahar': Authority(
    nickname = 'Faravahar',
    address = '154.35.175.225',
    or_port = 443,
    dir_port = 80,
    fingerprint = 'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC',
    v3ident = 'EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97',
  ),
  'longclaw': Authority(
    nickname = 'longclaw',
    address = '199.58.81.140',
    or_port = 443,
    dir_port = 80,
    fingerprint = '74A910646BCEEFBCD2E874FC1DC997430F968145',
    v3ident = '23D15D965BC35114467363C165C4F724B64B4F66',
  ),
  'bastet': Authority(
    nickname = 'bastet',
    address = '204.13.164.118',
    or_port = 443,
    dir_port = 80,
    fingerprint = '24E2F139121D4394C54B5BCC368B3B411857C413',
    orport_v6 = ('2620:13:4000:6000::1000:118', 443),
    v3ident = '27102BC123E7AF1D4741AE047E160C91ADC76B21',
  ),
  'Serge': Authority(
    nickname = 'Serge',
    address = '66.111.2.131',
    or_port = 9001,
    dir_port = 9030,
    fingerprint = 'BA44A889E64B93FAA2B114E02C2A279A8555C533',
    v3ident = None,  # does not vote in the consensus
  ),
}
