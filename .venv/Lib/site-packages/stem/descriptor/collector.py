# Copyright 2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Descriptor archives are available from `CollecTor
<https://metrics.torproject.org/collector.html>`_. If you need Tor's topology
at a prior point in time this is the place to go!

With CollecTor you can either read descriptors directly...

.. literalinclude:: /_static/example/collector_reading.py
   :language: python

... or download the descriptors to disk and read them later.

.. literalinclude:: /_static/example/collector_caching.py
   :language: python

::

  get_instance - Provides a singleton CollecTor used for...
    |- get_server_descriptors - published server descriptors
    |- get_extrainfo_descriptors - published extrainfo descriptors
    |- get_microdescriptors - published microdescriptors
    |- get_consensus - published router status entries
    |
    |- get_key_certificates - authority key certificates
    |- get_bandwidth_files - bandwidth authority heuristics
    +- get_exit_lists - TorDNSEL exit list

  File - Individual file residing within CollecTor
    |- read - provides descriptors from this file
    +- download - download this file to disk

  CollecTor - Downloader for descriptors from CollecTor
    |- get_server_descriptors - published server descriptors
    |- get_extrainfo_descriptors - published extrainfo descriptors
    |- get_microdescriptors - published microdescriptors
    |- get_consensus - published router status entries
    |
    |- get_key_certificates - authority key certificates
    |- get_bandwidth_files - bandwidth authority heuristics
    |- get_exit_lists - TorDNSEL exit list
    |
    |- index - metadata for content available from CollecTor
    +- files - files available from CollecTor

.. versionadded:: 1.8.0
"""

import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import shutil
import tempfile
import time

import stem.descriptor
import stem.util.connection
import stem.util.str_tools

from stem.descriptor import Compression, DocumentHandler

COLLECTOR_URL = 'https://collector.torproject.org/'
REFRESH_INDEX_RATE = 3600  # get new index if cached copy is an hour old
SINGLETON_COLLECTOR = None

YEAR_DATE = re.compile('-(\\d{4})-(\\d{2})\\.')
SEC_DATE = re.compile('(\\d{4}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-\\d{2})')

# distant future date so we can sort files without a timestamp at the end

FUTURE = datetime.datetime(9999, 1, 1)


def get_instance():
  """
  Provides the singleton :class:`~stem.descriptor.collector.CollecTor`
  used for this module's shorthand functions.

  :returns: singleton :class:`~stem.descriptor.collector.CollecTor` instance
  """

  global SINGLETON_COLLECTOR

  if SINGLETON_COLLECTOR is None:
    SINGLETON_COLLECTOR = CollecTor()

  return SINGLETON_COLLECTOR


def get_server_descriptors(start = None, end = None, cache_to = None, bridge = False, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_server_descriptors`
  on our singleton instance.
  """

  for desc in get_instance().get_server_descriptors(start, end, cache_to, bridge, timeout, retries):
    yield desc


def get_extrainfo_descriptors(start = None, end = None, cache_to = None, bridge = False, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_extrainfo_descriptors`
  on our singleton instance.
  """

  for desc in get_instance().get_extrainfo_descriptors(start, end, cache_to, bridge, timeout, retries):
    yield desc


def get_microdescriptors(start = None, end = None, cache_to = None, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_microdescriptors`
  on our singleton instance.
  """

  for desc in get_instance().get_microdescriptors(start, end, cache_to, timeout, retries):
    yield desc


def get_consensus(start = None, end = None, cache_to = None, document_handler = DocumentHandler.ENTRIES, version = 3, microdescriptor = False, bridge = False, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_consensus`
  on our singleton instance.
  """

  for desc in get_instance().get_consensus(start, end, cache_to, document_handler, version, microdescriptor, bridge, timeout, retries):
    yield desc


def get_key_certificates(start = None, end = None, cache_to = None, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_key_certificates`
  on our singleton instance.
  """

  for desc in get_instance().get_key_certificates(start, end, cache_to, timeout, retries):
    yield desc


def get_bandwidth_files(start = None, end = None, cache_to = None, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_bandwidth_files`
  on our singleton instance.
  """

  for desc in get_instance().get_bandwidth_files(start, end, cache_to, timeout, retries):
    yield desc


def get_exit_lists(start = None, end = None, cache_to = None, timeout = None, retries = 3):
  """
  Shorthand for
  :func:`~stem.descriptor.collector.CollecTor.get_exit_lists`
  on our singleton instance.
  """

  for desc in get_instance().get_exit_lists(start, end, cache_to, timeout, retries):
    yield desc


class File(object):
  """
  File within CollecTor.

  :var str path: file path within collector
  :var tuple types: descriptor types contained within this file
  :var stem.descriptor.Compression compression: file compression, **None** if
    this cannot be determined
  :var int size: size of the file
  :var str sha256: file's sha256 checksum

  :var datetime start: first publication within the file, **None** if this
    cannot be determined
  :var datetime end: last publication within the file, **None** if this cannot
    be determined
  :var datetime last_modified: when the file was last modified
  """

  def __init__(self, path, types, size, sha256, first_published, last_published, last_modified):
    self.path = path
    self.types = tuple(types) if types else ()
    self.compression = File._guess_compression(path)
    self.size = size
    self.sha256 = sha256
    self.last_modified = datetime.datetime.strptime(last_modified, '%Y-%m-%d %H:%M')
    self._downloaded_to = None  # location we last downloaded to

    # Most descriptor types have publication time fields, but microdescriptors
    # don't because these files lack timestamps to parse.

    if first_published and last_published:
      self.start = datetime.datetime.strptime(first_published, '%Y-%m-%d %H:%M')
      self.end = datetime.datetime.strptime(last_published, '%Y-%m-%d %H:%M')
    else:
      self.start, self.end = File._guess_time_range(path)

  def read(self, directory = None, descriptor_type = None, start = None, end = None, document_handler = DocumentHandler.ENTRIES, timeout = None, retries = 3):
    """
    Provides descriptors from this archive. Descriptors are downloaded or read
    from disk as follows...

    * If this file has already been downloaded through
      :func:`~stem.descriptor.collector.CollecTor.download' these descriptors
      are read from disk.

    * If a **directory** argument is provided and the file is already present
      these descriptors are read from disk.

    * If a **directory** argument is provided and the file is not present the
      file is downloaded this location then read.

    * If the file has neither been downloaded and no **directory** argument
      is provided then the file is downloaded to a temporary directory that's
      deleted after it is read.

    :param str directory: destination to download into
    :param str descriptor_type: `descriptor type
      <https://metrics.torproject.org/collector.html#data-formats>`_, this is
      guessed if not provided
    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param stem.descriptor.__init__.DocumentHandler document_handler: method in
      which to parse a :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
    :param int timeout: timeout when connection becomes idle, no timeout
      applied if **None**
    :param int retries: maximum attempts to impose

    :returns: iterator for :class:`~stem.descriptor.__init__.Descriptor`
      instances in the file

    :raises:
      * **ValueError** if unable to determine the descirptor type
      * **TypeError** if we cannot parse this descriptor type
      * :class:`~stem.DownloadFailed` if the download fails
    """

    if descriptor_type is None:
      # If archive contains multiple descriptor types the caller must provide a
      # 'descriptor_type' argument so we can disambiguate. However, if only the
      # version number varies we can probably simply pick one.

      base_types = set([t.split(' ')[0] for t in self.types])

      if not self.types:
        raise ValueError("Unable to determine this file's descriptor type")
      elif len(base_types) > 1:
        raise ValueError("Unable to disambiguate file's descriptor type from among %s" % ', '.join(self.types))
      else:
        descriptor_type = self.types[0]

    if directory is None:
      if self._downloaded_to and os.path.exists(self._downloaded_to):
        directory = os.path.dirname(self._downloaded_to)
      else:
        # TODO: The following can be replaced with simpler usage of
        # tempfile.TemporaryDirectory when we drop python 2.x support.

        tmp_directory = tempfile.mkdtemp()

        for desc in self.read(tmp_directory, descriptor_type, start, end, document_handler, timeout, retries):
          yield desc

        shutil.rmtree(tmp_directory)

        return

    path = self.download(directory, True, timeout, retries)

    # Archives can contain multiple descriptor types, so parsing everything and
    # filtering to what we're after.

    for desc in stem.descriptor.parse_file(path, document_handler = document_handler):
      if descriptor_type is None or descriptor_type.startswith(desc.type_annotation().name):
        # TODO: This can filter server and extrainfo times, but other
        # descriptor types may use other attribute names.

        published = getattr(desc, 'published', None)

        if published:
          if start and published < start:
            continue
          elif end and published > end:
            continue

        yield desc

  def download(self, directory, decompress = True, timeout = None, retries = 3, overwrite = False):
    """
    Downloads this file to the given location. If a file already exists this is
    a no-op.

    :param str directory: destination to download into
    :param bool decompress: decompress written file
    :param int timeout: timeout when connection becomes idle, no timeout
      applied if **None**
    :param int retries: maximum attempts to impose
    :param bool overwrite: if this file exists but mismatches CollecTor's
      checksum then overwrites if **True**, otherwise rases an exception

    :returns: **str** with the path we downloaded to

    :raises:
      * :class:`~stem.DownloadFailed` if the download fails
      * **IOError** if a mismatching file exists and **overwrite** is **False**
    """

    filename = self.path.split('/')[-1]

    if self.compression != Compression.PLAINTEXT and decompress:
      filename = filename.rsplit('.', 1)[0]

    directory = os.path.expanduser(directory)

    path = os.path.join(directory, filename)

    if not os.path.exists(directory):
      os.makedirs(directory)

    # check if this file already exists with the correct checksum

    if os.path.exists(path):
      with open(path) as prior_file:
        expected_hash = binascii.hexlify(base64.b64decode(self.sha256))
        actual_hash = hashlib.sha256(prior_file.read()).hexdigest()

        if expected_hash == actual_hash:
          return path  # nothing to do, we already have the file
        elif not overwrite:
          raise IOError("%s already exists but mismatches CollecTor's checksum (expected: %s, actual: %s)" % (path, expected_hash, actual_hash))

    response = stem.util.connection.download(COLLECTOR_URL + self.path, timeout, retries)

    if decompress:
      response = self.compression.decompress(response)

    with open(path, 'wb') as output_file:
      output_file.write(response)

    self._downloaded_to = path
    return path

  @staticmethod
  def _guess_compression(path):
    """
    Determine file comprssion from CollecTor's filename.
    """

    for compression in (Compression.LZMA, Compression.BZ2, Compression.GZIP):
      if path.endswith(compression.extension):
        return compression

    return Compression.PLAINTEXT

  @staticmethod
  def _guess_time_range(path):
    """
    Attemt to determine the (start, end) time range from CollecTor's filename.
    This provides (None, None) if this cannot be determined.
    """

    year_match = YEAR_DATE.search(path)

    if year_match:
      year, month = map(int, year_match.groups())
      start = datetime.datetime(year, month, 1)

      if month < 12:
        return (start, datetime.datetime(year, month + 1, 1))
      else:
        return (start, datetime.datetime(year + 1, 1, 1))

    sec_match = SEC_DATE.search(path)

    if sec_match:
      # Descriptors in the 'recent/*' section have filenames with second level
      # granularity. Not quite sure why, but since consensus documents are
      # published hourly we'll use that as the delta here.

      start = datetime.datetime.strptime(sec_match.group(1), '%Y-%m-%d-%H-%M-%S')
      return (start, start + datetime.timedelta(seconds = 3600))

    return (None, None)


class CollecTor(object):
  """
  Downloader for descriptors from CollecTor. The contents of CollecTor are
  provided in `an index <https://collector.torproject.org/index/index.json>`_
  that's fetched as required.

  :var int retries: number of times to attempt the request if downloading it
    fails
  :var float timeout: duration before we'll time out our request
  """

  def __init__(self, retries = 2, timeout = None):
    self.retries = retries
    self.timeout = timeout

    self._cached_index = None
    self._cached_files = None
    self._cached_index_at = 0

  def get_server_descriptors(self, start = None, end = None, cache_to = None, bridge = False, timeout = None, retries = 3):
    """
    Provides server descriptors published during the given time range, sorted
    oldest to newest.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param bool bridge: standard descriptors if **False**, bridge if **True**
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.server_descriptor.ServerDescriptor` for the
      given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    desc_type = 'server-descriptor' if not bridge else 'bridge-server-descriptor'

    for f in self.files(desc_type, start, end):
      for desc in f.read(cache_to, desc_type, start, end, timeout = timeout, retries = retries):
        yield desc

  def get_extrainfo_descriptors(self, start = None, end = None, cache_to = None, bridge = False, timeout = None, retries = 3):
    """
    Provides extrainfo descriptors published during the given time range,
    sorted oldest to newest.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param bool bridge: standard descriptors if **False**, bridge if **True**
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`
      for the given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    desc_type = 'extra-info' if not bridge else 'bridge-extra-info'

    for f in self.files(desc_type, start, end):
      for desc in f.read(cache_to, desc_type, start, end, timeout = timeout, retries = retries):
        yield desc

  def get_microdescriptors(self, start = None, end = None, cache_to = None, timeout = None, retries = 3):
    """
    Provides microdescriptors estimated to be published during the given time
    range, sorted oldest to newest. Unlike server/extrainfo descriptors,
    microdescriptors change very infrequently...

    ::

      "Microdescriptors are expected to be relatively static and only change
      about once per week." -dir-spec section 3.3

    CollecTor archives only contain microdescriptors that *change*, so hourly
    tarballs often contain very few. Microdescriptors also do not contain
    their publication timestamp, so this is estimated.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.microdescriptor.Microdescriptor
      for the given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    for f in self.files('microdescriptor', start, end):
      for desc in f.read(cache_to, 'microdescriptor', start, end, timeout = timeout, retries = retries):
        yield desc

  def get_consensus(self, start = None, end = None, cache_to = None, document_handler = DocumentHandler.ENTRIES, version = 3, microdescriptor = False, bridge = False, timeout = None, retries = 3):
    """
    Provides consensus router status entries published during the given time
    range, sorted oldest to newest.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param stem.descriptor.__init__.DocumentHandler document_handler: method in
      which to parse a :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
    :param int version: consensus variant to retrieve (versions 2 or 3)
    :param bool microdescriptor: provides the microdescriptor consensus if
      **True**, standard consensus otherwise
    :param bool bridge: standard descriptors if **False**, bridge if **True**
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.router_status_entry.RouterStatusEntry`
      for the given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    if version == 3 and not microdescriptor and not bridge:
      desc_type = 'network-status-consensus-3'
    elif version == 3 and microdescriptor and not bridge:
      desc_type = 'network-status-microdesc-consensus-3'
    elif version == 2 and not microdescriptor and not bridge:
      desc_type = 'network-status-2'
    elif bridge:
      desc_type = 'bridge-network-status'
    else:
      if microdescriptor and version != 3:
        raise ValueError('Only v3 microdescriptors are available (not version %s)' % version)
      else:
        raise ValueError('Only v2 and v3 router status entries are available (not version %s)' % version)

    for f in self.files(desc_type, start, end):
      for desc in f.read(cache_to, desc_type, start, end, document_handler, timeout = timeout, retries = retries):
        yield desc

  def get_key_certificates(self, start = None, end = None, cache_to = None, timeout = None, retries = 3):
    """
    Directory authority key certificates for the given time range,
    sorted oldest to newest.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.networkstatus.KeyCertificate
      for the given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    for f in self.files('dir-key-certificate-3', start, end):
      for desc in f.read(cache_to, 'dir-key-certificate-3', start, end, timeout = timeout, retries = retries):
        yield desc

  def get_bandwidth_files(self, start = None, end = None, cache_to = None, timeout = None, retries = 3):
    """
    Bandwidth authority heuristics for the given time range, sorted oldest to
    newest.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.bandwidth_file.BandwidthFile
      for the given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    for f in self.files('bandwidth-file', start, end):
      for desc in f.read(cache_to, 'bandwidth-file', start, end, timeout = timeout, retries = retries):
        yield desc

  def get_exit_lists(self, start = None, end = None, cache_to = None, timeout = None, retries = 3):
    """
    `TorDNSEL exit lists <https://www.torproject.org/projects/tordnsel.html.en>`_
    for the given time range, sorted oldest to newest.

    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with
    :param str cache_to: directory to cache archives into, if an archive is
      available here it is not downloaded
    :param int timeout: timeout for downloading each individual archive when
      the connection becomes idle, no timeout applied if **None**
    :param int retries: maximum attempts to impose on a per-archive basis

    :returns: **iterator** of
      :class:`~stem.descriptor.tordnsel.TorDNSEL
      for the given time range

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    for f in self.files('tordnsel', start, end):
      for desc in f.read(cache_to, 'tordnsel', start, end, timeout = timeout, retries = retries):
        yield desc

  def index(self, compression = 'best'):
    """
    Provides the archives available in CollecTor.

    :param descriptor.Compression compression: compression type to
      download from, if undefiled we'll use the best decompression available

    :returns: **dict** with the archive contents

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * :class:`~stem.DownloadFailed` if the download fails
    """

    if not self._cached_index or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      if compression == 'best':
        for option in (Compression.LZMA, Compression.BZ2, Compression.GZIP, Compression.PLAINTEXT):
          if option.available:
            compression = option
            break
      elif compression is None:
        compression = Compression.PLAINTEXT

      extension = compression.extension if compression != Compression.PLAINTEXT else ''
      url = COLLECTOR_URL + 'index/index.json' + extension
      response = compression.decompress(stem.util.connection.download(url, self.timeout, self.retries))

      self._cached_index = json.loads(stem.util.str_tools._to_unicode(response))
      self._cached_index_at = time.time()

    return self._cached_index

  def files(self, descriptor_type = None, start = None, end = None):
    """
    Provides files CollecTor presently has, sorted oldest to newest.

    :param str descriptor_type: descriptor type or prefix to retrieve
    :param datetime.datetime start: publication time to begin with
    :param datetime.datetime end: publication time to end with

    :returns: **list** of :class:`~stem.descriptor.collector.File`

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * :class:`~stem.DownloadFailed` if the download fails
    """

    if not self._cached_files or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      self._cached_files = sorted(CollecTor._files(self.index(), []), key = lambda x: x.start if x.start else FUTURE)

    matches = []

    for f in self._cached_files:
      if start and (f.end is None or f.end < start):
        continue  # only contains descriptors before time range
      elif end and (f.start is None or f.start > end):
        continue  # only contains descriptors after time range

      if descriptor_type is None or any([desc_type.startswith(descriptor_type) for desc_type in f.types]):
        matches.append(f)

    return matches

  @staticmethod
  def _files(val, path):
    """
    Recursively provies files within the index.

    :param dict val: index hash
    :param list path: path we've transversed into

    :returns: **list** of :class:`~stem.descriptor.collector.File`
    """

    if not isinstance(val, dict):
      return []  # leaf node without any files

    files = []

    for k, v in val.items():
      if k == 'files':
        for attr in v:
          file_path = '/'.join(path + [attr.get('path')])
          files.append(File(file_path, attr.get('types'), attr.get('size'), attr.get('sha256'), attr.get('first_published'), attr.get('last_published'), attr.get('last_modified')))
      elif k == 'directories':
        for attr in v:
          files.extend(CollecTor._files(attr, path + [attr.get('path')]))

    return files
