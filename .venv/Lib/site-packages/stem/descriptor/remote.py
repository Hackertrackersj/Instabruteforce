# Copyright 2013-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for remotely retrieving descriptors from directory authorities and
mirrors. This is the simplest method for getting current tor descriptor
information...

::

  import stem.descriptor.remote

  for desc in stem.descriptor.remote.get_server_descriptors():
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))

More custom downloading behavior can be done through the
:class:`~stem.descriptor.remote.DescriptorDownloader` class, which issues
:class:`~stem.descriptor.remote.Query` instances to get you descriptor
content. For example...

::

  from stem.descriptor.remote import DescriptorDownloader

  downloader = DescriptorDownloader(
    use_mirrors = True,
    timeout = 10,
  )

  query = downloader.get_server_descriptors()

  print('Exit Relays:')

  try:
    for desc in query.run():
      if desc.exit_policy.is_exiting_allowed():
        print('  %s (%s)' % (desc.nickname, desc.fingerprint))

    print
    print('Query took %0.2f seconds' % query.runtime)
  except Exception as exc:
    print('Unable to retrieve the server descriptors: %s' % exc)

::

  get_instance - Provides a singleton DescriptorDownloader used for...
    |- their_server_descriptor - provides the server descriptor of the relay we download from
    |- get_server_descriptors - provides present server descriptors
    |- get_extrainfo_descriptors - provides present extrainfo descriptors
    |- get_microdescriptors - provides present microdescriptors with the given digests
    |- get_consensus - provides the present consensus or router status entries
    |- get_bandwidth_file - provides bandwidth heuristics used to make the next consensus
    +- get_detached_signatures - authority signatures used to make the next consensus

  Query - Asynchronous request to download tor descriptors
    |- start - issues the query if it isn't already running
    +- run - blocks until the request is finished and provides the results

  DescriptorDownloader - Configurable class for issuing queries
    |- use_directory_mirrors - use directory mirrors to download future descriptors
    |- their_server_descriptor - provides the server descriptor of the relay we download from
    |- get_server_descriptors - provides present server descriptors
    |- get_extrainfo_descriptors - provides present extrainfo descriptors
    |- get_microdescriptors - provides present microdescriptors with the given digests
    |- get_consensus - provides the present consensus or router status entries
    |- get_vote - provides an authority's vote for the next consensus
    |- get_key_certificates - provides present authority key certificates
    |- get_bandwidth_file - provides bandwidth heuristics used to make the next consensus
    |- get_detached_signatures - authority signatures used to make the next consensus
    +- query - request an arbitrary descriptor resource

.. versionadded:: 1.1.0

.. data:: MAX_FINGERPRINTS

  Maximum number of descriptors that can requested at a time by their
  fingerprints.

.. data:: MAX_MICRODESCRIPTOR_HASHES

  Maximum number of microdescriptors that can requested at a time by their
  hashes.

.. data:: Compression (enum)

  Compression when downloading descriptors.

  .. versionadded:: 1.7.0

  =============== ===========
  Compression     Description
  =============== ===========
  **PLAINTEXT**   Uncompressed data.
  **GZIP**        `GZip compression <https://www.gnu.org/software/gzip/>`_.
  **ZSTD**        `Zstandard compression <https://www.zstd.net>`_, this requires the `zstandard module <https://pypi.org/project/zstandard/>`_.
  **LZMA**        `LZMA compression <https://en.wikipedia.org/wiki/LZMA>`_, this requires the 'lzma module <https://docs.python.org/3/library/lzma.html>`_.
  =============== ===========
"""

import io
import random
import socket
import sys
import threading
import time

import stem
import stem.client
import stem.descriptor
import stem.descriptor.networkstatus
import stem.directory
import stem.prereq
import stem.util.enum
import stem.util.tor_tools

from stem.util import log, str_tools

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

# TODO: remove in stem 2.x, replaced with stem.descriptor.Compression

Compression = stem.util.enum.Enum(
  ('PLAINTEXT', 'identity'),
  ('GZIP', 'gzip'),  # can also be 'deflate'
  ('ZSTD', 'x-zstd'),
  ('LZMA', 'x-tor-lzma'),
)

COMPRESSION_MIGRATION = {
  'identity': stem.descriptor.Compression.PLAINTEXT,
  'gzip': stem.descriptor.Compression.GZIP,
  'x-zstd': stem.descriptor.Compression.ZSTD,
  'x-tor-lzma': stem.descriptor.Compression.LZMA,
}

# Tor has a limited number of descriptors we can fetch explicitly by their
# fingerprint or hashes due to a limit on the url length by squid proxies.

MAX_FINGERPRINTS = 96
MAX_MICRODESCRIPTOR_HASHES = 90

SINGLETON_DOWNLOADER = None

# Detached signatures do *not* have a specified type annotation. But our
# parsers expect that all descriptors have a type. As such making one up.
# This may change in the future if these ever get an official @type.
#
#   https://trac.torproject.org/projects/tor/ticket/28615

DETACHED_SIGNATURE_TYPE = 'detached-signature'

# Some authorities intentionally break their DirPort to discourage DOS. In
# particular they throttle the rate to such a degree that requests can take
# hours to complete. Unfortunately Python's socket timeouts only kick in
# when we stop receiving data, so these 'sandtraps' cause our downloads to
# hang pretty much indefinitely.
#
# Best we can do is simply avoid attempting to use them in the first place.

DIR_PORT_BLACKLIST = ('tor26', 'Serge')


def get_instance():
  """
  Provides the singleton :class:`~stem.descriptor.remote.DescriptorDownloader`
  used for this module's shorthand functions.

  .. versionadded:: 1.5.0

  :returns: singleton :class:`~stem.descriptor.remote.DescriptorDownloader` instance
  """

  global SINGLETON_DOWNLOADER

  if SINGLETON_DOWNLOADER is None:
    SINGLETON_DOWNLOADER = DescriptorDownloader()

  return SINGLETON_DOWNLOADER


def their_server_descriptor(**query_args):
  """
  Provides the server descriptor of the relay we're downloading from.

  .. versionadded:: 1.7.0

  :param query_args: additional arguments for the
    :class:`~stem.descriptor.remote.Query` constructor

  :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors
  """

  return get_instance().their_server_descriptor(**query_args)


def get_server_descriptors(fingerprints = None, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_server_descriptors`
  on our singleton instance.

  .. versionadded:: 1.5.0
  """

  return get_instance().get_server_descriptors(fingerprints, **query_args)


def get_extrainfo_descriptors(fingerprints = None, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_extrainfo_descriptors`
  on our singleton instance.

  .. versionadded:: 1.5.0
  """

  return get_instance().get_extrainfo_descriptors(fingerprints, **query_args)


def get_microdescriptors(hashes, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_microdescriptors`
  on our singleton instance.

  .. versionadded:: 1.8.0
  """

  return get_instance().get_microdescriptors(hashes, **query_args)


def get_consensus(authority_v3ident = None, microdescriptor = False, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_consensus`
  on our singleton instance.

  .. versionadded:: 1.5.0
  """

  return get_instance().get_consensus(authority_v3ident, microdescriptor, **query_args)


def get_bandwidth_file(**query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_bandwidth_file`
  on our singleton instance.

  .. versionadded:: 1.8.0
  """

  return get_instance().get_bandwidth_file(**query_args)


def get_detached_signatures(**query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_detached_signatures`
  on our singleton instance.

  .. versionadded:: 1.8.0
  """

  return get_instance().get_detached_signatures(**query_args)


class Query(object):
  """
  Asynchronous request for descriptor content from a directory authority or
  mirror. These can either be made through the
  :class:`~stem.descriptor.remote.DescriptorDownloader` or directly for more
  advanced usage.

  To block on the response and get results either call
  :func:`~stem.descriptor.remote.Query.run` or iterate over the Query. The
  :func:`~stem.descriptor.remote.Query.run` method pass along any errors that
  arise...

  ::

    from stem.descriptor.remote import Query

    query = Query(
      '/tor/server/all',
      timeout = 30,
    )

    print('Current relays:')

    try:
      for desc in Query('/tor/server/all', 'server-descriptor 1.0').run():
        print(desc.fingerprint)
    except Exception as exc:
      print('Unable to retrieve the server descriptors: %s' % exc)

  ... while iterating fails silently...

  ::

    print('Current relays:')

    for desc in Query('/tor/server/all', 'server-descriptor 1.0'):
      print(desc.fingerprint)

  In either case exceptions are available via our 'error' attribute.

  Tor provides quite a few different descriptor resources via its directory
  protocol (see section 4.2 and later of the `dir-spec
  <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_).
  Commonly useful ones include...

  =============================================== ===========
  Resource                                        Description
  =============================================== ===========
  /tor/server/all                                 all present server descriptors
  /tor/server/fp/<fp1>+<fp2>+<fp3>                server descriptors with the given fingerprints
  /tor/extra/all                                  all present extrainfo descriptors
  /tor/extra/fp/<fp1>+<fp2>+<fp3>                 extrainfo descriptors with the given fingerprints
  /tor/micro/d/<hash1>-<hash2>                    microdescriptors with the given hashes
  /tor/status-vote/current/consensus              present consensus
  /tor/status-vote/current/consensus-microdesc    present microdescriptor consensus
  /tor/status-vote/next/bandwidth                 bandwidth authority heuristics for the next consenus
  /tor/status-vote/next/consensus-signatures      detached signature, used for making the next consenus
  /tor/keys/all                                   key certificates for the authorities
  /tor/keys/fp/<v3ident1>+<v3ident2>              key certificates for specific authorities
  =============================================== ===========

  **ZSTD** compression requires `zstandard
  <https://pypi.org/project/zstandard/>`_, and **LZMA** requires the `lzma
  module <https://docs.python.org/3/library/lzma.html>`_.

  For legacy reasons if our resource has a '.z' suffix then our **compression**
  argument is overwritten with Compression.GZIP.

  .. versionchanged:: 1.7.0
     Added support for downloading from ORPorts.

  .. versionchanged:: 1.7.0
     Added the compression argument.

  .. versionchanged:: 1.7.0
     Added the reply_headers attribute.

     The class this provides changed between Python versions. In python2
     this was called httplib.HTTPMessage, whereas in python3 the class was
     renamed to http.client.HTTPMessage.

  .. versionchanged:: 1.7.0
     Endpoints are now expected to be :class:`~stem.DirPort` or
     :class:`~stem.ORPort` instances. Usage of tuples for this
     argument is deprecated and will be removed in the future.

  .. versionchanged:: 1.7.0
     Avoid downloading from tor26. This directory authority throttles its
     DirPort to such an extent that requests either time out or take on the
     order of minutes.

  .. versionchanged:: 1.7.0
     Avoid downloading from Bifroest. This is the bridge authority so it
     doesn't vote in the consensus, and apparently times out frequently.

  .. versionchanged:: 1.8.0
     Serge has replaced Bifroest as our bridge authority. Avoiding descriptor
     downloads from it instead.

  .. versionchanged:: 1.8.0
     Defaulting to gzip compression rather than plaintext downloads.

  .. versionchanged:: 1.8.0
     Using :class:`~stem.descriptor.__init__.Compression` for our compression
     argument, usage of strings or this module's Compression enum is deprecated
     and will be removed in stem 2.x.

  :var str resource: resource being fetched, such as '/tor/server/all'
  :var str descriptor_type: type of descriptors being fetched (for options see
    :func:`~stem.descriptor.__init__.parse_file`), this is guessed from the
    resource if **None**

  :var list endpoints: :class:`~stem.DirPort` or :class:`~stem.ORPort` of the
    authority or mirror we're querying, this uses authorities if undefined
  :var list compression: list of :data:`stem.descriptor.Compression`
    we're willing to accept, when none are mutually supported downloads fall
    back to Compression.PLAINTEXT
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var bool fall_back_to_authority: when retrying request issues the last
    request to a directory authority if **True**

  :var str content: downloaded descriptor content
  :var Exception error: exception if a problem occured
  :var bool is_done: flag that indicates if our request has finished

  :var float start_time: unix timestamp when we first started running
  :var http.client.HTTPMessage reply_headers: headers provided in the response,
    **None** if we haven't yet made our request
  :var float runtime: time our query took, this is **None** if it's not yet
    finished

  :var bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :var stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse a :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :var dict kwargs: additional arguments for the descriptor constructor

  Following are only applicable when downloading from a
  :class:`~stem.DirPort`...

  :var float timeout: duration before we'll time out our request
  :var str download_url: last url used to download the descriptor, this is
    unset until we've actually made a download attempt

  :param bool start: start making the request when constructed (default is **True**)
  :param bool block: only return after the request has been completed, this is
    the same as running **query.run(True)** (default is **False**)
  """

  def __init__(self, resource, descriptor_type = None, endpoints = None, compression = (Compression.GZIP,), retries = 2, fall_back_to_authority = False, timeout = None, start = True, block = False, validate = False, document_handler = stem.descriptor.DocumentHandler.ENTRIES, **kwargs):
    if not resource.startswith('/'):
      raise ValueError("Resources should start with a '/': %s" % resource)

    if resource.endswith('.z'):
      compression = [Compression.GZIP]
      resource = resource[:-2]
    elif not compression:
      compression = [Compression.PLAINTEXT]
    else:
      if isinstance(compression, str):
        compression = [compression]  # caller provided only a single option

      if Compression.ZSTD in compression and not stem.prereq.is_zstd_available():
        compression.remove(Compression.ZSTD)

      if Compression.LZMA in compression and not stem.prereq.is_lzma_available():
        compression.remove(Compression.LZMA)

      if not compression:
        compression = [Compression.PLAINTEXT]

    # TODO: Normalize from our old compression enum to
    # stem.descriptor.Compression. This will get removed in Stem 2.x.

    new_compression = []

    for legacy_compression in compression:
      if isinstance(legacy_compression, stem.descriptor._Compression):
        new_compression.append(legacy_compression)
      elif legacy_compression in COMPRESSION_MIGRATION:
        new_compression.append(COMPRESSION_MIGRATION[legacy_compression])
      else:
        raise ValueError("'%s' (%s) is not a recognized type of compression" % (legacy_compression, type(legacy_compression).__name__))

    if descriptor_type:
      self.descriptor_type = descriptor_type
    else:
      self.descriptor_type = _guess_descriptor_type(resource)

    self.endpoints = []

    if endpoints:
      for endpoint in endpoints:
        if isinstance(endpoint, tuple) and len(endpoint) == 2:
          self.endpoints.append(stem.DirPort(endpoint[0], endpoint[1]))  # TODO: remove this in stem 2.0
        elif isinstance(endpoint, (stem.ORPort, stem.DirPort)):
          self.endpoints.append(endpoint)
        else:
          raise ValueError("Endpoints must be an stem.ORPort, stem.DirPort, or two value tuple. '%s' is a %s." % (endpoint, type(endpoint).__name__))

    self.resource = resource
    self.compression = new_compression
    self.retries = retries
    self.fall_back_to_authority = fall_back_to_authority

    self.content = None
    self.error = None
    self.is_done = False
    self.download_url = None

    self.start_time = None
    self.timeout = timeout
    self.runtime = None

    self.validate = validate
    self.document_handler = document_handler
    self.reply_headers = None
    self.kwargs = kwargs

    self._downloader_thread = None
    self._downloader_thread_lock = threading.RLock()

    if start:
      self.start()

    if block:
      self.run(True)

  def start(self):
    """
    Starts downloading the scriptors if we haven't started already.
    """

    with self._downloader_thread_lock:
      if self._downloader_thread is None:
        self._downloader_thread = threading.Thread(
          name = 'Descriptor query',
          target = self._download_descriptors,
          args = (self.retries, self.timeout)
        )

        self._downloader_thread.setDaemon(True)
        self._downloader_thread.start()

  def run(self, suppress = False):
    """
    Blocks until our request is complete then provides the descriptors. If we
    haven't yet started our request then this does so.

    :param bool suppress: avoids raising exceptions if **True**

    :returns: list for the requested :class:`~stem.descriptor.__init__.Descriptor` instances

    :raises:
      Using the iterator can fail with the following if **suppress** is
      **False**...

        * **ValueError** if the descriptor contents is malformed
        * :class:`~stem.DownloadTimeout` if our request timed out
        * :class:`~stem.DownloadFailed` if our request fails
    """

    return list(self._run(suppress))

  def _run(self, suppress):
    with self._downloader_thread_lock:
      self.start()
      self._downloader_thread.join()

      if self.error:
        if suppress:
          return

        raise self.error
      else:
        if self.content is None:
          if suppress:
            return

          raise ValueError('BUG: _download_descriptors() finished without either results or an error')

        try:
          # TODO: special handling until we have an official detatched
          # signature @type...
          #
          #   https://trac.torproject.org/projects/tor/ticket/28615

          if self.descriptor_type.startswith(DETACHED_SIGNATURE_TYPE):
            results = stem.descriptor.networkstatus._parse_file_detached_sigs(
              io.BytesIO(self.content),
              validate = self.validate,
            )
          else:
            results = stem.descriptor.parse_file(
              io.BytesIO(self.content),
              self.descriptor_type,
              validate = self.validate,
              document_handler = self.document_handler,
              **self.kwargs
            )

          for desc in results:
            yield desc
        except ValueError as exc:
          self.error = exc  # encountered a parsing error

          if suppress:
            return

          raise self.error

  def __iter__(self):
    for desc in self._run(True):
      yield desc

  def _pick_endpoint(self, use_authority = False):
    """
    Provides an endpoint to query. If we have multiple endpoints then one
    is picked at random.

    :param bool use_authority: ignores our endpoints and uses a directory
      authority instead

    :returns: :class:`stem.Endpoint` for the location to be downloaded
      from by this request
    """

    if use_authority or not self.endpoints:
      picked = random.choice([auth for auth in stem.directory.Authority.from_cache().values() if auth.nickname not in DIR_PORT_BLACKLIST])
      return stem.DirPort(picked.address, picked.dir_port)
    else:
      return random.choice(self.endpoints)

  def _download_descriptors(self, retries, timeout):
    try:
      self.start_time = time.time()
      endpoint = self._pick_endpoint(use_authority = retries == 0 and self.fall_back_to_authority)

      if isinstance(endpoint, stem.ORPort):
        downloaded_from = 'ORPort %s:%s (resource %s)' % (endpoint.address, endpoint.port, self.resource)
        self.content, self.reply_headers = _download_from_orport(endpoint, self.compression, self.resource)
      elif isinstance(endpoint, stem.DirPort):
        self.download_url = 'http://%s:%i/%s' % (endpoint.address, endpoint.port, self.resource.lstrip('/'))
        downloaded_from = self.download_url
        self.content, self.reply_headers = _download_from_dirport(self.download_url, self.compression, timeout)
      else:
        raise ValueError("BUG: endpoints can only be ORPorts or DirPorts, '%s' was a %s" % (endpoint, type(endpoint).__name__))

      self.runtime = time.time() - self.start_time
      log.trace('Descriptors retrieved from %s in %0.2fs' % (downloaded_from, self.runtime))
    except:
      exc = sys.exc_info()[1]

      if timeout is not None:
        timeout -= time.time() - self.start_time

      if retries > 0 and (timeout is None or timeout > 0):
        log.debug("Unable to download descriptors from '%s' (%i retries remaining): %s" % (self.download_url, retries, exc))
        return self._download_descriptors(retries - 1, timeout)
      else:
        log.debug("Unable to download descriptors from '%s': %s" % (self.download_url, exc))
        self.error = exc
    finally:
      self.is_done = True


class DescriptorDownloader(object):
  """
  Configurable class that issues :class:`~stem.descriptor.remote.Query`
  instances on your behalf.

  :param bool use_mirrors: downloads the present consensus and uses the directory
    mirrors to fetch future requests, this fails silently if the consensus
    cannot be downloaded
  :param default_args: default arguments for the
    :class:`~stem.descriptor.remote.Query` constructor
  """

  def __init__(self, use_mirrors = False, **default_args):
    self._default_args = default_args

    self._endpoints = None

    if use_mirrors:
      try:
        start_time = time.time()
        self.use_directory_mirrors()
        log.debug('Retrieved directory mirrors (took %0.2fs)' % (time.time() - start_time))
      except Exception as exc:
        log.debug('Unable to retrieve directory mirrors: %s' % exc)

  def use_directory_mirrors(self):
    """
    Downloads the present consensus and configures ourselves to use directory
    mirrors, in addition to authorities.

    :returns: :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`
      from which we got the directory mirrors

    :raises: **Exception** if unable to determine the directory mirrors
    """

    directories = [auth for auth in stem.directory.Authority.from_cache().values() if auth.nickname not in DIR_PORT_BLACKLIST]
    new_endpoints = set([(directory.address, directory.dir_port) for directory in directories])

    consensus = list(self.get_consensus(document_handler = stem.descriptor.DocumentHandler.DOCUMENT).run())[0]

    for desc in consensus.routers.values():
      if stem.Flag.V2DIR in desc.flags and desc.dir_port:
        new_endpoints.add((desc.address, desc.dir_port))

    # we need our endpoints to be a list rather than set for random.choice()

    self._endpoints = list(new_endpoints)

    return consensus

  def their_server_descriptor(self, **query_args):
    """
    Provides the server descriptor of the relay we're downloading from.

    .. versionadded:: 1.7.0

    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors
    """

    return self.query('/tor/server/authority', **query_args)

  def get_server_descriptors(self, fingerprints = None, **query_args):
    """
    Provides the server descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors known
    by the relay.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/server/all'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i descriptors at a time by their fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/server/fp/%s' % '+'.join(fingerprints)

    return self.query(resource, **query_args)

  def get_extrainfo_descriptors(self, fingerprints = None, **query_args):
    """
    Provides the extrainfo descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors in the present
    consensus.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the extrainfo descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/extra/all'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i descriptors at a time by their fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/extra/fp/%s' % '+'.join(fingerprints)

    return self.query(resource, **query_args)

  def get_microdescriptors(self, hashes, **query_args):
    """
    Provides the microdescriptors with the given hashes. To get these see the
    **microdescriptor_digest** attribute of
    :class:`~stem.descriptor.router_status_entry.RouterStatusEntryMicroV3`.
    Note that these are only provided via the **microdescriptor consensus**.
    For exampe...

    ::

      >>> import stem.descriptor.remote
      >>> consensus = stem.descriptor.remote.get_consensus(microdescriptor = True).run()
      >>> my_router_status_entry = list(filter(lambda desc: desc.nickname == 'caersidi', consensus))[0]
      >>> print(my_router_status_entry.microdescriptor_digest)
      IQI5X2A5p0WVN/MgwncqOaHF2f0HEGFEaxSON+uKRhU

      >>> my_microdescriptor = stem.descriptor.remote.get_microdescriptors([my_router_status_entry.microdescriptor_digest]).run()[0]
      >>> print(my_microdescriptor)
      onion-key
      -----BEGIN RSA PUBLIC KEY-----
      MIGJAoGBAOJo9yyVgG8ksEHQibqPIEbLieI6rh1EACRPiDiV21YObb+9QEHaR3Cf
      FNAzDbGhbvADLBB7EzuViL8w+eXQUOaIsJRdymh/wuUJ78bv5oEIJhthKq/Uqa4P
      wKHXSZixwAHfy8NASTX3kxu9dAHWU3Owb+4W4lR2hYM0ZpoYYkThAgMBAAE=
      -----END RSA PUBLIC KEY-----
      ntor-onion-key kWOHNd+2uBlMpcIUbbpFLiq/rry66Ep6MlwmNpwzcBg=
      id ed25519 xE/GeYImYAIB0RbzJXFL8kDLpDrj/ydCuCdvOgC4F/4

    :param str,list hashes: microdescriptor hash or list of hashes to be
      retrieved
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the microdescriptors

    :raises: **ValueError** if we request more than 92 microdescriptors by their
      hashes (this is due to a limit on the url length by squid proxies).
    """

    if isinstance(hashes, str):
      hashes = [hashes]

    if len(hashes) > MAX_MICRODESCRIPTOR_HASHES:
      raise ValueError('Unable to request more than %i microdescriptors at a time by their hashes' % MAX_MICRODESCRIPTOR_HASHES)

    return self.query('/tor/micro/d/%s' % '-'.join(hashes), **query_args)

  def get_consensus(self, authority_v3ident = None, microdescriptor = False, **query_args):
    """
    Provides the present router status entries.

    .. versionchanged:: 1.5.0
       Added the microdescriptor argument.

    :param str authority_v3ident: fingerprint of the authority key for which
      to get the consensus, see `'v3ident' in tor's config.c
      <https://gitweb.torproject.org/tor.git/tree/src/or/config.c>`_
      for the values.
    :param bool microdescriptor: provides the microdescriptor consensus if
      **True**, standard consensus otherwise
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the router status
      entries
    """

    if microdescriptor:
      resource = '/tor/status-vote/current/consensus-microdesc'
    else:
      resource = '/tor/status-vote/current/consensus'

    if authority_v3ident:
      resource += '/%s' % authority_v3ident

    consensus_query = self.query(resource, **query_args)

    # if we're performing validation then check that it's signed by the
    # authority key certificates

    if consensus_query.validate and consensus_query.document_handler == stem.descriptor.DocumentHandler.DOCUMENT and stem.prereq.is_crypto_available():
      consensus = list(consensus_query.run())[0]
      key_certs = self.get_key_certificates(**query_args).run()
      consensus.validate_signatures(key_certs)

    return consensus_query

  def get_vote(self, authority, **query_args):
    """
    Provides the present vote for a given directory authority.

    :param stem.directory.Authority authority: authority for which to retrieve a vote for
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the router status
      entries
    """

    resource = '/tor/status-vote/current/authority'

    if 'endpoint' not in query_args:
      query_args['endpoints'] = [(authority.address, authority.dir_port)]

    return self.query(resource, **query_args)

  def get_key_certificates(self, authority_v3idents = None, **query_args):
    """
    Provides the key certificates for authorities with the given fingerprints.
    If no fingerprints are provided then this returns all present key
    certificates.

    :param str authority_v3idents: fingerprint or list of fingerprints of the
      authority keys, see `'v3ident' in tor's config.c
      <https://gitweb.torproject.org/tor.git/tree/src/or/config.c#n819>`_
      for the values.
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the key certificates

    :raises: **ValueError** if we request more than 96 key certificates by
      their identity fingerprints (this is due to a limit on the url length by
      squid proxies).
    """

    resource = '/tor/keys/all'

    if isinstance(authority_v3idents, str):
      authority_v3idents = [authority_v3idents]

    if authority_v3idents:
      if len(authority_v3idents) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i key certificates at a time by their identity fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/keys/fp/%s' % '+'.join(authority_v3idents)

    return self.query(resource, **query_args)

  def get_bandwidth_file(self, **query_args):
    """
    Provides the bandwidth authority heuristics used to make the next
    consensus.

    .. versionadded:: 1.8.0

    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the bandwidth
      authority heuristics
    """

    return self.query('/tor/status-vote/next/bandwidth', **query_args)

  def get_detached_signatures(self, **query_args):
    """
    Provides the detached signatures that will be used to make the next
    consensus. Please note that **these are only available during minutes 55-60
    each hour**. If requested during minutes 0-55 tor will not service these
    requests, and this will fail with a 404.

    For example...

    ::

      import stem.descriptor.remote

      detached_sigs = stem.descriptor.remote.get_detached_signatures().run()[0]

      for i, sig in enumerate(detached_sigs.signatures):
        print('Signature %i is from %s' % (i + 1, sig.identity))

    **When available (minutes 55-60 of the hour)**

    ::

      % python demo.py
      Signature 1 is from 0232AF901C31A04EE9848595AF9BB7620D4C5B2E
      Signature 2 is from 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4
      Signature 3 is from 23D15D965BC35114467363C165C4F724B64B4F66
      ...

    **When unavailable (minutes 0-55 of the hour)**

    ::

      % python demo.py
      Traceback (most recent call last):
        File "demo.py", line 3, in
          detached_sigs = stem.descriptor.remote.get_detached_signatures().run()[0]
        File "/home/atagar/Desktop/stem/stem/descriptor/remote.py", line 533, in run
          return list(self._run(suppress))
        File "/home/atagar/Desktop/stem/stem/descriptor/remote.py", line 544, in _run
          raise self.error
      stem.DownloadFailed: Failed to download from http://154.35.175.225:80/tor/status-vote/next/consensus-signatures (HTTPError): Not found

    .. versionadded:: 1.8.0

    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the detached
      signatures
    """

    return self.query('/tor/status-vote/next/consensus-signatures', **query_args)

  def query(self, resource, **query_args):
    """
    Issues a request for the given resource.

    .. versionchanged:: 1.7.0
       The **fall_back_to_authority** default when using this method is now
       **False**, like the :class:`~stem.descriptor.Query` class.

    :param str resource: resource being fetched, such as '/tor/server/all'
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the descriptors

    :raises: **ValueError** if resource is clearly invalid or the descriptor
      type can't be determined when 'descriptor_type' is **None**
    """

    args = dict(self._default_args)
    args.update(query_args)

    if 'endpoints' not in args:
      args['endpoints'] = self._endpoints

    return Query(resource, **args)


def _download_from_orport(endpoint, compression, resource):
  """
  Downloads descriptors from the given orport. Payload is just like an http
  response (headers and all)...

  ::

    HTTP/1.0 200 OK
    Date: Mon, 23 Apr 2018 18:43:47 GMT
    Content-Type: text/plain
    X-Your-Address-Is: 216.161.254.25
    Content-Encoding: identity
    Expires: Wed, 25 Apr 2018 18:43:47 GMT

    router dannenberg 193.23.244.244 443 0 80
    identity-ed25519
    ... rest of the descriptor content...

  :param stem.ORPort endpoint: endpoint to download from
  :param list compression: compression methods for the request
  :param str resource: descriptor resource to download

  :returns: two value tuple of the form (data, reply_headers)

  :raises:
    * :class:`stem.ProtocolError` if not a valid descriptor response
    * :class:`stem.SocketError` if unable to establish a connection
  """

  link_protocols = endpoint.link_protocols if endpoint.link_protocols else [3]

  with stem.client.Relay.connect(endpoint.address, endpoint.port, link_protocols) as relay:
    with relay.create_circuit() as circ:
      request = '\r\n'.join((
        'GET %s HTTP/1.0' % resource,
        'Accept-Encoding: %s' % ', '.join(map(lambda c: c.encoding, compression)),
        'User-Agent: %s' % stem.USER_AGENT,
      )) + '\r\n\r\n'

      response = circ.directory(request, stream_id = 1)
      first_line, data = response.split(b'\r\n', 1)
      header_data, body_data = data.split(b'\r\n\r\n', 1)

      if not first_line.startswith(b'HTTP/1.0 2'):
        raise stem.ProtocolError("Response should begin with HTTP success, but was '%s'" % str_tools._to_unicode(first_line))

      headers = {}

      for line in str_tools._to_unicode(header_data).splitlines():
        if ': ' not in line:
          raise stem.ProtocolError("'%s' is not a HTTP header:\n\n%s" % line)

        key, value = line.split(': ', 1)
        headers[key] = value

      return _decompress(body_data, headers.get('Content-Encoding')), headers


def _download_from_dirport(url, compression, timeout):
  """
  Downloads descriptors from the given url.

  :param str url: dirport url from which to download from
  :param list compression: compression methods for the request
  :param float timeout: duration before we'll time out our request

  :returns: two value tuple of the form (data, reply_headers)

  :raises:
    * :class:`~stem.DownloadTimeout` if our request timed out
    * :class:`~stem.DownloadFailed` if our request fails
  """

  try:
    response = urllib.urlopen(
      urllib.Request(
        url,
        headers = {
          'Accept-Encoding': ', '.join(map(lambda c: c.encoding, compression)),
          'User-Agent': stem.USER_AGENT,
        }
      ),
      timeout = timeout,
    )
  except socket.timeout as exc:
    raise stem.DownloadTimeout(url, exc, sys.exc_info()[2], timeout)
  except:
    exc, stacktrace = sys.exc_info()[1:3]
    raise stem.DownloadFailed(url, exc, stacktrace)

  return _decompress(response.read(), response.headers.get('Content-Encoding')), response.headers


def _decompress(data, encoding):
  """
  Decompresses descriptor data.

  Tor doesn't include compression headers. As such when using gzip we
  need to include '32' for automatic header detection...

    https://stackoverflow.com/questions/3122145/zlib-error-error-3-while-decompressing-incorrect-header-check/22310760#22310760

  ... and with zstd we need to use the streaming API.

  :param bytes data: data we received
  :param str encoding: 'Content-Encoding' header of the response

  :raises:
    * **ValueError** if encoding is unrecognized
    * **ImportError** if missing the decompression module
  """

  if encoding == 'deflate':
    return stem.descriptor.Compression.GZIP.decompress(data)

  for compression in stem.descriptor.Compression:
    if encoding == compression.encoding:
      return compression.decompress(data)

  raise ValueError("'%s' isn't a recognized type of encoding" % encoding)


def _guess_descriptor_type(resource):
  # Attempts to determine the descriptor type based on the resource url. This
  # raises a ValueError if the resource isn't recognized.

  if resource.startswith('/tor/server/'):
    return 'server-descriptor 1.0'
  elif resource.startswith('/tor/extra/'):
    return 'extra-info 1.0'
  elif resource.startswith('/tor/micro/'):
    return 'microdescriptor 1.0'
  elif resource.startswith('/tor/keys/'):
    return 'dir-key-certificate-3 1.0'
  elif resource.startswith('/tor/status-vote/'):
    # The following resource urls can be for the present consensus
    # (/tor/status-vote/current/*) or the next (/tor/status-vote/next/*).

    if resource.endswith('/consensus') or resource.endswith('/authority'):
      return 'network-status-consensus-3 1.0'
    elif resource.endswith('/consensus-microdesc'):
      return 'network-status-microdesc-consensus-3 1.0'
    elif resource.endswith('/consensus-signatures'):
      return '%s 1.0' % DETACHED_SIGNATURE_TYPE
    elif stem.util.tor_tools.is_valid_fingerprint(resource.split('/')[-1]):
      return 'network-status-consensus-3 1.0'
    elif resource.endswith('/bandwidth'):
      return 'bandwidth-file 1.0'

  raise ValueError("Unable to determine the descriptor type for '%s'" % resource)


def get_authorities():
  """
  Provides cached Tor directory authority information. The directory
  information hardcoded into Tor and occasionally changes, so the information
  this provides might not necessarily match your version of tor.

  .. deprecated:: 1.7.0
     Use stem.directory.Authority.from_cache() instead.

  :returns: **dict** of **str** nicknames to :class:`~stem.directory.Authority` instances
  """

  return DirectoryAuthority.from_cache()


# TODO: drop aliases in stem 2.0

Directory = stem.directory.Directory
DirectoryAuthority = stem.directory.Authority
FallbackDirectory = stem.directory.Fallback
