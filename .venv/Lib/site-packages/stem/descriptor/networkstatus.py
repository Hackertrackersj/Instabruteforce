# Copyright 2012-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor network status documents. This supports both the v2 and v3
`dir-spec <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_.
Documents can be obtained from a few sources...

* The 'cached-consensus' file in Tor's data directory.

* Archived descriptors provided by `CollecTor
  <https://metrics.torproject.org/collector.html>`_.

* Directory authorities and mirrors via their DirPort.

... and contain the following sections...

* document header
* list of :class:`stem.descriptor.networkstatus.DirectoryAuthority`
* list of :class:`stem.descriptor.router_status_entry.RouterStatusEntry`
* document footer

**For a great graphical overview see** `Jordan Wright's chart describing the
anatomy of the consensus
<https://jordan-wright.github.io/images/blog/how_tor_works/consensus.png>`_.

Of these, the router status entry section can be quite large (on the order of
hundreds of kilobytes). As such we provide a couple of methods for reading
network status documents through :func:`~stem.descriptor.__init__.parse_file`.
For more information see :func:`~stem.descriptor.__init__.DocumentHandler`...

::

  from stem.descriptor import parse_file, DocumentHandler

  with open('.tor/cached-consensus', 'rb') as consensus_file:
    # Processes the routers as we read them in. The routers refer to a document
    # with an unset 'routers' attribute.

    for router in parse_file(consensus_file, 'network-status-consensus-3 1.0', document_handler = DocumentHandler.ENTRIES):
      print router.nickname

**Module Overview:**

::

  NetworkStatusDocument - Network status document
    |- NetworkStatusDocumentV2 - Version 2 network status document
    |- NetworkStatusDocumentV3 - Version 3 network status document
    +- BridgeNetworkStatusDocument - Version 3 network status document for bridges

  KeyCertificate - Certificate used to authenticate an authority
  DocumentSignature - Signature of a document by a directory authority
  DetachedSignature - Stand alone signature used when making the consensus
  DirectoryAuthority - Directory authority as defined in a v3 network status document
"""

import collections
import datetime
import hashlib
import io

import stem.descriptor.router_status_entry
import stem.util.str_tools
import stem.util.tor_tools
import stem.version

from stem.descriptor import (
  PGP_BLOCK_END,
  Descriptor,
  DigestHash,
  DigestEncoding,
  TypeAnnotation,
  DocumentHandler,
  _descriptor_content,
  _descriptor_components,
  _read_until_keywords,
  _value,
  _values,
  _parse_simple_line,
  _parse_if_present,
  _parse_timestamp_line,
  _parse_forty_character_hex,
  _parse_protocol_line,
  _parse_key_block,
  _mappings_for,
  _random_nickname,
  _random_fingerprint,
  _random_ipv4_address,
  _random_date,
  _random_crypto_blob,
)

from stem.descriptor.router_status_entry import (
  RouterStatusEntryV2,
  RouterStatusEntryBridgeV2,
  RouterStatusEntryV3,
  RouterStatusEntryMicroV3,
)

# Version 2 network status document fields, tuples of the form...
# (keyword, is_mandatory)

NETWORK_STATUS_V2_FIELDS = (
  ('network-status-version', True),
  ('dir-source', True),
  ('fingerprint', True),
  ('contact', True),
  ('dir-signing-key', True),
  ('client-versions', False),
  ('server-versions', False),
  ('published', True),
  ('dir-options', False),
  ('directory-signature', True),
)

# Network status document are either a 'vote' or 'consensus', with different
# mandatory fields for each. Both though require that their fields appear in a
# specific order. This is an ordered listing of the following...
#
# (field, in_votes, in_consensus, is_mandatory)

HEADER_STATUS_DOCUMENT_FIELDS = (
  ('network-status-version', True, True, True),
  ('vote-status', True, True, True),
  ('consensus-methods', True, False, False),
  ('consensus-method', False, True, False),
  ('published', True, False, True),
  ('valid-after', True, True, True),
  ('fresh-until', True, True, True),
  ('valid-until', True, True, True),
  ('voting-delay', True, True, True),
  ('client-versions', True, True, False),
  ('server-versions', True, True, False),
  ('package', True, True, False),
  ('known-flags', True, True, True),
  ('flag-thresholds', True, False, False),
  ('shared-rand-participate', True, False, False),
  ('shared-rand-commit', True, False, False),
  ('shared-rand-previous-value', True, True, False),
  ('shared-rand-current-value', True, True, False),
  ('bandwidth-file-headers', True, False, False),
  ('bandwidth-file-digest', True, False, False),
  ('recommended-client-protocols', True, True, False),
  ('recommended-relay-protocols', True, True, False),
  ('required-client-protocols', True, True, False),
  ('required-relay-protocols', True, True, False),
  ('params', True, True, False),
)

FOOTER_STATUS_DOCUMENT_FIELDS = (
  ('directory-footer', True, True, False),
  ('bandwidth-weights', False, True, False),
  ('directory-signature', True, True, True),
)

AUTH_START = 'dir-source'
ROUTERS_START = 'r'
FOOTER_START = 'directory-footer'
V2_FOOTER_START = 'directory-signature'

DEFAULT_PARAMS = {
  'bwweightscale': 10000,
  'cbtdisabled': 0,
  'cbtnummodes': 3,
  'cbtrecentcount': 20,
  'cbtmaxtimeouts': 18,
  'cbtmincircs': 100,
  'cbtquantile': 80,
  'cbtclosequantile': 95,
  'cbttestfreq': 60,
  'cbtmintimeout': 2000,
  'cbtinitialtimeout': 60000,
  'cbtlearntimeout': 180,
  'cbtmaxopencircs': 10,
  'UseOptimisticData': 1,
  'Support022HiddenServices': 1,
  'usecreatefast': 1,
  'max-consensuses-age-to-cache-for-diff': 72,
  'try-diff-for-consensus-newer-than': 72,
  'onion-key-rotation-days': 28,
  'onion-key-grace-period-days': 7,
  'hs_service_max_rdv_failures': 2,
  'circ_max_cell_queue_size': 50000,
  'circpad_max_circ_queued_cells': 1000,
  'HiddenServiceEnableIntroDoSDefense': 0,
}

# KeyCertificate fields, tuple is of the form...
# (keyword, is_mandatory)

KEY_CERTIFICATE_PARAMS = (
  ('dir-key-certificate-version', True),
  ('dir-address', False),
  ('fingerprint', True),
  ('dir-identity-key', True),
  ('dir-key-published', True),
  ('dir-key-expires', True),
  ('dir-signing-key', True),
  ('dir-key-crosscert', False),
  ('dir-key-certification', True),
)

# DetchedSignature fields, tuple is of the form...
# (keyword, is_mandatory, is_multiple)

DETACHED_SIGNATURE_PARAMS = (
  ('consensus-digest', True, False),
  ('valid-after', True, False),
  ('fresh-until', True, False),
  ('valid-until', True, False),
  ('additional-digest', False, True),
  ('additional-signature', False, True),
  ('directory-signature', False, True),
)

# all parameters are constrained to int32 range
MIN_PARAM, MAX_PARAM = -2147483648, 2147483647

PARAM_RANGE = {
  'circwindow': (100, 1000),
  'CircuitPriorityHalflifeMsec': (-1, MAX_PARAM),
  'perconnbwrate': (-1, MAX_PARAM),
  'perconnbwburst': (-1, MAX_PARAM),
  'refuseunknownexits': (0, 1),
  'bwweightscale': (1, MAX_PARAM),
  'cbtdisabled': (0, 1),
  'cbtnummodes': (1, 20),
  'cbtrecentcount': (3, 1000),
  'cbtmaxtimeouts': (3, 10000),
  'cbtmincircs': (1, 10000),
  'cbtquantile': (10, 99),
  'cbtclosequantile': (MIN_PARAM, 99),
  'cbttestfreq': (1, MAX_PARAM),
  'cbtmintimeout': (500, MAX_PARAM),
  'cbtlearntimeout': (10, 60000),
  'cbtmaxopencircs': (0, 14),
  'UseOptimisticData': (0, 1),
  'Support022HiddenServices': (0, 1),
  'usecreatefast': (0, 1),
  'UseNTorHandshake': (0, 1),
  'FastFlagMinThreshold': (4, MAX_PARAM),
  'NumDirectoryGuards': (0, 10),
  'NumEntryGuards': (1, 10),
  'GuardLifetime': (2592000, 157766400),  # min: 30 days, max: 1826 days
  'NumNTorsPerTAP': (1, 100000),
  'AllowNonearlyExtend': (0, 1),
  'AuthDirNumSRVAgreements': (1, MAX_PARAM),
  'max-consensuses-age-to-cache-for-diff': (0, 8192),
  'try-diff-for-consensus-newer-than': (0, 8192),
  'onion-key-rotation-days': (1, 90),
  'onion-key-grace-period-days': (1, 90),  # max is the highest onion-key-rotation-days
  'hs_service_max_rdv_failures': (1, 10),
  'circ_max_cell_queue_size': (1000, 4294967295),
  'circpad_max_circ_queued_cells': (0, 50000),
  'HiddenServiceEnableIntroDoSDefense': (0, 1),
}


class PackageVersion(collections.namedtuple('PackageVersion', ['name', 'version', 'url', 'digests'])):
  """
  Latest recommended version of a package that's available.

  :var str name: name of the package
  :var str version: latest recommended version
  :var str url: package's url
  :var dict digests: mapping of digest types to their value
  """


class SharedRandomnessCommitment(collections.namedtuple('SharedRandomnessCommitment', ['version', 'algorithm', 'identity', 'commit', 'reveal'])):
  """
  Directory authority's commitment for generating the next shared random value.

  :var int version: shared randomness protocol version
  :var str algorithm: hash algorithm used to make the commitment
  :var str identity: authority's sha1 identity fingerprint
  :var str commit: base64 encoded commitment hash to the shared random value
  :var str reveal: base64 encoded commitment to the shared random value,
    **None** of not provided
  """


class DocumentDigest(collections.namedtuple('DocumentDigest', ['flavor', 'algorithm', 'digest'])):
  """
  Digest of a consensus document.

  .. versionadded:: 1.8.0

  :var str flavor: consensus type this digest is for (for example, 'microdesc')
  :var str algorithm: hash algorithm used to make the digest
  :var str digest: digest value of the consensus
  """


def _parse_file(document_file, document_type = None, validate = False, is_microdescriptor = False, document_handler = DocumentHandler.ENTRIES, **kwargs):
  """
  Parses a network status and iterates over the RouterStatusEntry in it. The
  document that these instances reference have an empty 'routers' attribute to
  allow for limited memory usage.

  :param file document_file: file with network status document content
  :param class document_type: NetworkStatusDocument subclass
  :param bool validate: checks the validity of the document's contents if
    **True**, skips these checks otherwise
  :param bool is_microdescriptor: **True** if this is for a microdescriptor
    consensus, **False** otherwise
  :param stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: :class:`stem.descriptor.networkstatus.NetworkStatusDocument` object

  :raises:
    * **ValueError** if the document_version is unrecognized or the contents is
      malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  # we can't properly default this since NetworkStatusDocumentV3 isn't defined yet

  if document_type is None:
    document_type = NetworkStatusDocumentV3

  if document_type == NetworkStatusDocumentV2:
    document_type, router_type = NetworkStatusDocumentV2, RouterStatusEntryV2
  elif document_type == NetworkStatusDocumentV3:
    router_type = RouterStatusEntryMicroV3 if is_microdescriptor else RouterStatusEntryV3
  elif document_type == BridgeNetworkStatusDocument:
    document_type, router_type = BridgeNetworkStatusDocument, RouterStatusEntryBridgeV2
  elif document_type == DetachedSignature:
    yield document_type(document_file.read(), validate, **kwargs)
    return
  else:
    raise ValueError("Document type %i isn't recognized (only able to parse v2, v3, and bridge)" % document_type)

  if document_handler == DocumentHandler.DOCUMENT:
    yield document_type(document_file.read(), validate, **kwargs)
    return

  # getting the document without the routers section

  header = _read_until_keywords((ROUTERS_START, FOOTER_START, V2_FOOTER_START), document_file)

  if header and header[0].startswith(b'@type'):
    header = header[1:]

  routers_start = document_file.tell()
  _read_until_keywords((FOOTER_START, V2_FOOTER_START), document_file, skip = True)
  routers_end = document_file.tell()

  footer = document_file.readlines()
  document_content = bytes.join(b'', header + footer)

  if document_handler == DocumentHandler.BARE_DOCUMENT:
    yield document_type(document_content, validate, **kwargs)
  elif document_handler == DocumentHandler.ENTRIES:
    desc_iterator = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = router_type,
      entry_keyword = ROUTERS_START,
      start_position = routers_start,
      end_position = routers_end,
      extra_args = (document_type(document_content, validate),),
      **kwargs
    )

    for desc in desc_iterator:
      yield desc
  else:
    raise ValueError('Unrecognized document_handler: %s' % document_handler)


def _parse_file_key_certs(certificate_file, validate = False):
  """
  Parses a file containing one or more authority key certificates.

  :param file certificate_file: file with key certificates
  :param bool validate: checks the validity of the certificate's contents if
    **True**, skips these checks otherwise

  :returns: iterator for :class:`stem.descriptor.networkstatus.KeyCertificate`
    instances in the file

  :raises:
    * **ValueError** if the key certificates are invalid and validate is **True**
    * **IOError** if the file can't be read
  """

  while True:
    keycert_content = _read_until_keywords('dir-key-certification', certificate_file)

    # we've reached the 'router-signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    keycert_content += _read_until_keywords(block_end_prefix, certificate_file, True)

    if keycert_content:
      yield stem.descriptor.networkstatus.KeyCertificate(bytes.join(b'', keycert_content), validate = validate)
    else:
      break  # done parsing file


def _parse_file_detached_sigs(detached_signature_file, validate = False):
  """
  Parses a file containing one or more detached signatures.

  :param file detached_signature_file: file with detached signatures
  :param bool validate: checks the validity of the detached signature's
    contents if **True**, skips these checks otherwise

  :returns: iterator for :class:`stem.descriptor.networkstatus.DetachedSignature`
    instances in the file

  :raises:
    * **ValueError** if the detached signatures are invalid and validate is **True**
    * **IOError** if the file can't be read
  """

  while True:
    detached_sig_content = _read_until_keywords('consensus-digest', detached_signature_file, ignore_first = True)

    if detached_sig_content:
      yield stem.descriptor.networkstatus.DetachedSignature(bytes.join(b'', detached_sig_content), validate = validate)
    else:
      break  # done parsing file


class NetworkStatusDocument(Descriptor):
  """
  Common parent for network status documents.
  """

  def digest(self, hash_type = DigestHash.SHA1, encoding = DigestEncoding.HEX):
    """
    Digest of this descriptor's content. These are referenced by...

      * **DetachedSignature**

        * Referer: :class:`~stem.descriptor.networkstatus.DetachedSignature` **consensus_digest** attribute
        * Format: **SHA1/HEX**

    .. versionadded:: 1.8.0

    :param stem.descriptor.DigestHash hash_type: digest hashing algorithm
    :param stem.descriptor.DigestEncoding encoding: digest encoding

    :returns: **hashlib.HASH** or **str** based on our encoding argument
    """

    content = self._content_range(end = '\ndirectory-signature ')

    if hash_type == DigestHash.SHA1:
      return stem.descriptor._encode_digest(hashlib.sha1(content), encoding)
    elif hash_type == DigestHash.SHA256:
      return stem.descriptor._encode_digest(hashlib.sha256(content), encoding)
    else:
      raise NotImplementedError('Network status document digests are only available in sha1 and sha256, not %s' % hash_type)


def _parse_version_line(keyword, attribute, expected_version):
  def _parse(descriptor, entries):
    value = _value(keyword, entries)

    if not value.isdigit():
      raise ValueError('Document has a non-numeric version: %s %s' % (keyword, value))

    setattr(descriptor, attribute, int(value))

    if int(value) != expected_version:
      raise ValueError("Expected a version %i document, but got version '%s' instead" % (expected_version, value))

  return _parse


def _parse_dir_source_line(descriptor, entries):
  value = _value('dir-source', entries)
  dir_source_comp = value.split()

  if len(dir_source_comp) < 3:
    raise ValueError("The 'dir-source' line of a v2 network status document must have three values: dir-source %s" % value)

  if not dir_source_comp[0]:
    # https://trac.torproject.org/7055
    raise ValueError("Authority's hostname can't be blank: dir-source %s" % value)
  elif not stem.util.connection.is_valid_ipv4_address(dir_source_comp[1]):
    raise ValueError("Authority's address isn't a valid IPv4 address: %s" % dir_source_comp[1])
  elif not stem.util.connection.is_valid_port(dir_source_comp[2], allow_zero = True):
    raise ValueError("Authority's DirPort is invalid: %s" % dir_source_comp[2])

  descriptor.hostname = dir_source_comp[0]
  descriptor.address = dir_source_comp[1]
  descriptor.dir_port = None if dir_source_comp[2] == '0' else int(dir_source_comp[2])


def _parse_additional_digests(descriptor, entries):
  digests = []

  for val in _values('additional-digest', entries):
    comp = val.split(' ')

    if len(comp) < 3:
      raise ValueError("additional-digest lines should be of the form 'additional-digest [flavor] [algname] [digest]' but was: %s" % val)

    digests.append(DocumentDigest(*comp[:3]))

  descriptor.additional_digests = digests


def _parse_additional_signatures(descriptor, entries):
  signatures = []

  for val, block_type, block_contents in entries['additional-signature']:
    comp = val.split(' ')

    if len(comp) < 4:
      raise ValueError("additional-signature lines should be of the form 'additional-signature [flavor] [algname] [identity] [signing_key_digest]' but was: %s" % val)
    elif not block_contents or block_type != 'SIGNATURE':
      raise ValueError("'additional-signature' should be followed by a SIGNATURE block, but was a %s" % block_type)

    signatures.append(DocumentSignature(comp[1], comp[2], comp[3], block_contents, flavor = comp[0], validate = True))

  descriptor.additional_signatures = signatures


_parse_network_status_version_line = _parse_version_line('network-status-version', 'version', 2)
_parse_fingerprint_line = _parse_forty_character_hex('fingerprint', 'fingerprint')
_parse_contact_line = _parse_simple_line('contact', 'contact')
_parse_dir_signing_key_line = _parse_key_block('dir-signing-key', 'signing_key', 'RSA PUBLIC KEY')
_parse_client_versions_line = _parse_simple_line('client-versions', 'client_versions', func = lambda v: v.split(','))
_parse_server_versions_line = _parse_simple_line('server-versions', 'server_versions', func = lambda v: v.split(','))
_parse_published_line = _parse_timestamp_line('published', 'published')
_parse_dir_options_line = _parse_simple_line('dir-options', 'options', func = lambda v: v.split())
_parse_directory_signature_line = _parse_key_block('directory-signature', 'signature', 'SIGNATURE', value_attribute = 'signing_authority')
_parse_consensus_digest_line = _parse_simple_line('consensus-digest', 'consensus_digest')


class NetworkStatusDocumentV2(NetworkStatusDocument):
  """
  Version 2 network status document. These have been deprecated and are no
  longer generated by Tor.

  :var dict routers: fingerprints to :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV2`
    contained in the document

  :var int version: **\\*** document version

  :var str hostname: **\\*** hostname of the authority
  :var str address: **\\*** authority's IP address
  :var int dir_port: **\\*** authority's DirPort
  :var str fingerprint: **\\*** authority's fingerprint
  :var str contact: **\\*** authority's contact information
  :var str signing_key: **\\*** authority's public signing key

  :var list client_versions: list of recommended client tor version strings
  :var list server_versions: list of recommended server tor version strings
  :var datetime published: **\\*** time when the document was published
  :var list options: **\\*** list of things that this authority decides

  :var str signing_authority: **\\*** name of the authority signing the document
  :var str signature: **\\*** authority's signature for the document

  **\\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  TYPE_ANNOTATION_NAME = 'network-status-2'

  ATTRIBUTES = {
    'version': (None, _parse_network_status_version_line),
    'hostname': (None, _parse_dir_source_line),
    'address': (None, _parse_dir_source_line),
    'dir_port': (None, _parse_dir_source_line),
    'fingerprint': (None, _parse_fingerprint_line),
    'contact': (None, _parse_contact_line),
    'signing_key': (None, _parse_dir_signing_key_line),

    'client_versions': ([], _parse_client_versions_line),
    'server_versions': ([], _parse_server_versions_line),
    'published': (None, _parse_published_line),
    'options': ([], _parse_dir_options_line),

    'signing_authority': (None, _parse_directory_signature_line),
    'signatures': (None, _parse_directory_signature_line),
  }

  PARSER_FOR_LINE = {
    'network-status-version': _parse_network_status_version_line,
    'dir-source': _parse_dir_source_line,
    'fingerprint': _parse_fingerprint_line,
    'contact': _parse_contact_line,
    'dir-signing-key': _parse_dir_signing_key_line,
    'client-versions': _parse_client_versions_line,
    'server-versions': _parse_server_versions_line,
    'published': _parse_published_line,
    'dir-options': _parse_dir_options_line,
    'directory-signature': _parse_directory_signature_line,
  }

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False):
    if sign:
      raise NotImplementedError('Signing of %s not implemented' % cls.__name__)

    return _descriptor_content(attr, exclude, (
      ('network-status-version', '2'),
      ('dir-source', '%s %s 80' % (_random_ipv4_address(), _random_ipv4_address())),
      ('fingerprint', _random_fingerprint()),
      ('contact', 'arma at mit dot edu'),
      ('published', _random_date()),
      ('dir-signing-key', _random_crypto_blob('RSA PUBLIC KEY')),
    ), (
      ('directory-signature', 'moria2' + _random_crypto_blob('SIGNATURE')),
    ))

  def __init__(self, raw_content, validate = False):
    super(NetworkStatusDocumentV2, self).__init__(raw_content, lazy_load = not validate)

    # Splitting the document from the routers. Unlike v3 documents we're not
    # bending over backwards on the validation by checking the field order or
    # that header/footer attributes aren't in the wrong section. This is a
    # deprecated descriptor type - patches welcome if you want those checks.

    document_file = io.BytesIO(raw_content)
    document_content = bytes.join(b'', _read_until_keywords((ROUTERS_START, V2_FOOTER_START), document_file))

    router_iter = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = RouterStatusEntryV2,
      entry_keyword = ROUTERS_START,
      section_end_keywords = (V2_FOOTER_START,),
      extra_args = (self,),
    )

    self.routers = dict((desc.fingerprint, desc) for desc in router_iter)

    entries = _descriptor_components(document_content + b'\n' + document_file.read(), validate)

    if validate:
      self._check_constraints(entries)
      self._parse(entries, validate)

      # 'client-versions' and 'server-versions' are only required if 'Versions'
      # is among the options

      if 'Versions' in self.options and not ('client-versions' in entries and 'server-versions' in entries):
        raise ValueError("Version 2 network status documents must have a 'client-versions' and 'server-versions' when 'Versions' is listed among its dir-options:\n%s" % str(self))
    else:
      self._entries = entries

  def _check_constraints(self, entries):
    required_fields = [field for (field, is_mandatory) in NETWORK_STATUS_V2_FIELDS if is_mandatory]
    for keyword in required_fields:
      if keyword not in entries:
        raise ValueError("Network status document (v2) must have a '%s' line:\n%s" % (keyword, str(self)))

    # all recognized fields can only appear once
    single_fields = [field for (field, _) in NETWORK_STATUS_V2_FIELDS]
    for keyword in single_fields:
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("Network status document (v2) can only have a single '%s' line, got %i:\n%s" % (keyword, len(entries[keyword]), str(self)))

    if 'network-status-version' != list(entries.keys())[0]:
      raise ValueError("Network status document (v2) are expected to start with a 'network-status-version' line:\n%s" % str(self))


def _parse_header_network_status_version_line(descriptor, entries):
  # "network-status-version" version

  value = _value('network-status-version', entries)

  if ' ' in value:
    version, flavor = value.split(' ', 1)
  else:
    version, flavor = value, 'ns'

  if not version.isdigit():
    raise ValueError('Network status document has a non-numeric version: network-status-version %s' % value)

  descriptor.version = int(version)
  descriptor.version_flavor = flavor
  descriptor.is_microdescriptor = flavor == 'microdesc'

  if descriptor.version != 3:
    raise ValueError("Expected a version 3 network status document, got version '%s' instead" % descriptor.version)


def _parse_header_vote_status_line(descriptor, entries):
  # "vote-status" type
  #
  # The consensus-method and consensus-methods fields are optional since
  # they weren't included in version 1. Setting a default now that we
  # know if we're a vote or not.

  value = _value('vote-status', entries)

  if value == 'consensus':
    descriptor.is_consensus, descriptor.is_vote = True, False
  elif value == 'vote':
    descriptor.is_consensus, descriptor.is_vote = False, True
  else:
    raise ValueError("A network status document's vote-status line can only be 'consensus' or 'vote', got '%s' instead" % value)


def _parse_header_consensus_methods_line(descriptor, entries):
  # "consensus-methods" IntegerList

  if descriptor._lazy_loading and descriptor.is_vote:
    descriptor.consensus_methods = [1]

  value, consensus_methods = _value('consensus-methods', entries), []

  for entry in value.split(' '):
    if not entry.isdigit():
      raise ValueError("A network status document's consensus-methods must be a list of integer values, but was '%s'" % value)

    consensus_methods.append(int(entry))

  descriptor.consensus_methods = consensus_methods


def _parse_header_consensus_method_line(descriptor, entries):
  # "consensus-method" Integer

  if descriptor._lazy_loading and descriptor.is_consensus:
    descriptor.consensus_method = 1

  value = _value('consensus-method', entries)

  if not value.isdigit():
    raise ValueError("A network status document's consensus-method must be an integer, but was '%s'" % value)

  descriptor.consensus_method = int(value)


def _parse_header_voting_delay_line(descriptor, entries):
  # "voting-delay" VoteSeconds DistSeconds

  value = _value('voting-delay', entries)
  value_comp = value.split(' ')

  if len(value_comp) == 2 and value_comp[0].isdigit() and value_comp[1].isdigit():
    descriptor.vote_delay = int(value_comp[0])
    descriptor.dist_delay = int(value_comp[1])
  else:
    raise ValueError("A network status document's 'voting-delay' line must be a pair of integer values, but was '%s'" % value)


def _parse_versions_line(keyword, attribute):
  def _parse(descriptor, entries):
    value, entries = _value(keyword, entries), []

    for entry in value.split(','):
      try:
        entries.append(stem.version._get_version(entry))
      except ValueError:
        raise ValueError("Network status document's '%s' line had '%s', which isn't a parsable tor version: %s %s" % (keyword, entry, keyword, value))

    setattr(descriptor, attribute, entries)

  return _parse


def _parse_header_flag_thresholds_line(descriptor, entries):
  # "flag-thresholds" SP THRESHOLDS

  value, thresholds = _value('flag-thresholds', entries).strip(), {}

  for key, val in _mappings_for('flag-thresholds', value):
    try:
      if val.endswith('%'):
        # opting for string manipulation rather than just
        # 'float(entry_value) / 100' because floating point arithmetic
        # will lose precision

        thresholds[key] = float('0.' + val[:-1].replace('.', '', 1))
      elif '.' in val:
        thresholds[key] = float(val)
      else:
        thresholds[key] = int(val)
    except ValueError:
      raise ValueError("Network status document's 'flag-thresholds' line is expected to have float values, got: flag-thresholds %s" % value)

  descriptor.flag_thresholds = thresholds


def _parse_header_parameters_line(descriptor, entries):
  # "params" [Parameters]
  # Parameter ::= Keyword '=' Int32
  # Int32 ::= A decimal integer between -2147483648 and 2147483647.
  # Parameters ::= Parameter | Parameters SP Parameter

  if descriptor._lazy_loading:
    descriptor.params = dict(DEFAULT_PARAMS) if descriptor._default_params else {}

  value = _value('params', entries)

  if value != '':
    descriptor.params = _parse_int_mappings('params', value, True)
    descriptor._check_params_constraints()


def _parse_directory_footer_line(descriptor, entries):
  # nothing to parse, simply checking that we don't have a value

  value = _value('directory-footer', entries)

  if value:
    raise ValueError("A network status document's 'directory-footer' line shouldn't have any content, got 'directory-footer %s'" % value)


def _parse_footer_directory_signature_line(descriptor, entries):
  signatures = []

  for sig_value, block_type, block_contents in entries['directory-signature']:
    if sig_value.count(' ') not in (1, 2):
      raise ValueError("Authority signatures in a network status document are expected to be of the form 'directory-signature [METHOD] FINGERPRINT KEY_DIGEST', received: %s" % sig_value)

    if not block_contents or block_type != 'SIGNATURE':
      raise ValueError("'directory-signature' should be followed by a SIGNATURE block, but was a %s" % block_type)

    if sig_value.count(' ') == 1:
      method = 'sha1'  # default if none was provided
      fingerprint, key_digest = sig_value.split(' ', 1)
    else:
      method, fingerprint, key_digest = sig_value.split(' ', 2)

    signatures.append(DocumentSignature(method, fingerprint, key_digest, block_contents, validate = True))

  descriptor.signatures = signatures


def _parse_package_line(descriptor, entries):
  package_versions = []

  for value, _, _ in entries['package']:
    value_comp = value.split(' ', 3)

    if len(value_comp) < 3:
      raise ValueError("'package' must at least have a 'PackageName Version URL': %s" % value)

    name, version, url = value_comp[:3]
    digests = {}

    if len(value_comp) == 4:
      for key, val in _mappings_for('package', value_comp[3]):
        digests[key] = val

    package_versions.append(PackageVersion(name, version, url, digests))

  descriptor.packages = package_versions


def _parsed_shared_rand_commit(descriptor, entries):
  # "shared-rand-commit" Version AlgName Identity Commit [Reveal]

  commitments = []

  for value, _, _ in entries['shared-rand-commit']:
    value_comp = value.split()

    if len(value_comp) < 4:
      raise ValueError("'shared-rand-commit' must at least have a 'Version AlgName Identity Commit': %s" % value)

    version, algorithm, identity, commit = value_comp[:4]
    reveal = value_comp[4] if len(value_comp) >= 5 else None

    if not version.isdigit():
      raise ValueError("The version on our 'shared-rand-commit' line wasn't an integer: %s" % value)

    commitments.append(SharedRandomnessCommitment(int(version), algorithm, identity, commit, reveal))

  descriptor.shared_randomness_commitments = commitments


def _parse_shared_rand_previous_value(descriptor, entries):
  # "shared-rand-previous-value" NumReveals Value

  value = _value('shared-rand-previous-value', entries)
  value_comp = value.split(' ')

  if len(value_comp) == 2 and value_comp[0].isdigit():
    descriptor.shared_randomness_previous_reveal_count = int(value_comp[0])
    descriptor.shared_randomness_previous_value = value_comp[1]
  else:
    raise ValueError("A network status document's 'shared-rand-previous-value' line must be a pair of values, the first an integer but was '%s'" % value)


def _parse_shared_rand_current_value(descriptor, entries):
  # "shared-rand-current-value" NumReveals Value

  value = _value('shared-rand-current-value', entries)
  value_comp = value.split(' ')

  if len(value_comp) == 2 and value_comp[0].isdigit():
    descriptor.shared_randomness_current_reveal_count = int(value_comp[0])
    descriptor.shared_randomness_current_value = value_comp[1]
  else:
    raise ValueError("A network status document's 'shared-rand-current-value' line must be a pair of values, the first an integer but was '%s'" % value)


def _parse_bandwidth_file_headers(descriptor, entries):
  # "bandwidth-file-headers" KeyValues
  # KeyValues ::= "" | KeyValue | KeyValues SP KeyValue
  # KeyValue ::= Keyword '=' Value
  # Value ::= ArgumentChar+

  value = _value('bandwidth-file-headers', entries)
  results = {}

  for key, val in _mappings_for('bandwidth-file-headers', value):
    results[key] = val

  descriptor.bandwidth_file_headers = results


def _parse_bandwidth_file_digest(descriptor, entries):
  # "bandwidth-file-digest" 1*(SP algorithm "=" digest)

  value = _value('bandwidth-file-digest', entries)
  results = {}

  for key, val in _mappings_for('bandwidth-file-digest', value):
    results[key] = val

  descriptor.bandwidth_file_digest = results


_parse_header_valid_after_line = _parse_timestamp_line('valid-after', 'valid_after')
_parse_header_fresh_until_line = _parse_timestamp_line('fresh-until', 'fresh_until')
_parse_header_valid_until_line = _parse_timestamp_line('valid-until', 'valid_until')
_parse_header_client_versions_line = _parse_versions_line('client-versions', 'client_versions')
_parse_header_server_versions_line = _parse_versions_line('server-versions', 'server_versions')
_parse_header_known_flags_line = _parse_simple_line('known-flags', 'known_flags', func = lambda v: [entry for entry in v.split(' ') if entry])
_parse_footer_bandwidth_weights_line = _parse_simple_line('bandwidth-weights', 'bandwidth_weights', func = lambda v: _parse_int_mappings('bandwidth-weights', v, True))
_parse_shared_rand_participate_line = _parse_if_present('shared-rand-participate', 'is_shared_randomness_participate')
_parse_recommended_client_protocols_line = _parse_protocol_line('recommended-client-protocols', 'recommended_client_protocols')
_parse_recommended_relay_protocols_line = _parse_protocol_line('recommended-relay-protocols', 'recommended_relay_protocols')
_parse_required_client_protocols_line = _parse_protocol_line('required-client-protocols', 'required_client_protocols')
_parse_required_relay_protocols_line = _parse_protocol_line('required-relay-protocols', 'required_relay_protocols')


class NetworkStatusDocumentV3(NetworkStatusDocument):
  """
  Version 3 network status document. This could be either a vote or consensus.

  :var dict routers: fingerprint to :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`
    mapping for relays contained in the document

  :var int version: **\\*** document version
  :var str version_flavor: **\\*** flavor associated with the document (such as 'ns' or 'microdesc')
  :var bool is_consensus: **\\*** **True** if the document is a consensus
  :var bool is_vote: **\\*** **True** if the document is a vote
  :var bool is_microdescriptor: **\\*** **True** if this is a microdescriptor
    flavored document, **False** otherwise
  :var datetime valid_after: **\\*** time when the consensus became valid
  :var datetime fresh_until: **\\*** time when the next consensus should be produced
  :var datetime valid_until: **\\*** time when this consensus becomes obsolete
  :var int vote_delay: **\\*** number of seconds allowed for collecting votes
    from all authorities
  :var int dist_delay: **\\*** number of seconds allowed for collecting
    signatures from all authorities
  :var list client_versions: list of recommended client tor versions
  :var list server_versions: list of recommended server tor versions
  :var list packages: **\\*** list of :data:`~stem.descriptor.networkstatus.PackageVersion` entries
  :var list known_flags: **\\*** list of :data:`~stem.Flag` for the router's flags
  :var dict params: **\\*** dict of parameter(**str**) => value(**int**) mappings
  :var list directory_authorities: **\\*** list of :class:`~stem.descriptor.networkstatus.DirectoryAuthority`
    objects that have generated this document
  :var list signatures: **\\*** :class:`~stem.descriptor.networkstatus.DocumentSignature`
    of the authorities that have signed the document

  **Consensus Attributes:**

  :var int consensus_method: method version used to generate this consensus
  :var dict bandwidth_weights: dict of weight(str) => value(int) mappings

  :var int shared_randomness_current_reveal_count: number of commitments
    used to generate the current shared random value
  :var str shared_randomness_current_value: base64 encoded current shared
    random value

  :var int shared_randomness_previous_reveal_count: number of commitments
    used to generate the last shared random value
  :var str shared_randomness_previous_value: base64 encoded last shared random
    value

  **Vote Attributes:**

  :var list consensus_methods: list of ints for the supported method versions
  :var datetime published: time when the document was published
  :var dict flag_thresholds: **\\*** mapping of internal performance thresholds used while making the vote, values are **ints** or **floats**

  :var dict recommended_client_protocols: recommended protocols for clients
  :var dict recommended_relay_protocols: recommended protocols for relays
  :var dict required_client_protocols: required protocols for clients
  :var dict required_relay_protocols: required protocols for relays
  :var dict bandwidth_file_headers: headers from the bandwidth authority that
    generated this vote
  :var dict bandwidth_file_digest: hashes of the bandwidth authority file used
    to generate this vote, this is a mapping of hash functions to their resulting
    digest value

  **\\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as None if undefined

  .. versionchanged:: 1.4.0
     Added the packages attribute.

  .. versionchanged:: 1.5.0
     Added the is_shared_randomness_participate, shared_randomness_commitments,
     shared_randomness_previous_reveal_count,
     shared_randomness_previous_value,
     shared_randomness_current_reveal_count, and
     shared_randomness_current_value attributes.

  .. versionchanged:: 1.6.0
     Added the recommended_client_protocols, recommended_relay_protocols,
     required_client_protocols, and required_relay_protocols attributes.

  .. versionchanged:: 1.6.0
     The is_shared_randomness_participate and shared_randomness_commitments
     were misdocumented in the tor spec and as such never set. They're now an
     attribute of votes in the **directory_authorities**.

  .. versionchanged:: 1.7.0
     The shared_randomness_current_reveal_count and
     shared_randomness_previous_reveal_count attributes were undocumented and
     not provided properly if retrieved before their shred_randomness_*_value
     counterpart.

  .. versionchanged:: 1.7.0
     Added the bandwidth_file_headers attributbute.

  .. versionchanged:: 1.8.0
     Added the bandwidth_file_digest attributbute.
  """

  ATTRIBUTES = {
    'version': (None, _parse_header_network_status_version_line),
    'version_flavor': ('ns', _parse_header_network_status_version_line),
    'is_consensus': (True, _parse_header_vote_status_line),
    'is_vote': (False, _parse_header_vote_status_line),
    'is_microdescriptor': (False, _parse_header_network_status_version_line),
    'consensus_methods': ([], _parse_header_consensus_methods_line),
    'published': (None, _parse_published_line),
    'consensus_method': (None, _parse_header_consensus_method_line),
    'valid_after': (None, _parse_header_valid_after_line),
    'fresh_until': (None, _parse_header_fresh_until_line),
    'valid_until': (None, _parse_header_valid_until_line),
    'vote_delay': (None, _parse_header_voting_delay_line),
    'dist_delay': (None, _parse_header_voting_delay_line),
    'client_versions': ([], _parse_header_client_versions_line),
    'server_versions': ([], _parse_header_server_versions_line),
    'packages': ([], _parse_package_line),
    'known_flags': ([], _parse_header_known_flags_line),
    'flag_thresholds': ({}, _parse_header_flag_thresholds_line),
    'recommended_client_protocols': ({}, _parse_recommended_client_protocols_line),
    'recommended_relay_protocols': ({}, _parse_recommended_relay_protocols_line),
    'required_client_protocols': ({}, _parse_required_client_protocols_line),
    'required_relay_protocols': ({}, _parse_required_relay_protocols_line),
    'params': ({}, _parse_header_parameters_line),
    'shared_randomness_previous_reveal_count': (None, _parse_shared_rand_previous_value),
    'shared_randomness_previous_value': (None, _parse_shared_rand_previous_value),
    'shared_randomness_current_reveal_count': (None, _parse_shared_rand_current_value),
    'shared_randomness_current_value': (None, _parse_shared_rand_current_value),
    'bandwidth_file_headers': ({}, _parse_bandwidth_file_headers),
    'bandwidth_file_digest': ({}, _parse_bandwidth_file_digest),

    'signatures': ([], _parse_footer_directory_signature_line),
    'bandwidth_weights': ({}, _parse_footer_bandwidth_weights_line),
  }

  _HEADER_PARSER_FOR_LINE = {
    'network-status-version': _parse_header_network_status_version_line,
    'vote-status': _parse_header_vote_status_line,
    'consensus-methods': _parse_header_consensus_methods_line,
    'consensus-method': _parse_header_consensus_method_line,
    'published': _parse_published_line,
    'valid-after': _parse_header_valid_after_line,
    'fresh-until': _parse_header_fresh_until_line,
    'valid-until': _parse_header_valid_until_line,
    'voting-delay': _parse_header_voting_delay_line,
    'client-versions': _parse_header_client_versions_line,
    'server-versions': _parse_header_server_versions_line,
    'package': _parse_package_line,
    'known-flags': _parse_header_known_flags_line,
    'flag-thresholds': _parse_header_flag_thresholds_line,
    'recommended-client-protocols': _parse_recommended_client_protocols_line,
    'recommended-relay-protocols': _parse_recommended_relay_protocols_line,
    'required-client-protocols': _parse_required_client_protocols_line,
    'required-relay-protocols': _parse_required_relay_protocols_line,
    'params': _parse_header_parameters_line,
    'shared-rand-previous-value': _parse_shared_rand_previous_value,
    'shared-rand-current-value': _parse_shared_rand_current_value,
    'bandwidth-file-headers': _parse_bandwidth_file_headers,
    'bandwidth-file-digest': _parse_bandwidth_file_digest,
  }

  _FOOTER_PARSER_FOR_LINE = {
    'directory-footer': _parse_directory_footer_line,
    'bandwidth-weights': _parse_footer_bandwidth_weights_line,
    'directory-signature': _parse_footer_directory_signature_line,
  }

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False, authorities = None, routers = None):
    if sign:
      raise NotImplementedError('Signing of %s not implemented' % cls.__name__)

    attr = {} if attr is None else dict(attr)
    is_vote = attr.get('vote-status') == 'vote'

    if is_vote:
      extra_defaults = {'consensus-methods': '1 9', 'published': _random_date()}
    else:
      extra_defaults = {'consensus-method': '9'}

    if is_vote and authorities is None:
      authorities = [DirectoryAuthority.create(is_vote = is_vote)]

    for k, v in extra_defaults.items():
      if exclude and k in exclude:
        continue  # explicitly excluding this field
      elif k not in attr:
        attr[k] = v

    desc_content = _descriptor_content(attr, exclude, (
      ('network-status-version', '3'),
      ('vote-status', 'consensus'),
      ('consensus-methods', None),
      ('consensus-method', None),
      ('published', None),
      ('valid-after', _random_date()),
      ('fresh-until', _random_date()),
      ('valid-until', _random_date()),
      ('voting-delay', '300 300'),
      ('client-versions', None),
      ('server-versions', None),
      ('package', None),
      ('known-flags', 'Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid'),
      ('params', None),
    ), (
      ('directory-footer', ''),
      ('bandwidth-weights', None),
      ('directory-signature', '%s %s%s' % (_random_fingerprint(), _random_fingerprint(), _random_crypto_blob('SIGNATURE'))),
    ))

    # inject the authorities and/or routers between the header and footer

    if authorities:
      if b'directory-footer' in desc_content:
        footer_div = desc_content.find(b'\ndirectory-footer') + 1
      elif b'directory-signature' in desc_content:
        footer_div = desc_content.find(b'\ndirectory-signature') + 1
      else:
        if routers:
          desc_content += b'\n'

        footer_div = len(desc_content) + 1

      authority_content = stem.util.str_tools._to_bytes('\n'.join([str(a) for a in authorities]) + '\n')
      desc_content = desc_content[:footer_div] + authority_content + desc_content[footer_div:]

    if routers:
      if b'directory-footer' in desc_content:
        footer_div = desc_content.find(b'\ndirectory-footer') + 1
      elif b'directory-signature' in desc_content:
        footer_div = desc_content.find(b'\ndirectory-signature') + 1
      else:
        if routers:
          desc_content += b'\n'

        footer_div = len(desc_content) + 1

      router_content = stem.util.str_tools._to_bytes('\n'.join([str(r) for r in routers]) + '\n')
      desc_content = desc_content[:footer_div] + router_content + desc_content[footer_div:]

    return desc_content

  @classmethod
  def create(cls, attr = None, exclude = (), validate = True, sign = False, authorities = None, routers = None):
    return cls(cls.content(attr, exclude, sign, authorities, routers), validate = validate)

  def __init__(self, raw_content, validate = False, default_params = True):
    """
    Parse a v3 network status document.

    :param str raw_content: raw network status document data
    :param bool validate: **True** if the document is to be validated, **False** otherwise
    :param bool default_params: includes defaults in our params dict, otherwise
      it just contains values from the document

    :raises: **ValueError** if the document is invalid
    """

    super(NetworkStatusDocumentV3, self).__init__(raw_content, lazy_load = not validate)
    document_file = io.BytesIO(raw_content)

    # TODO: Tor misdocumented these as being in the header rather than the
    # authority section. As such these have never been set but we need the
    # attributes for stem 1.5 compatability. Drop these in 2.0.

    self.is_shared_randomness_participate = False
    self.shared_randomness_commitments = []

    self._default_params = default_params
    self._header(document_file, validate)

    self.directory_authorities = tuple(stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = DirectoryAuthority,
      entry_keyword = AUTH_START,
      section_end_keywords = (ROUTERS_START, FOOTER_START, V2_FOOTER_START),
      extra_args = (self.is_vote,),
    ))

    if validate and self.is_vote and len(self.directory_authorities) != 1:
      raise ValueError('Votes should only have an authority entry for the one that issued it, got %i: %s' % (len(self.directory_authorities), self.directory_authorities))

    router_iter = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = RouterStatusEntryMicroV3 if self.is_microdescriptor else RouterStatusEntryV3,
      entry_keyword = ROUTERS_START,
      section_end_keywords = (FOOTER_START, V2_FOOTER_START),
      extra_args = (self,),
    )

    self.routers = dict((desc.fingerprint, desc) for desc in router_iter)
    self._footer(document_file, validate)

  def type_annotation(self):
    if isinstance(self, BridgeNetworkStatusDocument):
      return TypeAnnotation('bridge-network-status', 1, 0)
    elif not self.is_microdescriptor:
      return TypeAnnotation('network-status-consensus-3' if not self.is_vote else 'network-status-vote-3', 1, 0)
    else:
      # Directory authorities do not issue a 'microdescriptor consensus' vote,
      # so unlike the above there isn't a 'network-status-microdesc-vote-3'
      # counterpart here.

      return TypeAnnotation('network-status-microdesc-consensus-3', 1, 0)

  def is_valid(self):
    """
    Checks if the current time is between this document's **valid_after** and
    **valid_until** timestamps. To be valid means the information within this
    document reflects the current network state.

    .. versionadded:: 1.8.0

    :returns: **True** if this consensus is presently valid and **False**
      otherwise
    """

    return self.valid_after < datetime.datetime.utcnow() < self.valid_until

  def is_fresh(self):
    """
    Checks if the current time is between this document's **valid_after** and
    **fresh_until** timestamps. To be fresh means this should be the latest
    consensus.

    .. versionadded:: 1.8.0

    :returns: **True** if this consensus is presently fresh and **False**
      otherwise
    """

    return self.valid_after < datetime.datetime.utcnow() < self.fresh_until

  def validate_signatures(self, key_certs):
    """
    Validates we're properly signed by the signing certificates.

    .. versionadded:: 1.6.0

    :param list key_certs: :class:`~stem.descriptor.networkstatus.KeyCertificates`
      to validate the consensus against

    :raises: **ValueError** if an insufficient number of valid signatures are present.
    """

    # sha1 hash of the body and header

    digest_content = self._content_range('network-status-version', 'directory-signature ')
    local_digest = hashlib.sha1(digest_content).hexdigest().upper()

    valid_digests, total_digests = 0, 0
    required_digests = len(self.signatures) / 2.0
    signing_keys = dict([(cert.fingerprint, cert.signing_key) for cert in key_certs])

    for sig in self.signatures:
      if sig.identity not in signing_keys:
        continue

      signed_digest = self._digest_for_signature(signing_keys[sig.identity], sig.signature)
      total_digests += 1

      if signed_digest == local_digest:
        valid_digests += 1

    if valid_digests < required_digests:
      raise ValueError('Network Status Document has %i valid signatures out of %i total, needed %i' % (valid_digests, total_digests, required_digests))

  def get_unrecognized_lines(self):
    if self._lazy_loading:
      self._parse(self._header_entries, False, parser_for_line = self._HEADER_PARSER_FOR_LINE)
      self._parse(self._footer_entries, False, parser_for_line = self._FOOTER_PARSER_FOR_LINE)
      self._lazy_loading = False

    return super(NetworkStatusDocumentV3, self).get_unrecognized_lines()

  def meets_consensus_method(self, method):
    """
    Checks if we meet the given consensus-method. This works for both votes and
    consensuses, checking our 'consensus-method' and 'consensus-methods'
    entries.

    :param int method: consensus-method to check for

    :returns: **True** if we meet the given consensus-method, and **False** otherwise
    """

    if self.consensus_method is not None:
      return self.consensus_method >= method
    elif self.consensus_methods is not None:
      return bool([x for x in self.consensus_methods if x >= method])
    else:
      return False  # malformed document

  def _header(self, document_file, validate):
    content = bytes.join(b'', _read_until_keywords((AUTH_START, ROUTERS_START, FOOTER_START), document_file))
    entries = _descriptor_components(content, validate)
    header_fields = [attr[0] for attr in HEADER_STATUS_DOCUMENT_FIELDS]

    if validate:
      # all known header fields can only appear once except

      for keyword, values in list(entries.items()):
        if len(values) > 1 and keyword in header_fields and keyword != 'package' and keyword != 'shared-rand-commit':
          raise ValueError("Network status documents can only have a single '%s' line, got %i" % (keyword, len(values)))

      if self._default_params:
        self.params = dict(DEFAULT_PARAMS)

      self._parse(entries, validate, parser_for_line = self._HEADER_PARSER_FOR_LINE)

      # should only appear in consensus-method 7 or later

      if not self.meets_consensus_method(7) and 'params' in list(entries.keys()):
        raise ValueError("A network status document's 'params' line should only appear in consensus-method 7 or later")

      _check_for_missing_and_disallowed_fields(self, entries, HEADER_STATUS_DOCUMENT_FIELDS)

      # default consensus_method and consensus_methods based on if we're a consensus or vote

      if self.is_consensus and not self.consensus_method:
        self.consensus_method = 1
      elif self.is_vote and not self.consensus_methods:
        self.consensus_methods = [1]
    else:
      self._header_entries = entries
      self._entries.update(entries)

  def _footer(self, document_file, validate):
    entries = _descriptor_components(document_file.read(), validate)
    footer_fields = [attr[0] for attr in FOOTER_STATUS_DOCUMENT_FIELDS]

    if validate:
      for keyword, values in list(entries.items()):
        # all known footer fields can only appear once except...
        # * 'directory-signature' in a consensus

        if len(values) > 1 and keyword in footer_fields:
          if not (keyword == 'directory-signature' and self.is_consensus):
            raise ValueError("Network status documents can only have a single '%s' line, got %i" % (keyword, len(values)))

      self._parse(entries, validate, parser_for_line = self._FOOTER_PARSER_FOR_LINE)

      # Check that the footer has the right initial line. Prior to consensus
      # method 9 it's a 'directory-signature' and after that footers start with
      # 'directory-footer'.

      if entries:
        if self.meets_consensus_method(9):
          if list(entries.keys())[0] != 'directory-footer':
            raise ValueError("Network status document's footer should start with a 'directory-footer' line in consensus-method 9 or later")
        else:
          if list(entries.keys())[0] != 'directory-signature':
            raise ValueError("Network status document's footer should start with a 'directory-signature' line prior to consensus-method 9")

        _check_for_missing_and_disallowed_fields(self, entries, FOOTER_STATUS_DOCUMENT_FIELDS)
    else:
      self._footer_entries = entries
      self._entries.update(entries)

  def _check_params_constraints(self):
    """
    Checks that the params we know about are within their documented ranges.
    """

    for key, value in self.params.items():
      minimum, maximum = PARAM_RANGE.get(key, (MIN_PARAM, MAX_PARAM))

      # there's a few dynamic parameter ranges

      if key == 'cbtclosequantile':
        minimum = self.params.get('cbtquantile', minimum)
      elif key == 'cbtinitialtimeout':
        minimum = self.params.get('cbtmintimeout', minimum)

      if value < minimum or value > maximum:
        raise ValueError("'%s' value on the params line must be in the range of %i - %i, was %i" % (key, minimum, maximum, value))


def _check_for_missing_and_disallowed_fields(document, entries, fields):
  """
  Checks that we have mandatory fields for our type, and that we don't have
  any fields exclusive to the other (ie, no vote-only fields appear in a
  consensus or vice versa).

  :param NetworkStatusDocumentV3 document: network status document
  :param dict entries: ordered keyword/value mappings of the header or footer
  :param list fields: expected field attributes (either
    **HEADER_STATUS_DOCUMENT_FIELDS** or **FOOTER_STATUS_DOCUMENT_FIELDS**)

  :raises: **ValueError** if we're missing mandatory fields or have fields we shouldn't
  """

  missing_fields, disallowed_fields = [], []

  for field, in_votes, in_consensus, mandatory in fields:
    if mandatory and ((document.is_consensus and in_consensus) or (document.is_vote and in_votes)):
      # mandatory field, check that we have it
      if field not in entries.keys():
        missing_fields.append(field)
    elif (document.is_consensus and not in_consensus) or (document.is_vote and not in_votes):
      # field we shouldn't have, check that we don't
      if field in entries.keys():
        disallowed_fields.append(field)

  if missing_fields:
    raise ValueError('Network status document is missing mandatory field: %s' % ', '.join(missing_fields))

  if disallowed_fields:
    raise ValueError("Network status document has fields that shouldn't appear in this document type or version: %s" % ', '.join(disallowed_fields))


def _parse_int_mappings(keyword, value, validate):
  # Parse a series of 'key=value' entries, checking the following:
  # - values are integers
  # - keys are sorted in lexical order

  results, seen_keys = {}, []
  error_template = "Unable to parse network status document's '%s' line (%%s): %s'" % (keyword, value)

  for key, val in _mappings_for(keyword, value):
    if validate:
      # parameters should be in ascending order by their key
      for prior_key in seen_keys:
        if prior_key > key:
          raise ValueError(error_template % 'parameters must be sorted by their key')

    try:
      # the int() function accepts things like '+123', but we don't want to

      if val.startswith('+'):
        raise ValueError()

      results[key] = int(val)
    except ValueError:
      raise ValueError(error_template % ("'%s' is a non-numeric value" % val))

    seen_keys.append(key)

  return results


def _parse_dirauth_source_line(descriptor, entries):
  # "dir-source" nickname identity address IP dirport orport

  value = _value('dir-source', entries)
  dir_source_comp = value.split(' ')

  if len(dir_source_comp) < 6:
    raise ValueError("Authority entry's 'dir-source' line must have six values: dir-source %s" % value)

  if not stem.util.tor_tools.is_valid_nickname(dir_source_comp[0].rstrip('-legacy')):
    raise ValueError("Authority's nickname is invalid: %s" % dir_source_comp[0])
  elif not stem.util.tor_tools.is_valid_fingerprint(dir_source_comp[1]):
    raise ValueError("Authority's v3ident is invalid: %s" % dir_source_comp[1])
  elif not dir_source_comp[2]:
    # https://trac.torproject.org/7055
    raise ValueError("Authority's hostname can't be blank: dir-source %s" % value)
  elif not stem.util.connection.is_valid_ipv4_address(dir_source_comp[3]):
    raise ValueError("Authority's address isn't a valid IPv4 address: %s" % dir_source_comp[3])
  elif not stem.util.connection.is_valid_port(dir_source_comp[4], allow_zero = True):
    raise ValueError("Authority's DirPort is invalid: %s" % dir_source_comp[4])
  elif not stem.util.connection.is_valid_port(dir_source_comp[5]):
    raise ValueError("Authority's ORPort is invalid: %s" % dir_source_comp[5])

  descriptor.nickname = dir_source_comp[0]
  descriptor.v3ident = dir_source_comp[1]
  descriptor.hostname = dir_source_comp[2]
  descriptor.address = dir_source_comp[3]
  descriptor.dir_port = None if dir_source_comp[4] == '0' else int(dir_source_comp[4])
  descriptor.or_port = int(dir_source_comp[5])
  descriptor.is_legacy = descriptor.nickname.endswith('-legacy')


_parse_legacy_dir_key_line = _parse_forty_character_hex('legacy-dir-key', 'legacy_dir_key')
_parse_vote_digest_line = _parse_forty_character_hex('vote-digest', 'vote_digest')


class DirectoryAuthority(Descriptor):
  """
  Directory authority information obtained from a v3 network status document.

  Authorities can optionally use a legacy format. These are no longer found in
  practice, but have the following differences...

  * The authority's nickname ends with '-legacy'.
  * There's no **contact** or **vote_digest** attribute.

  :var str nickname: **\\*** authority's nickname
  :var str v3ident: **\\*** identity key fingerprint used to sign votes and consensus
  :var str hostname: **\\*** hostname of the authority
  :var str address: **\\*** authority's IP address
  :var int dir_port: **\\*** authority's DirPort
  :var int or_port: **\\*** authority's ORPort
  :var bool is_legacy: **\\*** if the authority's using the legacy format
  :var str contact: contact information, this is included if is_legacy is **False**

  **Consensus Attributes:**

  :var str vote_digest: digest of the authority that contributed to the consensus, this is included if is_legacy is **False**

  **Vote Attributes:**

  :var str legacy_dir_key: fingerprint of and obsolete identity key
  :var stem.descriptor.networkstatus.KeyCertificate key_certificate: **\\***
    authority's key certificate

  :var bool is_shared_randomness_participate: **\\*** **True** if this authority
    participates in establishing a shared random value, **False** otherwise
  :var list shared_randomness_commitments: **\\*** list of
    :data:`~stem.descriptor.networkstatus.SharedRandomnessCommitment` entries
  :var int shared_randomness_previous_reveal_count: number of commitments
    used to generate the last shared random value
  :var str shared_randomness_previous_value: base64 encoded last shared random
    value
  :var int shared_randomness_current_reveal_count: number of commitments
    used to generate the current shared random value
  :var str shared_randomness_current_value: base64 encoded current shared
    random value

  **\\*** mandatory attribute

  .. versionchanged:: 1.4.0
     Renamed our 'fingerprint' attribute to 'v3ident' (prior attribute exists
     for backward compatability, but is deprecated).

  .. versionchanged:: 1.6.0
     Added the is_shared_randomness_participate, shared_randomness_commitments,
     shared_randomness_previous_reveal_count,
     shared_randomness_previous_value,
     shared_randomness_current_reveal_count, and
     shared_randomness_current_value attributes.
  """

  ATTRIBUTES = {
    'nickname': (None, _parse_dirauth_source_line),
    'v3ident': (None, _parse_dirauth_source_line),
    'hostname': (None, _parse_dirauth_source_line),
    'address': (None, _parse_dirauth_source_line),
    'dir_port': (None, _parse_dirauth_source_line),
    'or_port': (None, _parse_dirauth_source_line),
    'is_legacy': (False, _parse_dirauth_source_line),
    'contact': (None, _parse_contact_line),
    'vote_digest': (None, _parse_vote_digest_line),
    'legacy_dir_key': (None, _parse_legacy_dir_key_line),
    'is_shared_randomness_participate': (False, _parse_shared_rand_participate_line),
    'shared_randomness_commitments': ([], _parsed_shared_rand_commit),
    'shared_randomness_previous_reveal_count': (None, _parse_shared_rand_previous_value),
    'shared_randomness_previous_value': (None, _parse_shared_rand_previous_value),
    'shared_randomness_current_reveal_count': (None, _parse_shared_rand_current_value),
    'shared_randomness_current_value': (None, _parse_shared_rand_current_value),
  }

  PARSER_FOR_LINE = {
    'dir-source': _parse_dirauth_source_line,
    'contact': _parse_contact_line,
    'legacy-dir-key': _parse_legacy_dir_key_line,
    'vote-digest': _parse_vote_digest_line,
    'shared-rand-participate': _parse_shared_rand_participate_line,
    'shared-rand-commit': _parsed_shared_rand_commit,
    'shared-rand-previous-value': _parse_shared_rand_previous_value,
    'shared-rand-current-value': _parse_shared_rand_current_value,
  }

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False, is_vote = False):
    if sign:
      raise NotImplementedError('Signing of %s not implemented' % cls.__name__)

    attr = {} if attr is None else dict(attr)

    # include mandatory 'vote-digest' if a consensus

    if not is_vote and not ('vote-digest' in attr or (exclude and 'vote-digest' in exclude)):
      attr['vote-digest'] = _random_fingerprint()

    content = _descriptor_content(attr, exclude, (
      ('dir-source', '%s %s no.place.com %s 9030 9090' % (_random_nickname(), _random_fingerprint(), _random_ipv4_address())),
      ('contact', 'Mike Perry <email>'),
    ))

    if is_vote:
      content += b'\n' + KeyCertificate.content()

    return content

  @classmethod
  def create(cls, attr = None, exclude = (), validate = True, sign = False, is_vote = False):
    return cls(cls.content(attr, exclude, sign, is_vote), validate = validate, is_vote = is_vote)

  def __init__(self, raw_content, validate = False, is_vote = False):
    """
    Parse a directory authority entry in a v3 network status document.

    :param str raw_content: raw directory authority entry information
    :param bool validate: checks the validity of the content if True, skips
      these checks otherwise
    :param bool is_vote: True if this is for a vote, False if it's for a consensus

    :raises: ValueError if the descriptor data is invalid
    """

    super(DirectoryAuthority, self).__init__(raw_content, lazy_load = not validate)
    content = stem.util.str_tools._to_unicode(raw_content)

    # separate the directory authority entry from its key certificate
    key_div = content.find('\ndir-key-certificate-version')

    if key_div != -1:
      self.key_certificate = KeyCertificate(content[key_div + 1:], validate)
      content = content[:key_div + 1]
    else:
      self.key_certificate = None

    entries = _descriptor_components(content, validate)

    if validate and 'dir-source' != list(entries.keys())[0]:
      raise ValueError("Authority entries are expected to start with a 'dir-source' line:\n%s" % (content))

    # check that we have mandatory fields

    if validate:
      is_legacy, dir_source_entry = False, entries.get('dir-source')

      if dir_source_entry:
        is_legacy = dir_source_entry[0][0].split()[0].endswith('-legacy')

      required_fields, excluded_fields = ['dir-source'], []

      if not is_legacy:
        required_fields += ['contact']

      if is_vote:
        if not self.key_certificate:
          raise ValueError('Authority votes must have a key certificate:\n%s' % content)

        excluded_fields += ['vote-digest']
      elif not is_vote:
        if self.key_certificate:
          raise ValueError("Authority consensus entries shouldn't have a key certificate:\n%s" % content)

        if not is_legacy:
          required_fields += ['vote-digest']

        excluded_fields += ['legacy-dir-key']

      for keyword in required_fields:
        if keyword not in entries:
          raise ValueError("Authority entries must have a '%s' line:\n%s" % (keyword, content))

      for keyword in entries:
        if keyword in excluded_fields:
          type_label = 'votes' if is_vote else 'consensus entries'
          raise ValueError("Authority %s shouldn't have a '%s' line:\n%s" % (type_label, keyword, content))

      # all known attributes can only appear at most once
      for keyword, values in list(entries.items()):
        if len(values) > 1 and keyword in ('dir-source', 'contact', 'legacy-dir-key', 'vote-digest'):
          raise ValueError("Authority entries can only have a single '%s' line, got %i:\n%s" % (keyword, len(values), content))

      self._parse(entries, validate)
    else:
      self._entries = entries

    # TODO: Due to a bug we had a 'fingerprint' rather than 'v3ident' attribute
    # for a long while. Keeping this around for backward compatability, but
    # this will be dropped in stem's 2.0 release.

    self.fingerprint = self.v3ident


def _parse_dir_address_line(descriptor, entries):
  # "dir-address" IPPort

  value = _value('dir-address', entries)

  if ':' not in value:
    raise ValueError("Key certificate's 'dir-address' is expected to be of the form ADDRESS:PORT: dir-address %s" % value)

  address, dirport = value.rsplit(':', 1)

  if not stem.util.connection.is_valid_ipv4_address(address):
    raise ValueError("Key certificate's address isn't a valid IPv4 address: dir-address %s" % value)
  elif not stem.util.connection.is_valid_port(dirport):
    raise ValueError("Key certificate's dirport is invalid: dir-address %s" % value)

  descriptor.address = address
  descriptor.dir_port = int(dirport)


_parse_dir_key_certificate_version_line = _parse_version_line('dir-key-certificate-version', 'version', 3)
_parse_dir_key_published_line = _parse_timestamp_line('dir-key-published', 'published')
_parse_dir_key_expires_line = _parse_timestamp_line('dir-key-expires', 'expires')
_parse_identity_key_line = _parse_key_block('dir-identity-key', 'identity_key', 'RSA PUBLIC KEY')
_parse_signing_key_line = _parse_key_block('dir-signing-key', 'signing_key', 'RSA PUBLIC KEY')
_parse_dir_key_crosscert_line = _parse_key_block('dir-key-crosscert', 'crosscert', 'ID SIGNATURE')
_parse_dir_key_certification_line = _parse_key_block('dir-key-certification', 'certification', 'SIGNATURE')


class KeyCertificate(Descriptor):
  """
  Directory key certificate for a v3 network status document.

  :var int version: **\\*** version of the key certificate
  :var str address: authority's IP address
  :var int dir_port: authority's DirPort
  :var str fingerprint: **\\*** authority's fingerprint
  :var str identity_key: **\\*** long term authority identity key
  :var datetime published: **\\*** time when this key was generated
  :var datetime expires: **\\*** time after which this key becomes invalid
  :var str signing_key: **\\*** directory server's public signing key
  :var str crosscert: signature made using certificate's signing key
  :var str certification: **\\*** signature of this key certificate signed with
    the identity key

  **\\*** mandatory attribute
  """

  TYPE_ANNOTATION_NAME = 'dir-key-certificate-3'

  ATTRIBUTES = {
    'version': (None, _parse_dir_key_certificate_version_line),
    'address': (None, _parse_dir_address_line),
    'dir_port': (None, _parse_dir_address_line),
    'fingerprint': (None, _parse_fingerprint_line),
    'identity_key': (None, _parse_identity_key_line),
    'published': (None, _parse_dir_key_published_line),
    'expires': (None, _parse_dir_key_expires_line),
    'signing_key': (None, _parse_signing_key_line),
    'crosscert': (None, _parse_dir_key_crosscert_line),
    'certification': (None, _parse_dir_key_certification_line),
  }

  PARSER_FOR_LINE = {
    'dir-key-certificate-version': _parse_dir_key_certificate_version_line,
    'dir-address': _parse_dir_address_line,
    'fingerprint': _parse_fingerprint_line,
    'dir-key-published': _parse_dir_key_published_line,
    'dir-key-expires': _parse_dir_key_expires_line,
    'dir-identity-key': _parse_identity_key_line,
    'dir-signing-key': _parse_signing_key_line,
    'dir-key-crosscert': _parse_dir_key_crosscert_line,
    'dir-key-certification': _parse_dir_key_certification_line,
  }

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False):
    if sign:
      raise NotImplementedError('Signing of %s not implemented' % cls.__name__)

    return _descriptor_content(attr, exclude, (
      ('dir-key-certificate-version', '3'),
      ('fingerprint', _random_fingerprint()),
      ('dir-key-published', _random_date()),
      ('dir-key-expires', _random_date()),
      ('dir-identity-key', _random_crypto_blob('RSA PUBLIC KEY')),
      ('dir-signing-key', _random_crypto_blob('RSA PUBLIC KEY')),
    ), (
      ('dir-key-certification', _random_crypto_blob('SIGNATURE')),
    ))

  def __init__(self, raw_content, validate = False):
    super(KeyCertificate, self).__init__(raw_content, lazy_load = not validate)
    entries = _descriptor_components(raw_content, validate)

    if validate:
      if 'dir-key-certificate-version' != list(entries.keys())[0]:
        raise ValueError("Key certificates must start with a 'dir-key-certificate-version' line:\n%s" % (raw_content))
      elif 'dir-key-certification' != list(entries.keys())[-1]:
        raise ValueError("Key certificates must end with a 'dir-key-certification' line:\n%s" % (raw_content))

      # check that we have mandatory fields and that our known fields only
      # appear once

      for keyword, is_mandatory in KEY_CERTIFICATE_PARAMS:
        if is_mandatory and keyword not in entries:
          raise ValueError("Key certificates must have a '%s' line:\n%s" % (keyword, raw_content))

        entry_count = len(entries.get(keyword, []))
        if entry_count > 1:
          raise ValueError("Key certificates can only have a single '%s' line, got %i:\n%s" % (keyword, entry_count, raw_content))

      self._parse(entries, validate)
    else:
      self._entries = entries


class DocumentSignature(object):
  """
  Directory signature of a v3 network status document.

  :var str method: algorithm used to make the signature
  :var str identity: fingerprint of the authority that made the signature
  :var str key_digest: digest of the signing key
  :var str signature: document signature
  :var str flavor: consensus type this signature is for (such as 'microdesc'),
    **None** if for the standard consensus
  :param bool validate: checks validity if **True**

  :raises: **ValueError** if a validity check fails
  """

  def __init__(self, method, identity, key_digest, signature, flavor = None, validate = False):
    # Checking that these attributes are valid. Technically the key
    # digest isn't a fingerprint, but it has the same characteristics.

    if validate:
      if not stem.util.tor_tools.is_valid_fingerprint(identity):
        raise ValueError('Malformed fingerprint (%s) in the document signature' % identity)

      if not stem.util.tor_tools.is_valid_fingerprint(key_digest):
        raise ValueError('Malformed key digest (%s) in the document signature' % key_digest)

    self.method = method
    self.identity = identity
    self.key_digest = key_digest
    self.signature = signature
    self.flavor = flavor

  def _compare(self, other, method):
    if not isinstance(other, DocumentSignature):
      return False

    for attr in ('method', 'identity', 'key_digest', 'signature', 'flavor'):
      if getattr(self, attr) != getattr(other, attr):
        return method(getattr(self, attr), getattr(other, attr))

    return method(True, True)  # we're equal

  def __hash__(self):
    return hash(str(self).strip())

  def __eq__(self, other):
    return self._compare(other, lambda s, o: s == o)

  def __ne__(self, other):
    return not self == other

  def __lt__(self, other):
    return self._compare(other, lambda s, o: s < o)

  def __le__(self, other):
    return self._compare(other, lambda s, o: s <= o)


class DetachedSignature(Descriptor):
  """
  Stand alone signature of the consensus. These are exchanged between directory
  authorities when determining the next hour's consensus.

  Detached signatures are defined in section 3.10 of the dir-spec, and only
  available to be downloaded for five minutes between minute 55 until the end
  of the hour.

  .. versionadded:: 1.8.0

  :var str consensus_digest: **\\*** digest of the consensus being signed
  :var datetime valid_after: **\\*** time when the consensus became valid
  :var datetime fresh_until: **\\*** time when the next consensus should be produced
  :var datetime valid_until: **\\*** time when this consensus becomes obsolete
  :var list additional_digests: **\\***
    :class:`~stem.descriptor.networkstatus.DocumentDigest` for additional
    consensus flavors
  :var list additional_signatures: **\\***
    :class:`~stem.descriptor.networkstatus.DocumentSignature` for additional
    consensus flavors
  :var list signatures: **\\*** :class:`~stem.descriptor.networkstatus.DocumentSignature`
    of the authorities that have signed the document

  **\\*** mandatory attribute
  """

  TYPE_ANNOTATION_NAME = 'detached-signature-3'

  ATTRIBUTES = {
    'consensus_digest': (None, _parse_consensus_digest_line),
    'valid_after': (None, _parse_header_valid_after_line),
    'fresh_until': (None, _parse_header_fresh_until_line),
    'valid_until': (None, _parse_header_valid_until_line),
    'additional_digests': ([], _parse_additional_digests),
    'additional_signatures': ([], _parse_additional_signatures),
    'signatures': ([], _parse_footer_directory_signature_line),
  }

  PARSER_FOR_LINE = {
    'consensus-digest': _parse_consensus_digest_line,
    'valid-after': _parse_header_valid_after_line,
    'fresh-until': _parse_header_fresh_until_line,
    'valid-until': _parse_header_valid_until_line,
    'additional-digest': _parse_additional_digests,
    'additional-signature': _parse_additional_signatures,
    'directory-signature': _parse_footer_directory_signature_line,
  }

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False):
    if sign:
      raise NotImplementedError('Signing of %s not implemented' % cls.__name__)

    return _descriptor_content(attr, exclude, (
      ('consensus-digest', '6D3CC0EFA408F228410A4A8145E1B0BB0670E442'),
      ('valid-after', _random_date()),
      ('fresh-until', _random_date()),
      ('valid-until', _random_date()),
    ))

  def __init__(self, raw_content, validate = False):
    super(DetachedSignature, self).__init__(raw_content, lazy_load = not validate)
    entries = _descriptor_components(raw_content, validate)

    if validate:
      if 'consensus-digest' != list(entries.keys())[0]:
        raise ValueError("Detached signatures must start with a 'consensus-digest' line:\n%s" % (raw_content))

      # check that we have mandatory fields and certain fields only appear once

      for keyword, is_mandatory, is_multiple in DETACHED_SIGNATURE_PARAMS:
        if is_mandatory and keyword not in entries:
          raise ValueError("Detached signatures must have a '%s' line:\n%s" % (keyword, raw_content))

        entry_count = len(entries.get(keyword, []))
        if not is_multiple and entry_count > 1:
          raise ValueError("Detached signatures can only have a single '%s' line, got %i:\n%s" % (keyword, entry_count, raw_content))

      self._parse(entries, validate)
    else:
      self._entries = entries


class BridgeNetworkStatusDocument(NetworkStatusDocument):
  """
  Network status document containing bridges. This is only available through
  the metrics site.

  :var dict routers: fingerprint to :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`
    mapping for relays contained in the document
  :var datetime published: time when the document was published
  """

  TYPE_ANNOTATION_NAME = 'bridge-network-status'

  def __init__(self, raw_content, validate = False):
    super(BridgeNetworkStatusDocument, self).__init__(raw_content)

    self.published = None

    document_file = io.BytesIO(raw_content)
    published_line = stem.util.str_tools._to_unicode(document_file.readline())

    if published_line.startswith('published '):
      published_line = published_line.split(' ', 1)[1].strip()

      try:
        self.published = stem.util.str_tools._parse_timestamp(published_line)
      except ValueError:
        if validate:
          raise ValueError("Bridge network status document's 'published' time wasn't parsable: %s" % published_line)
    elif validate:
      raise ValueError("Bridge network status documents must start with a 'published' line:\n%s" % stem.util.str_tools._to_unicode(raw_content))

    router_iter = stem.descriptor.router_status_entry._parse_file(
      document_file,
      validate,
      entry_class = RouterStatusEntryV2,
      extra_args = (self,),
    )

    self.routers = dict((desc.fingerprint, desc) for desc in router_iter)
