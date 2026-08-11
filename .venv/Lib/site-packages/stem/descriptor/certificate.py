# Copyright 2017-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for `Tor Ed25519 certificates
<https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt>`_, which are
used to for a variety of purposes...

  * validating the key used to sign server descriptors
  * validating the key used to sign hidden service v3 descriptors
  * signing and encrypting hidden service v3 indroductory points

.. versionadded:: 1.6.0

**Module Overview:**

::

  Ed25519Certificate - Ed25519 signing key certificate
    | +- Ed25519CertificateV1 - version 1 Ed25519 certificate
    |      |- is_expired - checks if certificate is presently expired
    |      |- signing_key - certificate signing key
    |      +- validate - validates a descriptor's signature
    |
    |- from_base64 - decodes a base64 encoded certificate
    |- to_base64 - base64 encoding of this certificate
    |
    |- unpack - decodes a byte encoded certificate
    +- pack - byte encoding of this certificate

  Ed25519Extension - extension included within an Ed25519Certificate

.. data:: CertType (enum)

  Purpose of Ed25519 certificate. For more information see...

    * `cert-spec.txt <https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt>`_ section A.1
    * `rend-spec-v3.txt <https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt>`_ appendix E

  .. deprecated:: 1.8.0
     Replaced with :data:`stem.client.datatype.CertType`

  ========================  ===========
  CertType                  Description
  ========================  ===========
  **SIGNING**               signing key with an identity key
  **LINK_CERT**             TLS link certificate signed with ed25519 signing key
  **AUTH**                  authentication key signed with ed25519 signing key
  **HS_V3_DESC_SIGNING**    hidden service v3 short-term descriptor signing key
  **HS_V3_INTRO_AUTH**      hidden service v3 introductory point authentication key
  **HS_V3_INTRO_ENCRYPT**   hidden service v3 introductory point encryption key
  ========================  ===========

.. data:: ExtensionType (enum)

  Recognized exception types.

  ====================  ===========
  ExtensionType         Description
  ====================  ===========
  **HAS_SIGNING_KEY**   includes key used to sign the certificate
  ====================  ===========

.. data:: ExtensionFlag (enum)

  Flags that can be assigned to Ed25519 certificate extensions.

  ======================  ===========
  ExtensionFlag           Description
  ======================  ===========
  **AFFECTS_VALIDATION**  extension affects whether the certificate is valid
  **UNKNOWN**             extension includes flags not yet recognized by stem
  ======================  ===========
"""

import base64
import binascii
import datetime
import hashlib
import re

import stem.descriptor.hidden_service
import stem.descriptor.server_descriptor
import stem.prereq
import stem.util
import stem.util.enum
import stem.util.str_tools

from stem.client.datatype import Field, Size, split

# TODO: Importing under an alternate name until we can deprecate our redundant
# CertType enum in Stem 2.x.

from stem.client.datatype import CertType as ClientCertType

ED25519_KEY_LENGTH = 32
ED25519_HEADER_LENGTH = 40
ED25519_SIGNATURE_LENGTH = 64

SIG_PREFIX_SERVER_DESC = b'Tor router descriptor signature v1'
SIG_PREFIX_HS_V3 = b'Tor onion service descriptor sig v3'

DEFAULT_EXPIRATION_HOURS = 54  # HSv3 certificate expiration of tor

CertType = stem.util.enum.UppercaseEnum(
  'SIGNING',
  'LINK_CERT',
  'AUTH',
  'HS_V3_DESC_SIGNING',
  'HS_V3_INTRO_AUTH',
  'HS_V3_INTRO_ENCRYPT',
)

ExtensionType = stem.util.enum.Enum(('HAS_SIGNING_KEY', 4),)
ExtensionFlag = stem.util.enum.UppercaseEnum('AFFECTS_VALIDATION', 'UNKNOWN')


class Ed25519Extension(Field):
  """
  Extension within an Ed25519 certificate.

  :var stem.descriptor.certificate.ExtensionType type: extension type
  :var list flags: extension attribute flags
  :var int flag_int: integer encoding of the extension attribute flags
  :var bytes data: data the extension concerns
  """

  def __init__(self, ext_type, flag_val, data):
    self.type = ext_type
    self.flags = []
    self.flag_int = flag_val if flag_val else 0
    self.data = data

    if flag_val and flag_val % 2 == 1:
      self.flags.append(ExtensionFlag.AFFECTS_VALIDATION)
      flag_val -= 1

    if flag_val:
      self.flags.append(ExtensionFlag.UNKNOWN)

    if ext_type == ExtensionType.HAS_SIGNING_KEY and len(data) != 32:
      raise ValueError('Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was %i.' % len(data))

  def pack(self):
    encoded = bytearray()
    encoded += Size.SHORT.pack(len(self.data))
    encoded += Size.CHAR.pack(self.type)
    encoded += Size.CHAR.pack(self.flag_int)
    encoded += self.data
    return bytes(encoded)

  @staticmethod
  def pop(content):
    if len(content) < 4:
      raise ValueError('Ed25519 extension is missing header fields')

    data_size, content = Size.SHORT.pop(content)
    ext_type, content = Size.CHAR.pop(content)
    flags, content = Size.CHAR.pop(content)
    data, content = split(content, data_size)

    if len(data) != data_size:
      raise ValueError("Ed25519 extension is truncated. It should have %i bytes of data but there's only %i." % (data_size, len(data)))

    return Ed25519Extension(ext_type, flags, data), content

  def __hash__(self):
    return stem.util._hash_attr(self, 'type', 'flag_int', 'data', cache = True)


class Ed25519Certificate(object):
  """
  Base class for an Ed25519 certificate.

  :var int version: certificate format version
  :var unicode encoded: base64 encoded ed25519 certificate
  """

  def __init__(self, version):
    self.version = version
    self.encoded = None  # TODO: remove in stem 2.x

  @staticmethod
  def unpack(content):
    """
    Parses a byte encoded ED25519 certificate.

    :param bytes content: encoded certificate

    :returns: :class:`~stem.descriptor.certificate.Ed25519Certificate` subclsss
      for the given certificate

    :raises: **ValueError** if certificate is malformed
    """

    version = Size.CHAR.pop(content)[0]

    if version == 1:
      return Ed25519CertificateV1.unpack(content)
    else:
      raise ValueError('Ed25519 certificate is version %i. Parser presently only supports version 1.' % version)

  @staticmethod
  def from_base64(content):
    """
    Parses a base64 encoded ED25519 certificate.

    :param str content: base64 encoded certificate

    :returns: :class:`~stem.descriptor.certificate.Ed25519Certificate` subclsss
      for the given certificate

    :raises: **ValueError** if content is malformed
    """

    content = stem.util.str_tools._to_unicode(content)

    if content.startswith('-----BEGIN ED25519 CERT-----\n') and content.endswith('\n-----END ED25519 CERT-----'):
      content = content[29:-27]

    try:
      decoded = base64.b64decode(content)

      if not decoded:
        raise TypeError('empty')

      instance = Ed25519Certificate.unpack(decoded)
      instance.encoded = content
      return instance
    except (TypeError, binascii.Error) as exc:
      raise ValueError("Ed25519 certificate wasn't propoerly base64 encoded (%s):\n%s" % (exc, content))

  def pack(self):
    """
    Encoded byte representation of our certificate.

    :returns: **bytes** for our encoded certificate representation
    """

    raise NotImplementedError('Certificate encoding has not been implemented for %s' % type(self).__name__)

  def to_base64(self, pem = False):
    """
    Base64 encoded certificate data.

    :param bool pem: include `PEM header/footer
      <https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail>`_, for more
      information see `RFC 7468 <https://tools.ietf.org/html/rfc7468>`_

    :returns: **unicode** for our encoded certificate representation
    """

    encoded = b'\n'.join(stem.util.str_tools._split_by_length(base64.b64encode(self.pack()), 64))

    if pem:
      encoded = b'-----BEGIN ED25519 CERT-----\n%s\n-----END ED25519 CERT-----' % encoded

    return stem.util.str_tools._to_unicode(encoded)

  @staticmethod
  def _from_descriptor(keyword, attribute):
    def _parse(descriptor, entries):
      value, block_type, block_contents = entries[keyword][0]

      if not block_contents or block_type != 'ED25519 CERT':
        raise ValueError("'%s' should be followed by a ED25519 CERT block, but was a %s" % (keyword, block_type))

      setattr(descriptor, attribute, Ed25519Certificate.from_base64(block_contents))

    return _parse

  def __str__(self):
    return self.to_base64(pem = True)

  @staticmethod
  def parse(content):
    return Ed25519Certificate.from_base64(content)  # TODO: drop this alias in stem 2.x


class Ed25519CertificateV1(Ed25519Certificate):
  """
  Version 1 Ed25519 certificate, which are used for signing tor server
  descriptors.

  :var stem.client.datatype.CertType type: certificate purpose
  :var int type_int: integer value of the certificate purpose
  :var datetime expiration: expiration of the certificate
  :var int key_type: format of the key
  :var bytes key: key content
  :var list extensions: :class:`~stem.descriptor.certificate.Ed25519Extension` in this certificate
  :var bytes signature: certificate signature

  :param bytes signature: pre-calculated certificate signature
  :param cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey signing_key: certificate signing key
  """

  def __init__(self, cert_type = None, expiration = None, key_type = None, key = None, extensions = None, signature = None, signing_key = None):
    super(Ed25519CertificateV1, self).__init__(1)

    if cert_type is None:
      raise ValueError('Certificate type is required')
    elif key is None:
      raise ValueError('Certificate key is required')

    self.type, self.type_int = ClientCertType.get(cert_type)
    self.expiration = expiration if expiration else datetime.datetime.utcnow() + datetime.timedelta(hours = DEFAULT_EXPIRATION_HOURS)
    self.key_type = key_type if key_type else 1
    self.key = stem.util._pubkey_bytes(key)
    self.extensions = extensions if extensions else []
    self.signature = signature

    if signing_key:
      calculated_sig = signing_key.sign(self.pack())

      # if caller provides both signing key *and* signature then ensure they match

      if self.signature and self.signature != calculated_sig:
        raise ValueError("Signature calculated from its key (%s) mismatches '%s'" % (calculated_sig, self.signature))

      self.signature = calculated_sig

    if self.type in (ClientCertType.LINK, ClientCertType.IDENTITY, ClientCertType.AUTHENTICATE):
      raise ValueError('Ed25519 certificate cannot have a type of %i. This is reserved for CERTS cells.' % self.type_int)
    elif self.type == ClientCertType.ED25519_IDENTITY:
      raise ValueError('Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.')
    elif self.type == ClientCertType.UNKNOWN:
      raise ValueError('Ed25519 certificate type %i is unrecognized' % self.type_int)

  def pack(self):
    encoded = bytearray()
    encoded += Size.CHAR.pack(self.version)
    encoded += Size.CHAR.pack(self.type_int)
    encoded += Size.LONG.pack(int(stem.util.datetime_to_unix(self.expiration) / 3600))
    encoded += Size.CHAR.pack(self.key_type)
    encoded += self.key
    encoded += Size.CHAR.pack(len(self.extensions))

    for extension in self.extensions:
      encoded += extension.pack()

    if self.signature:
      encoded += self.signature

    return bytes(encoded)

  @staticmethod
  def unpack(content):
    if len(content) < ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH:
      raise ValueError('Ed25519 certificate was %i bytes, but should be at least %i' % (len(content), ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH))

    header, signature = split(content, len(content) - ED25519_SIGNATURE_LENGTH)

    version, header = Size.CHAR.pop(header)
    cert_type, header = Size.CHAR.pop(header)
    expiration_hours, header = Size.LONG.pop(header)
    key_type, header = Size.CHAR.pop(header)
    key, header = split(header, ED25519_KEY_LENGTH)
    extension_count, extension_data = Size.CHAR.pop(header)

    if version != 1:
      raise ValueError('Ed25519 v1 parser cannot read version %i certificates' % version)

    extensions = []

    for i in range(extension_count):
      extension, extension_data = Ed25519Extension.pop(extension_data)
      extensions.append(extension)

    if extension_data:
      raise ValueError('Ed25519 certificate had %i bytes of unused extension data' % len(extension_data))

    return Ed25519CertificateV1(cert_type, datetime.datetime.utcfromtimestamp(expiration_hours * 3600), key_type, key, extensions, signature)

  def is_expired(self):
    """
    Checks if this certificate is presently expired or not.

    :returns: **True** if the certificate has expired, **False** otherwise
    """

    return datetime.datetime.now() > self.expiration

  def signing_key(self):
    """
    Provides this certificate's signing key.

    .. versionadded:: 1.8.0

    :returns: **bytes** with the first signing key on the certificate, None if
      not present
    """

    for extension in self.extensions:
      if extension.type == ExtensionType.HAS_SIGNING_KEY:
        return extension.data

    return None

  def validate(self, descriptor):
    """
    Validate our descriptor content matches its ed25519 signature. Supported
    descriptor types include...

      * :class:`~stem.descriptor.server_descriptor.RelayDescriptor`
      * :class:`~stem.descriptor.hidden_service.HiddenServiceDescriptorV3`

    :param stem.descriptor.__init__.Descriptor descriptor: descriptor to validate

    :raises:
      * **ValueError** if signing key or descriptor are invalid
      * **TypeError** if descriptor type is unsupported
      * **ImportError** if cryptography module or ed25519 support unavailable
    """

    if not stem.prereq.is_crypto_available(ed25519 = True):
      raise ImportError('Certificate validation requires the cryptography module and ed25519 support')

    if isinstance(descriptor, stem.descriptor.server_descriptor.RelayDescriptor):
      signed_content = hashlib.sha256(Ed25519CertificateV1._signed_content(descriptor)).digest()
      signature = stem.util.str_tools._decode_b64(descriptor.ed25519_signature)

      self._validate_server_desc_signing_key(descriptor)
    elif isinstance(descriptor, stem.descriptor.hidden_service.HiddenServiceDescriptorV3):
      signed_content = Ed25519CertificateV1._signed_content(descriptor)
      signature = stem.util.str_tools._decode_b64(descriptor.signature)
    else:
      raise TypeError('Certificate validation only supported for server and hidden service descriptors, not %s' % type(descriptor).__name__)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    try:
      key = Ed25519PublicKey.from_public_bytes(self.key)
      key.verify(signature, signed_content)
    except InvalidSignature:
      raise ValueError('Descriptor Ed25519 certificate signature invalid (signature forged or corrupt)')

  @staticmethod
  def _signed_content(descriptor):
    """
    Provides this descriptor's signing constant, appended with the portion of
    the descriptor that's signed.
    """

    if isinstance(descriptor, stem.descriptor.server_descriptor.RelayDescriptor):
      prefix = SIG_PREFIX_SERVER_DESC
      regex = b'(.+router-sig-ed25519 )'
    elif isinstance(descriptor, stem.descriptor.hidden_service.HiddenServiceDescriptorV3):
      prefix = SIG_PREFIX_HS_V3
      regex = b'(.+)signature '
    else:
      raise ValueError('BUG: %s type unexpected' % type(descriptor).__name__)

    match = re.search(regex, descriptor.get_bytes(), re.DOTALL)

    if not match:
      raise ValueError('Malformed descriptor missing signature line')

    return prefix + match.group(1)

  def _validate_server_desc_signing_key(self, descriptor):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    if descriptor.ed25519_master_key:
      signing_key = base64.b64decode(stem.util.str_tools._to_bytes(descriptor.ed25519_master_key) + b'=')
    else:
      signing_key = self.signing_key()

    if not signing_key:
      raise ValueError('Server descriptor missing an ed25519 signing key')

    try:
      key = Ed25519PublicKey.from_public_bytes(signing_key)
      key.verify(self.signature, base64.b64decode(stem.util.str_tools._to_bytes(self.encoded))[:-ED25519_SIGNATURE_LENGTH])
    except InvalidSignature:
      raise ValueError('Ed25519KeyCertificate signing key is invalid (signature forged or corrupt)')
