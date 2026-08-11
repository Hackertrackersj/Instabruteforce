# Copyright 2018-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Messages communicated over a Tor relay's ORPort.

.. versionadded:: 1.7.0

**Module Overview:**

::

  Cell - Base class for ORPort messages.
    |- CircuitCell - Circuit management.
    |  |- CreateCell - Create a circuit.              (section 5.1)
    |  |- CreatedCell - Acknowledge create.           (section 5.1)
    |  |- RelayCell - End-to-end data.                (section 6.1)
    |  |- DestroyCell - Stop using a circuit.         (section 5.4)
    |  |- CreateFastCell - Create a circuit, no PK.   (section 5.1)
    |  |- CreatedFastCell - Circuit created, no PK.   (section 5.1)
    |  |- RelayEarlyCell - End-to-end data; limited.  (section 5.6)
    |  |- Create2Cell - Extended CREATE cell.         (section 5.1)
    |  +- Created2Cell - Extended CREATED cell.       (section 5.1)
    |
    |- PaddingCell - Padding negotiation.             (section 7.2)
    |- VersionsCell - Negotiate proto version.        (section 4)
    |- NetinfoCell - Time and address info.           (section 4.5)
    |- PaddingNegotiateCell - Padding negotiation.    (section 7.2)
    |- VPaddingCell - Variable-length padding.        (section 7.2)
    |- CertsCell - Relay certificates.                (section 4.2)
    |- AuthChallengeCell - Challenge value.           (section 4.3)
    |- AuthenticateCell - Client authentication.      (section 4.5)
    |- AuthorizeCell - Client authorization.          (not yet used)
    |
    |- pack - encodes cell into bytes
    |- unpack - decodes series of cells
    +- pop - decodes cell with remainder
"""

import copy
import datetime
import inspect
import os
import sys

import stem.util

from stem import UNDEFINED
from stem.client.datatype import HASH_LEN, ZERO, LinkProtocol, Address, Certificate, CloseReason, RelayCommand, Size, split
from stem.util import datetime_to_unix, str_tools

FIXED_PAYLOAD_LEN = 509  # PAYLOAD_LEN, per tor-spec section 0.2
AUTH_CHALLENGE_SIZE = 32

CELL_TYPE_SIZE = Size.CHAR
PAYLOAD_LEN_SIZE = Size.SHORT
RELAY_DIGEST_SIZE = Size.LONG

STREAM_ID_REQUIRED = (
  RelayCommand.BEGIN,
  RelayCommand.DATA,
  RelayCommand.END,
  RelayCommand.CONNECTED,
  RelayCommand.RESOLVE,
  RelayCommand.RESOLVED,
  RelayCommand.BEGIN_DIR,
)

STREAM_ID_DISALLOWED = (
  RelayCommand.EXTEND,
  RelayCommand.EXTENDED,
  RelayCommand.TRUNCATE,
  RelayCommand.TRUNCATED,
  RelayCommand.DROP,
  RelayCommand.EXTEND2,
  RelayCommand.EXTENDED2,
)


class Cell(object):
  """
  Metadata for ORPort cells.

  Unused padding are **not** used in equality checks or hashing. If two cells
  differ only in their *unused* attribute they are functionally equal.

  The following cell types explicitly don't have *unused* content:
    * PaddingCell (we consider all content part of payload)
    * VersionsCell (all content is unpacked and treated as a version specification)
    * VPaddingCell (we consider all content part of payload)

  :var bytes unused: unused filler that padded the cell to the expected size
  """

  NAME = 'UNKNOWN'
  VALUE = -1
  IS_FIXED_SIZE = False

  def __init__(self, unused = b''):
    super(Cell, self).__init__()
    self.unused = unused

  @staticmethod
  def by_name(name):
    """
    Provides cell attributes by its name.

    :param str name: cell command to fetch

    :raises: **ValueError** if cell type is invalid
    """

    for _, cls in inspect.getmembers(sys.modules[__name__]):
      if name == getattr(cls, 'NAME', UNDEFINED):
        return cls

    raise ValueError("'%s' isn't a valid cell type" % name)

  @staticmethod
  def by_value(value):
    """
    Provides cell attributes by its value.

    :param int value: cell value to fetch

    :raises: **ValueError** if cell type is invalid
    """

    for _, cls in inspect.getmembers(sys.modules[__name__]):
      if value == getattr(cls, 'VALUE', UNDEFINED):
        return cls

    raise ValueError("'%s' isn't a valid cell value" % value)

  def pack(self, link_protocol):
    raise NotImplementedError('Packing not yet implemented for %s cells' % type(self).NAME)

  @staticmethod
  def unpack(content, link_protocol):
    """
    Unpacks all cells from a response.

    :param bytes content: payload to decode
    :param int link_protocol: link protocol version

    :returns: :class:`~stem.client.cell.Cell` generator

    :raises:
      * ValueError if content is malformed
      * NotImplementedError if unable to unpack any of the cell types
    """

    while content:
      cell, content = Cell.pop(content, link_protocol)
      yield cell

  @staticmethod
  def pop(content, link_protocol):
    """
    Unpacks the first cell.

    :param bytes content: payload to decode
    :param int link_protocol: link protocol version

    :returns: (:class:`~stem.client.cell.Cell`, remainder) tuple

    :raises:
      * ValueError if content is malformed
      * NotImplementedError if unable to unpack this cell type
    """

    link_protocol = LinkProtocol(link_protocol)

    circ_id, content = link_protocol.circ_id_size.pop(content)
    command, content = CELL_TYPE_SIZE.pop(content)
    cls = Cell.by_value(command)

    if cls.IS_FIXED_SIZE:
      payload_len = FIXED_PAYLOAD_LEN
    else:
      payload_len, content = PAYLOAD_LEN_SIZE.pop(content)

    if len(content) < payload_len:
      raise ValueError('%s cell should have a payload of %i bytes, but only had %i' % (cls.NAME, payload_len, len(content)))

    payload, content = split(content, payload_len)
    return cls._unpack(payload, circ_id, link_protocol), content

  @classmethod
  def _pack(cls, link_protocol, payload, unused = b'', circ_id = None):
    """
    Provides bytes that can be used on the wire for these cell attributes.
    Format of a properly packed cell depends on if it's fixed or variable
    sized...

    ::

      Fixed:    [ CircuitID ][ Command ][ Payload ][ Padding ]
      Variable: [ CircuitID ][ Command ][ Size ][ Payload ]

    :param str name: cell command
    :param int link_protocol: link protocol version
    :param bytes payload: cell payload
    :param int circ_id: circuit id, if a CircuitCell

    :returns: **bytes** with the encoded payload

    :raises: **ValueError** if cell type invalid or payload makes cell too large
    """

    if issubclass(cls, CircuitCell):
      if circ_id is None:
        raise ValueError('%s cells require a circuit identifier' % cls.NAME)
      elif circ_id < 1:
        raise ValueError('Circuit identifiers must a positive integer, not %s' % circ_id)
    else:
      if circ_id is not None:
        raise ValueError('%s cells should not specify a circuit identifier' % cls.NAME)

      circ_id = 0  # cell doesn't concern a circuit, default field to zero

    link_protocol = LinkProtocol(link_protocol)

    cell = bytearray()
    cell += link_protocol.circ_id_size.pack(circ_id)
    cell += Size.CHAR.pack(cls.VALUE)
    cell += b'' if cls.IS_FIXED_SIZE else Size.SHORT.pack(len(payload) + len(unused))
    cell += payload

    # include the unused portion (typically from unpacking)
    cell += unused

    # pad fixed sized cells to the required length

    if cls.IS_FIXED_SIZE:
      if len(cell) > link_protocol.fixed_cell_length:
        raise ValueError('Cell of type %s is too large (%i bytes), must not be more than %i. Check payload size (was %i bytes)' % (cls.NAME, len(cell), link_protocol.fixed_cell_length, len(payload)))

      cell += ZERO * (link_protocol.fixed_cell_length - len(cell))

    return bytes(cell)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    """
    Subclass implementation for unpacking cell content.

    :param bytes content: payload to decode
    :param stem.client.datatype.LinkProtocol link_protocol: link protocol version
    :param int circ_id: circuit id cell is for

    :returns: instance of this cell type

    :raises: **ValueError** if content is malformed
    """

    raise NotImplementedError('Unpacking not yet implemented for %s cells' % cls.NAME)

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Cell) else False

  def __ne__(self, other):
    return not self == other


class CircuitCell(Cell):
  """
  Cell concerning circuits.

  :var int circ_id: circuit id
  """

  def __init__(self, circ_id, unused = b''):
    super(CircuitCell, self).__init__(unused)
    self.circ_id = circ_id


class PaddingCell(Cell):
  """
  Randomized content to either keep activity going on a circuit.

  :var bytes payload: randomized payload
  """

  NAME = 'PADDING'
  VALUE = 0
  IS_FIXED_SIZE = True

  def __init__(self, payload = None):
    if not payload:
      payload = os.urandom(FIXED_PAYLOAD_LEN)
    elif len(payload) != FIXED_PAYLOAD_LEN:
      raise ValueError('Padding payload should be %i bytes, but was %i' % (FIXED_PAYLOAD_LEN, len(payload)))

    super(PaddingCell, self).__init__()
    self.payload = payload

  def pack(self, link_protocol):
    return PaddingCell._pack(link_protocol, self.payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    return PaddingCell(content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'payload', cache = True)


class CreateCell(CircuitCell):
  NAME = 'CREATE'
  VALUE = 1
  IS_FIXED_SIZE = True

  def __init__(self):
    super(CreateCell, self).__init__()  # TODO: implement


class CreatedCell(CircuitCell):
  NAME = 'CREATED'
  VALUE = 2
  IS_FIXED_SIZE = True

  def __init__(self):
    super(CreatedCell, self).__init__()  # TODO: implement


class RelayCell(CircuitCell):
  """
  Command concerning a relay circuit.

  Our 'recognized' attribute provides a cheap (but incomplete) check for if our
  cell payload is encrypted. If non-zero our payload *IS* encrypted, but if
  zero we're *PROBABLY* fully decrypted. This uncertainty is because encrypted
  cells have a small chance of coincidently producing zero for this value as
  well.

  :var stem.client.RelayCommand command: command to be issued
  :var int command_int: integer value of our command
  :var bytes data: payload of the cell
  :var int recognized: non-zero if payload is encrypted
  :var int digest: running digest held with the relay
  :var int stream_id: specific stream this concerns
  """

  NAME = 'RELAY'
  VALUE = 3
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, command, data, digest = 0, stream_id = 0, recognized = 0, unused = b''):
    if 'hash' in str(type(digest)).lower():
      # Unfortunately hashlib generates from a dynamic private class so
      # isinstance() isn't such a great option. With python2/python3 the
      # name is 'hashlib.HASH' whereas PyPy calls it just 'HASH' or 'Hash'.

      digest_packed = digest.digest()[:RELAY_DIGEST_SIZE.size]
      digest = RELAY_DIGEST_SIZE.unpack(digest_packed)
    elif stem.util._is_str(digest):
      digest_packed = digest[:RELAY_DIGEST_SIZE.size]
      digest = RELAY_DIGEST_SIZE.unpack(digest_packed)
    elif stem.util._is_int(digest):
      pass
    else:
      raise ValueError('RELAY cell digest must be a hash, string, or int but was a %s' % type(digest).__name__)

    super(RelayCell, self).__init__(circ_id, unused)
    self.command, self.command_int = RelayCommand.get(command)
    self.recognized = recognized
    self.stream_id = stream_id
    self.digest = digest
    self.data = str_tools._to_bytes(data)

    if digest == 0:
      if not stream_id and self.command in STREAM_ID_REQUIRED:
        raise ValueError('%s relay cells require a stream id' % self.command)
      elif stream_id and self.command in STREAM_ID_DISALLOWED:
        raise ValueError('%s relay cells concern the circuit itself and cannot have a stream id' % self.command)

  def pack(self, link_protocol):
    payload = bytearray()
    payload += Size.CHAR.pack(self.command_int)
    payload += Size.SHORT.pack(self.recognized)
    payload += Size.SHORT.pack(self.stream_id)
    payload += Size.LONG.pack(self.digest)
    payload += Size.SHORT.pack(len(self.data))
    payload += self.data

    return RelayCell._pack(link_protocol, bytes(payload), self.unused, self.circ_id)

  @staticmethod
  def decrypt(link_protocol, content, key, digest):
    """
    Decrypts content as a relay cell addressed to us. This provides back a
    tuple of the form...

    ::

      (cell (RelayCell), new_key (CipherContext), new_digest (HASH))

    :param int link_protocol: link protocol version
    :param bytes content: cell content to be decrypted
    :param cryptography.hazmat.primitives.ciphers.CipherContext key:
      key established with the relay we received this cell from
    :param hashlib.HASH digest: running digest held with the relay

    :returns: **tuple** with our decrypted cell and updated key/digest

    :raises: :class:`stem.ProtocolError` if content doesn't belong to a relay
      cell
    """

    new_key = copy.copy(key)
    new_digest = digest.copy()

    if len(content) != link_protocol.fixed_cell_length:
      raise stem.ProtocolError('RELAY cells should be %i bytes, but received %i' % (link_protocol.fixed_cell_length, len(content)))

    circ_id, content = link_protocol.circ_id_size.pop(content)
    command, encrypted_payload = Size.CHAR.pop(content)

    if command != RelayCell.VALUE:
      raise stem.ProtocolError('Cannot decrypt as a RELAY cell. This had command %i instead.' % command)

    payload = new_key.update(encrypted_payload)

    cell = RelayCell._unpack(payload, circ_id, link_protocol)

    # TODO: Implement our decryption digest. It is used to support relaying
    # within multi-hop circuits. On first glance this should go something
    # like...
    #
    #   # Our updated digest is calculated based on this cell with a blanked
    #   # digest field.
    #
    #   digest_cell = RelayCell(self.circ_id, self.command, self.data, 0, self.stream_id, self.recognized, self.unused)
    #   new_digest.update(digest_cell.pack(link_protocol))
    #
    #   is_encrypted == cell.recognized != 0 or self.digest == new_digest
    #
    # ... or something like that. Until we attempt to support relaying this is
    # both moot and difficult to exercise in order to ensure we get it right.

    return cell, new_key, new_digest

  def encrypt(self, link_protocol, key, digest):
    """
    Encrypts our cell content to be sent with the given key. This provides back
    a tuple of the form...

    ::

      (payload (bytes), new_key (CipherContext), new_digest (HASH))

    :param int link_protocol: link protocol version
    :param cryptography.hazmat.primitives.ciphers.CipherContext key:
      key established with the relay we're sending this cell to
    :param hashlib.HASH digest: running digest held with the relay

    :returns: **tuple** with our encrypted payload and updated key/digest
    """

    new_key = copy.copy(key)
    new_digest = digest.copy()

    # Digests are computed from our payload, not including our header's circuit
    # id (2 or 4 bytes) and command (1 byte).

    header_size = link_protocol.circ_id_size.size + 1
    payload_without_digest = self.pack(link_protocol)[header_size:]
    new_digest.update(payload_without_digest)

    # Pack a copy of ourselves with our newly calculated digest, and encrypt
    # the payload. Header remains plaintext.

    cell = RelayCell(self.circ_id, self.command, self.data, new_digest, self.stream_id, self.recognized, self.unused)
    header, payload = split(cell.pack(link_protocol), header_size)

    return header + new_key.update(payload), new_key, new_digest

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    command, content = Size.CHAR.pop(content)
    recognized, content = Size.SHORT.pop(content)  # 'recognized' field
    stream_id, content = Size.SHORT.pop(content)
    digest, content = Size.LONG.pop(content)
    data_len, content = Size.SHORT.pop(content)
    data, unused = split(content, data_len)

    if len(data) != data_len:
      raise ValueError('%s cell said it had %i bytes of data, but only had %i' % (cls.NAME, data_len, len(data)))

    return RelayCell(circ_id, command, data, digest, stream_id, recognized, unused)

  def __hash__(self):
    return stem.util._hash_attr(self, 'command_int', 'stream_id', 'digest', 'data', cache = True)


class DestroyCell(CircuitCell):
  """
  Closes the given circuit.

  :var stem.client.CloseReason reason: reason the circuit is being closed
  :var int reason_int: integer value of our closure reason
  """

  NAME = 'DESTROY'
  VALUE = 4
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, reason = CloseReason.NONE, unused = b''):
    super(DestroyCell, self).__init__(circ_id, unused)
    self.reason, self.reason_int = CloseReason.get(reason)

  def pack(self, link_protocol):
    return DestroyCell._pack(link_protocol, Size.CHAR.pack(self.reason_int), self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    reason, unused = Size.CHAR.pop(content)
    return DestroyCell(circ_id, reason, unused)

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'reason_int', cache = True)


class CreateFastCell(CircuitCell):
  """
  Create a circuit with our first hop. This is lighter weight than further hops
  because we've already established the relay's identity and secret key.

  :var bytes key_material: randomized key material
  """

  NAME = 'CREATE_FAST'
  VALUE = 5
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, key_material = None, unused = b''):
    if not key_material:
      key_material = os.urandom(HASH_LEN)
    elif len(key_material) != HASH_LEN:
      raise ValueError('Key material should be %i bytes, but was %i' % (HASH_LEN, len(key_material)))

    super(CreateFastCell, self).__init__(circ_id, unused)
    self.key_material = key_material

  def pack(self, link_protocol):
    return CreateFastCell._pack(link_protocol, self.key_material, self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    key_material, unused = split(content, HASH_LEN)

    if len(key_material) != HASH_LEN:
      raise ValueError('Key material should be %i bytes, but was %i' % (HASH_LEN, len(key_material)))

    return CreateFastCell(circ_id, key_material, unused)

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'key_material', cache = True)


class CreatedFastCell(CircuitCell):
  """
  CREATE_FAST reply.

  :var bytes key_material: randomized key material
  :var bytes derivative_key: hash proving the relay knows our shared key
  """

  NAME = 'CREATED_FAST'
  VALUE = 6
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, derivative_key, key_material = None, unused = b''):
    if not key_material:
      key_material = os.urandom(HASH_LEN)
    elif len(key_material) != HASH_LEN:
      raise ValueError('Key material should be %i bytes, but was %i' % (HASH_LEN, len(key_material)))

    if len(derivative_key) != HASH_LEN:
      raise ValueError('Derivatived key should be %i bytes, but was %i' % (HASH_LEN, len(derivative_key)))

    super(CreatedFastCell, self).__init__(circ_id, unused)
    self.key_material = key_material
    self.derivative_key = derivative_key

  def pack(self, link_protocol):
    return CreatedFastCell._pack(link_protocol, self.key_material + self.derivative_key, self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    if len(content) < HASH_LEN * 2:
      raise ValueError('Key material and derivatived key should be %i bytes, but was %i' % (HASH_LEN * 2, len(content)))

    key_material, content = split(content, HASH_LEN)
    derivative_key, content = split(content, HASH_LEN)

    return CreatedFastCell(circ_id, derivative_key, key_material, content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'derivative_key', 'key_material', cache = True)


class VersionsCell(Cell):
  """
  Link version negotiation cell.

  :var list versions: link versions
  """

  NAME = 'VERSIONS'
  VALUE = 7
  IS_FIXED_SIZE = False

  def __init__(self, versions):
    super(VersionsCell, self).__init__()
    self.versions = versions

  def pack(self, link_protocol):
    payload = b''.join([Size.SHORT.pack(v) for v in self.versions])
    return VersionsCell._pack(link_protocol, payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    link_protocols = []

    while content:
      version, content = Size.SHORT.pop(content)
      link_protocols.append(version)

    return VersionsCell(link_protocols)

  def __hash__(self):
    return stem.util._hash_attr(self, 'versions', cache = True)


class NetinfoCell(Cell):
  """
  Information relays exchange about each other.

  :var datetime timestamp: current time
  :var stem.client.datatype.Address receiver_address: receiver's OR address
  :var list sender_addresses: sender's OR addresses
  """

  NAME = 'NETINFO'
  VALUE = 8
  IS_FIXED_SIZE = True

  def __init__(self, receiver_address, sender_addresses, timestamp = None, unused = b''):
    super(NetinfoCell, self).__init__(unused)
    self.timestamp = timestamp if timestamp else datetime.datetime.now()
    self.receiver_address = receiver_address
    self.sender_addresses = sender_addresses

  def pack(self, link_protocol):
    payload = bytearray()
    payload += Size.LONG.pack(int(datetime_to_unix(self.timestamp)))
    payload += self.receiver_address.pack()
    payload += Size.CHAR.pack(len(self.sender_addresses))

    for addr in self.sender_addresses:
      payload += addr.pack()

    return NetinfoCell._pack(link_protocol, bytes(payload), self.unused)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    timestamp, content = Size.LONG.pop(content)
    receiver_address, content = Address.pop(content)

    sender_addresses = []
    sender_addr_count, content = Size.CHAR.pop(content)

    for i in range(sender_addr_count):
      addr, content = Address.pop(content)
      sender_addresses.append(addr)

    return NetinfoCell(receiver_address, sender_addresses, datetime.datetime.utcfromtimestamp(timestamp), unused = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'timestamp', 'receiver_address', 'sender_addresses', cache = True)


class RelayEarlyCell(CircuitCell):
  NAME = 'RELAY_EARLY'
  VALUE = 9
  IS_FIXED_SIZE = True

  def __init__(self):
    super(RelayEarlyCell, self).__init__()  # TODO: implement


class Create2Cell(CircuitCell):
  NAME = 'CREATE2'
  VALUE = 10
  IS_FIXED_SIZE = True

  def __init__(self):
    super(Create2Cell, self).__init__()  # TODO: implement


class Created2Cell(Cell):
  NAME = 'CREATED2'
  VALUE = 11
  IS_FIXED_SIZE = True

  def __init__(self):
    super(Created2Cell, self).__init__()  # TODO: implement


class PaddingNegotiateCell(Cell):
  NAME = 'PADDING_NEGOTIATE'
  VALUE = 12
  IS_FIXED_SIZE = True

  def __init__(self):
    super(PaddingNegotiateCell, self).__init__()  # TODO: implement


class VPaddingCell(Cell):
  """
  Variable length randomized content to either keep activity going on a circuit.

  :var bytes payload: randomized payload
  """

  NAME = 'VPADDING'
  VALUE = 128
  IS_FIXED_SIZE = False

  def __init__(self, size = None, payload = None):
    if size is None and payload is None:
      raise ValueError('VPaddingCell constructor must specify payload or size')
    elif size is not None and size < 0:
      raise ValueError('VPaddingCell size (%s) cannot be negative' % size)
    elif size is not None and payload is not None and size != len(payload):
      raise ValueError('VPaddingCell constructor specified both a size of %i bytes and payload of %i bytes' % (size, len(payload)))

    super(VPaddingCell, self).__init__()
    self.payload = payload if payload is not None else os.urandom(size)

  def pack(self, link_protocol):
    return VPaddingCell._pack(link_protocol, self.payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    return VPaddingCell(payload = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'payload', cache = True)


class CertsCell(Cell):
  """
  Certificate held by the relay we're communicating with.

  :var list certificates: :class:`~stem.client.Certificate` of the relay
  """

  NAME = 'CERTS'
  VALUE = 129
  IS_FIXED_SIZE = False

  def __init__(self, certs, unused = b''):
    super(CertsCell, self).__init__(unused)
    self.certificates = certs

  def pack(self, link_protocol):
    return CertsCell._pack(link_protocol, Size.CHAR.pack(len(self.certificates)) + b''.join([cert.pack() for cert in self.certificates]), self.unused)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    cert_count, content = Size.CHAR.pop(content)
    certs = []

    for i in range(cert_count):
      if not content:
        raise ValueError('CERTS cell indicates it should have %i certificates, but only contained %i' % (cert_count, len(certs)))

      cert, content = Certificate.pop(content)
      certs.append(cert)

    return CertsCell(certs, unused = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'certificates', cache = True)


class AuthChallengeCell(Cell):
  """
  First step of the authentication handshake.

  :var bytes challenge: random bytes for us to sign to authenticate
  :var list methods: authentication methods supported by the relay we're
    communicating with
  """

  NAME = 'AUTH_CHALLENGE'
  VALUE = 130
  IS_FIXED_SIZE = False

  def __init__(self, methods, challenge = None, unused = b''):
    if not challenge:
      challenge = os.urandom(AUTH_CHALLENGE_SIZE)
    elif len(challenge) != AUTH_CHALLENGE_SIZE:
      raise ValueError('AUTH_CHALLENGE must be %i bytes, but was %i' % (AUTH_CHALLENGE_SIZE, len(challenge)))

    super(AuthChallengeCell, self).__init__(unused)
    self.challenge = challenge
    self.methods = methods

  def pack(self, link_protocol):
    payload = bytearray()
    payload += self.challenge
    payload += Size.SHORT.pack(len(self.methods))

    for method in self.methods:
      payload += Size.SHORT.pack(method)

    return AuthChallengeCell._pack(link_protocol, bytes(payload), self.unused)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    min_size = AUTH_CHALLENGE_SIZE + Size.SHORT.size
    if len(content) < min_size:
      raise ValueError('AUTH_CHALLENGE payload should be at least %i bytes, but was %i' % (min_size, len(content)))

    challenge, content = split(content, AUTH_CHALLENGE_SIZE)
    method_count, content = Size.SHORT.pop(content)

    if len(content) < method_count * Size.SHORT.size:
      raise ValueError('AUTH_CHALLENGE should have %i methods, but only had %i bytes for it' % (method_count, len(content)))

    methods = []

    for i in range(method_count):
      method, content = Size.SHORT.pop(content)
      methods.append(method)

    return AuthChallengeCell(methods, challenge, unused = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'challenge', 'methods', cache = True)


class AuthenticateCell(Cell):
  NAME = 'AUTHENTICATE'
  VALUE = 131
  IS_FIXED_SIZE = False

  def __init__(self):
    super(AuthenticateCell, self).__init__()  # TODO: implement


class AuthorizeCell(Cell):
  NAME = 'AUTHORIZE'
  VALUE = 132
  IS_FIXED_SIZE = False

  def __init__(self):
    super(AuthorizeCell, self).__init__()  # TODO: implement
