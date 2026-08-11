# Copyright 2011-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Utility functions used by the stem library.
"""

import datetime

import stem.prereq

__all__ = [
  'conf',
  'connection',
  'enum',
  'log',
  'lru_cache',
  'ordereddict',
  'proc',
  'str_tools',
  'system',
  'term',
  'test_tools',
  'tor_tools',

  'datetime_to_unix',
]

# Beginning with Stem 1.7 we take attribute types into account when hashing
# and checking equality. That is to say, if two Stem classes' attributes are
# the same but use different types we no longer consider them to be equal.
# For example...
#
#   s1 = Schedule(classes = ['Math', 'Art', 'PE'])
#   s2 = Schedule(classes = ('Math', 'Art', 'PE'))
#
# Prior to Stem 1.7 s1 and s2 would be equal, but afterward unless Stem's
# construcotr normalizes the types they won't.
#
# This change in behavior is the right thing to do but carries some risk, so
# we provide the following constant to revert to legacy behavior. If you find
# yourself using it them please let me know (https://www.atagar.com/contact/)
# since this flag will go away in the future.

HASH_TYPES = True


def _hash_value(val):
  if not HASH_TYPES:
    my_hash = 0
  else:
    # TODO: I hate doing this but until Python 2.x support is dropped we
    # can't readily be strict about bytes vs unicode for attributes. This
    # is because test assertions often use strings, and normalizing this
    # would require wrapping most with to_unicode() calls.
    #
    # This hack will go away when we drop Python 2.x support.

    if _is_str(val):
      my_hash = hash('str')
    else:
      # Hashing common builtins (ints, bools, etc) provide consistant values but many others vary their value on interpreter invokation.

      my_hash = hash(str(type(val)))

  if isinstance(val, (tuple, list)):
    for v in val:
      my_hash = (my_hash * 1024) + hash(v)
  elif isinstance(val, dict):
    for k in sorted(val.keys()):
      my_hash = (my_hash * 2048) + (hash(k) * 1024) + hash(val[k])
  else:
    my_hash += hash(val)

  return my_hash


def _is_str(val):
  """
  Check if a value is a string. This will be removed when we no longer provide
  backward compatibility for the Python 2.x series.

  :param object val: value to be checked

  :returns: **True** if the value is some form of string (unicode or bytes),
    and **False** otherwise
  """

  if stem.prereq.is_python_3():
    return isinstance(val, (bytes, str))
  else:
    return isinstance(val, (bytes, unicode))


def _is_int(val):
  """
  Check if a value is an integer. This will be removed when we no longer
  provide backward compatibility for the Python 2.x series.

  :param object val: value to be checked

  :returns: **True** if the value is some form of integer (int or long),
    and **False** otherwise
  """

  if stem.prereq.is_python_3():
    return isinstance(val, int)
  else:
    return isinstance(val, (int, long))


def datetime_to_unix(timestamp):
  """
  Converts a utc datetime object to a unix timestamp.

  .. versionadded:: 1.5.0

  :param datetime timestamp: timestamp to be converted

  :returns: **float** for the unix timestamp of the given datetime object
  """

  if stem.prereq._is_python_26():
    delta = (timestamp - datetime.datetime(1970, 1, 1))
    return delta.days * 86400 + delta.seconds
  else:
    return (timestamp - datetime.datetime(1970, 1, 1)).total_seconds()


def _pubkey_bytes(key):
  """
  Normalizes X25509 and ED25519 keys into their public key bytes.
  """

  if _is_str(key):
    return key

  if not stem.prereq.is_crypto_available():
    raise ImportError('Key normalization requires the cryptography module')
  elif not stem.prereq.is_crypto_available(ed25519 = True):
    raise ImportError('Key normalization requires the cryptography ed25519 support')

  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
  from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

  if isinstance(key, (X25519PrivateKey, Ed25519PrivateKey)):
    return key.public_key().public_bytes(
      encoding = serialization.Encoding.Raw,
      format = serialization.PublicFormat.Raw,
    )
  elif isinstance(key, (X25519PublicKey, Ed25519PublicKey)):
    return key.public_bytes(
      encoding = serialization.Encoding.Raw,
      format = serialization.PublicFormat.Raw,
    )
  else:
    raise ValueError('Key must be a string or cryptographic public/private key (was %s)' % type(key).__name__)


def _hash_attr(obj, *attributes, **kwargs):
  """
  Provide a hash value for the given set of attributes.

  :param Object obj: object to be hashed
  :param list attributes: attribute names to take into account
  :param bool cache: persists hash in a '_cached_hash' object attribute
  :param class parent: include parent's hash value
  """

  is_cached = kwargs.get('cache', False)
  parent_class = kwargs.get('parent', None)
  cached_hash = getattr(obj, '_cached_hash', None)

  if is_cached and cached_hash is not None:
    return cached_hash

  my_hash = parent_class.__hash__(obj) if parent_class else 0
  my_hash = my_hash * 1024 + hash(str(type(obj)))

  for attr in attributes:
    val = getattr(obj, attr)
    my_hash = my_hash * 1024 + _hash_value(val)

  if is_cached:
    setattr(obj, '_cached_hash', my_hash)

  return my_hash
