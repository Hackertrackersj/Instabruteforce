# Copyright 2012-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Checks for stem dependencies.

Aside from Python itself Stem only has soft dependencies, which is to say
module unavailability only impacts features that require it. For example,
descriptor signature validation requires 'cryptography'. If unavailable
stem will still read descriptors - just without signature checks.

::

  check_requirements - checks for minimum requirements for running stem
  is_python_3 - checks if python 3.0 or later is available
  is_sqlite_available - checks if the sqlite3 module is available
  is_crypto_available - checks if the cryptography module is available
  is_zstd_available - checks if the zstd module is available
  is_lzma_available - checks if the lzma module is available
  is_mock_available - checks if the mock module is available
"""

import functools
import hashlib
import inspect
import platform
import sys

# TODO: in stem 2.x consider replacing these functions with requirement
# annotations (like our tests)

CRYPTO_UNAVAILABLE = "Unable to import the cryptography module. Because of this we'll be unable to verify descriptor signature integrity. You can get cryptography from: https://pypi.org/project/cryptography/"
ZSTD_UNAVAILABLE = 'ZSTD compression requires the zstandard module (https://pypi.org/project/zstandard/)'
LZMA_UNAVAILABLE = 'LZMA compression requires the lzma module (https://docs.python.org/3/library/lzma.html)'
ED25519_UNSUPPORTED = 'Unable to verify descriptor ed25519 certificate integrity. ed25519 is not supported by installed versions of OpenSSL and/or cryptography'


def check_requirements():
  """
  Checks that we meet the minimum requirements to run stem. If we don't then
  this raises an ImportError with the issue.

  :raises: **ImportError** with the problem if we don't meet stem's
    requirements
  """

  major_version, minor_version = sys.version_info[0:2]

  if major_version < 2 or (major_version == 2 and minor_version < 6):
    raise ImportError('stem requires python version 2.6 or greater')


def _is_python_26():
  """
  Checks if we're running python 2.6. This isn't for users as it'll be removed
  in stem 2.0 (when python 2.6 support goes away).

  .. deprecated:: 1.8.0
     Stem 2.x will remove this method along with Python 2.x support.

  :returns: **True** if we're running python 2.6, **False** otherwise
  """

  major_version, minor_version = sys.version_info[0:2]

  return major_version == 2 and minor_version == 6


def is_python_27():
  """
  Checks if we're running python 2.7 or above (including the 3.x series).

  .. deprecated:: 1.5.0
     Stem 2.x will remove this method along with Python 2.x support.

  :returns: **True** if we meet this requirement and **False** otherwise
  """

  major_version, minor_version = sys.version_info[0:2]

  return major_version > 2 or (major_version == 2 and minor_version >= 7)


def is_python_3():
  """
  Checks if we're in the 3.0 - 3.x range.

  .. deprecated:: 1.8.0
     Stem 2.x will remove this method along with Python 2.x support.

  :returns: **True** if we meet this requirement and **False** otherwise
  """

  return sys.version_info[0] == 3


def is_pypy():
  """
  Checks if we're running PyPy.

  .. versionadded:: 1.7.0

  :returns: **True** if running pypy, **False** otherwise
  """

  return platform.python_implementation() == 'PyPy'


def is_sqlite_available():
  """
  Checks if the sqlite3 module is available. Usually this is built in, but some
  platforms such as FreeBSD and Gentoo exclude it by default.

  .. versionadded:: 1.6.0

  :returns: **True** if we can use the sqlite3 module and **False** otherwise
  """

  try:
    import sqlite3
    return True
  except ImportError:
    return False


def is_crypto_available(ed25519 = False):
  """
  Checks if the cryptography functions we use are available. This is used for
  verifying relay descriptor signatures.

  :param bool ed25519: check for `ed25519 support
    <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/>`_,
    which requires both cryptography version 2.6 and OpenSSL support

  :returns: **True** if we can use the cryptography module and **False**
    otherwise
  """

  from stem.util import log

  try:
    from cryptography.utils import int_to_bytes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    if not hasattr(rsa.RSAPrivateKey, 'sign'):
      raise ImportError()

    if ed25519:
      # The following import confirms cryptography support (ie. version 2.6+),
      # whereas ed25519_supported() checks for OpenSSL bindings.

      from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

      if not hasattr(backend, 'ed25519_supported') or not backend.ed25519_supported():
        log.log_once('stem.prereq._is_crypto_ed25519_supported', log.INFO, ED25519_UNSUPPORTED)
        return False

    return True
  except ImportError:
    log.log_once('stem.prereq.is_crypto_available', log.INFO, CRYPTO_UNAVAILABLE)
    return False


def is_zstd_available():
  """
  Checks if the `zstd module <https://pypi.org/project/zstandard/>`_ is
  available.

  .. versionadded:: 1.7.0

  :returns: **True** if we can use the zstd module and **False** otherwise
  """

  try:
    # Unfortunately the zstandard module uses the same namespace as another
    # zstd module (https://pypi.org/project/zstd/), so we need to
    # differentiate them.

    import zstd
    return hasattr(zstd, 'ZstdDecompressor')
  except ImportError:
    from stem.util import log
    log.log_once('stem.prereq.is_zstd_available', log.INFO, ZSTD_UNAVAILABLE)
    return False


def is_lzma_available():
  """
  Checks if the `lzma module <https://docs.python.org/3/library/lzma.html>`_ is
  available. This was added as a builtin in Python 3.3.

  .. versionadded:: 1.7.0

  :returns: **True** if we can use the lzma module and **False** otherwise
  """

  try:
    import lzma
    return True
  except ImportError:
    from stem.util import log
    log.log_once('stem.prereq.is_lzma_available', log.INFO, LZMA_UNAVAILABLE)
    return False


def is_mock_available():
  """
  Checks if the mock module is available. In python 3.3 and up it is a builtin
  unittest module, but before this it needed to be `installed separately
  <https://pypi.org/project/mock/>`_. Imports should be as follows....

  ::

    try:
      # added in python 3.3
      from unittest.mock import Mock
    except ImportError:
      from mock import Mock

  :returns: **True** if the mock module is available and **False** otherwise
  """

  try:
    # checks for python 3.3 version
    import unittest.mock
    return True
  except ImportError:
    pass

  try:
    import mock

    # check for mock's patch.dict() which was introduced in version 0.7.0

    if not hasattr(mock.patch, 'dict'):
      raise ImportError()

    # check for mock's new_callable argument for patch() which was introduced in version 0.8.0

    if 'new_callable' not in inspect.getfullargspec(mock.patch).args:
      raise ImportError()

    return True
  except ImportError:
    return False


def _is_lru_cache_available():
  """
  Functools added lru_cache to the standard library in Python 3.2. Prior to
  this using a bundled implementation. We're also using this with Python 3.5
  due to a buggy implementation. (:trac:`26412`)
  """

  major_version, minor_version = sys.version_info[0:2]

  if major_version == 3 and minor_version == 5:
    return False
  else:
    return hasattr(functools, 'lru_cache')


def _is_sha3_available():
  """
  Check if hashlib has sha3 support. This requires Python 3.6+ *or* the `pysha3
  module <https://github.com/tiran/pysha3>`_.
  """

  # If pysha3 is present then importing sha3 will monkey patch the methods we
  # want onto hashlib.

  if not hasattr(hashlib, 'sha3_256') or not hasattr(hashlib, 'shake_256'):
    try:
      import sha3
    except ImportError:
      pass

  return hasattr(hashlib, 'sha3_256') and hasattr(hashlib, 'shake_256')
