# Copyright 2011-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Utilities for working with the terminal.

**Module Overview:**

::

  encoding - provides the ANSI escape sequence for a terminal attribute
  format - wrap text with ANSI for the given colors or attributes

.. data:: Color (enum)
.. data:: BgColor (enum)

  Foreground or background terminal colors.

  =========== ===========
  Color       Description
  =========== ===========
  **BLACK**   black color
  **BLUE**    blue color
  **CYAN**    cyan color
  **GREEN**   green color
  **MAGENTA** magenta color
  **RED**     red color
  **WHITE**   white color
  **YELLOW**  yellow color
  =========== ===========

.. data:: Attr (enum)

  Terminal text attributes.

  .. versionchanged:: 1.5.0
     Added the LINES attribute.

  =================== ===========
  Attr                Description
  =================== ===========
  **BOLD**            heavy typeface
  **HIGHLIGHT**       inverted foreground and background
  **UNDERLINE**       underlined text
  **READLINE_ESCAPE** wrap encodings in `RL_PROMPT_START_IGNORE and RL_PROMPT_END_IGNORE sequences <https://stackoverflow.com/questions/9468435/look-how-to-fix-column-calculation-in-python-readline-if-use-color-prompt>`_
  **LINES**           formats lines individually
  =================== ===========
"""

import stem.util.enum
import stem.util.str_tools

TERM_COLORS = ('BLACK', 'RED', 'GREEN', 'YELLOW', 'BLUE', 'MAGENTA', 'CYAN', 'WHITE')

# DISABLE_COLOR_SUPPORT is *not* being vended to Stem users. This is likely to
# go away if I can think of a more graceful method for color toggling.

DISABLE_COLOR_SUPPORT = False

Color = stem.util.enum.Enum(*TERM_COLORS)
BgColor = stem.util.enum.Enum(*['BG_' + color for color in TERM_COLORS])
Attr = stem.util.enum.Enum('BOLD', 'UNDERLINE', 'HIGHLIGHT', 'READLINE_ESCAPE', 'LINES')

# mappings of terminal attribute enums to their ANSI escape encoding
FG_ENCODING = dict([(list(Color)[i], str(30 + i)) for i in range(8)])
BG_ENCODING = dict([(list(BgColor)[i], str(40 + i)) for i in range(8)])
ATTR_ENCODING = {Attr.BOLD: '1', Attr.UNDERLINE: '4', Attr.HIGHLIGHT: '7'}

CSI = '\x1B[%sm'
RESET = CSI % '0'


def encoding(*attrs):
  """
  Provides the ANSI escape sequence for these terminal color or attributes.

  .. versionadded:: 1.5.0

  :param list attr: :data:`~stem.util.terminal.Color`,
    :data:`~stem.util.terminal.BgColor`, or :data:`~stem.util.terminal.Attr` to
    provide an ecoding for

  :returns: **str** of the ANSI escape sequence, **None** no attributes are
    recognized
  """

  term_encodings = []

  for attr in attrs:
    # TODO: Account for an earlier misspelled attribute. This should be dropped
    # in Stem. 2.0.x.

    if attr == 'HILIGHT':
      attr = 'HIGHLIGHT'

    attr = stem.util.str_tools._to_camel_case(attr)
    term_encoding = FG_ENCODING.get(attr, None)
    term_encoding = BG_ENCODING.get(attr, term_encoding)
    term_encoding = ATTR_ENCODING.get(attr, term_encoding)

    if term_encoding:
      term_encodings.append(term_encoding)

  if term_encodings:
    return CSI % ';'.join(term_encodings)


def format(msg, *attr):
  """
  Simple terminal text formatting using `ANSI escape sequences
  <https://en.wikipedia.org/wiki/ANSI_escape_code#CSI_codes>`_.
  The following are some toolkits providing similar capabilities:

  * `django.utils.termcolors <https://github.com/django/django/blob/master/django/utils/termcolors.py>`_
  * `termcolor <https://pypi.org/project/termcolor/>`_
  * `colorama <https://pypi.org/project/colorama/>`_

  .. versionchanged:: 1.6.0
     Normalized return value to be unicode to better support python 2/3
     compatibility.

  :param str msg: string to be formatted
  :param str attr: text attributes, this can be :data:`~stem.util.term.Color`,
    :data:`~stem.util.term.BgColor`, or :data:`~stem.util.term.Attr` enums
    and are case insensitive (so strings like 'red' are fine)

  :returns: **unicode** wrapped with ANSI escape encodings, starting with the given
    attributes and ending with a reset
  """

  msg = stem.util.str_tools._to_unicode(msg)

  if DISABLE_COLOR_SUPPORT:
    return msg

  if Attr.LINES in attr:
    attr = list(attr)
    attr.remove(Attr.LINES)
    lines = [format(line, *attr) for line in msg.split('\n')]
    return '\n'.join(lines)

  # if we have reset sequences in the message then apply our attributes
  # after each of them

  if RESET in msg:
    return ''.join([format(comp, *attr) for comp in msg.split(RESET)])

  prefix, suffix = encoding(*attr), RESET

  if prefix:
    if Attr.READLINE_ESCAPE in attr:
      prefix = '\001%s\002' % prefix
      suffix = '\001%s\002' % suffix

    return prefix + msg + suffix
  else:
    return msg
