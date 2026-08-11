# Copyright 2015-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for testing.

Our **stylistic_issues**, **pyflakes_issues**, and **type_check_issues**
respect a 'exclude_paths' in our test config, excluding any absolute paths
matching those regexes. Issue strings can start or end with an asterisk
to match just against the prefix or suffix. For instance...

::

  exclude_paths .*/stem/test/data/.*

.. versionadded:: 1.2.0

::

  TimedTestRunner - test runner that tracks test runtimes
  test_runtimes - provides runtime of tests excuted through TimedTestRunners
  clean_orphaned_pyc - delete *.pyc files without corresponding *.py

  is_pyflakes_available - checks if pyflakes is available
  is_pycodestyle_available - checks if pycodestyle is available

  pyflakes_issues - static checks for problems via pyflakes
  stylistic_issues - checks for PEP8 and other stylistic issues
"""

import collections
import linecache
import multiprocessing
import os
import re
import threading
import time
import traceback
import unittest

import stem.prereq
import stem.util.conf
import stem.util.enum
import stem.util.system

CONFIG = stem.util.conf.config_dict('test', {
  'pep8.ignore': [],  # TODO: drop with stem 2.x, legacy alias for pycodestyle.ignore
  'pycodestyle.ignore': [],
  'pyflakes.ignore': [],
  'exclude_paths': [],
})

TEST_RUNTIMES = {}
ASYNC_TESTS = {}

AsyncStatus = stem.util.enum.UppercaseEnum('PENDING', 'RUNNING', 'FINISHED')
AsyncResult = collections.namedtuple('AsyncResult', 'type msg')

# TODO: Providing a copy of SkipTest that works with python 2.6. This will be
# dropped when we remove python 2.6 support.

if stem.prereq._is_python_26():
  class SkipTest(Exception):
    'Notes that the test was skipped.'
else:
  SkipTest = unittest.case.SkipTest


def assert_equal(expected, actual, msg = None):
  """
  Function form of a TestCase's assertEqual.

  .. versionadded:: 1.6.0

  :param object expected: expected value
  :param object actual: actual value
  :param str msg: message if assertion fails

  :raises: **AssertionError** if values aren't equal
  """

  if expected != actual:
    raise AssertionError("Expected '%s' but was '%s'" % (expected, actual) if msg is None else msg)


def assert_in(expected, actual, msg = None):
  """
  Asserts that a given value is within this content.

  .. versionadded:: 1.6.0

  :param object expected: expected value
  :param object actual: actual value
  :param str msg: message if assertion fails

  :raises: **AssertionError** if the expected value isn't in the actual
  """

  if expected not in actual:
    raise AssertionError("Expected '%s' to be within '%s'" % (expected, actual) if msg is None else msg)


def skip(msg):
  """
  Function form of a TestCase's skipTest.

  .. versionadded:: 1.6.0

  :param str msg: reason test is being skipped

  :raises: **unittest.case.SkipTest** for this reason
  """

  raise SkipTest(msg)


def asynchronous(func):
  test = stem.util.test_tools.AsyncTest(func)
  ASYNC_TESTS[test.name] = test
  return test.method


class AsyncTest(object):
  """
  Test that's run asychronously. These are functions (no self reference)
  performed like the following...

  ::

    class MyTest(unittest.TestCase):
      @staticmethod
      def run_tests():
        MyTest.test_addition = stem.util.test_tools.AsyncTest(MyTest.test_addition).method

      @staticmethod
      def test_addition():
        if 1 + 1 != 2:
          raise AssertionError('tisk, tisk')

    MyTest.run()

  .. versionadded:: 1.6.0
  """

  def __init__(self, runner, args = None, threaded = False):
    self.name = '%s.%s' % (runner.__module__, runner.__name__)

    self._runner = runner
    self._runner_args = args
    self._threaded = threaded

    self.method = lambda test: self.result(test)  # method that can be mixed into TestCases

    self._process = None
    self._process_pipe = None
    self._process_lock = threading.RLock()

    self._result = None
    self._status = AsyncStatus.PENDING

  def run(self, *runner_args, **kwargs):
    if stem.prereq._is_python_26():
      return  # not supported under python 2.6

    def _wrapper(conn, runner, args):
      os.nice(12)

      try:
        runner(*args) if args else runner()
        conn.send(AsyncResult('success', None))
      except AssertionError as exc:
        conn.send(AsyncResult('failure', str(exc)))
      except SkipTest as exc:
        conn.send(AsyncResult('skipped', str(exc)))
      except:
        conn.send(AsyncResult('error', traceback.format_exc()))
      finally:
        conn.close()

    with self._process_lock:
      if self._status == AsyncStatus.PENDING:
        if runner_args:
          self._runner_args = runner_args

        if 'threaded' in kwargs:
          self._threaded = kwargs['threaded']

        self._process_pipe, child_pipe = multiprocessing.Pipe()

        if self._threaded:
          self._process = threading.Thread(
            target = _wrapper,
            args = (child_pipe, self._runner, self._runner_args),
            name = 'Background test of %s' % self.name,
          )

          self._process.setDaemon(True)
        else:
          self._process = multiprocessing.Process(target = _wrapper, args = (child_pipe, self._runner, self._runner_args))

        self._process.start()
        self._status = AsyncStatus.RUNNING

  def pid(self):
    with self._process_lock:
      return self._process.pid if (self._process and not self._threaded) else None

  def join(self):
    self.result(None)

  def result(self, test):
    if stem.prereq._is_python_26():
      return  # not supported under python 2.6

    with self._process_lock:
      if self._status == AsyncStatus.PENDING:
        self.run()

      if self._status == AsyncStatus.RUNNING:
        self._result = self._process_pipe.recv()
        self._process.join()
        self._status = AsyncStatus.FINISHED

      if test and self._result.type == 'failure':
        test.fail(self._result.msg)
      elif test and self._result.type == 'error':
        test.fail(self._result.msg)
      elif test and self._result.type == 'skipped':
        test.skipTest(self._result.msg)


class Issue(collections.namedtuple('Issue', ['line_number', 'message', 'line'])):
  """
  Issue encountered by pyflakes or pycodestyle.

  :var int line_number: line number the issue occured on
  :var str message: description of the issue
  :var str line: content of the line the issue is about
  """


class TimedTestRunner(unittest.TextTestRunner):
  """
  Test runner that tracks the runtime of individual tests. When tests are run
  with this their runtimes are made available through
  :func:`stem.util.test_tools.test_runtimes`.

  .. versionadded:: 1.6.0
  """

  def run(self, test):
    for t in test._tests:
      original_type = type(t)

      class _TestWrapper(original_type):
        def run(self, result = None):
          start_time = time.time()
          result = super(type(self), self).run(result)
          TEST_RUNTIMES[self.id()] = time.time() - start_time
          return result

        # TODO: remove and drop unnecessary 'returns' when dropping python 2.6
        # support

        def skipTest(self, message):
          if not stem.prereq._is_python_26():
            return super(original_type, self).skipTest(message)

        # TODO: remove when dropping python 2.6 support

        def assertItemsEqual(self, expected, actual):
          if stem.prereq._is_python_26():
            self.assertEqual(set(expected), set(actual))
          else:
            return super(original_type, self).assertItemsEqual(expected, actual)

        def assertRaisesWith(self, exc_type, exc_msg, func, *args, **kwargs):
          """
          Asserts the given invokation raises the expected excepiton. This is
          similar to unittest's assertRaises and assertRaisesRegexp, but checks
          for an exact match.

          This method is **not** being vended to external users and may be
          changed without notice. If you want this method to be part of our
          vended API then please let us know.
          """

          return self.assertRaisesRegexp(exc_type, '^%s$' % re.escape(exc_msg), func, *args, **kwargs)

        def assertRaisesRegexp(self, exc_type, exc_msg, func, *args, **kwargs):
          if stem.prereq._is_python_26():
            try:
              func(*args, **kwargs)
              self.fail('Expected a %s to be raised but nothing was' % exc_type)
            except exc_type as exc:
              self.assertTrue(re.search(exc_msg, str(exc), re.MULTILINE))
          else:
            return super(original_type, self).assertRaisesRegexp(exc_type, exc_msg, func, *args, **kwargs)

        def id(self):
          return '%s.%s.%s' % (original_type.__module__, original_type.__name__, self._testMethodName)

        def __str__(self):
          return '%s (%s.%s)' % (self._testMethodName, original_type.__module__, original_type.__name__)

      t.__class__ = _TestWrapper

    return super(TimedTestRunner, self).run(test)


def test_runtimes():
  """
  Provides the runtimes of tests executed through TimedTestRunners.

  :returns: **dict** of fully qualified test names to floats for the runtime in
    seconds

  .. versionadded:: 1.6.0
  """

  return dict(TEST_RUNTIMES)


def clean_orphaned_pyc(paths):
  """
  Deletes any file with a \\*.pyc extention without a corresponding \\*.py. This
  helps to address a common gotcha when deleting python files...

  * You delete module 'foo.py' and run the tests to ensure that you haven't
    broken anything. They pass, however there *are* still some 'import foo'
    statements that still work because the bytecode (foo.pyc) is still around.

  * You push your change.

  * Another developer clones our repository and is confused because we have a
    bunch of ImportErrors.

  :param list paths: paths to search for orphaned pyc files

  :returns: list of absolute paths that were deleted
  """

  orphaned_pyc = []

  for path in paths:
    for pyc_path in stem.util.system.files_with_suffix(path, '.pyc'):
      py_path = pyc_path[:-1]

      # If we're running python 3 then the *.pyc files are no longer bundled
      # with the *.py. Rather, they're in a __pycache__ directory.

      pycache = '%s__pycache__%s' % (os.path.sep, os.path.sep)

      if pycache in pyc_path:
        directory, pycache_filename = pyc_path.split(pycache, 1)

        if not pycache_filename.endswith('.pyc'):
          continue  # should look like 'test_tools.cpython-32.pyc'

        py_path = os.path.join(directory, pycache_filename.split('.')[0] + '.py')

      if not os.path.exists(py_path):
        orphaned_pyc.append(pyc_path)
        os.remove(pyc_path)

  return orphaned_pyc


def is_pyflakes_available():
  """
  Checks if pyflakes is availalbe.

  :returns: **True** if we can use pyflakes and **False** otherwise
  """

  return _module_exists('pyflakes.api') and _module_exists('pyflakes.reporter')


def is_pycodestyle_available():
  """
  Checks if pycodestyle is availalbe.

  :returns: **True** if we can use pycodestyle and **False** otherwise
  """

  if _module_exists('pycodestyle'):
    import pycodestyle
  elif _module_exists('pep8'):
    import pep8 as pycodestyle
  else:
    return False

  return hasattr(pycodestyle, 'BaseReport')


def stylistic_issues(paths, check_newlines = False, check_exception_keyword = False, prefer_single_quotes = False):
  """
  Checks for stylistic issues that are an issue according to the parts of PEP8
  we conform to. You can suppress pycodestyle issues by making a 'test'
  configuration that sets 'pycodestyle.ignore'.

  For example, with a 'test/settings.cfg' of...

  ::

    # pycodestyle compliance issues that we're ignoreing...
    #
    # * E111 and E121 four space indentations
    # * E501 line is over 79 characters

    pycodestyle.ignore E111
    pycodestyle.ignore E121
    pycodestyle.ignore E501

    pycodestyle.ignore run_tests.py => E402: import stem.util.enum

  ... you can then run tests with...

  ::

    import stem.util.conf

    test_config = stem.util.conf.get_config('test')
    test_config.load('test/settings.cfg')

    issues = stylistic_issues('my_project')

  .. versionchanged:: 1.3.0
     Renamed from get_stylistic_issues() to stylistic_issues(). The old name
     still works as an alias, but will be dropped in Stem version 2.0.0.

  .. versionchanged:: 1.4.0
     Changing tuples in return value to be namedtuple instances, and adding the
     line that had the issue.

  .. versionchanged:: 1.4.0
     Added the prefer_single_quotes option.

  .. versionchanged:: 1.6.0
     Changed 'pycodestyle.ignore' code snippets to only need to match against
     the prefix.

  :param list paths: paths to search for stylistic issues
  :param bool check_newlines: check that we have standard newlines (\\n), not
    windows (\\r\\n) nor classic mac (\\r)
  :param bool check_exception_keyword: checks that we're using 'as' for
    exceptions rather than a comma
  :param bool prefer_single_quotes: standardize on using single rather than
    double quotes for strings, when reasonable

  :returns: dict of paths list of :class:`stem.util.test_tools.Issue` instances
  """

  issues = {}

  ignore_rules = []
  ignore_for_file = []
  ignore_all_for_files = []

  for rule in CONFIG['pycodestyle.ignore'] + CONFIG['pep8.ignore']:
    if '=>' in rule:
      path, rule_entry = rule.split('=>', 1)

      if ':' in rule_entry:
        rule, code = rule_entry.split(':', 1)
        ignore_for_file.append((path.strip(), rule.strip(), code.strip()))
      elif rule_entry.strip() == '*':
        ignore_all_for_files.append(path.strip())
    else:
      ignore_rules.append(rule)

  def is_ignored(path, rule, code):
    for ignored_path, ignored_rule, ignored_code in ignore_for_file:
      if path.endswith(ignored_path) and ignored_rule == rule and code.strip().startswith(ignored_code):
        return True

    for ignored_path in ignore_all_for_files:
      if path.endswith(ignored_path):
        return True

    return False

  if is_pycodestyle_available():
    if _module_exists('pep8'):
      import pep8 as pycodestyle
    else:
      import pycodestyle

    class StyleReport(pycodestyle.BaseReport):
      def init_file(self, filename, lines, expected, line_offset):
        super(StyleReport, self).init_file(filename, lines, expected, line_offset)

        if not check_newlines and not check_exception_keyword and not prefer_single_quotes:
          return

        is_block_comment = False

        for ignored_path in ignore_all_for_files:
          if filename.endswith(ignored_path):
            return

        for index, line in enumerate(lines):
          content = line.split('#', 1)[0].strip()

          if check_newlines and '\r' in line:
            issues.setdefault(filename, []).append(Issue(index + 1, 'contains a windows newline', line))

          if not content:
            continue  # blank line

          if '"""' in content:
            is_block_comment = not is_block_comment

          if check_exception_keyword and content.startswith('except') and content.endswith(', exc:'):
            # Python 2.6 - 2.7 supports two forms for exceptions...
            #
            #   except ValueError, exc:
            #   except ValueError as exc:
            #
            # The former is the old method and no longer supported in python 3
            # going forward.

            # TODO: This check only works if the exception variable is called
            # 'exc'. We should generalize this via a regex so other names work
            # too.

            issues.setdefault(filename, []).append(Issue(index + 1, "except clause should use 'as', not comma", line))

          if prefer_single_quotes and not is_block_comment:
            if '"' in content and "'" not in content and '"""' not in content and not content.endswith('\\'):
              # Checking if the line already has any single quotes since that
              # usually means double quotes are preferable for the content (for
              # instance "I'm hungry"). Also checking for '\' at the end since
              # that can indicate a multi-line string.

              issues.setdefault(filename, []).append(Issue(index + 1, 'use single rather than double quotes', line))

      def error(self, line_number, offset, text, check):
        code = super(StyleReport, self).error(line_number, offset, text, check)

        if code:
          line = linecache.getline(self.filename, line_number)

          if not is_ignored(self.filename, code, line):
            issues.setdefault(self.filename, []).append(Issue(line_number, text, line))

    style_checker = pycodestyle.StyleGuide(ignore = ignore_rules, reporter = StyleReport)
    style_checker.check_files(list(_python_files(paths)))

  return issues


def pyflakes_issues(paths):
  """
  Performs static checks via pyflakes. False positives can be ignored via
  'pyflakes.ignore' entries in our 'test' config. For instance...

  ::

    pyflakes.ignore stem/util/test_tools.py => 'pyflakes' imported but unused
    pyflakes.ignore stem/util/test_tools.py => 'pycodestyle' imported but unused

  .. versionchanged:: 1.3.0
     Renamed from get_pyflakes_issues() to pyflakes_issues(). The old name
     still works as an alias, but will be dropped in Stem version 2.0.0.

  .. versionchanged:: 1.4.0
     Changing tuples in return value to be namedtuple instances, and adding the
     line that had the issue.

  .. versionchanged:: 1.5.0
     Support matching against prefix or suffix issue strings.

  :param list paths: paths to search for problems

  :returns: dict of paths list of :class:`stem.util.test_tools.Issue` instances
  """

  issues = {}

  if is_pyflakes_available():
    import pyflakes.api
    import pyflakes.reporter

    class Reporter(pyflakes.reporter.Reporter):
      def __init__(self):
        self._ignored_issues = {}

        for line in CONFIG['pyflakes.ignore']:
          path, issue = line.split('=>')
          self._ignored_issues.setdefault(path.strip(), []).append(issue.strip())

      def unexpectedError(self, filename, msg):
        self._register_issue(filename, None, msg, None)

      def syntaxError(self, filename, msg, lineno, offset, text):
        self._register_issue(filename, lineno, msg, text)

      def flake(self, msg):
        self._register_issue(msg.filename, msg.lineno, msg.message % msg.message_args, None)

      def _is_ignored(self, path, issue):
        # Paths in pyflakes_ignore are relative, so we need to check to see if our
        # path ends with any of them.

        for ignored_path, ignored_issues in self._ignored_issues.items():
          if path.endswith(ignored_path):
            if issue in ignored_issues:
              return True

            for prefix in [i[:1] for i in ignored_issues if i.endswith('*')]:
              if issue.startswith(prefix):
                return True

            for suffix in [i[1:] for i in ignored_issues if i.startswith('*')]:
              if issue.endswith(suffix):
                return True

        return False

      def _register_issue(self, path, line_number, issue, line):
        if not self._is_ignored(path, issue):
          if path and line_number and not line:
            line = linecache.getline(path, line_number).strip()

          issues.setdefault(path, []).append(Issue(line_number, issue, line))

    reporter = Reporter()

    for path in _python_files(paths):
      pyflakes.api.checkPath(path, reporter)

  return issues


def _module_exists(module_name):
  """
  Checks if a module exists.

  :param str module_name: module to check existance of

  :returns: **True** if module exists and **False** otherwise
  """

  try:
    __import__(module_name)
    return True
  except ImportError:
    return False


def _python_files(paths):
  for path in paths:
    for file_path in stem.util.system.files_with_suffix(path, '.py'):
      skip = False

      for exclude_path in CONFIG['exclude_paths']:
        if re.match(exclude_path, file_path):
          skip = True
          break

      if not skip:
        yield file_path


# TODO: drop with stem 2.x
# We renamed our methods to drop a redundant 'get_*' prefix, so alias the old
# names for backward compatability, and account for pep8 being renamed to
# pycodestyle.

get_stylistic_issues = stylistic_issues
get_pyflakes_issues = pyflakes_issues
is_pep8_available = is_pycodestyle_available
