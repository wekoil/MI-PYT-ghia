Usage Example
=============

.. testsetup::

	from ghia import cli
	from ghia.cli import Cli

	gh = {'token': ''}
	dry = True

	rules = {}
	rules['patterns'] = {'Nejakej profik': 'any:python'}
	rules['fallback'] = {'label': 'Need assignment'}

	issue1 = {
	    'state': 'open',
	    'title': 'Python problem',
	    'body': 'python problem',
	    'labels': [],
	    'assignees': [{'login': 'Nejakej jouda'}]}

	issue2 = {
	    'state': 'open',
	    'title': 'Bug',
	    'body': 'Mas tam bug troubo!',
	    'labels': [],
	    'assignees': []}

	reposlug = 'user/repo'
	url1 = 'https://github.com/user/repo/issues/1'
	url2 = 'https://github.com/user/repo/issues/2'

Rules.cfg

.. code:: ini

	[patterns]
	Nejakej profik=any:Python

	[fallback]
	label=Need assignment

Issues:

.. code:: python

	issue1 = {
	    'state': 'open',
	    'title': 'Python problem',
	    'body': 'python problem',
	    'labels': [],
	    'assignees': [{'login': 'Nejakej jouda'}]}

	issue2 = {
	    'state': 'open',
	    'title': 'Bug',
	    'body': 'Mas tam bug troubo!',
	    'labels': [],
	    'assignees': []}

Doctest example:

.. testcode::

	Cli.print_issue(reposlug, 1, url1)
	cli.assign_issue(issue1, rules, 'change', dry, gh, reposlug)

This would output:

.. testoutput::

    -> user/repo#1 (https://github.com/user/repo/issues/1)
       - Nejakej jouda
       + Nejakej profik





.. testcode::

	Cli.print_issue(reposlug, 2, url2)
	cli.assign_issue(issue2, rules, 'append', dry, gh, reposlug)

This would output:

.. testoutput::

    -> user/repo#2 (https://github.com/user/repo/issues/2)
       FALLBACK: added label "Need assignment"