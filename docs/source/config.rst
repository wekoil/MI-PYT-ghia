Configuration
=============

GitHub Token
------------

Token is required for communication with GitHub. You can generate one `here <https://github.com/settings/tokens>`_. Make sure you do **NOT** make your token public.

Configuration files
-------------------

Two files are required. One for authentication on GitHub and second one for assignment rules. Both have to be written in `config parser <https://docs.python.org/3/library/configparser.html>`_ format.

Examples
________

auth.cfg

.. code:: ini

	[github]
	token=xxxxxxxxxx
	secret=xxxxxxxxx

rules.cfg

.. code:: ini

	[patterns]
	user1=
	    title:dummy
	    text:protocol
	    text:http[s]{0,1}://localhost:[0-9]{2,5}
	    label:^(network|networking)$
	user2=any:Python

	[fallback]
	label=Need assignment

Rules
-----

Rules start with `title`, `text`, `label` or `any`. Following with regular expresion. If rule match with some issue it will set corresponding user/label depending on strategy.

.. _strategy:

Strategy
________

You can set up strategy with param -s `append` (which is default), `set` or `change`. With `append` there are only set up next assignees due to rules. `Set` will set up assignees only when they were empty. `Change` will change assignees to only match rules and unset those who do not match rules.

Dry run
_______

With param `-d` module will not change anything on GitHub but only log changes.