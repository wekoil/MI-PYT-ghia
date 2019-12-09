.. ghia documentation master file, created by
   sphinx-quickstart on Sat Dec  7 11:58:02 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Github issue auto assigner tool
###############################

GHIA is python package which can be used to auto assign issues on GitHub. It has CLI mode and web mode.

.. toctree::
   :maxdepth: 2
   :caption: Contents


   config
   github
   cli
   web
   api
   usage

Installation
------------
from test pypi

.. code-block:: bash

  $ pip install -i https://test.pypi.org/simple/ ghia-michaj24

from package

.. code-block:: bash

    $ pip install .

Usage
-----

CLI mode 
________

.. code-block:: bash

  $ python -m ghia [OPTIONS] REPOSLUG

Example

.. code-block:: bash

  $ python -m ghia -a auth.cfg -r rules.cfg user/repo

Web mode
________

To start web mode you need to specify where is flask file located

.. code-block:: bash

  $ export FLASK_APP=ghia/web.py
  $ flask run


Documentation
-------------

Go to the ``docs`` dir and build html documentation.

.. code-block:: bash

  $ cd docs
  $ make html

Author

  Jan Michal michaj24@fit.cvut.cz

License

  MIT License




