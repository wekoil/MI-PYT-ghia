Web
===

This module contains flask webserver.

Module can proccess webhook sent from github to auto-assign issue from submited configuration rules. It can verify webhooks signature to be sure it realy came from GitHub.

On the index site of web is printed specified rules and user recognised from used token.

Webhook secret
--------------

To make sure that webhook was realy sent from GitHub you need to set secret on GitHub and set it via configuration file to web server. How you can set webhook for you repo refer `here <https://developer.github.com/webhooks/creating/>`_.

Strategy
--------

Webhook usage only support `append` strategy. See :ref:`strategy`.