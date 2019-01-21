Feature Options
===============

Password Strength
-----------------

By default, when a user signs up through Native Authenticator there is no password strength verification. If you need this, you can add a verification for password strength by adding the following parameter to your config file:

.. code-block:: python

    c.Authenticator.check_password_strength = True

The Authenticator will verify if the password has at least 8 characters and if it not a common password. The list of the common passwords it checks is available `on this link <https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt>`_ >._  


By default the Authenticator will verify if the password is at least 8 characters long. If you, however, need something different, you can change the minimum size adding this parameter to the config file:

.. code-block:: python

    c.Authenticator.password_length = 10


Block users after failed logins
-------------------------------

One thing that can make systems more safe is to block users after a number of failed logins. With Native Authenticator you can add this feature by adding `allowed_failed_logins` on the config file. The default is 0, which means that the system will not block users ever.

.. code-block:: python

    c.Authenticator.allowed_failed_logins = 3

You can also define the number of seconds a user must wait before trying again. The default value is 600 seconds.

.. code-block:: python

    c.Authenticator.secs_before_next_try = 1200
