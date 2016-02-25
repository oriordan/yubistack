YubiStack
=========

YubiStack provides a python re-implementation of:

* `yubiauth <https://github.com/Yubico/yubiauth>`_: Authentication client with a simple user management system
* `yubikey-val <https://github.com/Yubico/yubikey-val>`_: YubiKey validation server
* `yubikey-ksm <https://github.com/Yubico/yubikey-ksm>`_: YubiKey key storage module

NOTE: Only the authentication part is implemented from yubiauth, the user management system is NOT.

Installation
------------

To install yubistak, simply:

.. code-block:: bash

    $ sudo pip install yubistack

Configuration
-------------

The configuration file path is read from YUBISTACK_SETTINGS environment variable, otherwise defaults
to /etc/yubistack.conf. You can find a sample config in the repo.
