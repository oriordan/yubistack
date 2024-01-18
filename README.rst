YubiKit
=========

This repo borrows from `yubistack <https://github.com/oriordan/yubistack>`_

.. image:: https://github.com/timhilliard/yubikit/actions/workflows/main.yml/badge.svg?branch=main
   :target: https://github.com/timhilliard/yubikit/actions/workflows/main.yml?branch=main

YubiKit provides a python re-implementation of:

* `yubikey-val <https://github.com/Yubico/yubikey-val>`_: YubiKey validation server
* `yubikey-ksm <https://github.com/Yubico/yubikey-ksm>`_: YubiKey key storage module

YubiKit is designed to be a replacement for yubistack, with the following differences:

* written against modern python (3.8+)
* uses async methods
* uses Cryptodome instead of PyCrypto
* uses GitHub Actions for CI
* no wsgi support, only libs for interacting with the validation server and ksm

Installation
------------

To install yubistak, simply:

.. code-block:: bash

    $ sudo pip install yubikit

Configuration
-------------

The configuration file path is read from YUBIKIT_SETTINGS environment variable, otherwise defaults
to /etc/yubikit.conf. You can find a sample config in the repo.
