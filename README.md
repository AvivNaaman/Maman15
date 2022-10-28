# Secure File Server
> This project was originally built in the scope of OpenU course 20937.

## Server
Is written in Python 3.8+. 

It depends on PyCryptoDome.

_Hint: use `pip install -r server/requirement.txt` to auto install._

## Client 
Is written in CPP 17+, and currently only run on x86 (Win32) only build config due to dependency management.

It depends on:

* [Boost](boost.org) - asio
* [CryptoPP](cryptopp.com)


_Hint: use [vcpkg](vcpkg.io) package manager to install them (boost)_