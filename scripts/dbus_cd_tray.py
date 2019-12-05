#!/usr/bin/env python
# coding: utf-8
# Date:12/05/19

# Source : https://dbus.freedesktop.org/doc/dbus-python/tutorial.html

import dbus

# Connect to bus daemon
session_bus = dbus.SessionBus()
system_bus = dbus.SystemBus()


main()

if __name__ == '__main__':
    main()
