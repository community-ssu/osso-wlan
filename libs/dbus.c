/**
  @file dbus.c

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

  @author Johan Hedberg <johan.hedberg@nokia.com>  
  @author Janne Ylälehto <janne.ylalehto@nokia.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "../common.h"
#include "log.h"
#include "dbus.h"

static DBusConnection *_dbus_connection = NULL;

DBusConnection *get_dbus_connection(void) {
        return _dbus_connection;
}

int setup_dbus_connection(const char *service,
                          void (*handler_init)(DBusConnection *connection)) {
        DBusError derror;
        
        g_assert(_dbus_connection == NULL);

        dbus_error_init(&derror);
        _dbus_connection = dbus_bus_get(DBUS_BUS_SYSTEM, &derror);
        if (_dbus_connection == NULL) {
                DLOG_ERR("System DBus connection failed: %s", derror.message);
                dbus_error_free(&derror);
                return -1;
        }
        dbus_connection_setup_with_g_main(_dbus_connection, NULL);

        if (service) {
                int ret = dbus_bus_request_name(_dbus_connection, service, 0, 
                                                &derror);
                if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
                        DLOG_ERR("Could not aquire D-BUS name '%s' (ret: %d)",
                                 service, ret);
                        if (dbus_error_is_set(&derror)) {
                                DLOG_DEBUG("%s", derror.message);
                                dbus_error_free(&derror);
                        }
                        return -1;
                }
        }

        if (handler_init)
                handler_init(_dbus_connection);
        
        return 0;
}

void close_dbus_connection(void) {
        g_assert(_dbus_connection != NULL); 
        dbus_connection_unref(_dbus_connection);
        _dbus_connection = NULL;
}

