/**
  @file dbus-helper.c

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

  @author Janne Ylalehto <janne.ylalehto@nokia.com>
  @author Johan Hedberg <johan.hedberg@nokia.com>  

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
#include <osso-ic-dbus.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#ifdef USE_MCE_MODE
#include <mce/dbus-names.h>
#endif
#include "log.h"
#include "dbus-helper.h"
#include "../common.h"

DBusMessage *new_dbus_signal(const char *path,
                             const char *interface,
                             const char *name,
                             const char *destination) {
        DBusMessage *signal;

        signal = dbus_message_new_signal(path, interface, name);
        if (signal == NULL) {
                die("Out of memory during dbus_message_new_error()");
        }

        if (destination) {
                if (!dbus_message_set_destination(signal, destination)) {
                        die("Out of memory during dbus_message_set_destination()");
                }
        }

        dbus_message_set_no_reply(signal, TRUE);

        return signal;
}

DBusMessage *new_dbus_method_call(const char *service,
                                  const char *path,
                                  const char *interface,
                                  const char *method) {
        DBusMessage *message;

        message = dbus_message_new_method_call(service, path, interface, method);
        if (message == NULL) {
                die("Out of memory during dbus_message_new_method_call()");
        }

        return message;
}

DBusMessage *new_dbus_method_return(DBusMessage *message) {
        DBusMessage *reply;

        reply = dbus_message_new_method_return(message);
        if (reply == NULL) {
                die("Out of memory during dbus_message_new_method_return()");
        }

        return reply;
}

DBusMessage *new_dbus_error(DBusMessage *message, const char *name) {
        DBusMessage *error;

        error = dbus_message_new_error(message, name, NULL);
        if (error == NULL) {
                die("Out of memory during dbus_message_new_error()");
        }

        return error;
}

int send_and_unref(DBusConnection *connection, DBusMessage *message) {
        if (!dbus_connection_send(connection, message, NULL)) {
                dbus_message_unref(message);
                return -1;
        }

        dbus_connection_flush(connection);
        dbus_message_unref(message);

        return 0;
}

int send_invalid_args(DBusConnection *connection, DBusMessage *message) {
        DBusMessage *reply;

        reply = new_dbus_error(message, DBUS_ERROR_INVALID_ARGS);

        return send_and_unref(connection, reply);
}

void append_dbus_args(DBusMessage *message, int first_arg_type, ...) {
        dbus_bool_t ret;
        va_list ap;

        va_start(ap, first_arg_type);
        ret = dbus_message_append_args_valist(message, first_arg_type, ap);
        va_end(ap);

        if (ret == FALSE) {
                die("dbus_message_append_args failed");
        }
}
#ifdef USE_MCE_COVER
static DBusHandlerResult cover_filter(DBusConnection *connection,
                                      DBusMessage    *message,
                                      void (*cover_cb)(void)) {

        if (!dbus_message_is_signal(message,
                                    KEVENT_DBUS_IF,
                                    COVER_CHANGE)) {
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        
        cover_cb();
        
        return DBUS_HANDLER_RESULT_HANDLED;
}
#endif
gchar *get_device_mode(DBusConnection *connection) {
#ifdef USE_MCE_MODE
        DBusError derror;
        char *mode, *ret;
        DBusMessage *message, *reply;

        message = new_dbus_method_call(MCE_SERVICE,
                                       MCE_REQUEST_PATH,
                                       MCE_REQUEST_IF,
                                       MCE_DEVICE_MODE_GET);

        dbus_error_init(&derror);
        reply = dbus_connection_send_with_reply_and_block(connection,
                                                          message,
                                                          -1,
                                                          &derror);
        dbus_message_unref(message);
        if (dbus_error_is_set(&derror)) {
                DLOG_ERR("Getting device mode from MCE failed: %s", derror.message);
                dbus_error_free(&derror);
                return NULL;
        }
        if (!dbus_message_get_args(reply, NULL,
                                   DBUS_TYPE_STRING, &mode,
                                   DBUS_TYPE_INVALID)) {
                DLOG_ERR("Invalid arguments for MCE req_device_mode reply");
                dbus_message_unref(reply);
                return NULL;
        }
        
        ret = g_strdup(mode);
        
        dbus_message_unref(reply);
        
        return ret;
#else /* USE_MCE_MODE */
        return g_strdup("normal");
#endif
}

#ifdef USE_MCE_MODE
gboolean add_mode_listener(DBusConnection *connection) {

#ifdef ACTIVITY_CHECK
        dbus_bus_add_match(connection, 
                           "interface=" MCE_SIGNAL_IF
                           ",member=" MCE_INACTIVITY_SIG, NULL);
        dbus_bus_add_match(connection, 
                           "interface=" MCE_SIGNAL_IF
                           ",member=" MCE_DEVICE_MODE_SIG, NULL);
#else
        dbus_bus_add_match(connection, 
                           "interface=" MCE_SIGNAL_IF 
                           ",member=" MCE_DEVICE_MODE_SIG, NULL);        

#endif
        return dbus_connection_add_filter(connection, (DBusHandleMessageFunction)wlancond_req_handler, NULL, NULL);
}
#endif
#ifdef USE_MCE_COVER
gboolean add_cover_listener(DBusConnection *connection,
                            void (*cover_cb)(void)) {

        dbus_bus_add_match(connection,
                           "interface=" KEVENT_DBUS_IF
                           ",member=change"
                           ",path=" COVER_SWITCH_PATH, NULL);

        return dbus_connection_add_filter(
                connection,
                (DBusHandleMessageFunction)cover_filter,
                cover_cb,
                NULL);
}
#endif

gboolean add_icd_listener(DBusConnection *connection) {
        dbus_bus_add_match(connection, 
                           "interface=" ICD_DBUS_INTERFACE
                           ",member=" ICD_STATUS_CHANGED_SIG, NULL);        
        
        return dbus_connection_add_filter(connection, (DBusHandleMessageFunction)wlancond_req_handler, NULL, NULL);
}
