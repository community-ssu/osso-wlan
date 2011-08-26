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
#include "../dbus-handler.h"

#define OUT_OF_MEMORY_STR "Out of memory"

DBusMessage *new_dbus_signal(const char *path,
		const char *interface,
		const char *name,
		const char *destination) {
	DBusMessage *signal;

	signal = dbus_message_new_signal(path, interface, name);
	if (signal == NULL) {
		die(OUT_OF_MEMORY_STR);
	}

	if (destination) {
		if (!dbus_message_set_destination(signal, destination)) {
			die(OUT_OF_MEMORY_STR);
		}
	}

	dbus_message_set_no_reply(signal, TRUE);

	return signal;
}

DBusMessage *new_dbus_method_return(DBusMessage *message) {
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL) {
		die(OUT_OF_MEMORY_STR);
	}

	return reply;
}

DBusMessage *new_dbus_error(DBusMessage *message, const char *name) {
	DBusMessage *error;

	error = dbus_message_new_error(message, name, NULL);
	if (error == NULL) {
		die(OUT_OF_MEMORY_STR);
	}

	return error;
}

void send_and_unref(DBusConnection *connection, DBusMessage *message) {
	if (!dbus_connection_send(connection, message, NULL)) {
		DLOG_ERR("Sending message failed!");
	}
	dbus_connection_flush(connection);
	dbus_message_unref(message);
}

void send_invalid_args(DBusConnection *connection, DBusMessage *message) {
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
gchar *get_device_mode(DBusConnection *connection) {
#ifdef USE_MCE_MODE
	DBusError derror;
	char *mode, *ret;
	DBusMessage *message, *reply;

	message = dbus_message_new_method_call(MCE_SERVICE,
			MCE_REQUEST_PATH,
			MCE_REQUEST_IF,
			MCE_DEVICE_MODE_GET);

	if (message == NULL)
		return NULL;

	dbus_error_init(&derror);
	reply = dbus_connection_send_with_reply_and_block(connection,
			message,
			-1,
			&derror);
	dbus_message_unref(message);
	if (dbus_error_is_set(&derror)) {
		DLOG_ERR("Getting device mode from MCE failed: %s",
				derror.message);
		dbus_error_free(&derror);
		if (reply)
			dbus_message_unref(reply);
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
	return dbus_connection_add_filter(connection,
		(DBusHandleMessageFunction)wlancond_req_handler, NULL, NULL);
}
#endif

gboolean add_icd_listener(DBusConnection *connection) {
	dbus_bus_add_match(connection,
			"interface=" ICD_DBUS_INTERFACE
			",member=" ICD_STATUS_CHANGED_SIG, NULL);

	return dbus_connection_add_filter(connection,
		(DBusHandleMessageFunction)wlancond_req_handler, NULL, NULL);
}

gboolean add_csd_listener(DBusConnection *connection) {
	dbus_bus_add_match(connection,
			"type='signal',interface=" PHONE_NET_DBUS_INTERFACE
			",member=" PHONE_REGISTRATION_STATUS_CHANGE_SIG, NULL);

	return dbus_connection_add_filter(
			connection,
			(DBusHandleMessageFunction)wlancond_req_handler,
			NULL, NULL);
}
gboolean add_bluez_listener(DBusConnection *connection) {
	dbus_bus_add_match(connection,
			"type='signal',interface=" BLUEZ_ADAPTER_SERVICE_NAME
			",member=" BLUEZ_ADAPTER_PROPERTY_CHANGED_SIG, NULL);

	dbus_bus_add_match(connection,
			"type='signal',interface=" BLUEZ_HEADSET_SERVICE_NAME
			",member=" BLUEZ_HEADSET_PROPERTY_CHANGED_SIG, NULL);

	dbus_bus_add_match(connection,
			"type='signal',interface=" BLUEZ_AUDIOSINK_SERVICE_NAME
			",member=" BLUEZ_AUDIOSINK_PROPERTY_CHANGED_SIG, NULL);

#ifdef ENABLE_CALL_TYPE_CHECKING
	dbus_bus_add_match(connection,
			"type='signal',interface=" POLICY_SERVICE_NAME
			",member=" POLICY_ACTIONS_SIG, NULL);
#endif

	return dbus_connection_add_filter(
			connection,
			(DBusHandleMessageFunction)wlancond_req_handler,
			NULL, NULL);
}
