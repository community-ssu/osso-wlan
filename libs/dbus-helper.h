/**
  @file dbus-helper.h

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

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
#ifndef _DBUS_HELPER_H_
#define _DBUS_HELPER_H_

#ifndef DBUS_API_SUBJECT_TO_CHANGE
# define DBUS_API_SUBJECT_TO_CHANGE
# include <dbus/dbus.h>
#endif

#define KEVENT_DBUS_IF "org.kernel.kevent"

void append_dbus_args(DBusMessage *message, int first_arg_type, ...);

void send_and_unref(DBusConnection *connection, DBusMessage *message);

void send_invalid_args(DBusConnection *connection, DBusMessage *message);

DBusMessage *new_dbus_signal(const char *path,
                             const char *interface,
                             const char *name,
                             const char *destination);

DBusMessage *new_dbus_method_return(DBusMessage *message);

DBusMessage *new_dbus_error(DBusMessage *message, const char *name);

gchar *get_device_mode(DBusConnection *connection);
gboolean add_mode_listener(DBusConnection *connection);
gboolean add_cover_listener(DBusConnection *connection,
                            void (*cover_cb)(void));
gboolean add_icd_listener(DBusConnection *connection);
gboolean add_csd_listener(DBusConnection *connection);
gboolean add_bluez_listener(DBusConnection *connection);

#endif /* _DBUD_HELPER_H_ */
