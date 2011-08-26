/**
  @file dbus-handler.h

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

  @author Janne Ylalehto <janne.ylalehto@nokia.com>

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
#ifndef _DBUS_HANDLER_H_
#define _DBUS_HANDLER_H_

#ifndef DBUS_API_SUBJECT_TO_CHANGE
# define DBUS_API_SUBJECT_TO_CHANGE
# include <dbus/dbus.h>
#endif

/** Bind functions to corresponding D-Bus messages
 * @param connection D-Bus connection
 */
void init_dbus_handlers(DBusConnection *connection);

/** Free memory allocated to handlers
 * @param connection D-Bus connection
 */
void destroy_dbus_handlers(DBusConnection *connection);

int set_interface_state(int sock, int dir, short flags);

#define CLEAR 1
#define SET   2

#endif /* _DBUS_HANDLER_H_ */
