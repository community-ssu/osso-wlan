/**
  @file dbus.h

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

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
#ifndef _DBUS_H_
#define _DBUS_H_

#ifndef DBUS_API_SUBJECT_TO_CHANGE
# define DBUS_API_SUBJECT_TO_CHANGE
# include <dbus/dbus.h>
#endif

/** Connect to the system D-Bus
 * @returns 0 on success, -1 on failure
 */
int setup_dbus_connection(const char *service,
                          void (*handler_init)(DBusConnection *connection));

/** Disconnect from the system D-Bus */
void close_dbus_connection(void);

DBusConnection *get_dbus_connection(void);

#endif /* _DBUS_H_ */