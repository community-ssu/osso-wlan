/**
  @file daemon.h

  This module contains functions related to daemon behaviour.

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
#ifndef _DAEMON_H_
#define _DAEMON_H_

/** Remove the pid file
 * @param pidfile Filename to operate on
 * @returns -1 on failure, 0 on success
 */
int remove_pid(const char *pidfile);

/** Check if another instance is running
 * @param pidfile Filename to operate on
 * @returns 1 if another instance is running, 0 if not
 */
int check_pid(const char *pidfile);

/** Write our own pid to the pid file
 * @param pidfile Filename to operate on
 * @returns -1 on failure, 1 on success
 */
int write_pid(const char *pidfile);

/** Send the process to the background */
void daemonize(void);

#endif /* _DAEMON_H_ */
