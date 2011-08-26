/**
  @file log.h

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
#ifndef _LOG_H_
#define _LOG_H_

#include <osso-log.h>

/** Print error message and exit */
#define die(...) do {   \
    DLOG_ERR(__VA_ARGS__); \
    exit(EXIT_FAILURE); \
} while (0)

#endif /* _LOG_H_ */
