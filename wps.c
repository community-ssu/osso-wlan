/**
   @file wps.c

   Copyright (C) 2008 Nokia Corporation. All rights reserved.

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
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <glib.h>
#include <glib-object.h>
#include <unistd.h>
#include "common.h"
#include "wpa.h"
#include "wps.h"
#include "log.h"

#define WPS_VERSION              0x10
#define MAX_DEVICE_NAME          32

#define WPS_STATE_UNCONFIGURED   0x01
#define WPS_STATE_CONFIGURED     0x02

#define WPS_PIN_CODE             0
#define WPS_PUSH_BUTTON          4

/* TLV defitions */
#define WPS_VERSION_TLV                        0x104A
#define WPS_STATE_TLV                          0x1044
#define WPS_APSETUPLOCKED_TLV                  0x1057
#define WPS_SELECTEDREGISTRAR_TLV              0x1041
#define WPS_DEVICEPASSWORD_ID_TLV              0x1012
#define WPS_SELECTEDREGISTRARCONFIGMETHODS_TLV 0x1053
#define WPS_DEVICENAME_TLV                     0x1011
#define WPS_UUID_E_TLV                         0x1047

/**
  Get selected TLV value.
  @param msg WPS Information Element.
  @param msg_size Message size.
  @param type Type of TLV value to search.
  @param value Pointer to result.
  @param value_len Result lenght.
  @return status.
 */
static int get_tlv_value(guchar* msg, guint msg_size, guint type,
		guchar* value, guint value_len)
{
	guint len = 0;

	if (msg_size < 4) {
		DLOG_ERR("Message too short");
		return -1;
	}

	// Find the TLV value
	while (len + 4 < msg_size)
	{
		guint hi = msg[len];
		guint lo = msg[len+1];
		guint tmp_type = (hi << 8) + lo;

		//DLOG_DEBUG("tmp_type: %04x", tmp_type);

		guint length = 0;

		hi = msg[len+2];
		lo = msg[len+3];

		length = (hi << 8) + lo;

		// check the type
		if (tmp_type == type)
		{
			if (length > value_len) {
				DLOG_ERR("Too much data for buffer (%d)",
						value_len);
				return -1;
			}
			if (len + 4 + length > msg_size) {
				DLOG_ERR("Message data too short?");
				return -1;
			}

			memcpy(value, msg+len+4, length);
			//DLOG_DEBUG("value: %04x", *value);

			return length;
		}

		len = len + length + 4;
	}

	return -1;
}
/**
  Handle Wifi Protected Setup Information Element.
  @param p WPS Information Element.
  @param scan_results Scan results.
  @param length WPS Information Element length.
  @return status.
 */
int handle_wps_ie(unsigned char* p,
		struct scan_results_t *scan_results,
		unsigned int length)
{
	guint value = 0;
	char device_name[MAX_DEVICE_NAME+1];
#ifdef DEBUG_WPS
	char uuid_e[MAX_UUID_E_LEN];
#endif
	gint len;

	int ret = -1;

	if (length < 2) {
		DLOG_ERR("WPS IE too short");
		return -1;
	}
#if 0
	unsigned int i;
	for (i=0;i<length;i++) {
		DLOG_DEBUG("%02x", p[i]);
	}
#endif

	/* Mandatory fields */
	if (get_tlv_value(p, length, WPS_VERSION_TLV, (unsigned char*)&value,
				sizeof(value)) < 0 || value != WPS_VERSION) {
		DLOG_ERR("Unknown WPS version received (%02x)", value);
		return ret;
	}

	if (get_tlv_value(p, length, WPS_STATE_TLV, (unsigned char*)&value,
				sizeof(value)) < 0) {
		DLOG_ERR("Could not get WPS state");
		return ret;
	}

	DLOG_DEBUG("WPS state: %s", value == WPS_STATE_CONFIGURED?"configured":
			"unconfigured");

	scan_results->cap_bits |= WLANCOND_WPS;

	ret = 0;

	/* Everything else is optional */
	if (get_tlv_value(p, length, WPS_APSETUPLOCKED_TLV,
				(unsigned char*)&value, sizeof(value)) < 0) {
		//DLOG_ERR("Could not get ap_setup_locked");
	} else {
		DLOG_DEBUG("ap_setup_locked: %d", value);
	}

	if (get_tlv_value(p, length, WPS_SELECTEDREGISTRAR_TLV,
				(unsigned char*)&value, sizeof(value)) < 0) {
		//DLOG_ERR("Could not get selected_registrar");
	} else if (value) {
		DLOG_DEBUG("Device is selected registrar");
		scan_results->cap_bits |= WLANCOND_WPS_CONFIGURED;
	}

	if (get_tlv_value(p, length, WPS_DEVICEPASSWORD_ID_TLV,
				(unsigned char*)&value, sizeof(value)) < 0) {
		//DLOG_ERR("Assuming PUSH and PIN");
		// If AP does not give this info, let's assume the following
		scan_results->cap_bits |= WLANCOND_WPS_PIN;
		scan_results->cap_bits |= WLANCOND_WPS_PUSH_BUTTON;
	} else {
		if (GUINT16_FROM_BE(value) == WPS_PIN_CODE) {
			DLOG_ERR("PIN supported");
			scan_results->cap_bits |= WLANCOND_WPS_PIN;
		}
		if (GUINT16_FROM_BE(value) == WPS_PUSH_BUTTON) {
			DLOG_ERR("PBC supported");
			scan_results->cap_bits |= WLANCOND_WPS_PUSH_BUTTON;
		}
	}

	if ((len = get_tlv_value(p, length, WPS_DEVICENAME_TLV,
					(unsigned char*)&device_name,
					sizeof(device_name)-1)) < 0) {
		//DLOG_ERR("Could not get device name");
	} else {
		device_name[len] = '\0';
		DLOG_DEBUG("Device name: %s", device_name);
	}

#ifdef DEBUG_WPS

	if (get_tlv_value(p, length, WPS_SELECTEDREGISTRARCONFIGMETHODS_TLV,
				(unsigned char*)&value, sizeof(value)) < 0) {
		DLOG_ERR("Could not get config_methods");
	} else {
		DLOG_DEBUG("Config_methods: %04x", GUINT16_FROM_BE(value));
	}

	if ((len = get_tlv_value(p, length, WPS_UUID_E_TLV,
					(unsigned char*)&uuid_e,
					sizeof(uuid_e))) < 0) {
		DLOG_ERR("Could not get UUID-E");
	} else {
#if 0
		int j;
		for (j=0;j<len;j++) {
			DLOG_DEBUG("UUID-E: %d", uuid_e[j]);
		}
#endif
	}
#endif

	return ret;
}
