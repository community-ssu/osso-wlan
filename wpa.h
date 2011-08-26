/**
   @file wpa.h

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
#ifndef _WPA_H_
#define _WPA_H_

#include <asm/types.h>
#include "common.h"

#define MAX_WPA_KEY_LEN 32

#define WPA_ELEMENT 0xDD
#define RSN_ELEMENT 0x30

#define WPA_VERSION 1
#define RSN_VERSION 1

#define CIPHER_SUITE_LEN 4

#define WPA_PSK    1
#define WPA_802_1X 2

struct rsn_ie_t {
	guint8 element_id;
	guint8 length;
	guint16 version;
} __attribute__ ((packed));

struct wpa_ie_t {
	guint8 element_id;
	guint8 length;
	guint8 oui[3];
	guint8 oui_type;
	guint16 version;
} __attribute__ ((packed));

typedef struct ap_info_t {
	guint pairwise_cipher;
	guint group_cipher;
	guint key_mgmt;
} ap_info_t;

gint set_encryption_method(guint32 cipher,
			   struct wlan_status_t *wlan_status,
			   struct scan_results_t *scan_results);
int set_wpa_encryption(int encryption, struct wlan_status_t *wlan_status);
int set_wpa2_encryption(int encryption, struct wlan_status_t *wlan_status);
int handle_mic_failure(gboolean key_type, unsigned char *bssid);
int parse_rsn_ie(unsigned char* wpa_ie, unsigned int wpa_ie_len,
		struct ap_info_t* ap_info);
int parse_wpa_ie(unsigned char* wpa_ie, unsigned int wpa_ie_len,
		struct ap_info_t* ap_info);
int handle_wps_ie(unsigned char* p, struct scan_results_t *scan_results,
		unsigned int length);
int set_countermeasures(guint on_off);
gboolean is_ap_in_black_list(unsigned char* bssid);
int set_wpa_ie(struct wlan_status_t *wlan_status);

#endif /* _WPA_H_ */
