/**
   @file dbus-signal.c

   Copyright (C) 2004-2008 Nokia Corporation. All rights reserved.

   @author Janne Ylälehto <janne.ylalehto@nokia.com>

   Portions of this file are
   Copyright (c) 1997-2002 Jean Tourrilhes <jt@hpl.hp.com>

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
#include <glib.h>
#include <glib-object.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <wlancond-dbus.h>
#include <eap-dbus.h>

#include "common.h"
#include "daemon.h"
#include "dbus.h"
#include "dbus-handler.h"
#include "log.h"
#include "dbus-helper.h"
#include "wpa.h"

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>

/* Cache of wireless interfaces */
static struct wireless_iface *interface_cache = NULL;

extern struct wlan_status_t wlan_status;

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
};

/* Local functions */
static void handle_custom_event(char* event_pointer, int len,
		struct scan_results_t *scan_results);
static int handle_wpa_ie_event_binary(unsigned char* p, unsigned int length,
		struct scan_results_t *scan_results);

void print_mac(guint priority, const char *message, guchar* mac)
{
	if (priority > WLANCOND_PRIO_MEDIUM)
		DLOG_INFO("%s %02x:%02x:%02x:%02x:%02x:%02x", message, mac[0],
				mac[1], mac[2], mac[3], mac[4], mac[5]);
	else {
		DLOG_DEBUG("%s %02x:%02x:%02x:%02x:%02x:%02x", message, mac[0],
				mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
}
void clean_scan_results_item(gpointer data, gpointer user_data)
{
	struct scan_results_t *scan_results = data;
	g_free(scan_results->wpa_ie);
	g_slice_free(struct scan_results_t, scan_results);
}

/**
  Remove saved scan results.
  @param scan_results_save structure where scan results are saved.
 */
void clean_scan_results(GSList **scan_results_save)
{
	//DLOG_DEBUG("Cleaning scan results");

	g_slist_foreach(*scan_results_save, clean_scan_results_item, NULL);
	g_slist_free(*scan_results_save);

	*scan_results_save = NULL;

}

/**
  Save scan results to list.
  @param scan_results structure where scan results are.
  @param scan_results_save structure where scan results are saved.
 */
GSList *save_scan_results(struct scan_results_t *scan_results,
		GSList *scan_results_save)
{

	g_assert(scan_results != NULL);

	//DLOG_DEBUG("\nScan results to save\n");

	scan_results_save = g_slist_prepend(scan_results_save, scan_results);

	return scan_results_save;
}
/**
  Send scan results to DBUS.
  @param scan_results_save structure where scan results are saved.
  @param sender The message is sent to this entity.
 */
void send_dbus_scan_results(GSList *scan_results_save, const char* sender,
		dbus_int32_t number_of_results)
{
	DBusMessage *results;
	DBusMessageIter iter, sub;
	GSList *list;
	int list_count = 0;
	unsigned char* v;
	char* p;

	if (sender == NULL || strnlen(sender, 5) == 0)
		return;

	DLOG_INFO("Scan results (%d APs) to %s", number_of_results, sender);

	results = new_dbus_signal(WLANCOND_SIG_PATH,
			WLANCOND_SIG_INTERFACE,
			WLANCOND_SCAN_RESULTS_SIG,
			sender);

	dbus_message_iter_init_append(results, &iter);

	if (number_of_results > WLANCOND_MAX_NETWORKS) {
		DLOG_DEBUG("Limiting result %d to %d", number_of_results,
				WLANCOND_MAX_NETWORKS);
		number_of_results = WLANCOND_MAX_NETWORKS;
	}
	if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32,
				&number_of_results))
		die("Out of memory");

	for (list = scan_results_save; list != NULL && list_count++ <=
			number_of_results; list = list->next) {
		struct scan_results_t *scan_results = list->data;
		DLOG_DEBUG("AP (%d) is %s, rssi:%d channel:%d cap:%08x",
				list_count,
				scan_results->ssid,
				scan_results->rssi, scan_results->channel,
				scan_results->cap_bits);

		p = scan_results->ssid;

		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					"y", &sub))
			die("Out of memory");
		if (!dbus_message_iter_append_fixed_array(
					&sub, DBUS_TYPE_BYTE, &p,
					scan_results->ssid_len))
			die("Out of memory");
		if (!dbus_message_iter_close_container(&iter, &sub))
			die("Out of memory");

		v = scan_results->bssid;
		if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					"y", &sub))
			die("Out of memory");
		if (!dbus_message_iter_append_fixed_array(&sub, DBUS_TYPE_BYTE,
					&v, ETH_ALEN))
			die("Out of memory");
		if (!dbus_message_iter_close_container(&iter, &sub))
			die("Out of memory");
		if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32,
					&scan_results->rssi))
			die("Out of memory");
		if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32,
					&scan_results->channel))
			die("Out of memory");
		if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32,
					&scan_results->cap_bits))
			die("Out of memory");
	}

	send_and_unref(get_dbus_connection(), results);
}

/**
  Send disconnected signal.
 */
void disconnected_signal(void)
{
	DBusMessage *disconnected;

	disconnected = new_dbus_signal(
			WLANCOND_SIG_PATH,
			WLANCOND_SIG_INTERFACE,
			WLANCOND_DISCONNECTED_SIG,
			NULL);

	gchar* ifname = wlan_status.ifname;

	append_dbus_args(disconnected,
			DBUS_TYPE_STRING, &ifname,
			DBUS_TYPE_INVALID);

	send_and_unref(get_dbus_connection(), disconnected);
}

/**
  Send connected signal.
  @param scan_results Scan results to be sent.
  @param auth_status Authentication status.
 */
static void connected_signal(char* bssid, dbus_int32_t auth_status)
{
	DBusMessage *connected;

	connected = new_dbus_signal(
			WLANCOND_SIG_PATH,
			WLANCOND_SIG_INTERFACE,
			WLANCOND_CONNECTED_SIG,
			NULL);

	gchar* ifname = wlan_status.ifname;

	append_dbus_args(connected,
			DBUS_TYPE_STRING, &ifname,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bssid, ETH_ALEN,
			DBUS_TYPE_INT32, &auth_status,
			DBUS_TYPE_INVALID);

	send_and_unref(get_dbus_connection(), connected);
}

/**
  Handle WAP wireless event.
  @param event extracted token.
  @param scan_results structure where scan results are saved.
  @return status.
 */
static void handle_wap_event(struct scan_results_t *scan_results,
		struct iw_event *event, gboolean scan_event)
{

	// Spurious event
	if (get_wlan_state() == WLAN_NOT_INITIALIZED) {
		return;
	}

	if (scan_event == TRUE) {
		print_mac(WLANCOND_PRIO_LOW, "SIOCGIWAP:",
				(guchar*)event->u.ap_addr.sa_data);
		memcpy(scan_results->bssid, event->u.ap_addr.sa_data, ETH_ALEN);
		return;
	}

	print_mac(WLANCOND_PRIO_HIGH, "SIOCGIWAP:",
			(guchar*)event->u.ap_addr.sa_data);

	// Check if the address is valid
	if (memcmp(event->u.ap_addr.sa_data, "\0\0\0\0\0\0", ETH_ALEN)) {

		if (get_wlan_state() == WLAN_INITIALIZED_FOR_SCAN) {
			DLOG_ERR("Should not happen");
			return;
		}


		remove_connect_timer();
		wlan_status.retry_count = 0;

		set_wlan_signal(WLANCOND_HIGH);

		if (get_wpa_mode() == TRUE ||
				wlan_status.conn.authentication_type ==
				EAP_AUTH_TYPE_WFA_SC) {
			if (associate_supplicant() < 0) {
				set_wlan_state(WLAN_NOT_INITIALIZED,
						DISCONNECTED_SIGNAL,
						FORCE_YES);
				return;
			}
		}

		dbus_int32_t auth_status = get_encryption_info();

		connected_signal(event->u.ap_addr.sa_data, auth_status);
		// If not roaming, set NO_ADDRESS state
		if (wlan_status.ip_ok == FALSE) {
			set_wlan_state(WLAN_NO_ADDRESS, NO_SIGNAL, FORCE_NO);
		} else {
			set_wlan_state(WLAN_CONNECTED, NO_SIGNAL, FORCE_NO);
		}

		/* Clear AUTOCONNECT flag */
		wlan_status.conn.flags &= ~WLANCOND_AUTOCONNECT;
	} else {
		if (get_wlan_state() == WLAN_INITIALIZED_FOR_CONNECTION &&
				get_scan_state() == SCAN_ACTIVE) {
			/* We are alredy searching for better connection */
			return;
		}
		if (get_wlan_state() != WLAN_CONNECTED &&
				get_wlan_state() != WLAN_NO_ADDRESS &&
				get_wlan_state() !=
				WLAN_INITIALIZED_FOR_CONNECTION) {
			DLOG_ERR("Not even connected?!?");
			return;
		}
		/* No roaming in WPS state */
		if (wlan_status.conn.authentication_type ==
				EAP_AUTH_TYPE_WFA_SC) {
			return;
		}

		// Disconnect supplicant
		if (get_wpa_mode() == TRUE &&
				(get_wlan_state() == WLAN_CONNECTED ||
				 get_wlan_state() == WLAN_NO_ADDRESS)) {
			disassociate_eap();
			clear_wpa_keys(wlan_status.conn.bssid);
		}

		/* Clear SSID and BSSID to stop mac80211 from roaming */
		set_bssid(NULL_BSSID);
		set_essid((char*)"", 1);
		set_wpa_ie(&wlan_status);

		DLOG_DEBUG("Trying to find a new connection");

		/* Decrese failed AP signal */
		decrease_signal_in_roam_cache(wlan_status.conn.bssid);

		set_wlan_state(WLAN_INITIALIZED_FOR_CONNECTION, NO_SIGNAL,
				FORCE_NO);

		if (find_connection_and_associate(wlan_status.roam_cache,
						  FALSE, FALSE, FALSE) == 0)
			return;

		/* Break eternal loop if all APs are failing */
		if (++wlan_status.retry_count > WLANCOND_MAX_SCAN_TRIES) {
			DLOG_ERR("Too many failures: %d",
					wlan_status.retry_count);
			set_wlan_state(WLAN_NOT_INITIALIZED,
					DISCONNECTED_SIGNAL,
					FORCE_YES);
			return;
		}

		/* No luck, start scanning */
		if (scan(wlan_status.conn.ssid,
					wlan_status.conn.ssid_len, TRUE) < 0) {
			/* Set_wlan_state puts IF down */
			set_wlan_state(WLAN_NOT_INITIALIZED,
					DISCONNECTED_SIGNAL,
					FORCE_YES);
		}
	}
}

/**
  Print or save wireless events.
  @param event extracted token.
  @param scan_results structure where scan results are saved.
  @param ifindex Interface index.
  @return status.
 */
int print_event_token(struct iw_event *event,
		struct scan_results_t *scan_results,
		int ifindex, gboolean scan_event)
{

	/* Now, let's decode the event */
	switch(event->cmd)
	{
	case SIOCGIWESSID:
		{
			int len = event->u.essid.length;
			if (len > WLANCOND_MAX_SSID_SIZE) {
				//DLOG_ERR("Invalid length SSID (%d)", len);
				len = WLANCOND_MAX_SSID_SIZE;
			}

			if ((event->u.essid.pointer) && len) {
				memcpy(scan_results->ssid,
						event->u.essid.pointer, len);
			}

			// Keep the API the same i.e. add Null termination
			len++;

			scan_results->ssid_len = len;

			if (event->u.essid.flags)
			{
				/* Does it have an ESSID index ? */
				if((event->u.essid.flags & IW_ENCODE_INDEX) >
						1) {

#ifdef DEBUG
					DLOG_DEBUG("ESSID:\"%s\" [%d]\n",
							scan_results->ssid,
							(event->u.essid.flags &
							 IW_ENCODE_INDEX));
				} else {
					DLOG_DEBUG("ESSID:\"%s\"\n",
							scan_results->ssid);
#endif
				}
			} else {
#ifdef DEBUG
				DLOG_DEBUG("ESSID:off/any");
#endif
			}
		}
		break;
	case SIOCGIWAP:
		handle_wap_event(scan_results, event, scan_event);
		break;
	case IWEVQUAL:
		//DLOG_DEBUG("RSSI: %d dBm", (signed char)event->u.qual.level);
		scan_results->rssi = (signed char)event->u.qual.level;
		break;
	case SIOCGIWFREQ:
		{
			if (event->u.freq.e == 0) {
				scan_results->channel = event->u.freq.m;
				DLOG_DEBUG("Channel: %d", scan_results->channel);
			}
		}
		break;
	case SIOCGIWMODE:
		if (event->u.mode == IW_MODE_ADHOC) {
			DLOG_DEBUG("Adhoc network");
			scan_results->cap_bits |= WLANCOND_ADHOC;
		} else {
			scan_results->cap_bits |= WLANCOND_INFRA;
		}
		break;
	case SIOCGIWRATE:
		switch (event->u.bitrate.value) {
		case 2*500000:
			scan_results->cap_bits |= WLANCOND_RATE_10;
			break;
		case 4*500000:
			scan_results->cap_bits |= WLANCOND_RATE_20;
			break;
		case 11*500000:
			scan_results->cap_bits |= WLANCOND_RATE_55;
			break;
		case 12*500000:
			scan_results->cap_bits |= WLANCOND_RATE_60;
			break;
		case 18*500000:
			scan_results->cap_bits |= WLANCOND_RATE_90;
			break;
		case 22*500000:
			scan_results->cap_bits |= WLANCOND_RATE_110;
			break;
		case 24*500000:
			scan_results->cap_bits |= WLANCOND_RATE_120;
			break;
		case 36*500000:
			scan_results->cap_bits |= WLANCOND_RATE_180;
			break;
		case 48*500000:
			scan_results->cap_bits |= WLANCOND_RATE_240;
			break;
		case 52*500000:
			scan_results->cap_bits |= WLANCOND_RATE_260;
			break;
		case 72*500000:
			scan_results->cap_bits |= WLANCOND_RATE_360;
			break;
		case 96*500000:
			scan_results->cap_bits |= WLANCOND_RATE_480;
			break;
		case 108*500000:
			scan_results->cap_bits |= WLANCOND_RATE_540;
			break;
#ifdef DEBUG
		default:

			DLOG_DEBUG("Unknown rate %04x",
					(int)event->u.bitrate.value);
			break;
#endif
		}
		break;
	case SIOCGIWENCODE:
		/* WPA encryption is handled by a custom event */
		if (event->u.data.flags & ~IW_ENCODE_DISABLED) {
			DLOG_DEBUG("Encrypted network");
			scan_results->cap_bits |= WLANCOND_WEP;
		} else {
			scan_results->cap_bits |= WLANCOND_OPEN;
		}

		break;
	case SIOCGIWSCAN:
		{
			remove_scan_timer();

			if (get_scan_state() == SCAN_ACTIVE) {
				DLOG_INFO("Scan results ready -- scan active");
				if (ask_scan_results(ifindex) == FALSE) {
					DLOG_ERR("Getting scan results failed");

					set_wlan_state(WLAN_NOT_INITIALIZED,
							DISCONNECTED_SIGNAL,
							FORCE_YES);
				}
#ifdef DEBUG
			} else {
				DLOG_DEBUG("Scan results ready -- "
						"not requested");
#endif
			}
		}
		break;

	case IWEVCUSTOM:
		{
			//DLOG_DEBUG("Custom driver event");

			handle_custom_event(event->u.data.pointer,
					event->u.data.length, scan_results);
		}
		break;

	case IWEVGENIE:
		{
			if (handle_wpa_ie_event_binary(event->u.data.pointer,
						event->u.data.length,
						scan_results) < 0) {
				DLOG_ERR("Error in IE handling");
			}

		}
		break;
#if 0
	case IWEVASSOCRESPIE:
	case IWEVASSOCREQIE:
		{
			if (handle_wpa_ie_assoc_event_binary(
						event->u.data.pointer,
						event->u.data.length) < 0) {

				/* Set_wlan_state puts IF down */
				set_wlan_state(WLAN_NOT_INITIALIZED,
						DISCONNECTED_SIGNAL,
						FORCE_YES);
			}
		}
#endif
		break;
	case SIOCSIWFREQ:
	case SIOCSIWENCODE:
	case SIOCSIWMODE:
	case SIOCSIWESSID:
		break;

	default:
		DLOG_DEBUG("Unknown Wireless event 0x%04X", event->cmd);
	}

	return 0;
}
/**
  Save WPA capabilities and print them to log.
  @param scan_results Pointer to scan results structure.
  @param ap_info Pointer to AP information structure.
  @param p Pointer to event buffer.
  @param length Event buffer length.
 */
static void save_caps(struct scan_results_t *scan_results,
		struct ap_info_t *ap_info, unsigned char *p,
		unsigned int length)
{
	gboolean no_wep = FALSE;

	scan_results->wpa_ie = g_memdup(p, length);
	scan_results->wpa_ie_len = length;

	/* Key mgmt */
	if (ap_info->key_mgmt & WPA_PSK) {
		scan_results->cap_bits |= WLANCOND_WPA_PSK;
		no_wep = TRUE;
	}
	if (ap_info->key_mgmt & WPA_802_1X) {
		scan_results->cap_bits |= WLANCOND_WPA_EAP;
		/* No WPS in EAP mode */
		scan_results->cap_bits &= ~WLANCOND_WPS_MASK;
		no_wep = TRUE;
	}
	DLOG_DEBUG("%s %s supported",
			(scan_results->cap_bits & WLANCOND_WPA2) ? "WPA2":"WPA",
			(ap_info->key_mgmt & WPA_PSK) ? "PSK":"EAP");

	/* Algorithms */
	/* Pairwise */
	if (ap_info->pairwise_cipher & CIPHER_SUITE_CCMP) {
		scan_results->cap_bits |= WLANCOND_WPA_AES;
	}
	if (ap_info->pairwise_cipher & CIPHER_SUITE_TKIP) {
		scan_results->cap_bits |= WLANCOND_WPA_TKIP;
	}
	if (wlan_status.allow_all_ciphers == TRUE) {
		if (ap_info->pairwise_cipher & CIPHER_SUITE_WEP40) {
			scan_results->extra_cap_bits |= WLANCOND_WEP40;
		}
		if (ap_info->pairwise_cipher & CIPHER_SUITE_WEP104) {
			scan_results->extra_cap_bits |= WLANCOND_WEP104;
		}
		if (ap_info->group_cipher & CIPHER_SUITE_WEP40) {
			scan_results->extra_cap_bits |= WLANCOND_WEP40_GROUP;
		}
		if (ap_info->group_cipher & CIPHER_SUITE_WEP104) {
			scan_results->extra_cap_bits |= WLANCOND_WEP104_GROUP;
		}
	} else {
		if (ap_info->pairwise_cipher & CIPHER_SUITE_WEP40 ||
				ap_info->pairwise_cipher & CIPHER_SUITE_WEP104 ||
				ap_info->group_cipher & CIPHER_SUITE_WEP40 ||
				ap_info->group_cipher & CIPHER_SUITE_WEP104) {
			DLOG_DEBUG("In WPA mode WEP is not allowed");
			scan_results->cap_bits |=
				WLANCOND_UNSUPPORTED_NETWORK;
		}
	}

	DLOG_DEBUG("%s/%s/%s/%s for unicast",
			(ap_info->pairwise_cipher & CIPHER_SUITE_CCMP)?
			"AES":"-",
			(ap_info->pairwise_cipher & CIPHER_SUITE_TKIP)?
			"TKIP":"-",
			(ap_info->pairwise_cipher & CIPHER_SUITE_WEP104)?
			"WEP104":"-",
			(ap_info->pairwise_cipher & CIPHER_SUITE_WEP40)?
			"WEP40":"-");
	/* Group */
	if (ap_info->group_cipher & CIPHER_SUITE_CCMP) {
		scan_results->cap_bits |= WLANCOND_WPA_AES_GROUP;
	}
	if (ap_info->group_cipher & CIPHER_SUITE_TKIP) {
		scan_results->cap_bits |= WLANCOND_WPA_TKIP_GROUP;
	}
	if (ap_info->group_cipher & CIPHER_SUITE_WEP40 ||
			ap_info->group_cipher & CIPHER_SUITE_WEP104) {

		if (no_wep == TRUE && wlan_status.allow_all_ciphers == FALSE) {
			DLOG_DEBUG("In WPA mode WEP is not allowed");
			scan_results->cap_bits |= WLANCOND_UNSUPPORTED_NETWORK;
		}
	}
	DLOG_DEBUG("%s/%s/%s/%s for multicast",
			(ap_info->group_cipher & CIPHER_SUITE_CCMP)?"AES":"-",
			(ap_info->group_cipher & CIPHER_SUITE_TKIP)?"TKIP":"-",
			(ap_info->group_cipher & CIPHER_SUITE_WEP104)?
			"WEP104":"-",
			(ap_info->group_cipher & CIPHER_SUITE_WEP40)?
			"WEP40":"-");
	/* Remove WEP bit to make UI show correct dialogs */
	if (no_wep == TRUE) {
		scan_results->cap_bits &= ~WLANCOND_WEP;
	}

	//DLOG_DEBUG("Cap bits: 0x%08x", scan_results->cap_bits);
}

/**
  WPA Information element event binary.
  @param p Pointer to event buffer.
  @param length Event buffer length.
  @param scan_results Pointer to scan results structure.
 */
static int handle_wpa_ie_event_binary(unsigned char* p, unsigned int length,
		struct scan_results_t *scan_results)
{
	struct ap_info_t ap_info;
	const guint8 WPA1_OUI[] = { 0x00, 0x50, 0xf2, 0x01 };
	const guint8 WPS_OUI[] = { 0x00, 0x50, 0xf2, 0x04 };
	guchar* ie_pos = NULL;
	guint ie_len = 0;
	guint index = 0;

	while(index <= (length - 2))
	{
		// WPA2
		if (p[index] == RSN_ELEMENT && length-index > 3) {

			guint len = p[index+1]+2;

			if (len > length-index) {
				DLOG_ERR("Too long IE");
				return -1;
			}

			/* Add WPA2 */
			scan_results->cap_bits |= WLANCOND_WPA2;

			ie_pos = &p[index];
			ie_len = len;
		}
		// WPA1
		else if (p[index] == WPA_ELEMENT && length-index > 7 &&
				memcmp(&p[index + 2], WPA1_OUI,
					sizeof(WPA1_OUI)) == 0)
		{
			guint len = p[index+1]+2;

			if (len > length-index) {
				DLOG_ERR("Too long IE");
				return -1;
			}

			if (!(scan_results->cap_bits &
						WLANCOND_ENCRYPT_WPA2_MASK)) {
				ie_pos = &p[index];
				ie_len = len;
			} else {
				DLOG_DEBUG("Ignoring WPA IE");
			}
		}
		// Protected setup
		else if (p[index] == WPA_ELEMENT && length-index > 3 &&
				memcmp(&p[index + 2], WPS_OUI,
					sizeof(WPS_OUI)) == 0)
		{
			guint len = p[index+1]+2;

			if (len > length-index) {
				DLOG_ERR("Too long IE");
				return -1;
			}
			if (handle_wps_ie(&p[index+6], scan_results, len) < 0) {
				return -1;
			}
		}

		index +=p[index+1]+2;
	}

	if (ie_pos != NULL) {

		memset(&ap_info, 0, sizeof(ap_info));
		if (scan_results->cap_bits & WLANCOND_ENCRYPT_WPA2_MASK) {
			if (parse_rsn_ie(ie_pos, ie_len, &ap_info) < 0) {
				return -1;
			}
		} else {
			if (parse_wpa_ie(ie_pos, ie_len, &ap_info) < 0) {
				return -1;
			}
		}

		save_caps(scan_results, &ap_info, ie_pos, ie_len);
	}

	return 0;
}
/**
  Check if we have scanned in last WLANCOND_MIN_ROAM_SCAN_INTERVAL.
  @return TRUE if we have scanned, FALSE otherwise.
 */
static gboolean roam_scanning(void) {
	struct timeval tv;

	if (gettimeofday(&tv, NULL) <0)
		return FALSE;

	if (tv.tv_sec > wlan_status.last_scan + WLANCOND_MIN_ROAM_SCAN_INTERVAL)
		return FALSE;

	DLOG_DEBUG("Already roam scanning");
	return TRUE;
}

/**
  Handle custom event.
  @param event_pointer pointer to custom event.
  @param length custom event length.
  @param scan_results pointer to scan results struct.
 */
static void handle_custom_event(char* event_pointer, int length,
		struct scan_results_t *scan_results)
{

	if (length < 5 || length > IW_GENERIC_IE_MAX) {
		DLOG_DEBUG("Invalid length event");
		return;
	}
	if (strncmp(event_pointer, "tsf=", 4) == 0) {
		/* Do nothing for now */
	} else if (strncmp(event_pointer, "LOWSIGNAL", 10) == 0) {
		DLOG_INFO("Low signal");
		set_wlan_signal(WLANCOND_LOW);
		if (get_wlan_state() == WLAN_CONNECTED) {
			if (roam_scanning())
				/* Already roam scanned */
				schedule_scan(WLANCOND_MIN_ROAM_SCAN_INTERVAL);
			else
				schedule_scan(WLANCOND_INITIAL_ROAM_SCAN_DELAY);
		}
	} else if (strncmp(event_pointer, "HIGHSIGNAL", 11) == 0) {
		DLOG_INFO("High signal");
		set_wlan_signal(WLANCOND_HIGH);
	} else if (strncmp(event_pointer, "MLME-MICHAELMICFAILURE.indication",
				33) == 0) {
		dbus_bool_t key_type = TRUE;

		if (strstr(event_pointer, "unicast") != NULL)
			key_type = FALSE;

		DLOG_INFO("MIC failure event for %s key",
				key_type==FALSE?"unicast":"group");
		handle_mic_failure(key_type, wlan_status.conn.bssid);
	} else {
		//DLOG_DEBUG("Unknown custom event");
		//DLOG_DEBUG("%s\n", event_pointer);
	}
}

/**
  Get name of interface based on interface index.
  @param skfd Socket.
  @param ifindex Interface index.
  @param name Interface name.
  @return status.
 */
static int index2name(int skfd, int ifindex, char *name)
{
	struct ifreq irq;
	int ret = 0;

	memset(name, 0, IFNAMSIZ + 1);
	memset(&irq, 0, sizeof(irq));

	/* Get interface name */
	irq.ifr_ifindex = ifindex;

	if (ioctl(skfd, SIOCGIFNAME, &irq) < 0)
		ret = -1;
	else
		strncpy(name, irq.ifr_name, IFNAMSIZ);

	return ret;
}

/**
  Get interface data from cache or live interface.
  @param ifindex Interface index.
  @return wireless_iface The wireless interface.
 */
struct wireless_iface *get_interface_data(int ifindex)
{
	struct wireless_iface *curr;
	int skfd;

	/* Search for it in the database */
	curr = interface_cache;

	while(curr != NULL)
	{
		/* Match ? */
		if (curr->ifindex == ifindex)
		{
			//printf("Cache : found %d-%s\n", curr->ifindex,
			//curr->ifname);

			/* Return */
			return(curr);
		}
		/* Next entry */
		curr = curr->next;
	}

	skfd = socket_open();

	curr = g_new(struct wireless_iface, 1);

	curr->ifindex = ifindex;

	/* Extract static data */
	if (index2name(skfd, ifindex, curr->ifname) < 0)
	{
		perror("index2name");
		g_free(curr);
		return NULL;
	}
	curr->has_range = (iw_get_range_info(skfd, curr->ifname,
				&curr->range) >= 0);
	/* Link it */
	curr->next = interface_cache;
	interface_cache = curr;

	return(curr);
}

/**
  Event handling.
  @param ifindex Interface index.
  @param data Data.
  @param len Data length.
  @return status.
 */
static int print_event_stream(int ifindex, char *data, int len)
{
	struct iw_event	iwe;
	struct stream_descr stream;
	struct wireless_iface *wireless_if;
	struct scan_results_t scan_results;
	int ret;

	wireless_if = get_interface_data(ifindex);

	if (wireless_if == NULL)
		return (-1);

	memset(&scan_results, 0, sizeof(struct scan_results_t));
	memset(&iwe, 0, sizeof(iwe));

	/* We don't send scan_results at this point,
	   only some events are sent */

	iw_init_event_stream(&stream, data, len);
	do {
		ret = iw_extract_event_stream(&stream, &iwe,
				wireless_if->range.we_version_compiled);
		if (ret != 0)
		{
			if (ret > 0)
				print_event_token(&iwe, &scan_results, ifindex,
						FALSE);
			else
				die("Invalid event");
		}
	} while (ret > 0);

	return 0;
}
/**
  Deletes all interface data
 */
void del_all_interface_data(void)
{
	struct wireless_iface *curr;
	struct wireless_iface *next;

	curr = interface_cache;

	while(curr)
	{
		next = curr->next;

		g_free(curr);

		curr = next;
	}
}

/**
  Delete one interface from the list
  @param ifindex Interface index.
 */
static void del_interface_data(int ifindex)
{
	struct wireless_iface *	curr;
	struct wireless_iface *	prev = NULL;
	struct wireless_iface *	next;

	/* Go through the list, find the interface, kills it */
	curr = interface_cache;
	while(curr)
	{
		next = curr->next;

		DLOG_DEBUG("Removing interface %s.", curr->ifname);

		/* Got a match ? */
		if(curr->ifindex == ifindex)
		{
			/* Unlink. Root ? */
			if(!prev)
				interface_cache = next;
			else
				prev->next = next;
			//printf("Cache : purge %d-%s\n", curr->ifindex,
			//curr->ifname);

			if( !strcmp(wlan_status.ifname, curr->ifname) ) {
				DLOG_DEBUG("Current interface in use, "
						"disconnecting...");
				set_scan_state(SCAN_NOT_ACTIVE);

				/* Set_wlan_state puts IF down */
				set_wlan_state(WLAN_NOT_INITIALIZED,
						DISCONNECTED_SIGNAL,
						FORCE_YES);
			}

			/* Destroy */
			g_free(curr);
		}
		else
		{
			/* Keep as previous */
			prev = curr;
		}

		/* Next entry */
		curr = next;
	}
}
/**
  Netlink event handling continues, now we know that we have a message
  @param hdr Pointer to message header.
 */
static void handle_message(struct nlmsghdr *hdr)
{
	struct ifinfomsg *infomsg;
	int attrlen;
	struct rtattr *rtattr;

	infomsg = NLMSG_DATA(hdr);

	/* If interface is getting destoyed */
	if(hdr->nlmsg_type == RTM_DELLINK)
	{
		/* Remove from cache (if in cache) */
		del_interface_data(infomsg->ifi_index);
		return;
	}
	/* Only keep add/change events */
	if(hdr->nlmsg_type != RTM_NEWLINK)
		return;

	if(hdr->nlmsg_len > NLMSG_ALIGN(sizeof(struct ifinfomsg))) {
		attrlen = hdr->nlmsg_len-NLMSG_ALIGN(sizeof(struct ifinfomsg));
		rtattr = (void *) ((char *) infomsg +
				NLMSG_ALIGN(sizeof(struct ifinfomsg)));
		while (RTA_OK(rtattr, attrlen)) {

			if (rtattr->rta_type == IFLA_WIRELESS) {
				/* Go to display it */
				print_event_stream(infomsg->ifi_index,
					(char *)rtattr +
					RTA_ALIGN(sizeof(struct rtattr)),
					rtattr->rta_len -
					RTA_ALIGN(sizeof(struct rtattr)));
			}
			rtattr = RTA_NEXT(rtattr, attrlen);
		}
	}
}
/**
  Start netlink event handling
  @param fd File descriptor.
 */
static void handle_netlink_event(int fd)
{
	char buf[1024];
	struct sockaddr_nl nl;
	socklen_t nl_len = sizeof(struct sockaddr_nl);
	int res;

	while (1) {
		res = recvfrom (fd, buf, sizeof(buf), MSG_DONTWAIT,
				(struct sockaddr*)&nl, &nl_len);

		/* Error */
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				DLOG_ERR("Error reading netlink socket");
			}
			/* Don't do anything */
			return;
		}

		/* EOF */
		if (res == 0) {
			return;
		}
		int len;
		struct nlmsghdr *hdr = (struct nlmsghdr*)buf;
		/* real handling in this loop */
		while (res >= (int)sizeof(*hdr))
		{
			len = hdr->nlmsg_len;

			if ((len - (int)sizeof(*hdr) < 0) || len > res) {
				DLOG_ERR("Error in netlink message length");
				break;
			}
			/* Ok, we have good message */
			if (hdr->nlmsg_type == RTM_NEWLINK ||
					hdr->nlmsg_type == RTM_DELLINK) {
				handle_message(hdr);
			}

			/* Get ready for next message */
			len = NLMSG_ALIGN(len);
			res -= len;
			hdr = (struct nlmsghdr*)((char*)hdr+len);
		}
	}
}

/**
  Initialize wireless interface
  @param rth private struct.
  @return status.
 */
static int init_wi (struct rtnl_handle *rth)
{
	unsigned int addr_len;

	memset(rth, 0, sizeof(struct rtnl_handle));

	rth->fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rth->fd < 0) {
		DLOG_ERR("socket()");
		return -1;
	}
	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = RTMGRP_LINK;

	if (bind(rth->fd, (struct sockaddr*)&rth->local,
				sizeof(rth->local)) < 0) {
		DLOG_ERR("bind()");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		DLOG_ERR("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		DLOG_ERR("Wrong address length %d", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		DLOG_ERR("Wrong address family %d", rth->local.nl_family);
		return -1;
	}

	return 0;
}

/**
  Callback function for wireless events.
  @param chan GLIB IO Channel
  @param cond GLIB IO condition
  @param data privat pointer.
  @return status.
 */
static gboolean _monitor_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	int fd;

	if (cond != G_IO_IN) {
		guint watch_id = *((guint *)data);
		DLOG_ERR("Error message from wireless interface");
		g_source_remove(watch_id);
		g_io_channel_unref(chan);
		return FALSE;
	}

	fd = g_io_channel_unix_get_fd(chan);
	if (fd >= 0) {
		handle_netlink_event(fd);
	}

	return TRUE;
}

/**
  Starts monitoring of wireless events.
  @return status.
 */
gboolean monitor_wi(void) {
	static guint watch_id = 0;
	GIOChannel *gio;
	struct rtnl_handle rth;

	if (init_wi(&rth) < 0)
		return FALSE;

	gio = g_io_channel_unix_new(rth.fd);
	g_io_channel_set_close_on_unref(gio, TRUE);
	watch_id = g_io_add_watch(gio, G_IO_IN | G_IO_PRI | G_IO_ERR |
			G_IO_HUP, _monitor_cb, &watch_id);
	return TRUE;
}
