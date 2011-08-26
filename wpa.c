/**
   @file wpa.c

   Copyright (C) 2004-2008 Nokia Corporation. All rights reserved.

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
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <eap-dbus.h>

#include "wpa.h"
#include "common.h"
#include "dbus-handler.h"
#include "log.h"

/* MIC failure timer ID */
static guint mic_failure_timer_id = 0;

/* MIC failure timer running ID */
static guint mic_failure_running_timer_id = 0;

/* Black list of APs */
static GSList *ap_black_list = NULL;

/* Cipher suites */
static const guint8 WPA_CIPHER_SUITE_NONE[] = {0x00, 0x50, 0xf2, 0};
static const guint8 WPA_CIPHER_SUITE_WEP40[] = {0x00, 0x50, 0xf2, 1};
static const guint8 WPA_CIPHER_SUITE_TKIP[] = {0x00, 0x50, 0xf2, 2};
//static const guint8 WPA_CIPHER_SUITE_WRAP[] = {0x00, 0x50, 0xf2, 3};
static const guint8 WPA_CIPHER_SUITE_CCMP[] = {0x00, 0x50, 0xf2, 4};
static const guint8 WPA_CIPHER_SUITE_WEP104[] = {0x00, 0x50, 0xf2, 5};

static const guint8 RSN_CIPHER_SUITE_NONE[] = {0x00, 0x0f, 0xac, 0};
static const guint8 RSN_CIPHER_SUITE_WEP40[] = {0x00, 0x0f, 0xac, 1};
static const guint8 RSN_CIPHER_SUITE_TKIP[] = {0x00, 0x0f, 0xac, 2};
//static const guint8 RSN_CIPHER_SUITE_WRAP[] = {0x00, 0x0f, 0xac, 3};
static const guint8 RSN_CIPHER_SUITE_CCMP[] = {0x00, 0x0f, 0xac, 4};
static const guint8 RSN_CIPHER_SUITE_WEP104[] = {0x00, 0x0f, 0xac, 5};

/* Key management suites */
static const guint8 RSN_KEY_MGMT_802_1X[] = {0x00, 0x0f, 0xac, 1};
static const guint8 RSN_KEY_MGMT_PSK[] = {0x00, 0x0f, 0xac, 2};
static const guint8 WPA_KEY_MGMT_802_1X[] = {0x00, 0x50, 0xf2, 1};
static const guint8 WPA_KEY_MGMT_PSK[] = {0x00, 0x50, 0xf2, 2};

static const guint8 WPA_OUI[] = { 0x00, 0x50, 0xf2 };

static guint parse_rsn_cipher_suite(guint8 *suite)
{
	if (memcmp(suite, RSN_CIPHER_SUITE_TKIP, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_TKIP;
	if (memcmp(suite, RSN_CIPHER_SUITE_CCMP, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_CCMP;
	if (memcmp(suite, RSN_CIPHER_SUITE_NONE, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_NONE;
	if (memcmp(suite, RSN_CIPHER_SUITE_WEP40, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_WEP40;
	if (memcmp(suite, RSN_CIPHER_SUITE_WEP104, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_WEP104;
	return 0;
}

static guint parse_rsn_key_mgmt_suite(guint8 *suite)
{
	if (memcmp(suite, RSN_KEY_MGMT_802_1X, CIPHER_SUITE_LEN) == 0)
		return WPA_802_1X;
	if (memcmp(suite, RSN_KEY_MGMT_PSK, CIPHER_SUITE_LEN) == 0)
		return WPA_PSK;
	return 0;
}

static guint parse_wpa_cipher_suite(guint8* suite)
{
	if (memcmp(suite, WPA_CIPHER_SUITE_TKIP, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_TKIP;
	if (memcmp(suite, WPA_CIPHER_SUITE_CCMP, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_CCMP;
	if (memcmp(suite, WPA_CIPHER_SUITE_NONE, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_NONE;
	if (memcmp(suite, WPA_CIPHER_SUITE_WEP40, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_WEP40;
	if (memcmp(suite, WPA_CIPHER_SUITE_WEP104, CIPHER_SUITE_LEN) == 0)
		return CIPHER_SUITE_WEP104;
	return 0;
}

static guint parse_wpa_key_mgmt_suite(guint8 *suite)
{
	if (memcmp(suite, WPA_KEY_MGMT_802_1X, CIPHER_SUITE_LEN) == 0)
		return WPA_802_1X;
	if (memcmp(suite, WPA_KEY_MGMT_PSK, CIPHER_SUITE_LEN) == 0)
		return WPA_PSK;
	return 0;
}
/**
  Generate WPA1 Information Element.
  @param encryption encryption settings.
  @param wlan_status wlan status information.
  @return status.
 */
static int generate_wpa_ie(guint32 encryption,
		struct wlan_status_t *wlan_status)
{
	guint8 *wpa_ie;
	struct wpa_ie_t *wpa_hdr;
	guint8* hdr_p;

	/* Update the length if you change something */
	wpa_ie = g_malloc(sizeof(struct wpa_ie_t)+4+CIPHER_SUITE_LEN*3);

	wpa_hdr = (struct wpa_ie_t*) wpa_ie;
	wpa_hdr->element_id = WPA_ELEMENT;
	memcpy(&wpa_hdr->oui, WPA_OUI, sizeof(WPA_OUI));
	wpa_hdr->oui_type = 1;

	wpa_hdr->version = WPA_VERSION;
	hdr_p = (guint8*)(wpa_hdr + 1);

	/* Group cipher suite */
	switch (wlan_status->group_cipher) {
	case CIPHER_SUITE_TKIP:
		memcpy(hdr_p, WPA_CIPHER_SUITE_TKIP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_CCMP:
		memcpy(hdr_p, WPA_CIPHER_SUITE_CCMP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP104:
		memcpy(hdr_p, WPA_CIPHER_SUITE_WEP104, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP40:
		memcpy(hdr_p, WPA_CIPHER_SUITE_WEP40, CIPHER_SUITE_LEN);
		break;
	default:
		DLOG_ERR("Unsupported group cipher suite");
		g_free(wpa_ie);
		return -1;
	}

	hdr_p += CIPHER_SUITE_LEN;

	/* Pairwise count */
	*hdr_p++ = 1;
	*hdr_p++ = 0;

	switch (wlan_status->pairwise_cipher) {
	case CIPHER_SUITE_TKIP:
		memcpy(hdr_p, WPA_CIPHER_SUITE_TKIP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_CCMP:
		memcpy(hdr_p, WPA_CIPHER_SUITE_CCMP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP104:
		memcpy(hdr_p, WPA_CIPHER_SUITE_WEP104, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP40:
		memcpy(hdr_p, WPA_CIPHER_SUITE_WEP40, CIPHER_SUITE_LEN);
		break;
	default:
		DLOG_ERR("Unsupported pairwise cipher suite: %08x",
				wlan_status->pairwise_cipher);
		g_free(wpa_ie);
		return -1;
	}

	hdr_p += CIPHER_SUITE_LEN;

	/* Authentication count */
	*hdr_p++ = 1;
	*hdr_p++ = 0;

	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_PSK) {
		DLOG_DEBUG("WPA PSK selected");
		memcpy(hdr_p, WPA_KEY_MGMT_PSK, CIPHER_SUITE_LEN);
	} else if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) ==
			WLANCOND_WPA_EAP) {
		DLOG_DEBUG("WPA EAP selected");
		memcpy(hdr_p, WPA_KEY_MGMT_802_1X, CIPHER_SUITE_LEN);
	} else {
		DLOG_ERR("Unknown key management suite");
		g_free(wpa_ie);
		return 1;
	}

	hdr_p += CIPHER_SUITE_LEN;

	/* Capabilities are empty */

	wpa_hdr->length = (hdr_p - wpa_ie) - 2;

#ifdef DEBUG_IE
	int i;
	printf("Own WPA IE:\n");
	for (i=0;i<wpa_hdr->length;i++) {
		printf("0x%02x ", wpa_ie[i]);
	}
	printf("\n");
#endif

	update_own_ie(wpa_ie, wpa_hdr->length + 2);

	return 0;
}
/**
  Generate WPA2 Information Element.
  @param encryption encryption settings.
  @param wlan_status wlan status information.
  @return status.
 */
static int generate_wpa2_ie(guint32 encryption,
		struct wlan_status_t *wlan_status)
{

	guint8 *wpa_ie;
	struct rsn_ie_t *wpa_hdr;
	guint8* hdr_p;

	/* Update the length if you change something */
	wpa_ie = g_malloc(sizeof(struct rsn_ie_t)+8+CIPHER_SUITE_LEN*3+
			IW_PMKID_LEN);

	wpa_hdr = (struct rsn_ie_t*) wpa_ie;
	wpa_hdr->element_id = RSN_ELEMENT;

	wpa_hdr->version = RSN_VERSION;
	hdr_p = (guint8*)(wpa_hdr + 1);

	/* Group cipher suite */
	switch (wlan_status->group_cipher) {
	case CIPHER_SUITE_TKIP:
		memcpy(hdr_p, RSN_CIPHER_SUITE_TKIP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_CCMP:
		memcpy(hdr_p, RSN_CIPHER_SUITE_CCMP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP104:
		memcpy(hdr_p, RSN_CIPHER_SUITE_WEP104, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP40:
		memcpy(hdr_p, RSN_CIPHER_SUITE_WEP40, CIPHER_SUITE_LEN);
		break;
	default:
		DLOG_ERR("Unsupported group cipher suite");
		g_free(wpa_ie);
		return -1;
	}

	hdr_p += CIPHER_SUITE_LEN;

	/* Pairwise count */
	*hdr_p++ = 1;
	*hdr_p++ = 0;

	switch (wlan_status->pairwise_cipher) {
	case CIPHER_SUITE_TKIP:
		memcpy(hdr_p, RSN_CIPHER_SUITE_TKIP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_CCMP:
		memcpy(hdr_p, RSN_CIPHER_SUITE_CCMP, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP104:
		memcpy(hdr_p, RSN_CIPHER_SUITE_WEP104, CIPHER_SUITE_LEN);
		break;
	case CIPHER_SUITE_WEP40:
		memcpy(hdr_p, RSN_CIPHER_SUITE_WEP40, CIPHER_SUITE_LEN);
		break;
	default:
		DLOG_ERR("Unsupported pairwise cipher suite");
		g_free(wpa_ie);
		return -1;
	}

	hdr_p += CIPHER_SUITE_LEN;

	/* Authentication count */
	*hdr_p++ = 1;
	*hdr_p++ = 0;

	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_PSK) {
		memcpy(hdr_p, RSN_KEY_MGMT_PSK, CIPHER_SUITE_LEN);
	} else if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) ==
			WLANCOND_WPA_EAP){
		memcpy(hdr_p, RSN_KEY_MGMT_802_1X, CIPHER_SUITE_LEN);
	} else {
		DLOG_ERR("Unknown key management suite");
		g_free(wpa_ie);
		return -1;
	}

	hdr_p += CIPHER_SUITE_LEN;

	/* Capabilities are empty */
	*hdr_p++ = 0;
	*hdr_p++ = 0;

	/* PMKID */
	unsigned char *pmkid;

	if (find_pmkid_from_pmk_cache(wlan_status->conn.bssid, &pmkid)) {
		DLOG_ERR("Error trying to retrieve the pmkid.");
		return ESUPPLICANT;
	}

	if (pmkid != NULL) {
		*hdr_p++ = 1;
		*hdr_p++ = 0;
		memcpy(hdr_p, pmkid, IW_PMKID_LEN);
		hdr_p += IW_PMKID_LEN;
	}

	wpa_hdr->length = (hdr_p - wpa_ie) - 2;

#ifdef DEBUG_IE
	int i;
	printf("Own WPA IE:\n");
	for (i=0;i<wpa_hdr->length;i++) {
		printf("0x%02x ", wpa_ie[i]);
	}
	printf("\n");
#endif

	update_own_ie(wpa_ie, wpa_hdr->length + 2);

	return 0;
}
/**
  Set WPA Information Element.
  @param wpa_ie WPA Information Element.
  @param wpa_ie_len WPA Information Element length.
  @return status.
 */
int set_wpa_ie(struct wlan_status_t *wlan_status)
{
	struct iwreq req;

	DLOG_DEBUG("Setting IE, len:%d", wlan_status->wpa_ie.ie_len);

	init_iwreq(&req);

	req.u.data.pointer = (caddr_t) wlan_status->wpa_ie.ie;
	req.u.data.length = wlan_status->wpa_ie.ie_len;

	if (ioctl(socket_open(), SIOCSIWGENIE, &req) < 0) {
		DLOG_ERR("Set WPA IE failed\n");
		return -1;
	}

	return 0;
}

static guint32 pairwise_encryption_to_cipher(guint32 encryption,
		struct scan_results_t *scan_results)
{
	if ((encryption & WLANCOND_ENCRYPT_ALG_MASK) == WLANCOND_WPA_TKIP)
		return IW_AUTH_CIPHER_TKIP;
	if ((encryption & WLANCOND_ENCRYPT_ALG_MASK) == WLANCOND_WPA_AES)
		return IW_AUTH_CIPHER_CCMP;
	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_PSK ||
			(encryption & WLANCOND_ENCRYPT_METHOD_MASK)
			== WLANCOND_WPA_EAP) {
		if (scan_results->extra_cap_bits & WLANCOND_WEP40)
			return IW_AUTH_CIPHER_WEP40;
		else if (scan_results->extra_cap_bits & WLANCOND_WEP104)
			return IW_AUTH_CIPHER_WEP104;
	}
	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WEP)
		return IW_AUTH_CIPHER_WEP104;
	return IW_AUTH_CIPHER_NONE;
}

static guint32 group_encryption_to_cipher(guint32 encryption,
		struct scan_results_t *scan_results)
{
	if ((encryption & WLANCOND_ENCRYPT_GROUP_ALG_MASK) ==
			WLANCOND_WPA_TKIP_GROUP)
		return IW_AUTH_CIPHER_TKIP;
	if ((encryption & WLANCOND_ENCRYPT_GROUP_ALG_MASK) ==
			(guint32)WLANCOND_WPA_AES_GROUP)
		return IW_AUTH_CIPHER_CCMP;
	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_PSK ||
			(encryption & WLANCOND_ENCRYPT_METHOD_MASK)
			== WLANCOND_WPA_EAP) {
		if (scan_results->extra_cap_bits & WLANCOND_WEP40_GROUP)
			return IW_AUTH_CIPHER_WEP40;
		else if (scan_results->extra_cap_bits & WLANCOND_WEP104_GROUP)
			return IW_AUTH_CIPHER_WEP104;
	}
	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WEP)
		return IW_AUTH_CIPHER_WEP104;
	return IW_AUTH_CIPHER_NONE;
}
/**
  Helper function for setting the encryption settings.
  @param index Setting to be modified.
  @param value New value.
  @return status.
 */
static int set_encryption_method_helper(gint index, guint32 value)
{
	struct iwreq req;

	init_iwreq(&req);

	//DLOG_DEBUG("Setting param %d, value: 0x%X", index, value);

	req.u.param.flags = index & IW_AUTH_INDEX;
	req.u.param.value = value;

	if (ioctl(socket_open(), SIOCSIWAUTH, &req) < 0) {
		DLOG_ERR("Could not set auth mode %d, %X", index, value);
		return -1;
	}

	return 0;
}
/**
  Set WPA countermeasures.
  @param onoff On or Off.
  @return status.
 */
int set_countermeasures(guint on_off)
{
	return set_encryption_method_helper(IW_AUTH_TKIP_COUNTERMEASURES,
			on_off);
}

/**
  Set encryption settings.
  @param encryption Encryption settings.
  @param wlan_status WLAN status struct.
  @param scan_results Scan results
  @return status.
 */
gint set_encryption_method(guint32 encryption,
			   struct wlan_status_t *wlan_status,
			   struct scan_results_t *scan_results)
{
	gint32 value = 0;
	guint32 key_mgmt = 0;
	gboolean wpa2 = FALSE;
	guint32 authentication = wlan_status->conn.authentication_type;

	if (encryption & WLANCOND_ENCRYPT_WPA2_MASK)
		wpa2 = TRUE;

	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_PSK) {
		if (wpa2 == TRUE)
			value = IW_AUTH_WPA_VERSION_WPA2;
		else
			value = IW_AUTH_WPA_VERSION_WPA;
		key_mgmt = IW_AUTH_KEY_MGMT_PSK;

	} else if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) ==
			WLANCOND_WPA_EAP) {
		if (wpa2 == TRUE)
			value = IW_AUTH_WPA_VERSION_WPA2;
		else
			value = IW_AUTH_WPA_VERSION_WPA;
		key_mgmt = IW_AUTH_KEY_MGMT_802_1X;
	} else {
		value = IW_AUTH_WPA_VERSION_DISABLED;
	}

	if (key_mgmt != 0) {
		if (set_encryption_method_helper(IW_AUTH_WPA_ENABLED, 1) < 0)
			return -1;

		set_encryption_method_helper(IW_AUTH_DROP_UNENCRYPTED,
				1);

		set_encryption_method_helper(IW_AUTH_80211_AUTH_ALG,
				IW_AUTH_ALG_OPEN_SYSTEM);

	}

	if (set_encryption_method_helper(IW_AUTH_WPA_VERSION, value) < 0)
		return -1;

	if (key_mgmt != 0) {
		// Set Information Element if not WPS mode
		if (authentication != EAP_AUTH_TYPE_WFA_SC) {
			if (wpa2 == TRUE)
				value = generate_wpa2_ie(encryption,
						wlan_status);
			else
				value = generate_wpa_ie(encryption,
						wlan_status);
		}
	} else {
		if (set_encryption_method_helper(IW_AUTH_WPA_ENABLED, 0) < 0)
			return -1;

		/* Check for WEP */
		if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) != WLANCOND_WEP){
			set_encryption_method_helper(IW_AUTH_DROP_UNENCRYPTED,
					0);
		} else {
		
			set_encryption_method_helper(IW_AUTH_80211_AUTH_ALG,
				IW_AUTH_ALG_OPEN_SYSTEM|IW_AUTH_ALG_SHARED_KEY);
        	}

	}
	if (value < 0)
		return value;

	/* Set IE */
	if (set_wpa_ie(wlan_status) <0)
		return -1;

	value = pairwise_encryption_to_cipher(encryption, scan_results);

	if (set_encryption_method_helper(IW_AUTH_CIPHER_PAIRWISE, value) < 0)
		return -1;

	value = group_encryption_to_cipher(encryption, scan_results);

	if (set_encryption_method_helper(IW_AUTH_CIPHER_GROUP, value) < 0)
		return -1;

	if (set_encryption_method_helper(IW_AUTH_KEY_MGMT, key_mgmt) < 0)
		return -1;

	value = key_mgmt != 0 ||
		(encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WEP;

	if (set_encryption_method_helper(IW_AUTH_PRIVACY_INVOKED, value) < 0) {
		/* Ignore error in Adhoc */
		if (wlan_status->conn.mode != WLANCOND_ADHOC)
			return -1;
	}

	if (key_mgmt != 0) {
		value = 0;
	} else {
		value = 1;
	}

	if (set_encryption_method_helper(IW_AUTH_RX_UNENCRYPTED_EAPOL,
				value) < 0)
		return -1;

	return 0;
}

static gint compare_bssid(gconstpointer a, gconstpointer b)
{
	return memcmp(a, b, ETH_ALEN);
}

/**
  Remove access point from the black list.
  @param bssid BSSID.
 */
static void remove_ap_from_black_list(unsigned char* bssid)
{
	GSList *list;

	list = g_slist_find_custom(ap_black_list, bssid, &compare_bssid);

	if (list != NULL) {
		unsigned char* bssid_entry = list->data;
		print_mac(WLANCOND_PRIO_MEDIUM,
				"Found black list entry to be removed:",
				bssid);

		/* Remove the old entry */
		ap_black_list = g_slist_remove(ap_black_list,
				bssid_entry);
		g_free(bssid_entry);
	}
}

/**
  Mic failure timer callback.
  @param data callback data.
  @return status.
 */
static gboolean mic_failure_timer_cb(void* data)
{
	/* Since we get into this function no MIC failure
	   has happened within last 60 seconds.
	 */
	mic_failure_timer_id = 0;

	print_mac(WLANCOND_PRIO_MEDIUM,
			"No MIC failures within the last 60 seconds for:",
			data);

	remove_ap_from_black_list(data);

	return FALSE;
}

/**
  Check if access point is in the black list.
  @param bssid BSSID.
  @return TRUE if in the list.
 */
gboolean is_ap_in_black_list(unsigned char* bssid)
{
	GSList *list;

	list = g_slist_find_custom(ap_black_list, bssid, &compare_bssid);

	if (list != NULL) {
		print_mac(WLANCOND_PRIO_HIGH,
				"Found AP from black list:", bssid);
		return TRUE;
	}
	return FALSE;
}

/**
  Mic failure running timer callback.
  @param data callback data.
  @return status.
 */
static gboolean mic_failure_running_cb(void* data)
{
	mic_failure_running_timer_id = 0;

	print_mac(WLANCOND_PRIO_HIGH, "MIC failures off for:", data);

	remove_ap_from_black_list(data);

	return FALSE;
}

static void add_ap_to_black_list(unsigned char* bssid)
{
	ap_black_list = g_slist_prepend(ap_black_list,
			g_memdup(bssid, ETH_ALEN));
}

static void mic_destroy_cb(gpointer data)
{
	//print_mac("Destroying mac:", data);
	g_free(data);
}

/**
  Handle MIC failure.
  @param key_type Key type (pairwise/group).
  @return status.
 */
int handle_mic_failure(gboolean key_type, unsigned char* bssid)
{

	if (mic_failure_timer_id != 0) {

		g_source_remove(mic_failure_timer_id);
		mic_failure_timer_id = 0;

		/* Second failure in 60 seconds, fatal */
		wpa_mic_failure_event(key_type, TRUE);

		print_mac(WLANCOND_PRIO_HIGH,
				"Second MIC failure, disconnecting AP:", bssid);

		sleep(1);

		mlme_command(bssid, IW_MLME_DEAUTH,
				WLANCOND_REASON_MIC_FAILURE);

		set_wlan_state(WLAN_NOT_INITIALIZED,
				DISCONNECTED_SIGNAL,
				FORCE_NO);

		/* Set timer to remember this fatal error for 60 seconds */
		mic_failure_running_timer_id = g_timeout_add_seconds_full(
				G_PRIORITY_DEFAULT,
				MIC_FAILURE_TIMEOUT,
				mic_failure_running_cb,
				g_memdup(bssid, ETH_ALEN),
				mic_destroy_cb);

		add_ap_to_black_list(bssid);

		return 0;
	}

	wpa_mic_failure_event(key_type, FALSE);

	mic_failure_timer_id = g_timeout_add_seconds_full(
			G_PRIORITY_DEFAULT,
			MIC_FAILURE_TIMEOUT,
			mic_failure_timer_cb,
			g_memdup(bssid, ETH_ALEN),
			mic_destroy_cb);

	return 0;
}

/**
  Parse RSN IE.
  @param wpa_ie WPA IE.
  @param wpa_ie_len WPA IE length.
  @param ap_info AP Information pointer.
  @return status.
 */
int parse_rsn_ie(unsigned char* wpa_ie, unsigned int wpa_ie_len,
		struct ap_info_t* ap_info)
{
	struct rsn_ie_t *wpa_hdr;
	guint8 *hdr_p;
	guint ind;
	guint i;
	guint cipher_count = 0;

	/* Do data checking, we have to make sure all the time that we
	   don't go past the IE length , index variable counts the
	   remaining data, the spec says that all data after the version
	   field is optional */

	wpa_hdr = (struct rsn_ie_t*) wpa_ie;

	if (wpa_ie_len < sizeof(struct rsn_ie_t)) {
		DLOG_ERR("WPA IE too short");
		return -1;
	}

	if (wpa_hdr->element_id != RSN_ELEMENT) {
		DLOG_ERR("Unknown WPA IE received");
		return -1;
	}

	ind = wpa_ie_len - sizeof(*wpa_hdr);
	hdr_p = (guint8*)(wpa_hdr + 1);

	if (ind >= CIPHER_SUITE_LEN) {
		ap_info->group_cipher = parse_rsn_cipher_suite(hdr_p);
		hdr_p += CIPHER_SUITE_LEN;
		ind -= CIPHER_SUITE_LEN;
	} else {
		DLOG_ERR("Strange length in WPA IE");
		return -1;
	}

	if (ind >= 2) {
		ap_info->pairwise_cipher = 0;
		cipher_count = *(guint16*)hdr_p;

		ind -= 2;

		if (cipher_count == 0) {
			DLOG_ERR("No pairwise ciphers");
			// Return 0 instead or an error
			return 0;
		}

		if (ind < cipher_count * CIPHER_SUITE_LEN) {
			DLOG_ERR("Invalid pairwise cipher length");
			return -1;
		}

		hdr_p += 2;

		for (i = 0; i < cipher_count; i++) {
			ap_info->pairwise_cipher |= parse_rsn_cipher_suite(hdr_p);
			ind -= CIPHER_SUITE_LEN;
			hdr_p += CIPHER_SUITE_LEN;
		}
	} else if (ind == 1) {
		DLOG_ERR("Remaining data too short");
		return -1;
	}

	if (ind >= 2) {
		ap_info->key_mgmt = 0;
		cipher_count = *(guint16*)hdr_p;
		hdr_p += 2;
		ind -= 2;

		if (cipher_count == 0 || ind < cipher_count *
				CIPHER_SUITE_LEN) {
			DLOG_ERR("Invalid key mgmt cipher count or length");
			return -1;
		}

		for (i = 0; i < cipher_count; i++) {
			ap_info->key_mgmt |= parse_rsn_key_mgmt_suite(hdr_p);
			ind -= CIPHER_SUITE_LEN;
			hdr_p += CIPHER_SUITE_LEN;
		}
	} else if (ind == 1) {
		DLOG_ERR("Remaining data too short");
		return -1;
	}

	if (ind >= 2) {
		//ap_info->rsn_capabilities = *(guint16*)hdr_p;
		hdr_p += 2;
		ind -= 2;
	}

	if (ind > 0) {
		DLOG_DEBUG("IE includes PMKID data");
	}
	return 0;
}


/**
  Parse WPA IE.
  @param wpa_ie WPA IE.
  @param wpa_ie_len WPA IE length.
  @param ap_info AP Information pointer.
  @return status.
 */
int parse_wpa_ie(unsigned char* wpa_ie, unsigned int wpa_ie_len,
		struct ap_info_t* ap_info)
{
	struct wpa_ie_t *wpa_hdr;
	guint8 *hdr_p;
	guint ind, i;
	guint cipher_count = 0;
	const guint8 WPA1_OUI[] = { 0x00, 0x50, 0xf2, 1 };

	/* Do data checking, we have to make sure all the time that we
	   don't go past the IE length , index variable counts the
	   remaining data, the spec says that all data after the version
	   field is optional */

	wpa_hdr = (struct wpa_ie_t*) wpa_ie;

	if (wpa_ie_len < sizeof(struct wpa_ie_t)) {
		DLOG_ERR("WPA IE too short");
		return -1;
	}

	if (wpa_hdr->element_id != WPA_ELEMENT) {
		DLOG_ERR("Unknown WPA IE received");
		return -1;
	}

	if (memcmp(&wpa_hdr->oui, WPA1_OUI, CIPHER_SUITE_LEN) != 0) {
		DLOG_ERR("Invalid WPA header");
		return -1;
	}

	ind = wpa_ie_len - sizeof(*wpa_hdr);
	hdr_p = (guint8*)(wpa_hdr + 1);

	if (ind >= CIPHER_SUITE_LEN) {
		ap_info->group_cipher = parse_wpa_cipher_suite(hdr_p);
		ind -= CIPHER_SUITE_LEN;
		hdr_p += CIPHER_SUITE_LEN;
	} else {
		DLOG_ERR("Strange length in WPA IE");
		return -1;
	}

	if (ind >= 2) {
		ap_info->pairwise_cipher = 0;
		cipher_count = *(guint16*)hdr_p;
		ind -= 2;

		if (cipher_count == 0) {
			DLOG_ERR("No pairwise ciphers");
			// Return 0 instead or an error
			return 0;
		}

		if (ind < cipher_count * CIPHER_SUITE_LEN) {
			DLOG_ERR("Invalid pairwise cipher length");
			return -1;
		}

		hdr_p += 2;

		for (i = 0; i < cipher_count; i++) {
			ap_info->pairwise_cipher |=
				parse_wpa_cipher_suite(hdr_p);
			ind -= CIPHER_SUITE_LEN;
			hdr_p += CIPHER_SUITE_LEN;
		}
	} else if (ind == 1) {
		DLOG_ERR("Remaining data too short");
		return -1;
	}

	if (ind >= 2) {
		ap_info->key_mgmt = 0;
		cipher_count = *(guint16*)hdr_p;
		hdr_p += 2;
		ind -= 2;

		if (cipher_count == 0 || ind < cipher_count *
				CIPHER_SUITE_LEN) {
			DLOG_ERR("Invalid key mgmt cipher count (%d) or length",
					cipher_count);
			return -1;
		}

		for (i = 0; i < cipher_count; i++) {
			ap_info->key_mgmt |= parse_wpa_key_mgmt_suite(hdr_p);
			ind -= CIPHER_SUITE_LEN;
			hdr_p += CIPHER_SUITE_LEN;
		}
	} else if (ind == 1) {
		DLOG_ERR("Remaining data too short");
		return -1;
	}

	if (ind >= 2) {
		//ap_info->rsn_capabilities = *(guint16*)hdr_p;
		hdr_p += 2;
		ind -= 2;
	}

	if (ind > 0) {
		DLOG_ERR("IE too long?");
		return -1;
	}
	return 0;
}
