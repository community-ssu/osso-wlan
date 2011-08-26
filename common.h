/**
   @file common.h

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
#ifndef _COMMON_H_
#define _COMMON_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <iwlib.h>
#include <wireless.h>
#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <wlancond.h>

/* Scan results helper struct */
typedef struct scan_results_t
{
	char           ssid[WLANCOND_MAX_SSID_SIZE+1];
	gint32         ssid_len;
	unsigned char  bssid[ETH_ALEN];
	gint32         rssi;
	guint32        channel;
	guint32        cap_bits;
	guint32        wpa_ie_len;
	guint8         *wpa_ie;
} scan_results_t;

/* Generic WPA IE storage type */
typedef struct wpa_ie_list_t
{
	unsigned char  bssid[ETH_ALEN];
	guint32        ie_len;
	guint8         *wpa_ie;
} wpa_ie_list_t;

/* Own WPA IE storage type */
typedef struct wpa_ie_save_t
{
	guint32 ie_len;
	unsigned char *ie;
} wpa_ie_save_t;

/* This struct has all parameters needed for connection */
typedef struct connect_params_t
{
	dbus_int32_t mode;
	dbus_int32_t encryption;
	dbus_int32_t power_level;
	dbus_int32_t default_key;
	dbus_uint32_t adhoc_channel;
	dbus_uint32_t flags;
	char ssid[WLANCOND_MAX_SSID_SIZE+1];
	unsigned int ssid_len;
	unsigned int authentication_type;
	unsigned char key[4][32];
	int key_len[4];
	unsigned char bssid[ETH_ALEN];
} connect_params;

#define PMK_CACHE_SIZE 32
typedef struct pmksa_cache_t
{
	unsigned char mac[ETH_ALEN];
	unsigned char pmkid[IW_PMKID_LEN];
} pmksa_cache;

/* WLAN status and state is kept in this struct.
   Scanning is separated from the state because scanning
   can be initiated separately from other WLAN activity
 */
typedef struct wlan_status_t
{
	/* Interface name cache */
	gchar ifname[IFNAMSIZ+1];
	/* Own MAC address */
	gchar own_mac[ETH_ALEN];
	/* Scan ssid */
	gchar scan_ssid[WLANCOND_MAX_SSID_SIZE+1];
	/* Scan ssid length */
	gint scan_ssid_len;
	/* Scanning state */
	guint scan;
	/* WLAN state */
	guint state;
	/* Requested power state */
	guint requested_power;
	/* Real power state */
	guint real_power;
	/* Cipher suites */
	guint pairwise_cipher;
	guint group_cipher;
	/* Our WPA IE */
	struct wpa_ie_save_t wpa_ie;
	/* connect params */
	struct connect_params_t conn;
	/* pmksa cache */
	GSList* pmk_cache;
	/* Roam cache */
	GSList* roam_cache;
	/* Association retry counter */
	guint retry_count;
	/* Roam scan */
	guint roam_scan;
	/* Roam scan timer ID */
	guint roam_scan_id;
	/* Last scan (in seconds) */
	gint last_scan;
	/* Normal scan timer ID */
	guint scan_id;
	/* Country code */
	gint country_code;
	/* Signal state */
	gboolean signal;
	/* IP configuration state */
	gboolean ip_ok;
	/* Wlan+Bt co-existence state */
	guint coex_state;
	/* Call state */
	guint call_state;
} wlan_status_t;

typedef struct wireless_iface
{
	/* Linked list */
	struct wireless_iface *	next;

	/* Interface identification */
	int ifindex; /* Interface index == black magic */

	/* Interface data */
	char ifname[IFNAMSIZ + 1]; /* Interface name */
	struct iw_range	range; /* Wireless static data */
	int has_range;
} wireless_iface;

/* WLAN force type e.g. in WLAN interface shutdown */
typedef enum {
	FORCE_NO,
	FORCE_YES,
} force_t;

/* WLAN signal */
#define WLANCOND_LOW TRUE
#define WLANCOND_HIGH FALSE

/* Scan state */
enum scan_state {
	SCAN_NOT_ACTIVE = 0,
	SCAN_ACTIVE
};

/* Generic WLAN state */
enum wlan_state {
	WLAN_NOT_INITIALIZED = 0,
	WLAN_INITIALIZED,
	WLAN_INITIALIZED_FOR_SCAN,
	WLAN_INITIALIZED_FOR_CONNECTION,
	WLAN_NO_ADDRESS,
	WLAN_CONNECTED
};

/* WLAN power defines */
#define WLANCOND_TX_POWER10DBM  10 // 10mW = 10dBm
#define WLANCOND_TX_POWER100DBM 20 // 100mW = 20dBm

/* WLAN power state */
enum wlan_power_state {
	WLANCOND_POWER_ON = 1,
	WLANCOND_LONG_CAM,
	WLANCOND_SHORT_CAM,
	WLANCOND_VERY_SHORT_CAM,
	WLANCOND_FULL_POWERSAVE
};

enum bt_state {
	WLANCOND_BT_COEX_OFF,
	WLANCOND_BT_COEX_ON,
	WLANCOND_BT_COEX_MONOAUDIO
};

enum call_state {
	WLANCOND_CALL_NONE,
	WLANCOND_CALL_VOIP,
	WLANCOND_CALL_CELL,
	WLANCOND_CALL_UNKNOWN
};

#define NULL_BSSID (unsigned char*)"\x00\x00\x00\x00\x00\x00"

#define WLANCOND_DEFAULT_SLEEP_TIMEOUT 200000 // 200ms
#define WLANCOND_VERY_SHORT_CAM_TIMEOUT 100000 // 100ms
#define WLANCOND_LONG_CAM_TIMEOUT 4000000 // 4s

#define MIC_FAILURE_TIMEOUT 60 // 60 seconds

/* Signal sending defines */
#define NO_SIGNAL           0
#define DISCONNECTED_SIGNAL 1

/* Maximum values */
#define WLANCOND_MAX_NETWORKS 30
#define WLANCOND_MAX_SCAN_TRIES 3

#define WLANCOND_INITIAL_ROAM_SCAN_DELAY 2 // 2 seconds
#define WLANCOND_ROAM_THRESHOLD 10
#define WLANCOND_MIN_ROAM_SCAN_INTERVAL 60 // 60 seconds
#define WLANCOND_MAX_ROAM_SCAN_INTERVAL 16*60 // 16 minutes
#define WLANCOND_RSSI_PENALTY 25 // 25dBm
#define WLANCOND_MINIMUM_SIGNAL -99
#define WLANCOND_MINIMUM_AUTOCONNECT_RSSI -85

/* Gconf paths */
#define GCONF_PATH_PREFIX "/system/osso/connectivity/IAP/"
#define SLEEP_GCONF_PATH GCONF_PATH_PREFIX "wlan_sleep_timeout"
#define INACTIVE_SLEEP_GCONF_PATH GCONF_PATH_PREFIX "inactive_wlan_sleep_timeout"
#define DEBUG_LEVEL GCONF_PATH_PREFIX "wlancond_debug_level"

/* Debug printing priority */
#define WLANCOND_PRIO_HIGH   2
#define WLANCOND_PRIO_MEDIUM 1
#define WLANCOND_PRIO_LOW    0

/* Deauthenticate reasons */
#define WLANCOND_REASON_LEAVING 3
#define WLANCOND_REASON_MIC_FAILURE 14

/* Define for the Phone.Net interface */
#define PHONE_NET_DBUS_SERVICE "com.nokia.phone.net"
#define PHONE_NET_DBUS_PATH "/com/nokia/phone/net"
#define PHONE_NET_DBUS_INTERFACE "Phone.Net"
#define PHONE_REGISTRATION_STATUS_CHANGE_SIG "registration_status_change"

/* Bluez DBUS service name */
/* Apparently there is no header for these... */
#define BLUEZ_SERVICE_NAME                 "org.bluez"

#define BLUEZ_MANAGER_PATH_NAME            "/"
#define BLUEZ_MANAGER_INTERFACE_NAME       "org.bluez.Manager"
#define BLUEZ_MANAGER_DEFAULT_ADAPTER_METHOD "DefaultAdapter"

#define BLUEZ_ADAPTER_SERVICE_NAME         "org.bluez.Adapter"
#define BLUEZ_ADAPTER_PROPERTY_CHANGED_SIG "PropertyChanged"
#define BLUEZ_ADAPTER_PROPERTY_POWERED     "Powered"
#define BLUEZ_ADAPTER_GET_PROPERTIES_METHOD "GetProperties"

#define BLUEZ_HEADSET_SERVICE_NAME         "org.bluez.Headset"
#define BLUEZ_HEADSET_PROPERTY_CHANGED_SIG "PropertyChanged"
#define BLUEZ_HEADSET_PROPERTY_STATE       "State"
#define BLUEZ_HEADSET_PROPERTY_PLAYING     "playing"

#define BLUEZ_AUDIOSINK_SERVICE_NAME       "org.bluez.AudioSink"
#define BLUEZ_AUDIOSINK_PROPERTY_CHANGED_SIG "PropertyChanged"
#define BLUEZ_AUDIOSINK_PROPERTY_STATE     "State"
#define BLUEZ_AUDIOSINK_PROPERTY_PLAYING   "playing"

#define POLICY_SERVICE_NAME                "com.nokia.policy"
#define POLICY_ACTIONS_SIG                 "actions"

/* BT COEX */
#define WLANCOND_BT_COEX_FILE "/sys/devices/platform/wl12xx/bt_coex_mode"

/* Common functions */
void init_logging(void);
void wlancond_print(guint priority, const char *debug, ...);
gboolean monitor_wi(void);
void del_all_interface_data(void);
struct wireless_iface *get_interface_data(int ifindex);
int print_event_token(struct iw_event *	event, struct scan_results_t *scan_results, int ifindex, gboolean scan_event);
void send_dbus_scan_results(GSList* scan_results_save, const char* sender,
		dbus_int32_t number_of_results);
GSList *save_scan_results(struct scan_results_t *scan_results,
		GSList *scan_results_save);
void clean_scan_results(GSList **scan_results_save);
void disconnected_signal(void);
void mode_change(const char *mode);
#ifdef ACTIVITY_CHECK
void activity_check(dbus_bool_t activity);
#endif

void clean_scan_results_item(gpointer data, gpointer user_data);
void print_mac(guint priority, const char *message, guchar* mac);

#endif /* _COMMON_H_ */
