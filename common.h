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
#include <linux/compiler.h>
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
        guint32 ie_valid;
        guint32 ie_len;
        unsigned char *ie;
} wpa_ie_save_t;


/* WLAN status and state is kept in this struct. 
   Scanning is separated from the state because scanning
   can be initiated separately from other WLAN activity
*/
typedef struct wlan_status_t
{
        /* Scanning state */
        guint scan;
        /* WLAN state */
        guint state;
        /* Power state */
        guint power;
        /* Network mode */
        guint mode;
        /* Cipher suites */
        guint pairwise_cipher;
        guint group_cipher;
        /* Our WPA IE */
        struct wpa_ie_save_t wpa_ie;
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
        FORCE_MAYBE
} force_t;

/* WPA Information Element status */
#define IE_NOT_VALID 0
#define IE_VALID     1

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

#define WLANCOND_DEFAULT_SLEEP_TIMEOUT 200 // 200ms
#define WLANCOND_VERY_SHORT_CAM_TIMEOUT 100 // 100ms
#define WLANCOND_LONG_CAM_TIMEOUT 4000 // 4000ms

#define MIC_FAILURE_TIMEOUT 60000 // 60 seconds

/* Signal sending defines */
#define NO_SIGNAL           0
#define DISCONNECTED_SIGNAL 1

#define WLANCOND_MAX_NETWORKS 30

#define WLANCOND_DEFAULT_DMA_THRESHOLD 200
#define WLANCOND_DEFAULT_BGSCAN_THRESHOLD 75
#define WLANCOND_DEFAULT_IDLE_BGSCAN_THRESHOLD 85

/* Gconf paths */
#define GCONF_PATH_PREFIX "/system/osso/connectivity/IAP/"
#define SLEEP_GCONF_PATH GCONF_PATH_PREFIX "wlan_sleep_timeout"
#define INACTIVE_SLEEP_GCONF_PATH GCONF_PATH_PREFIX "inactive_wlan_sleep_timeout"
#define DMA_THRESHOLD_GCONF_PATH GCONF_PATH_PREFIX "dma_threshold"
#define BGSCAN_THRESHOLD_GCONF_PATH GCONF_PATH_PREFIX "bgscan_threshold"
#define BGSCAN_INTERVAL_GCONF_PATH GCONF_PATH_PREFIX "bgscan_interval"

/* Common functions */
gboolean monitor_wi(void);
void del_all_interface_data(void);
struct wireless_iface *get_interface_data(int ifindex);
int print_event_token(struct iw_event *	event, 
                      struct scan_results_t *scan_results, int ifindex);
void send_dbus_scan_results(GSList* scan_results_save, const char* sender,
                            dbus_int32_t number_of_results);
int get_we_device_name(void);
GSList *save_scan_results(struct scan_results_t *scan_results,
                         GSList *scan_results_save);
void clean_scan_results(GSList *scan_results_save);
int socket_open(void);
void init_iwreq(struct iwreq* req);
int ask_scan_results(int ifindex);
void set_wlan_state(int new_state, int send_signal, force_t force);
int get_wlan_state(void);
void set_scan_state(guint new_state);
int get_scan_state(void);
int init_dbus_handler(void);
int clean_dbus_handler(void);
int parse_rsn_cipher_suite(guint8 *suite);
int parse_rsn_key_mgmt_suite(guint8 *suite);
int parse_wpa_cipher_suite(guint8* suite);
int parse_wpa_key_mgmt_suite(guint8 *suite);
void clear_wpa_mode(void);
int wpa_ie_push(unsigned char* ap_mac_addr, unsigned char* ap_wpa_ie, 
                int ap_wpa_ie_len);
int wpa_mic_failure_event(dbus_bool_t key_type, dbus_bool_t is_fatal);
gboolean get_wpa_mode(void);
void disconnected_signal(void);
void mode_change(const char *mode);
#ifdef ACTIVITY_CHECK
void activity_check(dbus_bool_t activity);
#endif
void init_cover_state(void);
void update_own_ie(unsigned char* wpa_ie, guint wpa_ie_len);
gboolean set_power_state(guint state, int sock);
int get_encryption_info(void);
void remove_connect_timer(void);
int disassociate_eap(void);
int get_mode(void);
DBusHandlerResult wlancond_req_handler(DBusConnection *connection,
                                       DBusMessage *message, void *user_data);

#endif /* _COMMON_H_ */
