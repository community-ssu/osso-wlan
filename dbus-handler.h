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

#include "common.h"

/** Bind functions to corresponding D-Bus messages
 * @param connection D-Bus connection
 */
void init_dbus_handlers(DBusConnection *connection);

/** Free memory allocated to handlers
 * @param connection D-Bus connection
 */
void destroy_dbus_handlers(DBusConnection *connection);

int socket_open(void);
void init_iwreq(struct iwreq* req);
gboolean ask_scan_results(int ifindex);
void set_wlan_state(int new_state, int send_signal, force_t force);
guint get_wlan_state(void);
void set_scan_state(guint new_state);
guint get_scan_state(void);
int init_dbus_handler(void);
int clean_dbus_handler(void);
void clear_wpa_mode(void);
int wpa_ie_push(unsigned char* ap_mac_addr, unsigned char* ap_wpa_ie,
		int ap_wpa_ie_len, char* ssid, int ssid_len,
		unsigned int authentication_type);
gboolean get_wpa_mode(void);
int set_interface_state(int sock, int dir, short flags);
void clear_wpa_keys(unsigned char* bssid);
void clean_roam_cache(void);
guint get_mode(void);
gboolean set_real_power_state(guint new_state, int sock);
int scan(gchar *ssid, int ssid_len, gboolean add_timer);
void update_own_ie(unsigned char* wpa_ie, guint wpa_ie_len);
gboolean set_power_state(guint state, int sock);
guint get_encryption_info(void);
void remove_connect_timer(void);
int disassociate_eap(void);
int check_pmksa_cache(unsigned char* own_mac, int own_mac_len,
		unsigned char* bssid, int bssid_len,
		uint32_t authentication_type,
		uint32_t pairwise_key_cipher_suite,
		uint32_t group_key_cipher_suite,
		int *status);
void set_call_type(const char *type);
int context_parser(DBusMessageIter *actit);
void handle_policy_actions(DBusMessage *msg);
int wpa_mic_failure_event(dbus_bool_t key_type, dbus_bool_t is_fatal);
int get_we_device_name(void);
gboolean remove_from_pmksa_cache(unsigned char* mac);
int find_pmkid_from_pmk_cache(unsigned char* mac, unsigned char** pmkid);
DBusHandlerResult wlancond_req_handler(DBusConnection *connection,
		DBusMessage *message, void *user_data);

int associate(struct scan_results_t *scan_results);
gboolean remove_from_roam_cache(unsigned char *bssid);
struct scan_results_t* find_connection(
		GSList* scan_list, struct connect_params_t *conn,
		gboolean update_roam_cache);
void remove_roam_scan_timer(void);
void remove_scan_timer(void);
int associate_supplicant(void);
int set_bssid(unsigned char *bssid);
int set_essid(char* essid, int essid_len);
int find_connection_and_associate(GSList *scan_results,
				  gboolean update_roam_cache,
				  gboolean create_new_adhoc,
				  gboolean autoconnect);
int scan_results_ioctl(int ifindex, GSList** scan_results_save);
void set_wlan_signal(gboolean high_or_low);
gboolean decrease_signal_in_roam_cache(unsigned char *bssid);
int mlme_command(guchar* addr, guint16 cmd, guint16 reason_code);
void schedule_scan(guint seconds);

#define CLEAR 1
#define SET   2

#define ETOOMANYREGISTRARS -500
#define ETOOWEAKAP         -2
#define ESUPPLICANT        -5

#endif /* _DBUS_HANDLER_H_ */
