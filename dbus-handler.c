/**
   @file dbus-handler.c

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
#include <glib.h>
#include <net/ethernet.h>
#include <linux/socket.h>
#include <gconf/gconf-client.h>
#include <osso-ic-dbus.h>
#include <syslog.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <eap-dbus.h>
#include <wlancond-dbus.h>
#ifdef USE_MCE_MODE
#include <mce/dbus-names.h>
#endif
#include "log.h"
#include "dbus.h"
#include "dbus-helper.h"
#include "dbus-handler.h"
#include "common.h"
#include "wpa.h"

#define WLANCOND_SHUTDOWN_DELAY 4 //4s
#define WLANCOND_CONNECT_TIMEOUT 10 //10s
#define WLANCOND_SCAN_TIMEOUT 8 //8s
#define WLANCOND_RESCAN_DELAY 1

/* Saved DBUS names */
static char *scan_name_cache = NULL;
static char *connect_name_cache = NULL;

static int wlan_socket = -1;

struct wlan_status_t wlan_status;

static gboolean _flight_mode = FALSE;
static gboolean power_down_after_scan = FALSE;
static dbus_bool_t saved_inactivity = FALSE;
static dbus_bool_t saved_bt_power = FALSE;

/* Timer IDs */
static guint wlan_if_down_timer_id = 0;
static guint wlan_connect_timer_id = 0;

/* This is the desired powersave and can be set from DBUS when connecting */
static guint powersave = WLANCOND_SHORT_CAM;

/* Debug level */
static gint debug_level = 0;

#define WLAN_PREFIX_STR "wlan"
/**
   Wlancond debug printing function.
*/
void wlancond_print(guint priority, const char *debug, ...) {
	va_list args;
	char buffer[200];

	switch (debug_level) {
		/* In debug level 0 only high prio printing (release) */
	case 0:
		if (priority > WLANCOND_PRIO_MEDIUM) {
			va_start(args, debug);
			vsnprintf(buffer, sizeof(buffer), debug, args);
			va_end(args);

			syslog(LOG_INFO | LOG_DAEMON, "%s", buffer);
			return;
		}
		break;
	case 1:
		if (priority > WLANCOND_PRIO_LOW) {
			va_start(args, debug);
			vsnprintf(buffer, sizeof(buffer), debug, args);
			va_end(args);

			syslog(LOG_INFO | LOG_DAEMON, "%s", buffer);
			return;
		}
		break;
		/* Print everything */
	default:
		va_start(args, debug);
		vsnprintf(buffer, sizeof(buffer), debug, args);
		va_end(args);

		syslog(LOG_INFO | LOG_DAEMON, "%s", buffer);
		return;
	}
}
/**
 * Helper function for socket opening.
 */
int socket_open(void)
{
        if (wlan_socket > 0)
                return wlan_socket;

        wlan_socket = socket(AF_INET, SOCK_DGRAM, 0);

        if (wlan_socket < 0)
                die("socket() failed");

        return wlan_socket;
}
/**
 * Helper function for initializing the iwreq.
 */
void init_iwreq(struct iwreq* req)
{
        memset(req, 0, sizeof(struct iwreq));
        strncpy(req->ifr_name, wlan_status.ifname, IFNAMSIZ);
}
/**
   Function to get own MAC address.
*/
static int get_own_mac(void)
{
        struct ifreq req;

        memset(&req , 0, sizeof(req));
        memcpy(req.ifr_name, wlan_status.ifname, IFNAMSIZ);

        if (ioctl(socket_open(), SIOCGIFHWADDR, &req) < 0)
        {
                return -1;
        }

        memcpy(wlan_status.own_mac, req.ifr_hwaddr.sa_data, ETH_ALEN);

        return 0;
}

/**
    Helper function for getting Gconf values.
    @param path Gconf path to search for user specified value.
    @return CAM timeout.
*/
static gint get_gconf_int(const gchar* path)
{
	GConfClient *client;
	GConfValue *gconf_value;
	GError *error = NULL;
	gint value = -1;

	client = gconf_client_get_default();
	if (client == NULL) {
		return -1;
	}

	gconf_value = gconf_client_get(client, path, &error); 

	g_object_unref(client);

	if (error != NULL) {
		DLOG_ERR("Could not get setting:%s, error:%s", path, 
				error->message);

		g_clear_error(&error);
		return -1;
	}

	if (gconf_value == NULL) {
		return -1;
	}
	if (gconf_value->type == GCONF_VALUE_INT) {
		value = gconf_value_get_int(gconf_value);
		DLOG_DEBUG("User selected value: %d", value);
	}

	gconf_value_free(gconf_value);
	return value;
}

/**
    Helper function for getting boolean value from the settings.
    @param path Setting path to search for user specified value.
    @param error Variable to hold possible error.
    @return value Boolean value.
*/
static gboolean get_setting_bool(const gchar* path, gboolean *error)
{
	gboolean value = FALSE;
	GConfClient *client;
	GConfValue *gconf_value;
	GError *g_error = NULL;

	*error = TRUE;

	client = gconf_client_get_default();
	if (client == NULL) {
		return value;
	}

	gconf_value = gconf_client_get(client, path, &g_error);

	g_object_unref(client);

	if (g_error != NULL) {
		DLOG_ERR("Could not get setting:%s, error:%s", path,
				g_error->message);

		g_clear_error(&g_error);
		return value;
	}

	if (gconf_value == NULL) {
		return value;
	}
	if (gconf_value->type == GCONF_VALUE_BOOL) {
		value = gconf_value_get_bool(gconf_value);
		DLOG_DEBUG("User selected value: %d for %s", value, path);
		*error = FALSE;
	}

	gconf_value_free(gconf_value);

	return value;
}

/**
   Initialize logging.
*/
void init_logging(void) {
	debug_level = get_gconf_int(DEBUG_LEVEL);
	if (debug_level < 0)
		debug_level = 0;

	if (debug_level > 0) {
		DLOG_DEBUG("Debug level increased to %d", debug_level);
	}
}

/**
   Update our Information Element.
   @param wpa_ie WPA Information Element.
   @param wpa_ie_len WPA Information Element length.
*/
void update_own_ie(unsigned char* wpa_ie, guint wpa_ie_len) 
{
	g_free(wlan_status.wpa_ie.ie);
	wlan_status.wpa_ie.ie = wpa_ie;
	wlan_status.wpa_ie.ie_len = wpa_ie_len;
}
/**
   Get encryption info.
   @return status.
*/
guint get_encryption_info(void) 
{
	guint auth_status = 0;

	if (wlan_status.pairwise_cipher & CIPHER_SUITE_CCMP) {
		auth_status |= WLANCOND_WPA_AES;
	} else if (wlan_status.pairwise_cipher & CIPHER_SUITE_TKIP) {
		auth_status |= WLANCOND_WPA_TKIP;
	} else if (wlan_status.pairwise_cipher & CIPHER_SUITE_WEP40 ||
			wlan_status.pairwise_cipher & CIPHER_SUITE_WEP104) {
		auth_status |= WLANCOND_WEP;
	} else {
		auth_status |= WLANCOND_OPEN;
	}
	return auth_status;
}

/**
   Helper function for cleaning handler.
*/
int clean_dbus_handler(void)
{
	if (wlan_socket > 0)
		close(wlan_socket);

	return 0;
}
/**
   Helper function for mode change.
   @param mode New mode.
*/
void mode_change(const char *mode) {

	DLOG_INFO("WLAN flight mode changed to \"%s\"", mode);

	if (g_str_equal(mode, "flight")) {
		set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL,
				FORCE_YES);
		_flight_mode = TRUE;
	}
	else if (g_str_equal(mode, "normal")) {
		_flight_mode = FALSE;
	}
	else {
		DLOG_ERR("Invalid mode \"%s\" passed to mode_change()", mode);
	}
}
/**
   Helper function for mode change DBUS handling.
   @param message DBUS message.
*/
#ifdef USE_MCE_MODE
static DBusHandlerResult mode_change_dbus(DBusMessage *message) {

	char *mode;

	if (!dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &mode,
				DBUS_TYPE_INVALID)) {
		DLOG_ERR("Invalid arguments for device_mode_ind signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	mode_change(mode);

	return DBUS_HANDLER_RESULT_HANDLED;
}
#ifdef ACTIVITY_CHECK
static DBusHandlerResult activity_check_dbus(DBusMessage *message) {

	if (!dbus_message_get_args(message, NULL,
				DBUS_TYPE_BOOLEAN, &saved_inactivity,
				DBUS_TYPE_INVALID)) {
		DLOG_ERR("Invalid arguments for device_activity signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	activity_check(saved_inactivity);

	return DBUS_HANDLER_RESULT_HANDLED;
}
#endif
#endif

#ifdef ACTIVITY_CHECK
/**
 * Helper function for mode change.
 */
void activity_check(dbus_bool_t inactivity) {

	int sock;

	if (get_wlan_state() != WLAN_CONNECTED) {
                return;
	}

	sock = socket_open();

	if (inactivity == FALSE) {
		//DLOG_DEBUG("WLAN activity mode changed to active");
	} else {
		//DLOG_DEBUG("WLAN activity mode changed to inactive");
	}

	set_power_state(powersave, sock);
}

/**
 * Helper function for determining inactivity.
 */
static gboolean get_inactivity_status(void)
{
	return saved_inactivity;
}
#endif
/**
   Check ICD DBUS signal.
   @param message DBUS message.
   @return DBusHandlerResult.
*/
static DBusHandlerResult icd_check_signal_dbus(DBusMessage *message) {

	char *icd_name;
	char *icd_type;
	char *icd_state;
	char *icd_disconnect_reason;
	DBusError dbus_error;

	if ((get_wlan_state() != WLAN_CONNECTED &&
				get_wlan_state() != WLAN_NO_ADDRESS) ||
			get_mode() != WLANCOND_INFRA) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_error_init(&dbus_error);
	if (!dbus_message_get_args(message, &dbus_error,
				DBUS_TYPE_STRING, &icd_name,
				DBUS_TYPE_STRING, &icd_type,
				DBUS_TYPE_STRING, &icd_state,
				DBUS_TYPE_STRING, &icd_disconnect_reason,
				DBUS_TYPE_INVALID ) )
	{
		DLOG_ERR("Could not get args from signal, '%s'",
				dbus_error.message);
		dbus_error_free(&dbus_error);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (icd_state != NULL && strncmp(icd_state, "CONNECTED", 9) == 0) {

		set_wlan_state(WLAN_CONNECTED, NO_SIGNAL, FORCE_NO);

		DLOG_DEBUG("Going to power save");

		if (set_power_state(powersave, socket_open()) == FALSE) {
			DLOG_ERR("Failed to set power save");
		}

	}

	//DLOG_DEBUG("Handled icd signal, icd_state:%s", icd_state);

	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
   Runs calibration data to WLAN firmware.
*/
static gint run_calibration(void) {
	gchar *args[2];
	gint count = 0;
	args[count++] = (gchar*)"/usr/bin/wl1251-cal";
	args[count++] = NULL;

	if (!g_spawn_sync (NULL, args, NULL, 0,
			   NULL, NULL, NULL, NULL, NULL, NULL)) {
		return -1;
	}
	return 0;
}
/**
   Kill supplicant.
*/
#define KILL_SUPPLICANT "/usr/bin/killall"
#define SUPPLICANT_NAME "eapd"
static void kill_supplicant(void) {
	gchar *args[3];
	guint count = 0;
	args[count++] = (gchar*)KILL_SUPPLICANT;
	args[count++] = (gchar*)"-9";
	args[count++] = (gchar*)SUPPLICANT_NAME;

	if (!g_spawn_sync (NULL, args, NULL, 0,
			   NULL, NULL, NULL, NULL, NULL, NULL)) {
		DLOG_ERR("Failed to run %s", KILL_SUPPLICANT);
	}
}
#define WLANCOND_WAIT_COUNTRY 2000 //2s
/**
   Check country code.
   @return country code or error.
*/
static gint check_country_code(void) {
	DBusMessage *msg, *reply;
	DBusError error;
	dbus_uint32_t current_cell_id;
	dbus_uint32_t network_code;
	dbus_uint32_t country_code;
	dbus_uint16_t current_lac;
	guchar reg_status;
	guchar network_type;
	guchar supported_services;

	dbus_error_init(&error);

	msg = dbus_message_new_method_call(
		"com.nokia.phone.net",
		"/com/nokia/phone/net",
		"Phone.Net",
		"get_registration_status");

	if (msg == NULL) {
		return -1;
	}

	reply = dbus_connection_send_with_reply_and_block(
		get_dbus_connection(), msg, WLANCOND_WAIT_COUNTRY, &error);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&error)) {
		DLOG_ERR("Failed to ask registration status: %s",
				error.name);
		dbus_error_free(&error);
		if (reply)
			dbus_message_unref(reply);
		return -1;
	}
	dbus_error_init(&error);

	if (!dbus_message_get_args(reply, &error,
				DBUS_TYPE_BYTE, &reg_status,
				DBUS_TYPE_UINT16, &current_lac,
				DBUS_TYPE_UINT32, &current_cell_id,
				DBUS_TYPE_UINT32, &network_code,
				DBUS_TYPE_UINT32, &country_code,
				DBUS_TYPE_BYTE, &network_type,
				DBUS_TYPE_BYTE, &supported_services,
				DBUS_TYPE_INVALID))
	{
		DLOG_ERR("Could not get args from reply, '%s'",
				error.message);
		dbus_error_free(&error);
		if (reply)
			dbus_message_unref(reply);
		return -1;
	}
	DLOG_INFO("Device country: %d", country_code);

	dbus_message_unref(reply);

	return country_code;
}
static void set_bt_coex_state(unsigned int state) {
	FILE * file;
	char buf[4];

	DLOG_DEBUG("Setting coex state to %i", state);

	file = fopen(WLANCOND_BT_COEX_FILE, "w");
	if (file == NULL) {
		DLOG_DEBUG("Cannot open: %s", WLANCOND_BT_COEX_FILE);
		return;
	}

	sprintf(buf, "%d", state);

	if (fwrite(buf, 1, 1, file) != 1) {
		DLOG_DEBUG("Could not write to: %s", WLANCOND_BT_COEX_FILE);
	}
	fclose(file);

	wlan_status.coex_state = state;
	if (wlan_status.state != WLAN_NOT_INITIALIZED)
		if (!set_power_state(wlan_status.requested_power,
					socket_open()))
			DLOG_DEBUG("Unable to set the power state");

	return;
}
/**
   Check CSD DBUS signal.
   @param message DBUS message.
   @return DBusHandlerResult.
*/
static DBusHandlerResult csd_check_signal_dbus(DBusMessage *message) {

	DBusError error;
	dbus_uint32_t current_cell_id;
	dbus_uint32_t network_code;
	dbus_uint32_t country_code;
	dbus_uint16_t current_lac;
	guchar reg_status;
	guchar network_type;
	guchar supported_services;

	dbus_error_init(&error);

	if (!dbus_message_get_args(message, &error,
				DBUS_TYPE_BYTE, &reg_status,
				DBUS_TYPE_UINT16, &current_lac,
				DBUS_TYPE_UINT32, &current_cell_id,
				DBUS_TYPE_UINT32, &network_code,
				DBUS_TYPE_UINT32, &country_code,
				DBUS_TYPE_BYTE, &network_type,
				DBUS_TYPE_BYTE, &supported_services,
				DBUS_TYPE_INVALID))
	{
		DLOG_ERR("Could not get args from signal, '%s'",
				error.message);
		dbus_error_free(&error);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	DLOG_DEBUG("Handled csd signal, country:%d", country_code);

	if ((gint)country_code != wlan_status.country_code &&
			wlan_status.country_code != -1) {
		wlan_status.country_code = -1;
		DLOG_INFO("Country changed to: %d", country_code);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
   Check BlueZ Adapter DBUS signal.
   @param message DBUS message.
   @return DBusHandlerResult.
*/
static DBusHandlerResult bluez_check_adapter_signal_dbus(DBusMessage *message) {
	DBusError error;
	const gchar *property_name = NULL;
	DBusMessageIter msg_iter;
	DBusMessageIter variant_iter;
	dbus_error_init(&error);

	if (!dbus_message_get_args (message, &error,
				    DBUS_TYPE_STRING, &property_name,
				    DBUS_TYPE_INVALID))
	{
		DLOG_ERR("Could not get args from signal, '%s'",
                         error.message);
		dbus_error_free(&error);
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (property_name != NULL &&
	    strcmp (property_name, BLUEZ_ADAPTER_PROPERTY_POWERED) == 0)
	{
		dbus_message_iter_init (message, &msg_iter);
		dbus_message_iter_next(&msg_iter);
		if (dbus_message_iter_get_arg_type(&msg_iter)
		    != DBUS_TYPE_VARIANT) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		dbus_message_iter_recurse(&msg_iter, &variant_iter);
		if (dbus_message_iter_get_arg_type(&variant_iter)
		    != DBUS_TYPE_BOOLEAN) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		dbus_message_iter_get_basic(&variant_iter, &saved_bt_power);

		DLOG_DEBUG("Got signal, powered: %d", saved_bt_power);

		if (saved_bt_power == TRUE)
			set_bt_coex_state(WLANCOND_BT_COEX_ON);
		else
			set_bt_coex_state(WLANCOND_BT_COEX_OFF);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
   Check BlueZ Headset DBUS signal.
   @param message DBUS message.
   @return DBusHandlerResult.
*/
static DBusHandlerResult bluez_check_headset_signal_dbus(DBusMessage *message) {
	DBusError error;
	const gchar *property_name = NULL;
	DBusMessageIter msg_iter;
	DBusMessageIter variant_iter;
	const gchar *state;
	dbus_error_init(&error);

	if (!dbus_message_get_args (message, &error,
				    DBUS_TYPE_STRING, &property_name,
				    DBUS_TYPE_INVALID))
	{
		DLOG_ERR("Could not get args from signal, '%s'",
				error.message);
		dbus_error_free(&error);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (property_name != NULL &&
	    strcmp (property_name, BLUEZ_HEADSET_PROPERTY_STATE) == 0)
	{
		dbus_message_iter_init (message, &msg_iter);
		dbus_message_iter_next(&msg_iter);
		if (dbus_message_iter_get_arg_type(&msg_iter)
		    != DBUS_TYPE_VARIANT) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		dbus_message_iter_recurse(&msg_iter, &variant_iter);
		if (dbus_message_iter_get_arg_type(&variant_iter)
		    != DBUS_TYPE_STRING) {
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		dbus_message_iter_get_basic(&variant_iter, &state);

		if (state != NULL) {
			DLOG_DEBUG("State: %s", state);
			/* When putting BT down the headset disconnect signal
			   comes after the adapter state change. That's
			   why we need to use saved power state.
			*/
			if (!strcmp(state, BLUEZ_HEADSET_PROPERTY_PLAYING)) {
				set_bt_coex_state(WLANCOND_BT_COEX_MONOAUDIO);
			} else {
				if (saved_bt_power == TRUE)
					set_bt_coex_state(WLANCOND_BT_COEX_ON);
				else
					set_bt_coex_state(WLANCOND_BT_COEX_OFF);
			}
		}
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

/**
   Check Bluez default adpater.
   @return path to default adapter.
*/
static gchar *gateway_bluez_default_adapter_path (void)
{
	DBusMessage *msg, *reply = NULL;
	gchar *path = NULL;
	DBusError derr;

	msg = dbus_message_new_method_call(
			BLUEZ_SERVICE_NAME,
			BLUEZ_MANAGER_PATH_NAME,
			BLUEZ_MANAGER_INTERFACE_NAME,
			BLUEZ_MANAGER_DEFAULT_ADAPTER_METHOD);

	if (msg == NULL) {
		return NULL;
	}

	dbus_error_init(&derr);

	reply = dbus_connection_send_with_reply_and_block(
			get_dbus_connection(), msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		DLOG_ERR("BlueZ returned error: %s", derr.name);

		dbus_error_free(&derr);
		if (reply)
			dbus_message_unref(reply);
		return NULL;
	}

	if (reply == NULL)
		return NULL;

	dbus_error_init (&derr);
	if (!dbus_message_get_args (reply, &derr,
				    DBUS_TYPE_OBJECT_PATH, &path,
				    DBUS_TYPE_INVALID))
	{
		DLOG_ERR("Could not get arguments: %s",
			 derr.message);
		dbus_error_free (&derr);
		dbus_message_unref (reply);
		return NULL;
	}

	path = g_strdup(path);
	dbus_message_unref (reply);

	return path;
}
static gboolean gateway_adapter_point_iter_to_value (
	DBusMessageIter *msg_iter,
	const gchar *property_name)
{
	DBusMessageIter array_iter;


	/* Get for dictionary, i.e. "a{sv}" */
	if (dbus_message_iter_get_arg_type (msg_iter) != DBUS_TYPE_ARRAY ||
	    dbus_message_iter_get_element_type (msg_iter) !=
	    DBUS_TYPE_DICT_ENTRY)
		return FALSE;

	for (dbus_message_iter_recurse(msg_iter, &array_iter);
	     dbus_message_iter_get_arg_type (&array_iter) != DBUS_TYPE_INVALID;
	     dbus_message_iter_next (&array_iter))
	{
		DBusMessageIter dict_iter;
		const gchar *name = NULL;

		/* Check that array entry is dict entry */
		if (dbus_message_iter_get_arg_type (&array_iter) != DBUS_TYPE_DICT_ENTRY)
			continue;

		/* Recurse to dict entry and refresh BT device according to values */
		dbus_message_iter_recurse (&array_iter, &dict_iter);

		if (dbus_message_iter_get_arg_type(&dict_iter)
		    != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&dict_iter, &name);
		dbus_message_iter_next(&dict_iter);


		/* Check if this was the correct property */
		if (name == NULL || strcmp (name, property_name) != 0)
			continue; /* No it was not - continue */

		/* Read following variant value */
		if (dbus_message_iter_get_arg_type (&dict_iter) == DBUS_TYPE_VARIANT)
		{
			dbus_message_iter_recurse(&dict_iter, msg_iter);
			return TRUE;
		}
	}
	return FALSE;
}

static DBusMessage *gateway_adapter_get_property_values (
	const gchar *adapter_path,
	...)
{
	DBusMessage *request = NULL, *reply = NULL;
	const gchar *property_name = NULL;
	DBusMessageIter msg_iter;
	va_list ap;

	request = dbus_message_new_method_call(
		BLUEZ_SERVICE_NAME,
		adapter_path,
		BLUEZ_ADAPTER_SERVICE_NAME,
		BLUEZ_ADAPTER_GET_PROPERTIES_METHOD);

	if (request == NULL)
		return NULL;

	reply = dbus_connection_send_with_reply_and_block(
			get_dbus_connection(), request, -1, NULL);

	dbus_message_unref(request);

	if (reply == NULL)
		return NULL;

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
	{
		DLOG_ERR("gateway_adapter_get_property_values: %s",
			 dbus_message_get_error_name(reply));
		dbus_message_unref(reply);
		return NULL;
	}

	for (va_start(ap, adapter_path);
	     (property_name = va_arg(ap, const gchar *)) != NULL;)
	{
		DBusMessageIter *msg_iter_ret = va_arg(ap, DBusMessageIter *);

		if (!dbus_message_iter_init(reply, &msg_iter) ||
		    !gateway_adapter_point_iter_to_value (
			    &msg_iter, property_name))
		{
			DLOG_ERR("Unable to point to property '%s'",
				 property_name);
			va_end(ap);
			dbus_message_unref(reply);
			return NULL;
		}

		if (msg_iter_ret != NULL)
			*msg_iter_ret = msg_iter;
		else
			break;
	}
	va_end(ap);

	return reply;
}
/**
   Handles WLAN country.
   @return status.
*/
static gint handle_country(void) {
	/* Negative country code means calibration must be run 
	   either because we initialize or because country
	   has changed.
	*/
	if (wlan_status.country_code < 0) {
		/* Read the code so we can check
		   if the code changes in CSD signal.
		*/
		gint code = check_country_code();
		if (code >= 0)
			wlan_status.country_code = code;
		if (run_calibration() < 0) {
			DLOG_ERR("Fatal: Could not calibrate");
		}
	}
	return 0;
}
/**
   Handles BT state.
*/
static void check_bt_status(void) {
	DBusMessageIter msg_iter;
	char* default_adapter;
	dbus_bool_t powered;
	DBusMessage *property_message = NULL;

	default_adapter = gateway_bluez_default_adapter_path();

	if (default_adapter != NULL) {
		property_message = gateway_adapter_get_property_values(
			default_adapter,
			BLUEZ_ADAPTER_PROPERTY_POWERED, &msg_iter,
			NULL);

		g_free(default_adapter);

		if (property_message == NULL)
		{
			DLOG_ERR("Unable to get properties");
			return;
		}

		dbus_message_iter_get_basic(&msg_iter, &powered);

		DLOG_DEBUG("Default adapter is %s", powered == TRUE?"powered":
			   "not powered");

		if (powered == TRUE)
			set_bt_coex_state(WLANCOND_BT_COEX_ON);
		else
			set_bt_coex_state(WLANCOND_BT_COEX_OFF);

		dbus_message_unref(property_message);
	} else {
		DLOG_DEBUG("Default adapter was NULL");
		set_bt_coex_state(WLANCOND_BT_COEX_OFF);
	}
}
/**
 * Helper function for initializing handler structs
 */
int init_dbus_handler(void)
{
	gboolean error;

	handle_country();

	if (get_own_mac() < 0) {
		DLOG_ERR("Could not get own MAC address");
		return -1;
	}

	check_bt_status();

	wlan_status.allow_all_ciphers = get_setting_bool(
			WLANCOND_ALLOW_ALL_CIPHERS, &error);

	return 0;
}

static gboolean in_flight_mode(void) {
	return _flight_mode;
}

void set_wlan_signal(gboolean high_or_low)
{
	if (high_or_low == WLANCOND_HIGH) {
		wlan_status.signal = WLANCOND_HIGH;
		remove_roam_scan_timer();
	} else {
		wlan_status.signal = WLANCOND_LOW;
	}
}

void remove_roam_scan_timer(void)
{
	if (wlan_status.roam_scan_id) {
		g_source_remove(wlan_status.roam_scan_id);
		wlan_status.roam_scan_id = 0;
	}
}

void remove_connect_timer(void)
{
	if (wlan_connect_timer_id) {
		g_source_remove(wlan_connect_timer_id);
		wlan_connect_timer_id = 0;
	}
}

static void remove_wlan_if_timer(void)
{
        // Remove shutdown timer if exists
	if (wlan_if_down_timer_id) {
		g_source_remove(wlan_if_down_timer_id);
		wlan_if_down_timer_id = 0;
	}
}

void remove_scan_timer(void)
{
	if (wlan_status.scan_id) {
		g_source_remove(wlan_status.scan_id);
		wlan_status.scan_id = 0;
	}
}

/**
   WLAN connect timer callback.
   @param data User data.
   @return status.
*/
static gboolean wlan_connect_timer_cb(void* data)
{
	if (wlan_connect_timer_id && get_wlan_state() ==
			WLAN_INITIALIZED_FOR_CONNECTION) {

		wlan_connect_timer_id = 0;

		DLOG_DEBUG("Association timeout, try: %d",
				wlan_status.retry_count);

		/* Remove the failed AP from the list */
		remove_from_roam_cache(wlan_status.conn.bssid);

		/* Set BSSID to 0 */
		memset(wlan_status.conn.bssid, 0, ETH_ALEN);

		set_bssid(NULL_BSSID);
		set_essid((char*)"", 1);

		if (find_connection_and_associate(wlan_status.roam_cache,
						  FALSE, FALSE, FALSE) == 0)
			return FALSE;

		/* Try to scan again if retries left */
		if (++wlan_status.retry_count < WLANCOND_MAX_SCAN_TRIES) {
			if (scan(wlan_status.conn.ssid,
				wlan_status.conn.ssid_len, TRUE) == 0) {
				return FALSE;
			}
		}

		set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL,
				FORCE_YES);
		return FALSE;
	}

	wlan_connect_timer_id = 0;

	//DLOG_DEBUG("Association OK");

	return FALSE;
}
/**
   WLAN scan callback.
   @param data User data.
   @return status.
*/
static gboolean wlan_scan_cb(void* data)
{

	wlan_status.scan_id = 0;

	DLOG_ERR("Scan failed, should not happen!");

	set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, FORCE_YES);

	return FALSE;
}
/**
   WLAN scan later callback.
   @param req iwreq.
   @return status.
*/
static gboolean wlan_scan_later_cb(void* data)
{
	struct iwreq req;
	struct iw_scan_req scan_req;

	if (get_scan_state() == SCAN_NOT_ACTIVE) {
		wlan_status.scan_id = 0;
		return FALSE;
	}

	init_iwreq(&req);

	memset(&scan_req, 0, sizeof(scan_req));

	if (wlan_status.scan_ssid_len > 1 && wlan_status.scan_ssid != NULL) {
		//DLOG_DEBUG("Active scan for: %s (len=%d)", ssid, ssid_len -1);
		scan_req.essid_len = wlan_status.scan_ssid_len -1;
		scan_req.bssid.sa_family = ARPHRD_ETHER;
		memset(scan_req.bssid.sa_data, 0xff, ETH_ALEN);
		memcpy(scan_req.essid, wlan_status.scan_ssid,
		       wlan_status.scan_ssid_len -1);
		req.u.data.pointer = (caddr_t) &scan_req;
		req.u.data.length = sizeof(scan_req);
		req.u.data.flags = IW_SCAN_THIS_ESSID;
	}

	if (ioctl(socket_open(), SIOCSIWSCAN, &req) < 0) {
		if (errno == EBUSY) {
			DLOG_ERR("Scan busy, retrying later");
			return TRUE;
		} else {
			DLOG_ERR("Scan failed, errno %d if %s", errno, req.ifr_name);
			wlan_status.scan_id = 0;
			return FALSE;
		}
	}

	wlan_status.scan_id = g_timeout_add_seconds(
			WLANCOND_SCAN_TIMEOUT,
			wlan_scan_cb,
			NULL);

        DLOG_INFO("Scan issued");

	return FALSE;
}
/**
   WLAN interface down callback.
   @param data User data.
   @return status.
*/
static gboolean wlan_if_down_cb(void* data)
{

	wlan_if_down_timer_id = 0;

	if (get_wlan_state() == WLAN_NOT_INITIALIZED) {
		DLOG_DEBUG("Delayed shutdown occurred");
		set_wlan_state(WLAN_NOT_INITIALIZED, NO_SIGNAL, FORCE_YES);
		return FALSE;
	}

	//DLOG_DEBUG("Delayed shutdown did not happen");

	return FALSE;
}
/**
   MLME command.
   @param addr Access point MAC address.
   @param cmd Command.
   @param reason_code Reason for leaving.
   @return status.
*/
int mlme_command(guchar* addr, guint16 cmd, guint16 reason_code)
{
	struct iwreq req;
	struct iw_mlme mlme;

	init_iwreq(&req);

	DLOG_INFO("%s", cmd==IW_MLME_DEAUTH?"Deauthenticating":
		  "Disassociating");

	memset(&mlme, 0, sizeof(mlme));

	mlme.cmd = cmd;
	mlme.reason_code = reason_code;
	mlme.addr.sa_family = ARPHRD_ETHER;
	memcpy(mlme.addr.sa_data, addr, ETH_ALEN);

	req.u.data.pointer = (caddr_t) &mlme;
	req.u.data.length = sizeof(mlme);

	if (ioctl(socket_open(), SIOCSIWMLME, &req) < 0) {
		DLOG_ERR("Failed to run MLME command");
		return -1;
	}

	return 0;
}
/**
   Helper function for setting the operating mode.
*/
static int set_mode(guint32 mode)
{
	struct iwreq req;

	init_iwreq(&req);

	switch (mode) {
	case WLANCOND_ADHOC:
		req.u.mode = IW_MODE_ADHOC;
		DLOG_DEBUG("Setting mode: adhoc");
		break;
	case WLANCOND_INFRA:
		req.u.mode = IW_MODE_INFRA;
		DLOG_DEBUG("Setting mode: infra");
		break;
	default:
		DLOG_ERR("Operating mode undefined\n");
		return -1;
	}

	if (ioctl(socket_open(), SIOCSIWMODE, &req) < 0) {
		DLOG_ERR("Operating mode setting failed\n");
		return -1;
        }
	return 0;
}
/**
    Helper function for setting the WEP keys.
    @param conn Connection parameters.
    @return status.
*/
static int set_wep_keys(struct connect_params_t *conn)
{
	struct iwreq req;
	guint nbr_of_keys = 0;
	int sock;
	guint i;

	sock = socket_open();

	/* Encryption keys */
	for (i=0;i<4;i++) {
		if(conn->key_len[i] == 0) {
			continue;
		} else {
			if (conn->key_len[i] < WLANCOND_MIN_KEY_LEN ||
				conn->key_len[i] > WLANCOND_MAX_KEY_LEN) {
				return -1;
			}

			init_iwreq(&req);
			req.u.data.length = conn->key_len[i];
			req.u.data.pointer = (caddr_t) &conn->key[i][0];
			req.u.data.flags |= IW_ENCODE_RESTRICTED;
			req.u.encoding.flags = i+1;
			nbr_of_keys++;
		}
//#define DEBUG_KEY
#ifdef DEBUG_KEY
		int k;
		unsigned char* p = &conn->key[i][0];
		for (k=0;k<conn->key_len[i];k++) {
			DLOG_DEBUG("Key %d, 0x%02x\n", i, *(p+k));
		}
#endif
		if (ioctl(sock, SIOCSIWENCODE, &req) < 0) {
			DLOG_ERR("Set encode failed\n");
			return -1;
		}

	}

	if (nbr_of_keys) {

		DLOG_DEBUG("Default key: %d\n", conn->default_key);

		init_iwreq(&req);

		/* Set the default key */
		req.u.encoding.flags = conn->default_key;

		if (ioctl(sock, SIOCSIWENCODE, &req) < 0) {
			DLOG_ERR("Set encode failed\n");
			return -1;
		}
	}

	return 0;
}

/**
   Helper function for setting the ESSID.
   @param essid ESSID.
   @param essid_len ESSID length.
   @return status.
*/
int set_essid(char* essid, int essid_len)
{
	struct iwreq req;

	DLOG_INFO("Setting SSID: %s", essid);

	init_iwreq(&req);

	req.u.essid.pointer = (caddr_t)essid;
	req.u.essid.length = essid_len -1; // Remove NULL termination
	req.u.essid.flags = 1;

	if (ioctl(socket_open(), SIOCSIWESSID, &req) < 0) {
		DLOG_ERR("set ESSID failed");
		return -1;
	}
	return 0;
}
/**
    Helper function for setting the BSSID.
    @param bssid BSSID.
    @return status.
*/
int set_bssid(unsigned char *bssid)
{
	struct iwreq req;

	print_mac(WLANCOND_PRIO_HIGH, "Setting BSSID", bssid);

	init_iwreq(&req);

	req.u.ap_addr.sa_family = ARPHRD_ETHER;

	memcpy(req.u.ap_addr.sa_data, bssid, ETH_ALEN);

	if (ioctl(socket_open(), SIOCSIWAP, &req) < 0) {
		DLOG_ERR("Failed to set BSSID");
		return -1;
	}
	return 0;
}

/**
    Helper function for setting new wlan state
    @param new_state New state for WLAN.
    @param send_signal Should signal be sent.
    @param force If shutdown is forced or not.
*/
void set_wlan_state(int new_state, int send_signal, force_t force)
{
	const char *status_table[] =
	{
		(char*)"WLAN_NOT_INITIALIZED",
		(char*)"WLAN_INITIALIZED",
		(char*)"WLAN_INITIALIZED_FOR_SCAN",
		(char*)"WLAN_INITIALIZED_FOR_CONNECTION",
		(char*)"WLAN_NO_ADDRESS",
		(char*)"WLAN_CONNECTED"
	};

	switch (new_state) {

	case WLAN_NOT_INITIALIZED:

		if (wlan_status.state == WLAN_CONNECTED ||
		    wlan_status.state == WLAN_NO_ADDRESS) {
			/* Disconnect previous connection */
			mlme_command(wlan_status.conn.bssid,
					IW_MLME_DEAUTH,
					WLANCOND_REASON_LEAVING);
			set_bssid(NULL_BSSID);
			set_essid((char*)"", 1);
		}

		set_scan_state(SCAN_NOT_ACTIVE);

		if (get_wlan_state() != WLAN_NOT_INITIALIZED &&
			get_wlan_state() != WLAN_INITIALIZED_FOR_SCAN)
			clear_wpa_mode();

		wlan_status.retry_count = 0;
		wlan_status.roam_scan = WLANCOND_MIN_ROAM_SCAN_INTERVAL;
		wlan_status.ip_ok = FALSE;
		wlan_status.last_scan = 0;

		/* Remove association timer */
		remove_connect_timer();

		/* Remove scan timer */
		remove_scan_timer();

		set_wlan_signal(WLANCOND_HIGH);

		// Remove shutdown timer if exists
		remove_wlan_if_timer();

		if (force == FORCE_YES) {

			clean_roam_cache();

			if (set_interface_state(socket_open(), CLEAR,
						IFF_UP)<0) {
				DLOG_ERR("Could not set interface down");
			}

		} else {

			DLOG_DEBUG("Delaying interface shutdown");

			/* Removed, does not reduce power consumption
			   when not connected */
			//set_power_state(WLANCOND_FULL_POWERSAVE, sock);

			wlan_if_down_timer_id = g_timeout_add_seconds(
					WLANCOND_SHUTDOWN_DELAY,
					wlan_if_down_cb,
					NULL);

		}

		if (send_signal == DISCONNECTED_SIGNAL)
			disconnected_signal();

		break;
	case WLAN_INITIALIZED_FOR_CONNECTION:
		/*
		   Set BSSID to 0, this state happens e.g when we drop from
		   the network
		*/
		memset(wlan_status.conn.bssid, 0, ETH_ALEN);

		/* Remove association timer */
		remove_connect_timer();

		set_power_state(WLANCOND_POWER_ON, socket_open());

		break;
	case WLAN_CONNECTED:

		/* With WPA we get signal when we can go to powersave */
		if (get_wpa_mode() == FALSE)
			set_power_state(powersave, socket_open());

		wlan_status.ip_ok = TRUE;
		break;
	default:
		break;
	}
	DLOG_DEBUG("Wlancond state change, old_state: %s, new_state: %s",
		status_table[wlan_status.state], status_table[new_state]);
	wlan_status.state = new_state;
}

/**
    Helper function for getting the wlan state.
    @return state.
*/
guint get_wlan_state(void)
{
	return wlan_status.state;
}

/**
    Helper function for setting new scan state.
    @param new_state New scan state.
*/
void set_scan_state(guint new_state)
{
	if (wlan_status.scan == new_state) {
		return;
	}
	if (new_state == SCAN_NOT_ACTIVE && wlan_status.scan == SCAN_ACTIVE &&
			scan_name_cache != NULL) {
		remove_scan_timer();
		DLOG_DEBUG("Sending empty results");
		send_dbus_scan_results(NULL, scan_name_cache, 0);
		g_free(scan_name_cache);
		scan_name_cache = NULL;
	}

	DLOG_DEBUG("Wlancond scan change, old_state: %s, new_state: %s",
		wlan_status.scan==SCAN_NOT_ACTIVE ? "SCAN_IDLE":"SCANNING",
		new_state == SCAN_NOT_ACTIVE ? "SCAN_IDLE":"SCANNING");
	wlan_status.scan = new_state;
}

/**
    Helper function for getting the scan state.
    @return state.
*/
guint get_scan_state(void)
{
	return wlan_status.scan;
}
/**
    Helper function for getting the wlan mode.
    @return mode.
*/
guint get_mode(void)
{
	return wlan_status.conn.mode;
}

/**
   Sets the real WLAN hardware power state.
   @param state New power state.
   @param sock socket.
   @return status.
*/
gboolean set_real_power_state(guint new_state, int sock)
{
	struct iwreq req;
	gint sleep_timeout;

	if (wlan_status.real_power == new_state) {
		return TRUE;
	}

	init_iwreq(&req);

	switch (new_state) {
	case WLANCOND_POWER_ON:
		req.u.power.disabled = 1;
		break;
	case WLANCOND_LONG_CAM:
		req.u.power.flags = IW_POWER_TIMEOUT | IW_POWER_ALL_R;
		req.u.power.value = WLANCOND_LONG_CAM_TIMEOUT;
		break;
	case WLANCOND_SHORT_CAM:
		req.u.power.flags = IW_POWER_TIMEOUT | IW_POWER_ALL_R;
		sleep_timeout = get_gconf_int(SLEEP_GCONF_PATH);
		if (sleep_timeout < 0)
			sleep_timeout = WLANCOND_DEFAULT_SLEEP_TIMEOUT;
		req.u.power.value = sleep_timeout;
		break;
	case WLANCOND_VERY_SHORT_CAM:
		req.u.power.flags = IW_POWER_TIMEOUT | IW_POWER_ALL_R ;
		sleep_timeout = get_gconf_int(INACTIVE_SLEEP_GCONF_PATH);
		if (sleep_timeout < 0)
			sleep_timeout = WLANCOND_VERY_SHORT_CAM_TIMEOUT;
		req.u.power.value = sleep_timeout;
		break;
	case WLANCOND_FULL_POWERSAVE:
		req.u.power.flags = IW_POWER_TIMEOUT | IW_POWER_ALL_R;
		req.u.power.value = 0;
	default:
		req.u.power.flags = IW_POWER_ALL_R;
		break;
	}

	if (ioctl(sock, SIOCSIWPOWER, &req) < 0) {
		DLOG_ERR("set power failed, state:%d", new_state);
		return FALSE;
	}

	if (req.u.power.value) {
		DLOG_DEBUG("CAM timeout: %d ms", req.u.power.value / 1000);
	}

	wlan_status.real_power = new_state;
	DLOG_DEBUG("New power state set: %i", new_state);

	return TRUE;
}

/**
   Request WLAN power state.
   @param state New power state.
   @param sock socket.
   @return status.
*/
gboolean set_power_state(guint new_state, int sock)
{
	gboolean status;

	if (new_state == WLANCOND_SHORT_CAM && get_inactivity_status() == TRUE)
		new_state = WLANCOND_VERY_SHORT_CAM;

	/* If we are in the monoaudio mode set the full powersave */
	if (wlan_status.coex_state == WLANCOND_BT_COEX_MONOAUDIO &&
			wlan_status.call_state != WLANCOND_CALL_VOIP) {
		DLOG_DEBUG("Overriding power state with full power save.");
		new_state = WLANCOND_FULL_POWERSAVE;
	}

	status = set_real_power_state(new_state, sock);

	/* Only save the requested power save state if we are not in the
	   BT audio-mode */
	if (status && wlan_status.coex_state != WLANCOND_BT_COEX_MONOAUDIO)
		wlan_status.requested_power = new_state;

	return status;
}

/**
   Initialize the WLAN interface.
   @param sock socket.
   @return previous state.
*/
static int init_if(int sock)
{
	int previous_state = get_wlan_state();

	if (previous_state == WLAN_NOT_INITIALIZED) {
		/* Check if interface is still up from delayed shutdown */
		if (wlan_if_down_timer_id == 0) {

			/* Start from the beginning */
			if (handle_country() < 0)
				return -1;

			if (set_interface_state(sock, SET, 
						IFF_UP | IFF_RUNNING) < 0) {
				return -1;
			}
		}
		set_power_state(WLANCOND_POWER_ON, sock);
		set_wlan_state(WLAN_INITIALIZED, NO_SIGNAL, FORCE_YES);
	}

	return previous_state;
}

/**
   Cache the wireless interface name.
   @param sock socket.
   @param name inteface name.
   @param args not used.
   @param count not used.
   @return status.
*/
static int set_we_name(int sock, char *name, char *args[], int count)
{
	struct iwreq req;

	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, name, IFNAMSIZ);

	if (ioctl(sock, SIOCGIWNAME, &req) < 0) {
		//DLOG_DEBUG("Ifname %s does not support wireless extensions\n",        name);
	} else {
		//DLOG_DEBUG("Found interface %s", name);
		if (g_str_has_prefix(name, WLAN_PREFIX_STR)) {
			DLOG_DEBUG("Found WLAN interface %s", name);
			memcpy(&wlan_status.ifname, name, IFNAMSIZ);
			wlan_status.ifname[IFNAMSIZ] = '\0';
		}
	}

	return 0;
}
/**
 * Find the name of the wireless device, needed in all ioctl calls.
 * Save the result so that we don't need to find it in every ioctl call.
 * @return status.
 */
int get_we_device_name(void)
{
	memset(&wlan_status, 0, sizeof(wlan_status));

	wlan_status.country_code = -1;

	iw_enum_devices(socket_open(), &set_we_name, NULL, 0);

	if (strnlen(wlan_status.ifname, IFNAMSIZ) < 2)
		return -1;

	return 0;
}
/**
   Set interface state.
   @param socket socket.
   @param dir direction.
   @param flags settings flags.
   @return status.
*/
int set_interface_state(int sock, int dir, short flags)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, wlan_status.ifname, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		DLOG_ERR("Could not get interface %s flags\n",
				wlan_status.ifname);
		return -1;
	}
	if (dir == SET) {
		ifr.ifr_flags |= flags;
	} else {
		ifr.ifr_flags &= ~flags;
	}

	if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
		DLOG_ERR("Could not set interface %s flags\n",
				wlan_status.ifname);
		return -1;
	}

	DLOG_DEBUG("%s is %s", wlan_status.ifname, dir == SET ? "UP":"DOWN");

	return 0;
}

/**
    Set tx power level.
    @param power Power level.
    @param sock socket.
    @return status.
*/
static gboolean set_tx_power(guint power, int sock)
{
	struct iwreq req;
	init_iwreq(&req);

	req.u.txpower.fixed = 1;
	req.u.txpower.disabled = 0;
	req.u.txpower.flags = IW_TXPOW_DBM;

	if (power == WLANCOND_TX_POWER10) {
		req.u.txpower.value = WLANCOND_TX_POWER10DBM;
	} else if (power == WLANCOND_TX_POWER100) {
		req.u.txpower.value = WLANCOND_TX_POWER100DBM;
	} else {
		return FALSE;
	}

	if (ioctl(sock, SIOCSIWTXPOW, &req) < 0) {
		DLOG_ERR("set power failed\n");
		return FALSE;
	}
	return TRUE;

}
/**
   Updates algorithms to internal status.
   @param encryption Encryption settings.
   @return status.
*/
static int update_algorithms(guint32 encryption,
		struct scan_results_t *scan_results)
{
	wlan_status.group_cipher = 0;
	wlan_status.pairwise_cipher = 0;

	// Open
	if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_OPEN) {
		DLOG_DEBUG("Open mode");
		wlan_status.pairwise_cipher = CIPHER_SUITE_NONE;
		return 0;
	}

	// WEP
        if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WEP) {
		DLOG_DEBUG("WEP enabled");
		wlan_status.pairwise_cipher = CIPHER_SUITE_WEP40;
		return 0;
	}

	// WPA modes
	if ((encryption & WLANCOND_ENCRYPT_ALG_MASK)
			== WLANCOND_WPA_TKIP) {
		DLOG_DEBUG("TKIP Selected for unicast");
		wlan_status.pairwise_cipher = CIPHER_SUITE_TKIP;
	} else if ((encryption & WLANCOND_ENCRYPT_ALG_MASK) ==
			WLANCOND_WPA_AES) {
		DLOG_DEBUG("AES selected for unicast");
		wlan_status.pairwise_cipher = CIPHER_SUITE_CCMP;
	} else if (wlan_status.allow_all_ciphers == TRUE) {
		if (scan_results->extra_cap_bits & WLANCOND_WEP40) {
			DLOG_DEBUG("WEP40 selected for unicast");
			wlan_status.pairwise_cipher = CIPHER_SUITE_WEP40;
		} else if (scan_results->extra_cap_bits & WLANCOND_WEP104) {
			DLOG_DEBUG("WEP104 selected for unicast");
			wlan_status.pairwise_cipher = CIPHER_SUITE_WEP104;
		} else {
			DLOG_ERR("Not supported encryption %08x", encryption);
			return -1;
		}
	} else {
		DLOG_ERR("Not supported encryption %08x", encryption);
		return -1;
	}

	if ((encryption & WLANCOND_ENCRYPT_GROUP_ALG_MASK) ==
			WLANCOND_WPA_TKIP_GROUP) {
		DLOG_DEBUG("TKIP Selected for multicast");
		wlan_status.group_cipher = CIPHER_SUITE_TKIP;
	} else if ((encryption & WLANCOND_ENCRYPT_GROUP_ALG_MASK) ==
			(unsigned int)WLANCOND_WPA_AES_GROUP) {
		DLOG_DEBUG("AES Selected for multicast");
		wlan_status.group_cipher = CIPHER_SUITE_CCMP;
	} else if (wlan_status.allow_all_ciphers == TRUE) {
		if (scan_results->extra_cap_bits & WLANCOND_WEP40_GROUP) {
			DLOG_DEBUG("WEP40 selected for group key");
			wlan_status.group_cipher = CIPHER_SUITE_WEP40;
		} else if (scan_results->extra_cap_bits
				& WLANCOND_WEP104_GROUP) {
			DLOG_DEBUG("WEP104 selected for group key");
			wlan_status.group_cipher = CIPHER_SUITE_WEP104;
		} else {
			DLOG_ERR("Not supported encryption %08x", encryption);
			return -1;
		}
	} else {
		DLOG_ERR("Not supported encryption %08x", encryption);
		return -1;
	}

	return 0;
}
/**
   Clean roaming cache.
*/
void clean_roam_cache(void)
{
	clean_scan_results(&wlan_status.roam_cache);
}
/**
   Clear WPA mode related stuff.
*/
void clear_wpa_mode(void)
{
	g_free(wlan_status.wpa_ie.ie);
	wlan_status.wpa_ie.ie_len = 0;
	wlan_status.wpa_ie.ie = NULL;

	wlan_status.pairwise_cipher = CIPHER_SUITE_NONE;
	wlan_status.group_cipher = CIPHER_SUITE_NONE;

	//set_encryption_method(wlan_status.pairwise_cipher, &wlan_status);
	clear_wpa_keys(NULL);
	/* Clean PMK cache */
	g_slist_foreach(wlan_status.pmk_cache, (GFunc)g_free, NULL);
	g_slist_free(wlan_status.pmk_cache);
	wlan_status.pmk_cache = NULL;
}
/**
   Check if WPA mode is in use.
   @return TRUE if mode is in use.
*/
gboolean get_wpa_mode(void)
{
	if (wlan_status.pairwise_cipher & CIPHER_SUITE_TKIP ||
			wlan_status.pairwise_cipher & CIPHER_SUITE_CCMP) {
		return TRUE;
	}
	return FALSE;
}

static gint compare_pmk_entry(gconstpointer a, gconstpointer b)
{
	const struct pmksa_cache_t *pmk_cache = a;

	return memcmp(pmk_cache->mac, b, ETH_ALEN);
}

/**
   Add PMKID to PMKSA cache.
   @param pmkid PMKID to add.
   @param mac MAC address associated to PMKID.
*/
static void add_to_pmksa_cache(unsigned char* pmkid, unsigned char* mac)
{
	guint i = 0;
	GSList *list;
	gboolean entry_found = FALSE;

	for (list = wlan_status.pmk_cache; list != NULL &&
			entry_found == FALSE; list = list->next) {
		struct pmksa_cache_t *pmk_cache = list->data;
		/* First find if we have already the cache entry */
		if (memcmp(pmk_cache->mac, mac, ETH_ALEN) == 0) {
			DLOG_DEBUG("Found old entry: %i", i);
			/* Remove the old entry */
			wlan_status.pmk_cache = g_slist_remove(
					wlan_status.pmk_cache, pmk_cache);
			g_free(pmk_cache);

			entry_found = TRUE;
		} else {
			i++;
		}
	}

	if (i == PMK_CACHE_SIZE) {
		DLOG_DEBUG("Cache full, remove oldest");
		GSList *last_entry = g_slist_last(wlan_status.pmk_cache);
		wlan_status.pmk_cache = g_slist_remove(wlan_status.pmk_cache,
				last_entry->data);
		g_free(last_entry->data);
	}
	print_mac(WLANCOND_PRIO_LOW, "Adding new entry:", mac);

	struct pmksa_cache_t *new_entry = g_malloc(sizeof(*new_entry));
	memcpy(new_entry->mac, mac, ETH_ALEN);
	memcpy(new_entry->pmkid, pmkid, IW_PMKID_LEN);

	wlan_status.pmk_cache = g_slist_prepend(wlan_status.pmk_cache,
			new_entry);
	return;
}

/**
 * Removes an entry with the given mac address from the PMKSA cache.
 *
 * @param mac The mac address to be removed.
 * @return status True if the entry was actually removed.
 */
gboolean remove_from_pmksa_cache(unsigned char* mac)
{
	GSList *list = g_slist_find_custom(wlan_status.pmk_cache, mac,
			&compare_pmk_entry);
	if(!list)
		return FALSE;

	struct pmksa_cache_t *entry = list->data;

	print_mac(WLANCOND_PRIO_MEDIUM, "Removing PMKSA entry for:", mac);

	wlan_status.pmk_cache = g_slist_remove(wlan_status.pmk_cache,
			entry);

	g_free(entry);

	return TRUE;
}

/**
   Find entry from PMKSA cache.
   @param mac MAC address to identify the entry.
   @param pmkid This pointer will be set to point the pmkid. This won't be
   set on errors.
   @return Zero on success, non-zero on errors.
*/
int find_pmkid_from_pmk_cache(unsigned char* mac,
			      unsigned char **pmkid)
{
	GSList *list;
	int pmksa_found;

	if (check_pmksa_cache((unsigned char *)wlan_status.own_mac, ETH_ALEN,
			      mac, ETH_ALEN,
			      wlan_status.conn.authentication_type,
			      wlan_status.pairwise_cipher,
			      wlan_status.group_cipher,
			      &pmksa_found))
	{
		DLOG_ERR("Error while querying the pmksa cache status "
			 "from eapd");
		return -1;
	}

	if(!pmksa_found) {
		DLOG_DEBUG("No cached pmksa found from eapd");

		remove_from_pmksa_cache(mac);
		*pmkid = NULL;

		return 0;
	}

	list = g_slist_find_custom(wlan_status.pmk_cache, mac, &compare_pmk_entry);
	if (list != NULL) {
		struct pmksa_cache_t *pmk_cache = list->data;
		print_mac(WLANCOND_PRIO_MEDIUM, "Found PMKSA entry for:", mac);
		*pmkid = pmk_cache->pmkid;
		return 0;
	}

	DLOG_DEBUG("No cached pmksa found from eapd");
	*pmkid = NULL;

	return 0;
}

/**
   Helper function for scanning.
   @param ssid SSID to scan.
   @param ssid_len SSID length.
   @return status.
*/
int scan(gchar *ssid, int ssid_len, gboolean add_timer)
{
	struct iwreq req;
	struct iw_scan_req scan_req;

	if (get_scan_state() == SCAN_ACTIVE)
		return 0;

	set_scan_state(SCAN_ACTIVE);

	init_iwreq(&req);

	memset(&scan_req, 0, sizeof(scan_req));

	if (ssid_len > 1 && ssid != NULL) {
		//DLOG_DEBUG("Active scan for: %s (len=%d)", ssid, ssid_len -1);
		scan_req.essid_len = ssid_len -1;
		scan_req.bssid.sa_family = ARPHRD_ETHER;
		memset(scan_req.bssid.sa_data, 0xff, ETH_ALEN);
		memcpy(scan_req.essid, ssid, ssid_len -1);
		req.u.data.pointer = (caddr_t) &scan_req;
		req.u.data.length = sizeof(scan_req);
		req.u.data.flags = IW_SCAN_THIS_ESSID;
	}

	if (ioctl(socket_open(), SIOCSIWSCAN, &req) < 0) {
		if (errno == EBUSY && add_timer == TRUE) {
			DLOG_ERR("Scan busy, retrying later");

			if (ssid != wlan_status.scan_ssid) {
				if (ssid_len <= WLANCOND_MAX_SSID_SIZE+1) {
					wlan_status.scan_ssid_len = ssid_len;
				} else {
					wlan_status.scan_ssid_len = 1;
				}

				memset(wlan_status.scan_ssid, 0, sizeof(wlan_status.scan_ssid));
				if (ssid != NULL && wlan_status.scan_ssid_len > 1) {
					memcpy(wlan_status.scan_ssid, ssid, wlan_status.scan_ssid_len);
				}
			}

			wlan_status.scan_id = g_timeout_add_seconds(
					WLANCOND_RESCAN_DELAY,
					wlan_scan_later_cb,
					NULL);
			return 0;
		} else {
			DLOG_ERR("Scan failed, errno %d", errno);
			return -1;
		}
	}

	if (add_timer == TRUE) {
		wlan_status.scan_id = g_timeout_add_seconds(
				WLANCOND_SCAN_TIMEOUT,
				wlan_scan_cb,
				NULL);
	}

        DLOG_INFO("Scan issued");

	return 0;
}
/**
   Helper function for setting the channel.
   @param channel Channel.
   @return status.
*/
static int set_freq(int channel)
{
	struct iwreq req;

	DLOG_DEBUG("Setting channel: %d", channel);

	init_iwreq(&req);

	req.u.freq.m = channel;

	if (ioctl(socket_open(), SIOCSIWFREQ, &req) < 0) {
		DLOG_ERR("Freq failed");
		return -1;
	}

	return 0;
}
static void init_conn_params(struct connect_params_t *conn_params)
{
	memset(conn_params, 0, sizeof(*conn_params));
}
/**
   Clear WPA keys.
   @param bssid optional BSSID which keys to remove.
*/
void clear_wpa_keys(unsigned char* bssid)
{
	struct iwreq req;
	struct iw_encode_ext ext;
	int sock;
	guint i;

	init_iwreq(&req);

	sock = socket_open();

	for (i=0;i<4;i++) {

		memset(&ext, 0, sizeof(ext));

		req.u.encoding.flags = i + 1;
		req.u.encoding.flags |= IW_ENCODE_DISABLED;
		req.u.encoding.pointer = (caddr_t) &ext;
		req.u.encoding.length = sizeof(ext);

		ext.ext_flags |= IW_ENCODE_EXT_GROUP_KEY;
		ext.addr.sa_family = ARPHRD_ETHER;

		memset(ext.addr.sa_data, 0xff, ETH_ALEN);
		ext.alg = IW_ENCODE_ALG_NONE;

		if (ioctl(sock, SIOCSIWENCODEEXT, &req) < 0) {
			DLOG_ERR("Key %i clearing failed", i);
		}
	}
	if (bssid != NULL) {

		memset(&ext, 0, sizeof(ext));

		req.u.encoding.flags = 1;
		req.u.encoding.flags |= IW_ENCODE_DISABLED;
		req.u.encoding.pointer = (caddr_t) &ext;
		req.u.encoding.length = sizeof(ext);

		ext.addr.sa_family = ARPHRD_ETHER;

		memcpy(ext.addr.sa_data, bssid, ETH_ALEN);
		ext.alg = IW_ENCODE_ALG_NONE;

		if (ioctl(sock, SIOCSIWENCODEEXT, &req) < 0) {
			DLOG_ERR("Key clearing failed");
		}
	}

	return;
}
/**
   Helper function for checking settings_and_connect DBUS parameters.
   @param conn Connection parameters.
   @param ssid SSID.
   @param key Encryption keys.
   @return status.
*/
static int check_connect_arguments(struct connect_params_t *conn, char* ssid,
                                   unsigned char** key)
{
	guint i;

	if (conn->flags & WLANCOND_DISABLE_POWERSAVE) {
		DLOG_DEBUG("Powersave disabled");
		powersave = WLANCOND_POWER_ON;
	} else if (conn->flags & WLANCOND_MINIMUM_POWERSAVE) {
		DLOG_DEBUG("Powersave minimum");
		powersave = WLANCOND_LONG_CAM;
	} else if (conn->flags & WLANCOND_MAXIMUM_POWERSAVE) {
		DLOG_DEBUG("Powersave maximum");
		powersave = WLANCOND_SHORT_CAM;
	} else {
		powersave = WLANCOND_SHORT_CAM;
	}

	if (conn->power_level != WLANCOND_TX_POWER10 &&
			conn->power_level != WLANCOND_TX_POWER100) {
		DLOG_ERR("Invalid power level");
		return -1;
	}

	switch (conn->mode) {
	case WLANCOND_ADHOC:
	case WLANCOND_INFRA:
		break;
	default:
		DLOG_ERR("Operating mode undefined\n");
		return -1;
	}
	/* Encryption settings */
	guint32 wpa2_mode = conn->encryption & WLANCOND_ENCRYPT_WPA2_MASK;

	DLOG_DEBUG("Encryption setting: %08x", conn->encryption);

	switch (conn->encryption & WLANCOND_ENCRYPT_METHOD_MASK) {
	case WLANCOND_OPEN:
		break;
	case WLANCOND_WEP:
		break;
	case WLANCOND_WPA_PSK:
		DLOG_DEBUG("%s PSK selected",
				wpa2_mode!=0?"WPA2":"WPA");
		if (wpa2_mode != 0)
			conn->authentication_type = EAP_AUTH_TYPE_WPA2_PSK;
		else
			conn->authentication_type = EAP_AUTH_TYPE_WPA_PSK;
		break;
	case WLANCOND_WPA_EAP:
		DLOG_DEBUG("%s EAP selected", wpa2_mode!=0?"WPA2":"WPA");
		if (wpa2_mode != 0)
			conn->authentication_type = EAP_AUTH_TYPE_WPA2_EAP;
		else
			conn->authentication_type = EAP_AUTH_TYPE_WPA_EAP;
		break;
	default:
		DLOG_DEBUG("Unsupported encryption mode");
		return -1;
	}
	if ((conn->encryption & WLANCOND_WPS_MASK) != 0) {
		DLOG_DEBUG("WPS selected");
		conn->authentication_type = EAP_AUTH_TYPE_WFA_SC;
	}

	if (!ssid || conn->ssid_len == 0 ||
			conn->ssid_len > WLANCOND_MAX_SSID_SIZE + 1) {
		DLOG_DEBUG("Invalid SSID");
		return -1;
	}
	for (i=0;i<4;i++) {
		if (conn->key_len[i] != 0) {
			DLOG_DEBUG("Found key %d", i);
			memcpy(&conn->key[i][0], key[i], conn->key_len[i]);
		}
	}
	return 0;
}

/**
    Settings and connect D-BUS request.
    @param message DBUS message.
    @param connection DBUS connection.
    @return status.
*/
static DBusHandlerResult settings_and_connect_request(
		DBusMessage    *message,
		DBusConnection *connection) {

	DBusMessage *reply = NULL;
	DBusError derror;
	struct connect_params_t *conn;
	char *ssid;
	unsigned char* key[4];
	dbus_int32_t old_mode;
	int res;
	gboolean autoconnect = FALSE;

	dbus_error_init(&derror);

	if (in_flight_mode()) {
		reply = new_dbus_error(message, WLANCOND_ERROR_WLAN_DISABLED);
		send_and_unref(connection, reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	remove_wlan_if_timer();

	conn = &wlan_status.conn;
	/* Save previous mode */
	old_mode = conn->mode;
	init_conn_params(conn);

	if (dbus_message_get_args(
		message, NULL,
		DBUS_TYPE_INT32, &conn->power_level,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ssid, &conn->ssid_len,
		DBUS_TYPE_INT32, &conn->mode,
		DBUS_TYPE_INT32, &conn->encryption,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[0], &conn->key_len[0],
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[1], &conn->key_len[1],
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[2], &conn->key_len[2],
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[3], &conn->key_len[3],
		DBUS_TYPE_INT32, &conn->default_key,
		DBUS_TYPE_UINT32, &conn->adhoc_channel,
		DBUS_TYPE_UINT32, &conn->flags,
		DBUS_TYPE_INVALID) == FALSE)
	{
		/* Try without flags */
		if (dbus_message_get_args(
			message, &derror,
			DBUS_TYPE_INT32, &conn->power_level,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ssid,
			&conn->ssid_len,
			DBUS_TYPE_INT32, &conn->mode,
			DBUS_TYPE_INT32, &conn->encryption,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&key[0], &conn->key_len[0],
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&key[1], &conn->key_len[1],
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&key[2], &conn->key_len[2],
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&key[3], &conn->key_len[3],
			DBUS_TYPE_INT32, &conn->default_key,
			DBUS_TYPE_UINT32, &conn->adhoc_channel,
			DBUS_TYPE_INVALID) == FALSE) {

			DLOG_ERR("Failed to parse setting_and_connect: %s",
					derror.message);
			dbus_error_free(&derror);
			goto param_err;
		}
	}

	if (check_connect_arguments(conn, ssid, key) < 0)
		goto param_err;

	set_power_state(WLANCOND_POWER_ON, socket_open());

	/* If we change mode, do it when interface is down.
	   Also put interface down in WPS mode to clear old
	   scan results.
	*/
	if (old_mode != conn->mode ||
	    conn->encryption & WLANCOND_WPS_PUSH_BUTTON) {
		set_wlan_state(WLAN_NOT_INITIALIZED, NO_SIGNAL, FORCE_YES);
	}

	/* Mode */
	if (set_mode(conn->mode) < 0) {
                goto param_err;
	}

	if (init_if(socket_open()) < 0) {
		reply = new_dbus_error(message, WLANCOND_ERROR_INIT_FAILED);
		goto param_err;
	}

	if (set_tx_power(conn->power_level, socket_open()) != TRUE) {
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}
	
	if (conn->flags & WLANCOND_AUTOCONNECT) {
		DLOG_DEBUG("Autoconnect attempt");
		autoconnect = TRUE;
	}

	memcpy(conn->ssid, ssid, conn->ssid_len);

	set_scan_state(SCAN_NOT_ACTIVE);
	set_wlan_state(WLAN_INITIALIZED_FOR_CONNECTION, NO_SIGNAL, FORCE_NO);

	/* Make a broadcast scan to catch all WPS PBC registrars */
	if (conn->encryption & WLANCOND_WPS_PUSH_BUTTON) {
		DLOG_DEBUG("Broadcast scan for WPS");
		if (scan(NULL, 0, TRUE) < 0) {
			goto param_err;
		}
	} else {
		/* Try if our own cache has results */
		if ((res = find_connection_and_associate(
			    wlan_status.roam_cache,
			    FALSE, FALSE, autoconnect)) != 0) {
			
			/* If res == ETOOWEAKAP, all APs were too weak for
			   autoconnection, no need to continue */
			if (res == ETOOWEAKAP)
				goto param_err;
			
			/* Try if mac80211 has cached results */
			DLOG_DEBUG("Checking mac80211 cache...");

			GSList *scan_results = NULL;
			scan_results_ioctl(0, &scan_results);

			if (find_connection_and_associate(
				    scan_results, 
				    TRUE, FALSE, autoconnect) != 0) {
				
				/* If res == ETOOWEAKAP, all APs were too weak 
				   for autoconnection, no need to continue */
				if (res == ETOOWEAKAP)
					goto param_err;

				clean_scan_results(&scan_results);
				if (scan(conn->ssid, conn->ssid_len, TRUE)
						< 0) {
					goto param_err;
				}
			} else {
				clean_scan_results(&scan_results);
			}
		}
	}

	g_free(connect_name_cache);
	connect_name_cache = g_strdup(dbus_message_get_sender(message));

	reply = new_dbus_method_return(message);

	gchar* ifname = wlan_status.ifname;

	append_dbus_args(reply,
			DBUS_TYPE_STRING, &ifname,
			DBUS_TYPE_INVALID);

	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;

param_err:
	if (reply == NULL) {
		DLOG_DEBUG("Parameter error in settings_and_connect\n");
		reply = new_dbus_error(message, DBUS_ERROR_INVALID_ARGS);
	}
	send_and_unref(connection, reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
    Associate function to associate to selected access point.
    @param scan_results Scan results.
    @return status.
*/
int associate(struct scan_results_t *scan_results)
{
	struct connect_params_t *conn = &wlan_status.conn;
	gint ret;
	
	DLOG_INFO("Starting to associate");

	if (memcmp(conn->bssid, "\0\0\0\0\0\0", ETH_ALEN)) {
		clear_wpa_keys(conn->bssid);
	}

	if (update_algorithms(conn->encryption, scan_results) < 0) {
		return -1;
	}

	/* WEP keys */
	if ((conn->encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WEP){
		if (set_wep_keys(conn) < 0) {
			return -1;
                }
	}

	memcpy(conn->bssid, scan_results->bssid, ETH_ALEN);

	if ((ret = set_encryption_method(conn->encryption, &wlan_status,
					scan_results)) < 0) {
		return ret;
	}

	if (get_wpa_mode() == TRUE ||
			conn->authentication_type == EAP_AUTH_TYPE_WFA_SC) {

		// Initialize authentication SW if mode is WPA or WPS
		if (wpa_ie_push(scan_results->bssid,
					scan_results->wpa_ie,
					scan_results->wpa_ie_len,
					scan_results->ssid,
					scan_results->ssid_len -1,
					conn->authentication_type) < 0)
			return -1;
        }

	/* Channel */
	/* Ad-hoc channel */
	if (conn->adhoc_channel != 0 && (conn->mode & WLANCOND_ADHOC)) {
		if (conn->adhoc_channel < WLANCOND_MIN_WLAN_CHANNEL ||
			conn->adhoc_channel > WLANCOND_MAX_WLAN_CHANNEL) {
			DLOG_ERR("Invalid ad-hoc channel: %d",
					conn->adhoc_channel);
			return -1;
		}

		scan_results->channel = conn->adhoc_channel;
	}

	set_freq(scan_results->channel);

        /* Set BSSID if known and no Adhoc */
	if (conn->mode != WLANCOND_ADHOC &&
		memcmp(scan_results->bssid, "\0\0\0\0\0\0", ETH_ALEN)) {
		if (set_bssid(scan_results->bssid) < 0) {
			return -1;
		}
	}
	/* ESSID */
	if (set_essid(conn->ssid, conn->ssid_len) < 0) {
		return -1;
	}

	/* Set association timeout timer */
	wlan_connect_timer_id = g_timeout_add_seconds(
		WLANCOND_CONNECT_TIMEOUT,
		wlan_connect_timer_cb, NULL);

	return 0;
}

/**
     Scan D-BUS request.
     @param message DBUS message.
     @param connection DBUS connection.
     @return status.
*/
static DBusHandlerResult scan_request(DBusMessage    *message,
		DBusConnection *connection) {

	DBusMessage *reply = NULL;
	DBusMessageIter iter, array_iter;
	char *ssid;
	const char* sender;
	dbus_int32_t power_level;
	dbus_int32_t flags;
	gint previous_state = 0;

	if (in_flight_mode()) {
		reply = new_dbus_error(message, WLANCOND_ERROR_WLAN_DISABLED);
		send_and_unref(connection, reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	sender = dbus_message_get_sender(message);
	if (sender == NULL) {
		goto param_err;
	}

	DLOG_DEBUG("Got scan request from %s", sender);

	/* Do not scan if we are scanning already or if we are associating */
	if (get_scan_state() == SCAN_ACTIVE || wlan_connect_timer_id != 0) {
		reply = new_dbus_error(message, WLANCOND_ERROR_ALREADY_ACTIVE);
		send_and_unref(connection, reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if ((previous_state = init_if(socket_open())) < 0) {
		reply = new_dbus_error(message, WLANCOND_ERROR_INIT_FAILED);
		goto param_err;
	}

	if (previous_state == WLAN_NOT_INITIALIZED) {
		set_wlan_state(WLAN_INITIALIZED_FOR_SCAN, NO_SIGNAL, FORCE_NO);
	}

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32)
		goto param_err;
	dbus_message_iter_get_basic(&iter, &power_level);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY ||
		dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_BYTE)
		goto param_err;
	dbus_message_iter_recurse(&iter, &array_iter);
	dbus_message_iter_get_fixed_array(&array_iter, &ssid,
			&wlan_status.scan_ssid_len);

	if (wlan_status.scan_ssid_len > WLANCOND_MAX_SSID_SIZE+1)
		goto param_err;

	dbus_message_iter_next(&iter);

	power_down_after_scan = FALSE;

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_UINT32) {
		dbus_message_iter_get_basic(&iter, &flags);
		DLOG_DEBUG("Found flags: %08x", flags);

		if (flags & WLANCOND_NO_DELAYED_SHUTDOWN)
			power_down_after_scan = TRUE;
	}

	if (power_level != WLANCOND_TX_POWER10 &&
			power_level != WLANCOND_TX_POWER100) {
		DLOG_ERR("Invalid power level");
		goto param_err;
	}

	if (set_tx_power(power_level, socket_open()) != TRUE) {
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}

	memset(wlan_status.scan_ssid, 0, sizeof(wlan_status.scan_ssid));

	if (ssid != NULL && wlan_status.scan_ssid_len > 1) {
		memcpy(wlan_status.scan_ssid, ssid, wlan_status.scan_ssid_len);
	}

	if (scan(wlan_status.scan_ssid, wlan_status.scan_ssid_len, TRUE) < 0) {
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}

	g_free(scan_name_cache);
	scan_name_cache = g_strdup(sender);

	reply = new_dbus_method_return(message);
	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;

param_err:
	if (get_wlan_state() == WLAN_INITIALIZED_FOR_SCAN) {
		set_wlan_state(WLAN_NOT_INITIALIZED, NO_SIGNAL, FORCE_YES);
	}
	if (reply == NULL) {
		DLOG_DEBUG("Parameter error in scan request");
		reply = new_dbus_error(message, DBUS_ERROR_INVALID_ARGS);
	}
	send_and_unref(connection, reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
     Network compare.
     @param a Pointer to scan_result 1.
     @param b Pointer to scan result 2.
     @return 0 if a=b, -1 if a is better than b and 1 if b is better than a.
*/
static int network_compare(gconstpointer a, gconstpointer b)
{
	const struct scan_results_t *results_a = a;
	const struct scan_results_t *results_b = b;

	if (wlan_status.scan_ssid_len > 1) {

		//DLOG_DEBUG("Scan ssid = %s", scan_ssid);

		gint a_eq = strncmp(wlan_status.scan_ssid,
				results_a->ssid, WLANCOND_MAX_SSID_SIZE);
                gint b_eq = strncmp(wlan_status.scan_ssid,
				results_b->ssid, WLANCOND_MAX_SSID_SIZE);
		// Check if either network match the scan SSID
		if (!a_eq && !b_eq) {
			//DLOG_DEBUG("Both (%s, %s) match scan SSID",
			//results_a->ssid, results_b->ssid);
			return 0;
		}

		if (!a_eq && b_eq) {
			//DLOG_DEBUG("%s is better than %s",
			//results_a->ssid, results_b->ssid);
			return -1;
		}

		if (a_eq && !b_eq) {

			//DLOG_DEBUG("%s is better than %s",
			//results_b->ssid, results_a->ssid);
			return 1;
		}

	}
	//DLOG_DEBUG("No scan ssid, returning just RSSI values");

	return (results_a->rssi > results_b->rssi) ?
		-1 : (results_a->rssi < results_b->rssi) ? 1 : 0;
}

static gint compare_scan_entry(gconstpointer a, gconstpointer b)
{
	const struct scan_results_t *scan_entry = a;
	return memcmp(scan_entry->bssid, b, ETH_ALEN);
}
/**
   Add scan results to roam cache.
   @param scan_results Scan results to add.
*/
static void add_to_roam_cache(struct scan_results_t *scan_results)
{
	GSList *list;

	list = g_slist_find_custom(wlan_status.roam_cache, scan_results->bssid,
			&compare_scan_entry);

	if (list != NULL) {
		struct scan_results_t *roam_cache_entry = list->data;
		print_mac(WLANCOND_PRIO_LOW, "Found old entry for:",
			  scan_results->bssid);

		/* Remove the old entry */
		wlan_status.roam_cache = g_slist_remove(
				wlan_status.roam_cache, roam_cache_entry);

		clean_scan_results_item(roam_cache_entry, NULL);
	}

	print_mac(WLANCOND_PRIO_LOW, "New AP to roam cache:",
			scan_results->bssid);

	struct scan_results_t *results_to_list =
		g_slice_dup(struct scan_results_t, scan_results);
	results_to_list->wpa_ie = g_memdup(scan_results->wpa_ie,
			scan_results->wpa_ie_len);
	wlan_status.roam_cache = g_slist_prepend(wlan_status.roam_cache,
			results_to_list);

	return;
}
/**
   Remove from roam cache.
   @param bssid BSSID to remove.
   @return status.
*/
gboolean remove_from_roam_cache(unsigned char *bssid)
{
	GSList *list;

	list = g_slist_find_custom(wlan_status.roam_cache, bssid,
			&compare_scan_entry);

	if (list != NULL) {
		struct scan_results_t *roam_cache_entry = list->data;
		print_mac(WLANCOND_PRIO_LOW, "Found entry to be removed:",
				bssid);

                wlan_status.roam_cache = g_slist_remove(
				wlan_status.roam_cache, roam_cache_entry);

		clean_scan_results_item(roam_cache_entry, NULL);

		return TRUE;
	}

	return FALSE;
}

/**
   Give penalty to failed AP.
   @param bssid BSSID.
   @return status.
*/
gboolean decrease_signal_in_roam_cache(unsigned char *bssid)
{
	GSList *list;

	list = g_slist_find_custom(wlan_status.roam_cache, bssid,
			&compare_scan_entry);

	if (list != NULL) {
		struct scan_results_t *roam_cache_entry = list->data;
		print_mac(WLANCOND_PRIO_LOW, "Found entry to be decreased:",
				bssid);

		roam_cache_entry->rssi -= WLANCOND_RSSI_PENALTY;

		return TRUE;
	}

	return FALSE;
}
/**
   Compare group ciphers.
   @param c1 Cipher 1.
   @param c2 Cipher 2.
   @return 1 if matches.
*/
static int check_group_cipher(guint32 c1, guint32 c2)
{
	guint32 m1 = (c1 & WLANCOND_ENCRYPT_GROUP_ALG_MASK);
	guint32 m2 = (c2 & WLANCOND_ENCRYPT_GROUP_ALG_MASK);

	if (m1 == m2)
                return 1;
	if (m2 == WLANCOND_WPA_TKIP_GROUP && (m1 & WLANCOND_WPA_TKIP_GROUP))
		return 1;
	if (m2 == (unsigned int)WLANCOND_WPA_AES_GROUP &&
			(m1 & WLANCOND_WPA_AES_GROUP))
		return 1;

	DLOG_DEBUG("Group ciphers don't match");

	return -1;
}
/**
   Compare ciphers.
   @param c1 Cipher 1.
   @param c2 Cipher 2.
   @return 1 if matches.
*/
static int check_ciphers(guint32 c1, guint32 c2)
{
	guint32 u1 = (c1 & WLANCOND_ENCRYPT_ALG_MASK);
	guint32 u2 = (c2 & WLANCOND_ENCRYPT_ALG_MASK);

	if (check_group_cipher(c1, c2) < 0)
                return -1;

	if (u1 == u2)
                return 1;
	if (u2 == WLANCOND_WPA_TKIP && (u1 & WLANCOND_WPA_TKIP))
		return 1;
	if (u2 == WLANCOND_WPA_AES && (u1 & WLANCOND_WPA_AES))
		return 1;

	DLOG_DEBUG("Unicast ciphers don't match");

	return -1;
}

static gboolean wlan_roam_scan_cb(void* data)
{
	wlan_status.roam_scan_id = 0;
	struct timeval tv;

	if (wlan_status.signal == WLANCOND_LOW &&
			get_wlan_state() == WLAN_CONNECTED) {

		DLOG_DEBUG("Roam scan timeout, initiating new scan");

		if (scan(wlan_status.conn.ssid, wlan_status.conn.ssid_len, 
			 TRUE) <0) {
			set_wlan_state(WLAN_NOT_INITIALIZED,
				       DISCONNECTED_SIGNAL,
				       FORCE_YES);
			return FALSE;
		}
		if (gettimeofday(&tv, NULL) >= 0)
			wlan_status.last_scan = tv.tv_sec;
	}

        return FALSE;
}

/**
   Schedule scan.
   @param seconds Delay scan for this many seconds.
*/
void schedule_scan(guint seconds) {

	/* Remove old timer */
	remove_roam_scan_timer();
	wlan_status.roam_scan_id = g_timeout_add_seconds(
			seconds,
			wlan_roam_scan_cb,
			NULL);
}

/**
   Reschedule scan.
*/
static void reschedule_scan(void)
{
        /*
           If we are active use shortest scan interval, otherwise
           use exponential backoff
        */
	if (get_inactivity_status() == TRUE) {
		wlan_status.roam_scan = WLANCOND_MIN_ROAM_SCAN_INTERVAL;
	} else {
                if (wlan_status.roam_scan <= WLANCOND_MIN_ROAM_SCAN_INTERVAL) {
			wlan_status.roam_scan = WLANCOND_MIN_ROAM_SCAN_INTERVAL;
		} else if (wlan_status.roam_scan >=
				WLANCOND_MAX_ROAM_SCAN_INTERVAL) {
			wlan_status.roam_scan = WLANCOND_MAX_ROAM_SCAN_INTERVAL;
		} else {
			wlan_status.roam_scan = wlan_status.roam_scan * 2;
		}
	}

	schedule_scan(wlan_status.roam_scan);
}

/**
   Check capabilities from scan results.
   @param scan_results Scan results.
   @param conn Connection paramters.
   @return status.
*/
static gboolean check_capabilities(struct scan_results_t *scan_results,
                                   struct connect_params_t *conn)
{
	// Check mode
	if ((scan_results->cap_bits & WLANCOND_MODE_MASK) != (guint32)conn->mode)
		return FALSE;
	if ((scan_results->cap_bits & WLANCOND_ENCRYPT_METHOD_MASK) !=
			(guint32)(conn->encryption &
				WLANCOND_ENCRYPT_METHOD_MASK))
		return FALSE;
	if ((scan_results->cap_bits & WLANCOND_ENCRYPT_WPA2_MASK) !=
			(guint32)(conn->encryption &
				WLANCOND_ENCRYPT_WPA2_MASK))
		return FALSE;
	if (check_ciphers(scan_results->cap_bits, conn->encryption) < 0)
		return FALSE;

	return TRUE;
}

/**
     Find connection.
     @param ap_list List of access points.
     @param conn Connection parameters.
     @param update_roam_cache Update roaming cache or not.
     @return scan_results_t Returns best connection if found.
*/
struct scan_results_t* find_connection(
		GSList* ap_list, struct connect_params_t *conn,
		gboolean update_roam_cache)
{
	GSList *list;
	struct scan_results_t *best_connection = NULL;
	gint current_rssi = 0;

	/* If update roam cache, clean it first */
	if (update_roam_cache == TRUE)
		clean_roam_cache();

	for (list = ap_list; list != NULL; list = list->next) {
		struct scan_results_t *scan_results = list->data;
		if (memcmp(scan_results->ssid, conn->ssid,
					scan_results->ssid_len) == 0) {
			print_mac(WLANCOND_PRIO_LOW, "Found AP:",
					scan_results->bssid);

			/* Find the current AP so that we know it's RSSI */
			if (memcmp(scan_results->bssid, wlan_status.conn.bssid,
						ETH_ALEN) == 0) {
				current_rssi = scan_results->rssi;
				DLOG_DEBUG("Current AP: %d", current_rssi);
			}

			if (check_capabilities(scan_results, conn) ==
					FALSE)
				continue;

			if (is_ap_in_black_list(scan_results->bssid) == TRUE) {
				DLOG_INFO("AP is in black list, discarded");
				continue;
			}

			/* At this point we know the connection is good,
			   add to the roam cache
			 */
			if (update_roam_cache == TRUE) {
				add_to_roam_cache(scan_results);
			}

			if (best_connection == NULL ||
				best_connection->rssi < scan_results->rssi) {
				DLOG_DEBUG("Best connection: %d (old %d)",
						scan_results->rssi,
						best_connection == NULL ?
						WLANCOND_MINIMUM_SIGNAL:
						best_connection->rssi);
				best_connection = scan_results;
			}
		}
	}

	/* Did not find any connection */
	if (best_connection == NULL)
		return NULL;

	/* Check if we are already connected but the best connection is not
	   worth changing
	 */
	if (current_rssi != 0) {
		if (best_connection->rssi < current_rssi +
				WLANCOND_ROAM_THRESHOLD) {
			DLOG_DEBUG("Best connection not good enough");
			return NULL;
		}
	}

	/* Check if the signal level is good enough for connection */
	if (best_connection->rssi < WLANCOND_MINIMUM_SIGNAL)
		return NULL;

	return best_connection;
}
/**
   Select Adhoc channel.
   @param ap_list List of scanned APs.
   @return selected channel.
*/
static dbus_uint32_t find_adhoc_channel(GSList *ap_list) {

	dbus_uint32_t used_channel_list = 0;
	dbus_uint32_t selected_channel = 0;
	GSList* list;
	guint32 i;

	/* Create a map of free channels */
	for (list = ap_list; list != NULL; list = list->next) {
		struct scan_results_t *scan_results = list->data;
		used_channel_list |= 1 << scan_results->channel;
	}

	for (i = 1; i <= 11; i++) {
		if (!(used_channel_list & (1 << i))) {
			selected_channel = i;
			break;
		}
	}

	if (selected_channel == 0) {
		/* No free channel found, choose one randomly from
		 * channels 1 - 11. */
		selected_channel = g_random_int_range(1, 12);
	}

	//DLOG_DEBUG("Selected adhoc channel: %d", selected_channel);

	return selected_channel;
}
/**
   Find connection and associate.
   @param scan_results Scan results.
   @return status.
*/
int find_connection_and_associate(GSList *scan_results,
				  gboolean update_roam_cache,
				  gboolean create_new_adhoc,
				  gboolean autoconnect)
{
	struct scan_results_t adhoc;
	struct connect_params_t *conn = &wlan_status.conn;
	guint wps_pbc_registrars = 0;
	GSList* list;

	/* Check for too many registrars in the WPS PBC
	   method */
	if (conn->encryption & WLANCOND_WPS_PUSH_BUTTON) {
		for (list = scan_results; list != NULL; list = list->next) {
			struct scan_results_t *scan_results = list->data;

			if (scan_results->cap_bits & WLANCOND_WPS_PUSH_BUTTON
			    &&
			    scan_results->cap_bits & WLANCOND_WPS_CONFIGURED) {
				if (++wps_pbc_registrars > 1) {
					DLOG_ERR("Too many WPS PBC registrars");
					return ETOOMANYREGISTRARS;
				}
			}
		}
	}

	struct scan_results_t *connection = find_connection(
			scan_results, &wlan_status.conn, update_roam_cache);

        if (connection == NULL && conn->mode == WLANCOND_ADHOC &&
			create_new_adhoc == TRUE) {
		DLOG_DEBUG("No existing adhoc connection");
		memset(&adhoc, 0, sizeof(adhoc));
		connection = &adhoc;
		memcpy(connection->ssid, conn->ssid, conn->ssid_len);
		connection->channel = find_adhoc_channel(scan_results);
	}

	if (connection) {
		if (autoconnect == TRUE && 
		    connection->rssi < WLANCOND_MINIMUM_AUTOCONNECT_RSSI) {
			DLOG_WARN("RSSI too low for autoconnect");
			return ETOOWEAKAP;
		}
		int ret = associate(connection);
		if (ret < 0)
			memset(wlan_status.conn.bssid, 0, ETH_ALEN);
		return ret;
	}
	return -1;
}
/**
   Send WPS too many registrars signal.
*/
static void registrar_error_signal(void)
{
	DBusMessage *registrar_error;

	registrar_error = new_dbus_signal(
			WLANCOND_SIG_PATH,
			WLANCOND_SIG_INTERFACE,
			WLANCOND_REGISTRAR_ERROR_SIG,
			NULL);

	send_and_unref(get_dbus_connection(), registrar_error);
}
/**
   Helper function for rescanning from a timer.
*/
static gboolean rescan(void* data)
{
	if (get_wlan_state() == WLAN_INITIALIZED_FOR_CONNECTION) {
		if (scan(wlan_status.conn.ssid,
			 wlan_status.conn.ssid_len, TRUE) < 0) {
		        set_wlan_state(WLAN_NOT_INITIALIZED,
				       DISCONNECTED_SIGNAL,
				       FORCE_YES);
		}
	}
	return FALSE;
}
/**
    Connects based on scan results.
    @param scan_results_save List of scan results.
*/
static void connect_from_scan_results(GSList *scan_results)
{
	gboolean autoconnect = !!(wlan_status.conn.flags & WLANCOND_AUTOCONNECT);

	int status = find_connection_and_associate(
		scan_results, TRUE, TRUE, autoconnect);

	clean_scan_results(&scan_results);

	if (status == 0)
		return;

	DLOG_DEBUG("Could not find suitable network");

	if (get_wlan_state() == WLAN_INITIALIZED_FOR_CONNECTION) {
		/* Try rescanning if retries left */
		if (status != ETOOWEAKAP && status != ESUPPLICANT &&
		    ++wlan_status.retry_count <= WLANCOND_MAX_SCAN_TRIES) {
			DLOG_DEBUG("Rescanning");
			g_timeout_add_seconds(
				WLANCOND_RESCAN_DELAY,
				rescan,
				NULL);
		} else {
			/* In WPS too many registrars case we send
			   different signal
			*/
			if (status == ETOOMANYREGISTRARS) {
				set_wlan_state(WLAN_NOT_INITIALIZED,
					       NO_SIGNAL, FORCE_YES);
				registrar_error_signal();
			} else {
				if (status == ESUPPLICANT) {
					DLOG_ERR("Supplicant error");
					kill_supplicant();
				}
				set_wlan_state(WLAN_NOT_INITIALIZED,
					       DISCONNECTED_SIGNAL, FORCE_YES);
			}
		}
		return;
	}

	/* We are connected but would prefer better connection */
	reschedule_scan();
}
/**
    Get scan results from mac80211.
    @param ifindex Interface index.
    @param scan_results_save Scan results to save.
    @return status.
*/
int scan_results_ioctl(int ifindex, GSList** scan_results_save)
{
	struct iwreq req;
	char *buffer;
	unsigned int buflen = IW_SCAN_MAX_DATA*2;
	int sock;
	unsigned int counter = 3;

	//DLOG_DEBUG("Scan results ioctl");

	init_iwreq(&req);

	sock = socket_open();

	buffer = g_malloc(buflen);

try_again:

	/* Read the results */
	req.u.data.pointer = buffer;
	req.u.data.flags = 0;
	req.u.data.length = buflen;

	if (ioctl(sock, SIOCGIWSCAN, &req) < 0) {
		/* Check if we got too many results for
		   our buffer*/
		if (errno == E2BIG && buflen != G_MAXUINT16) {
			DLOG_DEBUG("Too much data for buffer length %d "
				"needed %d\n", buflen, req.u.data.length);

			char* new_buffer = NULL;
			buflen = (req.u.data.length > buflen ?
					req.u.data.length : buflen * 2);

			/* There is a limit of 16 bits in the length */
			if (buflen > G_MAXUINT16)
				buflen = G_MAXUINT16;
			new_buffer = g_realloc(buffer, buflen);

			buffer = new_buffer;
			goto try_again;
		}

		/* Check if results not available yet */
		if (errno == EAGAIN)
		{
			DLOG_DEBUG("Not yet ready...");
			if (counter-- > 0) {
				sleep(1);
				goto try_again;
			}
		}

		DLOG_ERR("Get scan results failed");

		g_free(buffer);
		return -1;
	}

	if (req.u.data.length)
	{
		struct iw_event            iwe;
		struct stream_descr        stream;
		struct scan_results_t      *scan_results;
		struct wireless_iface      *wireless_if;
		int                        ret;
		gboolean                   wap_handled = FALSE;
		int			   we_version;

		scan_results = g_slice_new0(struct scan_results_t);
		memset(&iwe, 0, sizeof(iwe));

		if (ifindex != 0) {
			wireless_if = get_interface_data(ifindex);
			we_version = wireless_if->range.we_version_compiled;
		} else {
			struct iw_range range;
			if (iw_get_range_info(socket_open(),
						wlan_status.ifname,
						&range)<0)
				memset(&range, 0, sizeof(range));
			we_version = range.we_version_compiled;
		}

		iw_init_event_stream(&stream, buffer, req.u.data.length);
		do
                {
			/* Extract an event */
			ret = iw_extract_event_stream(
					&stream, &iwe,
					we_version);
			if (ret > 0) {
				/* Let's peek what is coming so that we can
				   separate different access points from
				   the stream */

				if (iwe.cmd == SIOCGIWAP) {
					/* Do not save if first time
					   because WAP comes first, then other
					   parameters */
					if (wap_handled == TRUE) {
						*scan_results_save =
						save_scan_results(
							scan_results,
							*scan_results_save);
						scan_results = g_slice_new0(
							struct scan_results_t);
					} else {
						wap_handled = TRUE;
					}
				}
				print_event_token(&iwe, scan_results, ifindex,
						TRUE);
			}

		}
		while (ret > 0);

		/* Check if the final results is still in the queue before
		   the result is sent into DBUS */
		if (wap_handled == TRUE) {
			*scan_results_save = save_scan_results(
					scan_results,
					*scan_results_save);
		} else {
			// No results
			g_slice_free(struct scan_results_t, scan_results);
		}
	}

	g_free(buffer);

	return 0;
}


/**
     Scan results request.
     @param ifindex Interface index.
     @return status.
*/
gboolean ask_scan_results(int ifindex)
{
	GSList *scan_results_save = NULL;
	dbus_int32_t number_of_results;

	if (scan_results_ioctl(ifindex, &scan_results_save) < 0)
		return FALSE;

	/* First send scan results if someone was expecting them */
	if (scan_name_cache != NULL) {
		number_of_results = g_slist_length(scan_results_save);

		/* Sort the list only if the amount of networks is very high and
		   we need to restrict the results */
		if (number_of_results > WLANCOND_MAX_NETWORKS)
			scan_results_save = g_slist_sort(scan_results_save,
					network_compare);

		send_dbus_scan_results(scan_results_save, scan_name_cache,
				number_of_results);
		g_free(scan_name_cache);
		scan_name_cache = NULL;
	}

	/* Try to associate if state is initialized_for_connection or
	   signal level is low */
	if ((get_wlan_state() == WLAN_INITIALIZED_FOR_CONNECTION ||
				wlan_status.signal == WLANCOND_LOW) &&
			get_scan_state() == SCAN_ACTIVE) {

		DLOG_DEBUG("Connect from scan");

		set_scan_state(SCAN_NOT_ACTIVE);

		connect_from_scan_results(scan_results_save);

                return TRUE;
	}

	set_scan_state(SCAN_NOT_ACTIVE);

	if (get_wlan_state() == WLAN_INITIALIZED_FOR_SCAN &&
			power_down_after_scan == TRUE) {
		set_interface_state(socket_open(), CLEAR, IFF_UP);
	}

	if (get_wlan_state() == WLAN_INITIALIZED_FOR_SCAN) {
		/* Save scan results temporarily */
		if (wlan_status.roam_cache) {
			clean_roam_cache();
		}
		wlan_status.roam_cache = scan_results_save;
		set_wlan_state(WLAN_NOT_INITIALIZED, NO_SIGNAL, FORCE_NO);
	} else {
		clean_scan_results(&scan_results_save);
	}

	return TRUE;
}

/**
    Disconnect WLAN and remove kernel module D-BUS request.
    @param message DBUS message.
    @param connection DBUS connection.
    @return status.
*/
static DBusHandlerResult disconnect_request(DBusMessage    *message,
		DBusConnection *connection) {
	DBusMessage *reply;

	set_scan_state(SCAN_NOT_ACTIVE);

	/* Set_wlan_state puts IF down */
	set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, FORCE_YES);

	reply = new_dbus_method_return(message);
	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
    Disassociate WLAN D-BUS request.
    @param message DBUS message.
    @param connection DBUS connection.
    @return status.
*/
static DBusHandlerResult disassociate_request(DBusMessage    *message,
		DBusConnection *connection) {
	DBusMessage *reply;

	if (get_wlan_state() != WLAN_CONNECTED &&
			get_wlan_state() != WLAN_NO_ADDRESS) {
		DLOG_DEBUG("Not in correct state for disassociation");

		reply = new_dbus_method_return(message);
		send_and_unref(connection, reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (get_wpa_mode() == TRUE) {
		clear_wpa_keys(wlan_status.conn.bssid);
	}

	mlme_command(wlan_status.conn.bssid, IW_MLME_DISASSOC,
			WLANCOND_REASON_LEAVING);

	set_wlan_state(WLAN_INITIALIZED_FOR_CONNECTION, NO_SIGNAL, FORCE_NO);

	DLOG_DEBUG("Disassociated, trying to find a new connection");

	if (scan(wlan_status.conn.ssid, wlan_status.conn.ssid_len, TRUE) < 0) {
		/* Set_wlan_state puts IF down */
		set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL,
				FORCE_YES);
	}

	reply = new_dbus_method_return(message);
        send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
   Status D_BUS request.
   @param message DBUS message.
   @param connection DBUS connection.
   @return status.
*/
static DBusHandlerResult status_request(DBusMessage    *message,
		DBusConnection *connection) {
	DBusMessage *reply = NULL;
	struct iwreq req;
	struct iw_range range;
	char *essid = NULL;
	int essid_len;
	dbus_uint32_t sens = 0;
	dbus_uint32_t security = 0;
	dbus_uint32_t capability = 0;
	dbus_uint32_t channel = 0;
	unsigned char *bssid = NULL;
	//unsigned char *key = NULL;
	int sock;

	if (get_wlan_state() != WLAN_CONNECTED &&
			get_wlan_state() != WLAN_NO_ADDRESS &&
			get_mode() != WLANCOND_ADHOC) {
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		send_and_unref(connection, reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	sock = socket_open();

	init_iwreq(&req);

	essid = g_malloc0(IW_ESSID_MAX_SIZE+1);
	req.u.essid.pointer = (caddr_t)essid;
	req.u.essid.length = IW_ESSID_MAX_SIZE;
	req.u.essid.flags = 0;

	/* essid */
	if (ioctl(sock, SIOCGIWESSID, &req) < 0) {
		DLOG_ERR("Could not get ESSID");
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}
	essid_len = req.u.essid.length;

	// Handle corner cases to keep the API the same
	if (essid_len == 0 || essid_len == 32)
		essid_len++;

	init_iwreq(&req);

	/* bssid */
	if (ioctl(sock, SIOCGIWAP, &req) < 0) {
		DLOG_ERR("Could not get BSSID");
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}
	bssid = g_malloc(ETH_ALEN);
	memcpy(bssid, &req.u.ap_addr.sa_data, ETH_ALEN);

	init_iwreq(&req);
	struct iw_statistics stats;
	memset(&stats, 0, sizeof(struct iw_statistics));

	req.u.data.pointer = (caddr_t) &stats;
	req.u.data.length = sizeof(struct iw_statistics);
	req.u.data.flags = 1;

	/* Link quality i.e. stats */
	if (ioctl(sock, SIOCGIWSTATS, &req) < 0) {
		DLOG_ERR("Could not get statistics");
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}
	sens = stats.qual.level - 0x100;

	/* Channel */
	init_iwreq(&req);

	if (ioctl(sock, SIOCGIWFREQ, &req) < 0) {
		DLOG_DEBUG("Could not get channel");
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}

	if (iw_get_range_info(sock, wlan_status.ifname, &range) >= 0) {
		double freq = iw_freq2float(&(req.u.freq));
		channel = iw_freq_to_channel(freq, &range);
	}

	if (channel < WLANCOND_MIN_WLAN_CHANNEL ||
			channel > WLANCOND_MAX_WLAN_CHANNEL) {
		channel = 0;
		DLOG_DEBUG("Got invalid channel\n");
	}

	/* Mode (Adhoc/Infra) */
	init_iwreq(&req);

	if (ioctl(sock, SIOCGIWMODE, &req) < 0) {
		DLOG_ERR("Could not get operating mode");
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}

	if (req.u.mode == IW_MODE_ADHOC) {
		capability |= WLANCOND_ADHOC;
	} else if (req.u.mode == IW_MODE_INFRA) {
		capability |= WLANCOND_INFRA;
	}

	init_iwreq(&req);

	/* encryption status */
	security = wlan_status.conn.encryption;

#if 0
	key = g_malloc(IW_ENCODING_TOKEN_MAX);
	req.u.data.pointer = (caddr_t) key;
	req.u.data.length = IW_ENCODING_TOKEN_MAX;
	req.u.data.flags = 0;

	if (ioctl(sock, SIOCGIWENCODE, &req) < 0) {
		reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
		goto param_err;
	}

	if (req.u.data.flags & IW_ENCODE_OPEN)
		security |= WLANCOND_OPEN;

	if (req.u.data.flags & IW_ENCODE_RESTRICTED)
		security |= WLANCOND_WEP;

	/* Currently we don't know if EAP or PSK is in use */
	if (req.u.data.flags & IW_ENCODE_TKIP)
		security |= WLANCOND_WPA_PSK & WLANCOND_WPA_EAP &
			WLANCOND_WPA_TKIP;

	if (req.u.data.flags & IW_ENCODE_AES)
		security |= WLANCOND_WPA_PSK & WLANCOND_WPA_EAP &
			WLANCOND_WPA_AES;

	g_free(key);
#endif
	init_iwreq(&req);

	/* Speed / Rate */
	if (ioctl(sock, SIOCGIWRATE, &req) < 0) {
		DLOG_ERR("Could not get the rate");
	}
	capability |= req.u.bitrate.value;

	reply = new_dbus_method_return(message);

	gchar* ifname = wlan_status.ifname;

	append_dbus_args(reply,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&essid, essid_len,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bssid, ETH_ALEN,
			DBUS_TYPE_UINT32, &sens,
			DBUS_TYPE_UINT32, &channel,
			DBUS_TYPE_UINT32, &capability,
			DBUS_TYPE_UINT32, &security,
			DBUS_TYPE_STRING, &ifname,
			DBUS_TYPE_INVALID);

	send_and_unref(connection, reply);

	g_free(essid);
	g_free(bssid);

	return DBUS_HANDLER_RESULT_HANDLED;

param_err:
	g_free(essid);
	g_free(bssid);
	//g_free(key);
	if (reply == NULL) {
		DLOG_DEBUG("Parameter error in status request");
		reply = new_dbus_error(message, DBUS_ERROR_INVALID_ARGS);
	}
	send_and_unref(connection, reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

/**
   Interface D_BUS request.
   @param message DBUS message.
   @param connection DBUS connection.
   @return status.
*/
static DBusHandlerResult interface_request(DBusMessage    *message,
		DBusConnection *connection) {
	DBusMessage *reply;
	gchar* ifname = wlan_status.ifname;

	reply = new_dbus_method_return(message);

	append_dbus_args(reply,
			DBUS_TYPE_STRING, &ifname,
			DBUS_TYPE_INVALID);

	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/**
   Connection status D_BUS request.
   @param message DBUS message.
   @param connection DBUS connection.
   @return status.
*/
static DBusHandlerResult connection_status_request(
		DBusMessage    *message,
		DBusConnection *connection) {

	DBusMessage *reply;
	dbus_bool_t state = FALSE;

	guint state_v = get_wlan_state();

	if (state_v == WLAN_INITIALIZED ||
			state_v == WLAN_NO_ADDRESS ||
			state_v == WLAN_CONNECTED)
		state = TRUE;

	reply = new_dbus_method_return(message);

	append_dbus_args(reply,
			DBUS_TYPE_BOOLEAN, &state,
			DBUS_TYPE_INVALID);

	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}
/**
   Set pmksa D-BUS request.
   @param message DBUS message.
   @param connection DBUS connection.
   @return status.
*/
static DBusHandlerResult set_pmksa_request(DBusMessage    *message,
		DBusConnection *connection) {

	DBusMessage *reply = NULL;
	unsigned int pmkid_len, mac_len;
	unsigned char *pmkid;
	unsigned char *mac;
	dbus_uint32_t action;
	DBusError derror;

	dbus_error_init(&derror);

	if (dbus_message_get_args(
		message, &derror,
		DBUS_TYPE_UINT32, &action,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pmkid, &pmkid_len,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &mac, &mac_len,
		DBUS_TYPE_INVALID) == FALSE)
	{
		DLOG_ERR("Failed to parse set_pmksa request: %s",
				derror.message);
		dbus_error_free(&derror);
		goto param_err;
	}

	if (action != IW_PMKSA_ADD) {
		DLOG_ERR("Invalid action");
		goto param_err;
	}

	if (pmkid == NULL || pmkid_len != WLANCOND_PMKID_LEN || mac == NULL
			|| mac_len != ETH_ALEN) {
		DLOG_ERR("Invalid arguments");
		goto param_err;
	}

	add_to_pmksa_cache(pmkid, mac);

	print_mac(WLANCOND_PRIO_LOW, "PMKSA added successfully for address:",
			mac);

	reply = new_dbus_method_return(message);
	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;

param_err:
	if (reply == NULL) {
		DLOG_DEBUG("Parameter error in set_pmksa");
		reply = new_dbus_error(message, DBUS_ERROR_INVALID_ARGS);
	}
	send_and_unref(connection, reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

/**
   Set powersave D-BUS request.
   @param message DBUS message.
   @param connection DBUS connection.
   @return status.
*/
static DBusHandlerResult set_powersave_request(DBusMessage    *message,
		DBusConnection *connection) {

	DBusMessage *reply = NULL;
	int sock;
	DBusError error;
	dbus_bool_t onoff;

	sock = socket_open();

	dbus_error_init(&error);

	if (dbus_message_get_args(message, &error,
				DBUS_TYPE_BOOLEAN, &onoff,
				DBUS_TYPE_INVALID) == FALSE) {
		DLOG_ERR("Failed to parse message: %s",
				error.message);
		dbus_error_free(&error);

		send_invalid_args(connection, message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Powersave can be allowed only when we are properly connected
	   or when the entity asking for connection wants powersave despite of
	   the state */
	if (onoff == TRUE) {
		if (get_wlan_state() == WLAN_NOT_INITIALIZED) {
			set_wlan_state(WLAN_NOT_INITIALIZED,
					NO_SIGNAL, FORCE_YES);
		} else if (get_wlan_state() != WLAN_NO_ADDRESS ||
				(connect_name_cache != NULL &&
				 strcmp(dbus_message_get_sender(message),
					 connect_name_cache) == 0)) {
			if (set_power_state(powersave, sock) == FALSE) {
				DLOG_ERR("Setting powersave failed");
				// Not fatal
			}
		}
	} else {
		// Go to full power
		if (set_power_state(WLANCOND_POWER_ON, sock) == FALSE) {
			DLOG_ERR("Setting powersave failed");
			// Not fatal
		}
	}

	DLOG_DEBUG("WLAN powersave %s", onoff==TRUE?"on":"off");

	reply = new_dbus_method_return(message);
	send_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

/**
    WPA IE callback.
    @param pending Pending DBUS message.
    @param user_data Callback data.
    @return status
*/
static void wpa_ie_push_cb(DBusPendingCall *pending,
		void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	//DLOG_DEBUG("WPA IE callback");

	dbus_error_init (&error);

	reply = dbus_pending_call_steal_reply(pending);

	if (dbus_set_error_from_message(&error, reply)) {

		DLOG_DEBUG("EAP WPA IE push call result:%s", error.name);

		dbus_error_free(&error);

		set_wlan_state(WLAN_NOT_INITIALIZED,
				DISCONNECTED_SIGNAL,
				FORCE_YES);
	}

	if (reply)
		dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
}

/**
   WPA IE D-BUS push.
   @param ap_mac_addr Access point MAC address.
   @param ap_wpa_ie Pointer to access point WPA IE.
   @param ap_wpa_ie_len Access point WPA IE length.
   @param authentication_type authentication type.
   @return status.
*/
int wpa_ie_push(unsigned char* ap_mac_addr, unsigned char* ap_wpa_ie,
		int ap_wpa_ie_len, char* ssid, int ssid_len,
		unsigned int authentication_type) {

	DBusMessage *msg;
	DBusPendingCall *pending;

	if (authentication_type != EAP_AUTH_TYPE_WFA_SC) {
		if (wlan_status.wpa_ie.ie_len == 0 || ap_wpa_ie == NULL ||
				ssid == NULL) {
			DLOG_ERR("WPA IE / SSID (%s) not valid", ssid);
			return -1;
		}
	}

	msg = dbus_message_new_method_call(
			EAP_SERVICE,
			EAP_REQ_PATH,
			EAP_REQ_INTERFACE,
			EAP_WPA_IE_PUSH_REQ);

	if (msg == NULL) {
		return -1;
	}

	append_dbus_args(
			msg,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&wlan_status.wpa_ie.ie, wlan_status.wpa_ie.ie_len,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ap_wpa_ie,
			ap_wpa_ie_len,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&ssid, ssid_len,
			DBUS_TYPE_UINT32, &wlan_status.pairwise_cipher,
			DBUS_TYPE_UINT32, &wlan_status.group_cipher,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&ap_mac_addr, ETH_ALEN,
			DBUS_TYPE_UINT32, &authentication_type,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(get_dbus_connection(),
				msg, &pending, -1))
		die("Out of memory");

	if (!dbus_pending_call_set_notify (pending, wpa_ie_push_cb, NULL, NULL))
		die("Out of memory");

	dbus_message_unref(msg);

	return 0;
}
/**
   WPA MIC failure event D-BUS request.
   @param key_type Key type, Unicast/Broadcast key.
   @param is_fatal Error is fatal if true.
   @return status.
*/
int wpa_mic_failure_event(dbus_bool_t key_type, dbus_bool_t is_fatal) {
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr;

	msg = dbus_message_new_method_call(
			EAP_SERVICE,
			EAP_REQ_PATH,
			EAP_REQ_INTERFACE,
			EAP_WPA_MIC_FAILURE_REQ);

	if (msg == NULL) {
		return -1;
	}

	append_dbus_args(msg,
			DBUS_TYPE_BOOLEAN, &key_type,
			DBUS_TYPE_BOOLEAN, &is_fatal,
			DBUS_TYPE_INVALID);

	dbus_error_init(&derr);

	reply = dbus_connection_send_with_reply_and_block(
			get_dbus_connection(), msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		DLOG_ERR("EAP returned error: %s", derr.name);

		dbus_error_free(&derr);
		if (reply)
			dbus_message_unref(reply);
		return -1;
	}

	dbus_message_unref(reply);

	return 0;
}
/**
   Associate EAP D-BUS request.
   @return status.
*/
int associate_supplicant(void) {
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError derr;

	msg = dbus_message_new_method_call(
			EAP_SERVICE,
			EAP_REQ_PATH,
			EAP_REQ_INTERFACE,
			EAP_ASSOCIATE_REQ);

	if (msg == NULL) {
		return -1;
	}

	dbus_error_init(&derr);

	reply = dbus_connection_send_with_reply_and_block(
			get_dbus_connection(), msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		DLOG_ERR("EAP returned error: %s", derr.name);

		dbus_error_free(&derr);
		if (reply)
			dbus_message_unref(reply);
		return -1;
	}

	dbus_message_unref(reply);

	return 0;
}
/**
    Disassociate callback.
    @param pending Pending DBUS message.
    @param user_data Callback data.
    @return status
*/
static void disassociate_cb(DBusPendingCall *pending,
		void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	dbus_error_init (&error);

	reply = dbus_pending_call_steal_reply(pending);

	if (dbus_set_error_from_message(&error, reply)) {

		DLOG_DEBUG("EAP disassociate call result:%s", error.name);

		dbus_error_free(&error);
	}

	if (reply)
		dbus_message_unref(reply);
	dbus_pending_call_unref(pending);
}

/**
   Disassociate EAP D-BUS request.
   @return status.
*/
int disassociate_eap(void) {
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call(
			EAP_SERVICE,
			EAP_REQ_PATH,
			EAP_REQ_INTERFACE,
			EAP_DISASSOCIATE_REQ);

	if (msg == NULL) {
		return -1;
	}

	if (!dbus_connection_send_with_reply(get_dbus_connection(),
				msg, &pending, -1))
		die("Out of memory");

	if (!dbus_pending_call_set_notify (pending, disassociate_cb, NULL,
				NULL))
		die("Out of memory");

	dbus_message_unref(msg);

	return 0;
}

/**
 * Checks the PMKSA cache status from the EAP daemon.
 *
 * @param own_mac                   Our own mac address.
 * @param own_mac_len               The length of the address(usually ETH_ALEN)
 * @param bssid                     The mac address of the access point.
 * @param bssid_len                 The length of the address(usually ETH_ALEN)
 * @param authentication_type       The authentication type used.
 * @param pairwise_key_cipher_suite The cipher suite to be used
 * @param group_key_cipher_suite    The cipher suite to be used
 * @param status                    TRUE if the key exists in the cache. On
 *                                  errors this value won't be set.
 * @return                          0 on success, non-zero on errors.
 */
int check_pmksa_cache(unsigned char* own_mac, int own_mac_len,
		      unsigned char* bssid, int bssid_len,
		      uint32_t authentication_type,
		      uint32_t pairwise_key_cipher_suite,
		      uint32_t group_key_cipher_suite,
		      int *status)
{
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	dbus_bool_t found;

	dbus_error_init (&error);

	msg = dbus_message_new_method_call(
			EAP_SERVICE,
			EAP_REQ_PATH,
			EAP_REQ_INTERFACE,
			EAP_CHECK_PMKSA_CACHE_REQ);

	if (msg == NULL)
		return -1;

	if (dbus_message_append_args(
		msg,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &own_mac, own_mac_len,
		DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bssid, bssid_len,
		DBUS_TYPE_UINT32, &authentication_type,
		DBUS_TYPE_UINT32, &pairwise_key_cipher_suite,
		DBUS_TYPE_UINT32, &group_key_cipher_suite,
		DBUS_TYPE_INVALID) == FALSE)
	{
		DLOG_ERR("Unable to add args to dbus method call.");
		dbus_message_unref(msg);
		return -1;
	}

	reply = dbus_connection_send_with_reply_and_block(
			get_dbus_connection(), msg, -1, &error);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&error)) {
		DLOG_ERR("EAP returned error: %s", error.message);
		dbus_error_free(&error);

		goto error;
	}

	if (!dbus_message_get_args(reply, &error,
				DBUS_TYPE_BOOLEAN, &found,
				DBUS_TYPE_INVALID))
	{
		DLOG_ERR("Error parsing the return value: %s", error.message);
		if (dbus_error_is_set(&error))
			dbus_error_free(&error);

		goto error;
	}

	dbus_message_unref(reply);

	*status = found;

	return 0;

error:
	if(reply)
		dbus_message_unref(reply);

	return -1;
}

#ifdef ENABLE_CALL_TYPE_CHECKING
/**
 * Sets the call type. This might also change the power save mode.
 *
 * @param type The call type as a string.
 */
void set_call_type(const char *type)
{
	guint new_type;

	if (!type || !strcmp(type, "none"))
		new_type = WLANCOND_CALL_NONE;
	else if (!strcmp(type, "skype"))
		new_type = WLANCOND_CALL_VOIP;
	else if (!strcmp(type, "cellular"))
		new_type = WLANCOND_CALL_CELL;
	else {
		DLOG_DEBUG("Unknown call type: %s", type);
		new_type = WLANCOND_CALL_UNKNOWN;
	}

	if (new_type == wlan_status.call_state)
		return;

	DLOG_DEBUG("Switching call type to %i (%s)", new_type, type);

	wlan_status.call_state = new_type;

	/* Redetermine the power state */
	set_power_state(wlan_status.requested_power, socket_open());
}

/**
 * Parses the context from the policy actions method params. This sets the
 * call type according to the call_audio_type variable.
 *
 * @param actit Dbus message iterator to the context.
 * @return TRUE on success, FALSE otherwise.
 */
int context_parser(DBusMessageIter *actit)
{
	DBusMessageIter  cmdit;
	DBusMessageIter  argit;
	DBusMessageIter  valit;
	char            *argname;
	char            *argval;
	char            *variable;
	char            *value;

	do {
		variable = value = NULL;

		dbus_message_iter_recurse(actit, &cmdit);

		do {
			if (dbus_message_iter_get_arg_type(&cmdit) !=
					DBUS_TYPE_STRUCT)
				return FALSE;

			dbus_message_iter_recurse(&cmdit, &argit);

			if (dbus_message_iter_get_arg_type(&argit) !=
					DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&argit, (void *)&argname);

			if (!dbus_message_iter_next(&argit))
				return FALSE;

			if (dbus_message_iter_get_arg_type(&argit) !=
					DBUS_TYPE_VARIANT)
				return FALSE;

			dbus_message_iter_recurse(&argit, &valit);

			if (dbus_message_iter_get_arg_type(&valit) !=
					DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&valit, (void *)&argval);

			if (!strcmp(argname, "variable")) {
				variable = argval;
			}
			else if (!strcmp(argname, "value")) {
				value = argval;
			}

			if (!strcmp(variable, "call_audio_type"))
				set_call_type(value);

		} while (dbus_message_iter_next(&cmdit));

	} while (dbus_message_iter_next(actit));

	return TRUE;
}

/**
 * Handles policy actions method call. This parses the context out of the
 * paramteres and calls the context_parser for them.
 */
void handle_policy_actions(DBusMessage *msg)
{
	dbus_uint32_t    txid;
	char            *actname;
	DBusMessageIter  msgit;
	DBusMessageIter  arrit;
	DBusMessageIter  entit;
	DBusMessageIter  actit;
	int              success = TRUE;

	dbus_message_iter_init(msg, &msgit);

	if (dbus_message_iter_get_arg_type(&msgit) != DBUS_TYPE_UINT32)
		return;

	dbus_message_iter_get_basic(&msgit, (void *)&txid);

	if (!dbus_message_iter_next(&msgit) ||
			dbus_message_iter_get_arg_type(&msgit) !=
			DBUS_TYPE_ARRAY) {
		success = FALSE;
		goto out;
	}

	dbus_message_iter_recurse(&msgit, &arrit);

	do {
		if (dbus_message_iter_get_arg_type(&arrit) !=
				DBUS_TYPE_DICT_ENTRY) {
			success = FALSE;
			continue;
		}

		dbus_message_iter_recurse(&arrit, &entit);

		do {
			if (dbus_message_iter_get_arg_type(&entit) !=
					DBUS_TYPE_STRING) {
				success = FALSE;
				continue;
			}

			dbus_message_iter_get_basic(&entit, (void *)&actname);

			if (!dbus_message_iter_next(&entit) ||
					dbus_message_iter_get_arg_type(&entit)
					!= DBUS_TYPE_ARRAY) {
				success = FALSE;
				continue;
			}

			dbus_message_iter_recurse(&entit, &actit);

			if (dbus_message_iter_get_arg_type(&actit) !=
					DBUS_TYPE_ARRAY) {
				success = FALSE;
				continue;
			}

			if (!strcmp(actname, "com.nokia.policy.context"))
				success &= context_parser(&actit);

		} while (dbus_message_iter_next(&entit));

	} while (dbus_message_iter_next(&arrit));

out:
	if (!success)
		DLOG_DEBUG("Failed to parse the policy actions message.");
}
#endif


typedef DBusHandlerResult (*handler_func)(DBusMessage *message,
		DBusConnection *connection);

typedef struct {
	const char *interface;
	const char *name;
	handler_func func;
} method_handler_t;

static method_handler_t handlers[] = {
	{ WLANCOND_REQ_INTERFACE, WLANCOND_SETTINGS_AND_CONNECT_REQ,
		settings_and_connect_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_SCAN_REQ, scan_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_STATUS_REQ, status_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_INTERFACE_REQ, interface_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_CONNECTION_STATUS_REQ,
		connection_status_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_SET_PMKSA_REQ, set_pmksa_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_SET_POWERSAVE_REQ,
		set_powersave_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_DISCONNECT_REQ, disconnect_request},
	{ WLANCOND_REQ_INTERFACE, WLANCOND_DISASSOCIATE_REQ,
		disassociate_request},
	{ NULL }
};

/**
    Generic handler for D-Bus requests.
    @param message DBUS message.
    @param connection DBUS connection.
    @return status.
*/
DBusHandlerResult wlancond_req_handler(DBusConnection     *connection,
		DBusMessage        *message,
		void               *user_data)
{
	method_handler_t *handler;

	DLOG_DEBUG("Received %s.%s",
			dbus_message_get_interface(message),
			dbus_message_get_member(message));


#ifdef USE_MCE_MODE
	if (dbus_message_is_signal(message,
				MCE_SIGNAL_IF,
				MCE_DEVICE_MODE_SIG)) {
		return mode_change_dbus(message);
	}
#ifdef ACTIVITY_CHECK
	if (dbus_message_is_signal(message,
				MCE_SIGNAL_IF,
				MCE_INACTIVITY_SIG)) {
		return activity_check_dbus(message);
	}
#endif
#endif
	if (dbus_message_is_signal(message,
				ICD_DBUS_INTERFACE,
				ICD_STATUS_CHANGED_SIG))
		return icd_check_signal_dbus(message);

	if (dbus_message_is_signal(message,
				PHONE_NET_DBUS_INTERFACE,
				PHONE_REGISTRATION_STATUS_CHANGE_SIG))
		return csd_check_signal_dbus(message);

	if (dbus_message_is_signal (message,
				BLUEZ_ADAPTER_SERVICE_NAME,
				BLUEZ_ADAPTER_PROPERTY_CHANGED_SIG))
		return bluez_check_adapter_signal_dbus(message);

	if (dbus_message_is_signal (message,
				BLUEZ_HEADSET_SERVICE_NAME,
				BLUEZ_HEADSET_PROPERTY_CHANGED_SIG))
		return bluez_check_headset_signal_dbus(message);

	if (dbus_message_is_signal (message,
				BLUEZ_AUDIOSINK_SERVICE_NAME,
				BLUEZ_AUDIOSINK_PROPERTY_CHANGED_SIG))
		return bluez_check_headset_signal_dbus(message);

#ifdef ENABLE_CALL_TYPE_CHECKING
	if (dbus_message_is_signal(message, POLICY_SERVICE_NAME,
				POLICY_ACTIONS_SIG)) {
		handle_policy_actions(message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
#endif

	/* The rest should be just method calls */
	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_METHOD_CALL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	for (handler = handlers; handler->interface != NULL; handler++) {
		if (dbus_message_is_method_call(message,
					handler->interface,
					handler->name)) {
			DLOG_DEBUG("Received %s", handler->name);
			return handler->func(message, connection);
		}
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable wlancond_req_vtable = {
	.message_function    = wlancond_req_handler,
	.unregister_function = NULL
};


/**
    Create bindings for D-BUS handlers.
    @param connection DBUS connection.
*/
void init_dbus_handlers(DBusConnection *connection) {
	dbus_bool_t ret;
	ret = dbus_connection_register_object_path(connection,
			WLANCOND_REQ_PATH,
			&wlancond_req_vtable,
			NULL);
	if (ret == FALSE) {
		DLOG_ERR("dbus_connection_register_object_path failed");
        }
#ifdef USE_MCE_MODE
	if (!add_mode_listener(connection)) {
		DLOG_ERR("Adding mode listener failed");
	}
#endif
	if (!add_icd_listener(connection)) {
		DLOG_ERR("Adding icd listener failed");
	}

	if (!add_csd_listener(connection)) {
		DLOG_ERR("Adding csd listener failed");
	}
	if (!add_bluez_listener(connection)) {
		DLOG_ERR("Adding Bluez listener failed");
	}
}

/**
   Destroy D-BUS handlers.
   @param connection DBUS connection.
*/
void destroy_dbus_handlers(DBusConnection *connection) {
	dbus_connection_unregister_object_path(connection, WLANCOND_REQ_PATH);
}
