/**
  @file dbus-handler.c

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

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
#include <osso-log.h>
#include <gconf/gconf-client.h>
#include <osso-ic-dbus.h>

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

#define WLANCOND_SHUTDOWN_DELAY 4000 //4s
#define WLANCOND_CONNECT_TIMEOUT 10000 //10s

/* Interface name cache */
char *ifname = NULL;

/* Save DBUS names */
static char *scan_name_cache = NULL;
static char *connect_name_cache = NULL;

/* Selected SSID is saved */
static gchar *selected_ssid = NULL;

/* Scan SSID is saved */
static gchar *scan_ssid = NULL;

gchar own_mac[ETH_ALEN];
static int wlan_socket = -1;

static struct wlan_status_t wlan_status;
static gboolean _flight_mode = FALSE;
static gboolean _cover_closed = FALSE;
static gboolean power_down_after_scan = FALSE;
static gboolean scan_threshold_supported = FALSE;
static dbus_bool_t saved_inactivity = FALSE;

/* Timer IDs */
static guint wlan_if_down_timer_id = 0;
static guint wlan_connect_timer_id = 0;

/* This is the desired powersave and can be set from DBUS when connecting */
static guint powersave = WLANCOND_SHORT_CAM;

#ifdef USE_MCE_COVER
static const char ignore_cover_sgn[] = { DBUS_TYPE_BOOLEAN,
                                         DBUS_TYPE_INVALID };
static gboolean ignore_cover_events = FALSE;
#define SYSFS_COVER_FILE "/sys/devices/platform/gpio-switch/prot_shell/cover_switch"
#define OPEN_STR "open"
#endif

#define WLAN_PREFIX_STR "wlan"

/** 
 * Helper function for socket opening 
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
 * Helper function for initializing the iwreq
 */
void init_iwreq(struct iwreq* req) 
{
        memset(req, 0, sizeof(struct iwreq));
        strncpy(req->ifr_name, ifname, IFNAMSIZ);
}

static gboolean cover_closed(void)
{
#ifdef USE_MCE_COVER
        if (ignore_cover_events)
                return FALSE;
#endif  
        return _cover_closed;
}

#ifdef USE_MCE_COVER
/**
 * Reads the state file 
 */
static void _read_cover_state(void) 
{
        gchar* buf = NULL;
        GError *err = NULL;
        
        g_file_get_contents(SYSFS_COVER_FILE, &buf, NULL, &err);
        if (err != NULL) {
                DLOG_ERR("couldn't read cover state file %s",
                         SYSFS_COVER_FILE);
                g_error_free(err);
                return; /* buf is not allocated */
        }
        if (strncmp(buf, OPEN_STR, strlen(OPEN_STR)) == 0) {
                _cover_closed = FALSE;
        } else {
                set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, FORCE_YES);
                _cover_closed = TRUE;
        }
        DLOG_DEBUG("WLAN cover state changed to \"%s\"", 
                   _cover_closed == FALSE ? "Open":"Closed");
        g_free(buf);
}
/**
 * Reads the state file 
 */
static void reread_cover_state(void) 
{
        if (ignore_cover_events)
                return;

        _read_cover_state();
}
#endif

/**
 * Initialises the cover state.
 * */
void init_cover_state(void)
{
#ifdef USE_MCE_COVER
        reread_cover_state();
#endif
}

static int get_own_mac(void) 
{
        struct ifreq req;
        int sock;
        
        sock = socket_open();
        
        memset(&req , 0, sizeof(req));
        memcpy(req.ifr_name, ifname, IFNAMSIZ);
        
        if (ioctl(sock, SIOCGIFHWADDR, &req) < 0)
        {
                return -1;
        }
        
        memcpy(own_mac, req.ifr_hwaddr.sa_data, ETH_ALEN);
        
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
 
        client = gconf_client_get_default();
        if (client == NULL) {
                return -1;
        }

        gconf_value = gconf_client_get(client, path, &error); 

        if (error != NULL) {
                DLOG_ERR("Could not get setting:%s, error:%s", path, 
                         error->message);
                
                g_clear_error(&error);
                g_object_unref(client);
                return -1;
        }
        g_object_unref(client);
        
        if (gconf_value == NULL) {
                return -1;
        }
        if (gconf_value->type == GCONF_VALUE_INT) {
                gint value = gconf_value_get_int(gconf_value);
                DLOG_DEBUG("User selected value: %d", value);
                gconf_value_free(gconf_value);
                return value;
        }
        
        gconf_value_free(gconf_value);
        return -1;
}

static void set_dma_threshold(void) 
{
        struct iwreq req;
        int sock, dma_threshold;

        init_iwreq(&req);

        sock = socket_open();

        dma_threshold = get_gconf_int(DMA_THRESHOLD_GCONF_PATH);

        if (dma_threshold < 0)
                dma_threshold = WLANCOND_DEFAULT_DMA_THRESHOLD;

        req.u.mode = dma_threshold;
        
        if (ioctl(sock, SIOCIWFIRSTPRIV + 20, &req) < 0) {
                DLOG_ERR("set DMA failed");
                return;
        }
        //DLOG_DEBUG("Set DMA threshold to %d", dma_threshold);
}

#define MCE_DEVLOCK_FILENAME "/var/run/mce/call"
/** 
    Check if call is going 
    @return TRUE if call going.
*/
static gboolean call_going(void) 
{
        GIOChannel *iochan = NULL;
	GIOStatus iostatus;
	GError *error = NULL;
        gchar* buf;
        gboolean ret = TRUE;

	if ((iochan = g_io_channel_new_file(MCE_DEVLOCK_FILENAME,
					    "r", &error)) == NULL) {
		DLOG_DEBUG("Cannot open for reading: %s", error->message);
		g_clear_error(&error);
                
		return ret;
	}
        
	g_clear_error(&error);
        
        buf = g_malloc0(4);
        
        iostatus = g_io_channel_read_chars(iochan, buf, sizeof(buf),
                                           NULL, &error);
        
	if (iostatus != G_IO_STATUS_NORMAL)
		DLOG_DEBUG("Cannot read: %s", error->message);
        
	g_clear_error(&error);
        
	iostatus = g_io_channel_shutdown(iochan, TRUE, &error);
        
	if (iostatus != G_IO_STATUS_NORMAL)
		DLOG_DEBUG("Cannot close: %s", error->message);
        
        if (strncmp(buf, "no", 2) == 0)
        {
                ret = FALSE;
        }
        
        g_free(buf);
	g_clear_error(&error);
	g_io_channel_unref(iochan);
        
	return ret;
}

static void set_bgscan_params(gboolean activity) 
{
        struct iwreq req;
        int sock, bgscan_threshold;
        
        if (scan_threshold_supported == FALSE)
                return;
        
        init_iwreq(&req);

        sock = socket_open();

        bgscan_threshold = get_gconf_int(BGSCAN_THRESHOLD_GCONF_PATH);

        if (bgscan_threshold < 0) {
                if (activity == TRUE && call_going() == FALSE)
                        bgscan_threshold = WLANCOND_DEFAULT_IDLE_BGSCAN_THRESHOLD;
                else
                        bgscan_threshold = WLANCOND_DEFAULT_BGSCAN_THRESHOLD;
        }
                
        req.u.mode = -bgscan_threshold;
        
        if (ioctl(sock, SIOCIWFIRSTPRIV + 4, &req) < 0) {
                DLOG_ERR("set bgscan failed");
        }
        //DLOG_DEBUG("Set bgscan_threshold to %d", -bgscan_threshold);

        return;
}

static void set_bgscan_interval(void) 
{
        struct iwreq req;
        int sock, bgscan_interval;
        
        if (scan_threshold_supported == FALSE)
                return;

        bgscan_interval = get_gconf_int(BGSCAN_INTERVAL_GCONF_PATH);
        
        if (bgscan_interval < 0 || bgscan_interval >= G_MAXUINT16) {
                // No user set interval, don't do anything
                return;
        }

        init_iwreq(&req);

        sock = socket_open();
        
        req.u.mode = bgscan_interval;
        
        if (ioctl(sock, SIOCIWFIRSTPRIV + 2, &req) < 0) {
                DLOG_ERR("set bgscan failed");
        }
        DLOG_DEBUG("Set bgscan_interval to %d", bgscan_interval);
}

void update_own_ie(unsigned char* wpa_ie, guint wpa_ie_len) 
{
        if (wlan_status.wpa_ie.ie != NULL) {
                g_free(wlan_status.wpa_ie.ie);
        }
        
        wlan_status.wpa_ie.ie = wpa_ie;
        wlan_status.wpa_ie.ie_len =  wpa_ie_len;
        wlan_status.wpa_ie.ie_valid = IE_VALID;
}
/**
   Get encryption info.
   @return status.
 */
int get_encryption_info(void) 
{
        int auth_status = 0;

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
 * Helper function for initializing handler structs
 */
int init_dbus_handler(void)
{
        int sock, count, i;
        iwprivargs *priv;
        
        memset(&wlan_status, 0, sizeof(wlan_status));

        if (get_own_mac() < 0) {
                DLOG_ERR("Could not get own MAC address");
                return -1; 
        }

        set_dma_threshold();

        sock = socket_open();

        count = iw_get_priv_info(sock, ifname, &priv);

        if (count > 0)
        {
                for (i = 0; i < count; i++)
                        if (priv[i].name[0] != '\0') {
                                if (strcmp(priv[i].name, "set_scanthres") == 0) 
                                {
                                        scan_threshold_supported = TRUE;
                                        break;
                                }
                        }
        }
        if (priv)
                free(priv);
        
        return 0;
}
/**
   Helper function for cleaning handler.
*/
int clean_dbus_handler(void)
{
        if (ifname != NULL)
                g_free(ifname);
        if (wlan_socket > 0)
                close(wlan_socket);
        return 0;
}
/**
   Helper function for mode change.
   @param mode New mode.
*/
void mode_change(const char *mode) {

        DLOG_DEBUG("WLAN flight mode changed to \"%s\"", mode);
        
        if (g_str_equal(mode, "flight")) {
                set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, FORCE_YES);
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
 * Helper function for mode change
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

        set_bgscan_params(inactivity);
        set_power_state(powersave, sock);     
}

/**
 * Helper function for determining inactivity
 */
static gboolean get_inactivity_status(void) 
{
        return saved_inactivity;
}
#endif

static DBusHandlerResult icd_check_signal_dbus(DBusMessage *message) {

        char *icd_name;
        char *icd_type;
        char *icd_state;
        char *icd_disconnect_reason;
        DBusError dbus_error;
        int sock;

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
                
                sock = socket_open();
                        
                DLOG_DEBUG("Going to power save");
                        
                if (set_power_state(powersave, sock) == FALSE) {
                        DLOG_ERR("Failed to set power save");
                }
        }
        //DLOG_DEBUG("Handled icd signal, icd_state:%s", icd_state);
        
        return DBUS_HANDLER_RESULT_HANDLED;
}

static gboolean in_flight_mode(void) {
        return _flight_mode;
}

static void clean_ssid(void) 
{
        if (selected_ssid != NULL) {
                g_free(selected_ssid);
                selected_ssid = NULL;
        }
        if (scan_ssid != NULL) {
                g_free(scan_ssid);
                scan_ssid = NULL;
        }
}

void remove_connect_timer(void) 
{
     if (wlan_connect_timer_id) {
             g_source_remove(wlan_connect_timer_id);
             wlan_connect_timer_id = 0;
     }
}

static gboolean wlan_connect_timer_cb(void* data) 
{
        wlan_connect_timer_id = 0;
        
        if (get_wlan_state() == WLAN_INITIALIZED && !get_mic_status()) {
                DLOG_DEBUG("Association timeout");
                set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, 
                               FORCE_YES);
                return FALSE;
        }
        
        //DLOG_DEBUG("Association OK");        

        return FALSE;
}

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
    Helper function for setting new wlan state 
    @param new_state New state for WLAN.
    @param send_signal Should signal be sent.
    @param force If shutdown is forced or not.
*/
void set_wlan_state(int new_state, int send_signal, force_t force) 
{
        int sock;
        guint shutdown_delay = WLANCOND_SHUTDOWN_DELAY;

#ifdef DEBUG
        static char *status_table[] = 
                {
                        (char*)"WLAN_NOT_INITIALIZED",
                        (char*)"WLAN_INITIALIZED",
                        (char*)"WLAN_INITIALIZED_FOR_SCAN",
                        (char*)"WLAN_NO_ADDRESS",
                        (char*)"WLAN_CONNECTED"
                };
#endif        
        
        if (new_state == WLAN_NOT_INITIALIZED) {

                set_scan_state(SCAN_NOT_ACTIVE);
                
                if (get_wlan_state() != WLAN_NOT_INITIALIZED)
                        clear_wpa_mode();
                clean_ssid();

                wlan_status.mode = 0;

                /* Remove association timer */
                remove_connect_timer();

                /* Check the shutdown delay */
                if (get_mic_status()) {
                        shutdown_delay = MIC_FAILURE_TIMEOUT;
                }
                
                if (force == FORCE_MAYBE) {
                        if (get_mic_status()) {
                                // MIC failure going on
                                force = FORCE_NO;
                        } else {
                                force = FORCE_YES;
                        }
                }               
                
                sock = socket_open();
                
                if (force == FORCE_YES) {

                        // Remove shutdown timer if exists
                        if (wlan_if_down_timer_id != 0) {        
                                g_source_remove(wlan_if_down_timer_id);
                                wlan_if_down_timer_id = 0;
                        }
                        
                        if (set_interface_state(sock, CLEAR, IFF_UP)<0) {
                                DLOG_ERR("Could not set interface down");
                                return;
                        }
                        
                } else {
                        
                        DLOG_DEBUG("Delaying interface shutdown");
                        
                        /* Removed, does not reduce power consumption
                           when not connected */
                        //set_power_state(WLANCOND_FULL_POWERSAVE, sock);

                        if (wlan_if_down_timer_id != 0) {
                                DLOG_DEBUG("Already delaying...");
                                g_source_remove(wlan_if_down_timer_id);
                        }
                        
                        wlan_if_down_timer_id = g_timeout_add(
                                shutdown_delay,
                                wlan_if_down_cb,
                                NULL); 
                        
                }
                
                if (send_signal == DISCONNECTED_SIGNAL)
                        disconnected_signal();       
                
        }
        DLOG_DEBUG("Wlancond state change, old_state: %s, new_state: %s", 
                   status_table[wlan_status.state], status_table[new_state]);
        wlan_status.state = new_state;
}

/** 
    Helper function for getting the wlan state.
    @return state.
*/
int get_wlan_state(void) 
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
int get_scan_state(void) 
{
        return wlan_status.scan;
}
/** 
    Helper function for getting the wlan mode.
    @return mode.
*/
int get_mode(void) 
{
        return wlan_status.mode;
}

/**
   Set WLAN power state.
   @param state New power state.
   @param sock socket.
   @return status.
*/
gboolean set_power_state(guint new_state, int sock) 
{
        struct iwreq req;
        gint sleep_timeout;
        
        if (new_state == WLANCOND_SHORT_CAM && get_inactivity_status() == TRUE)
                new_state = WLANCOND_VERY_SHORT_CAM;
        
        if (wlan_status.power == new_state) {
                return TRUE;
        }

        init_iwreq(&req);

        switch (new_state) {
            case WLANCOND_POWER_ON:
                    req.u.power.disabled = 1;
                    break;
            case WLANCOND_LONG_CAM:
                    req.u.power.flags = IW_POWER_MULTICAST_R;
                    req.u.power.value = WLANCOND_LONG_CAM_TIMEOUT;
                    break;
            case WLANCOND_SHORT_CAM:
                    req.u.power.flags = IW_POWER_MULTICAST_R;
                    sleep_timeout = get_gconf_int(SLEEP_GCONF_PATH);
                    if (sleep_timeout < 0)
                            sleep_timeout = WLANCOND_DEFAULT_SLEEP_TIMEOUT;
                    req.u.power.value = sleep_timeout;
                    break;
            case WLANCOND_VERY_SHORT_CAM:
                    req.u.power.flags = IW_POWER_MULTICAST_R;
                    sleep_timeout = get_gconf_int(INACTIVE_SLEEP_GCONF_PATH);
                    if (sleep_timeout < 0)
                            sleep_timeout = WLANCOND_VERY_SHORT_CAM_TIMEOUT;
                    req.u.power.value = sleep_timeout;
                    break;
            default:
                    req.u.power.flags = IW_POWER_ALL_R;
                    break;
        }
        
        if (ioctl(sock, SIOCSIWPOWER, &req) < 0) {
                DLOG_ERR("set power failed, state:%d", new_state);
                return FALSE;
        }
        
        //DLOG_DEBUG("Power state set to %d", new_state);
        wlan_status.power = new_state;
        
        return TRUE;
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
                DLOG_DEBUG("Ifname %s does not support wireless extensions\n", 
                           name);
        } else {
                //DLOG_DEBUG("Found interface %s", name);
                if (g_str_has_prefix(name, WLAN_PREFIX_STR)) {
                        DLOG_DEBUG("Found WLAN interface %s", name);
                        if (ifname != NULL)
                                g_free(ifname);
                        ifname = g_malloc(IFNAMSIZ+1);
                        strncpy(ifname, name, IFNAMSIZ);
                        ifname[IFNAMSIZ] = '\0';
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
        int sock;
        
        sock = socket_open();
        
        iw_enum_devices(sock, &set_we_name, NULL, 0);

        if (strnlen(ifname, IFNAMSIZ) < 2)
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
        
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
                DLOG_ERR("Could not get interface %s flags\n", ifname); 
                return -1;
        }
        if (dir == SET) {
                ifr.ifr_flags |= flags;
        } else {
                ifr.ifr_flags &= ~flags;
        }
        
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
                DLOG_ERR("Could not set interface %s flags\n", ifname); 
                return -1;
        }
        
        DLOG_DEBUG("%s is %s", ifname, dir == SET ? "UP":"DOWN");

        return 0;
}

/** 
    Set tx power level.
    @param power Power level.
    @param sock socket.
    @param req iwrequest structure.
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

static guint get_auth_mode(guint encryption, guint wpa2_mode) 
{
        if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_PSK) {
                if (wpa2_mode)
                        return IW_AUTH_WPA2_PSK;
                else
                        return IW_AUTH_WPA_PSK;
        }
        if ((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WPA_EAP) {
                if (wpa2_mode)
                        return IW_AUTH_WPA2;
                else
                        return IW_AUTH_WPA;
        }
        
        return IW_AUTH_NOWPA;
}

static guint get_encryption_mode(guint32 encryption) 
{
        if ((encryption & WLANCOND_ENCRYPT_ALG_MASK) == WLANCOND_WPA_TKIP)
                return CIPHER_SUITE_TKIP;
        if ((encryption & WLANCOND_ENCRYPT_ALG_MASK) == WLANCOND_WPA_AES)
                return CIPHER_SUITE_CCMP;
        return CIPHER_SUITE_NONE;
}

static int update_algorithms(guint32 encryption) 
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
        } else {
                DLOG_ERR("Not supported encryption %08x", encryption);
                return -1;
        }       

        return 0;
}

void clear_wpa_mode(void) 
{
        if (wlan_status.wpa_ie.ie != NULL) {
                g_free(wlan_status.wpa_ie.ie);
                wlan_status.wpa_ie.ie = NULL;
        }
                
        wlan_status.wpa_ie.ie_valid = IE_NOT_VALID;
        wlan_status.pairwise_cipher = CIPHER_SUITE_NONE;
        wlan_status.group_cipher = CIPHER_SUITE_NONE;
        
        set_encryption_method(wlan_status.pairwise_cipher);
        
}

gboolean get_wpa_mode(void)
{
        if (wlan_status.pairwise_cipher & CIPHER_SUITE_TKIP ||
            wlan_status.pairwise_cipher & CIPHER_SUITE_CCMP) {
                return TRUE;
        }
        return FALSE;
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
        struct iwreq req;
        dbus_int32_t mode, encryption, power_level, default_key;
        dbus_uint32_t adhoc_channel = 0;
        dbus_uint32_t flags = 0;
        char *ssid;
        unsigned char* key[4];
        int key_len[4];
        int sock, i;
        int ssid_len;
        int previous_state;
        DBusError derror;

	dbus_error_init(&derror);

        if (in_flight_mode() || cover_closed()) {
                reply = new_dbus_error(message, WLANCOND_ERROR_WLAN_DISABLED);
                send_and_unref(connection, reply);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        remove_connect_timer();
        
        sock = socket_open();

        if ((previous_state = init_if(sock)) < 0) {
                reply = new_dbus_error(message, WLANCOND_ERROR_INIT_FAILED);
                goto param_err;
        }
        if (previous_state == WLAN_INITIALIZED_FOR_SCAN)
                set_wlan_state(WLAN_INITIALIZED, NO_SIGNAL, FORCE_NO);
        
        set_power_state(WLANCOND_POWER_ON, sock);

        set_bgscan_interval();

	if (dbus_message_get_args(
                    message, NULL,        
                    DBUS_TYPE_INT32, &power_level,
                    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ssid, &ssid_len,
                    DBUS_TYPE_INT32, &mode,
                    DBUS_TYPE_INT32, &encryption,
                    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[0], &key_len[0],
                    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[1], &key_len[1],
                    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[2], &key_len[2],
                    DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &key[3], &key_len[3],
                    DBUS_TYPE_INT32, &default_key,
                    DBUS_TYPE_UINT32, &adhoc_channel,
                    DBUS_TYPE_UINT32, &flags,
                    DBUS_TYPE_INVALID) == FALSE) 
        {
                /* Try without flags */
                if (dbus_message_get_args(
                            message, &derror,        
                            DBUS_TYPE_INT32, &power_level,
                            DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ssid, &ssid_len,
                            DBUS_TYPE_INT32, &mode,
                            DBUS_TYPE_INT32, &encryption,
                            DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, 
                            &key[0], &key_len[0],
                            DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, 
                            &key[1], &key_len[1],
                            DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, 
                            &key[2], &key_len[2],
                            DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, 
                            &key[3], &key_len[3],
                            DBUS_TYPE_INT32, &default_key,
                            DBUS_TYPE_UINT32, &adhoc_channel,
                            DBUS_TYPE_INVALID) == FALSE) {

                        DLOG_ERR("Failed to parse setting_and_connect: %s",
                                 derror.message);
                        dbus_error_free(&derror);
                        goto param_err;
                }
        }

        if (flags & WLANCOND_DISABLE_POWERSAVE) {
                DLOG_DEBUG("Powersave disabled");
                powersave = WLANCOND_POWER_ON;
        } else if (flags & WLANCOND_MINIMUM_POWERSAVE) {
                DLOG_DEBUG("Powersave minimum");
                powersave = WLANCOND_LONG_CAM;
        } else if (flags & WLANCOND_MAXIMUM_POWERSAVE) {
                DLOG_DEBUG("Powersave maximum");
                powersave = WLANCOND_SHORT_CAM;
        } else {
                powersave = WLANCOND_SHORT_CAM;
        }
        
        if (power_level != WLANCOND_TX_POWER10 &&
            power_level != WLANCOND_TX_POWER100) {
                DLOG_ERR("Invalid power level");
                goto param_err;
        }
        
        if (set_tx_power(power_level, sock) != TRUE) {
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        }
        
        if (!ssid || ssid_len == 0 || ssid_len > WLANCOND_MAX_SSID_SIZE + 1) {
                DLOG_DEBUG("Invalid SSID");
                goto param_err;
        }
                
        if (selected_ssid != NULL)
                g_free(selected_ssid);
        
        selected_ssid = g_strdup(ssid);
        
        init_iwreq(&req);

        switch (mode) {
            case WLANCOND_ADHOC:
                    req.u.mode = IW_MODE_ADHOC;
                    wlan_status.mode = WLANCOND_ADHOC;
                    break;
            case WLANCOND_INFRA:
                    req.u.mode = IW_MODE_INFRA;
                    wlan_status.mode = WLANCOND_INFRA;
                    break;
            default:
                    DLOG_ERR("Operating mode undefined\n");
                    goto param_err;
        }                               
        
        /* Operating mode */
        if (ioctl(sock, SIOCSIWMODE, &req) < 0) {
                DLOG_ERR("Operating mode setting failed\n");
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        }

        /* Encryption settings */
        guint32 wpa2_mode = encryption & WLANCOND_ENCRYPT_WPA2_MASK;

        DLOG_DEBUG("Encryption setting: %08x", encryption);
        
        switch (encryption & WLANCOND_ENCRYPT_METHOD_MASK) {
            case WLANCOND_OPEN:
                    break;
            case WLANCOND_WEP:
                    break;
            case WLANCOND_WPA_PSK:
                    DLOG_DEBUG("%s PSK selected", wpa2_mode!=0?"WPA2":"WPA");
                    break;
            case WLANCOND_WPA_EAP:
                    DLOG_DEBUG("%s EAP selected", wpa2_mode!=0?"WPA2":"WPA");
                    break;
            default:
                    DLOG_DEBUG("Unsupported encryption mode: %08x\n", 
                               encryption);
                    goto param_err;
        }
        if (update_algorithms(encryption) < 0) {
                goto param_err;
        }
        if (set_encryption_method(get_encryption_mode(encryption)) == 
            FALSE) {
                goto param_err;
        }

        int nbr_of_keys = 0;
        init_iwreq(&req);
        
        /* Encryption keys */
        for (i=0;i<4;i++) {
                if(!key[i] || key_len[i] == 0) {
                        continue;
                } else {
                        if (key_len[i] < WLANCOND_MIN_KEY_LEN || 
                            key_len[i] > WLANCOND_MAX_KEY_LEN) {
                                goto param_err;
                        }
                        
                        init_iwreq(&req);
                        req.u.data.length = key_len[i];
                        req.u.data.pointer = (caddr_t) key[i];
                        req.u.data.flags |= IW_ENCODE_RESTRICTED;
                        req.u.encoding.flags = i+1;
                        nbr_of_keys++;
                }
//#define DEBUG_KEY
#ifdef DEBUG_KEY
                for (int k=0;k<key_len[i];k++) {
                        DLOG_DEBUG("Key %d, 0x%02x\n", i, *(key[i]+k));
                }
#endif
                if (ioctl(sock, SIOCSIWENCODE, &req) < 0) {
                        DLOG_ERR("Set encode failed\n");
                        reply = new_dbus_error(message, 
                                               WLANCOND_ERROR_IOCTL_FAILED);
                        goto param_err;
                }
                
        }
        /* Default key */
        if (((encryption & WLANCOND_ENCRYPT_METHOD_MASK) == WLANCOND_WEP) && 
            nbr_of_keys == 0) {
                DLOG_ERR("WEP is selected but there are no WEP keys");
                goto param_err;
        }
        
        if (nbr_of_keys && (default_key < 1 || default_key > 4))
                goto param_err;
        
        if (nbr_of_keys) {
                
                DLOG_DEBUG("Default key: %d\n", default_key);

                init_iwreq(&req);
                
                /* Set the default key */
                req.u.encoding.flags = default_key;
                
                if (ioctl(sock, SIOCSIWENCODE, &req) < 0) {
                        DLOG_ERR("Set encode failed\n");
                        reply = new_dbus_error(message, 
                                               WLANCOND_ERROR_IOCTL_FAILED);
                        goto param_err;
                }
        }

        /* Ad-hoc channel */
        if (adhoc_channel != 0 && (mode & WLANCOND_ADHOC)) {
                if (adhoc_channel < WLANCOND_MIN_WLAN_CHANNEL ||
                    adhoc_channel > WLANCOND_MAX_WLAN_CHANNEL) {
                        DLOG_ERR("Invalid ad-hoc channel: %d", adhoc_channel);
                        goto param_err;
                }
                
                init_iwreq(&req);
                req.u.freq.m = adhoc_channel;
                
                if (ioctl(sock, SIOCSIWFREQ, &req) < 0) {
                        DLOG_ERR("Set channel failed\n");
                        reply = new_dbus_error(message,
                                               WLANCOND_ERROR_IOCTL_FAILED);
                        goto param_err;
                }
        }
        
        init_iwreq(&req);

        req.u.essid.pointer = (caddr_t)ssid;
        req.u.essid.length = ssid_len -1; // Remove NULL termination
        req.u.essid.flags = 1 | get_auth_mode(encryption, wpa2_mode);
        
        /* ESSID is set as a last item*/
        if (ioctl(sock, SIOCSIWESSID, &req) < 0) {
                DLOG_ERR("set ESSID failed");
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        }
        
        if (mode == WLANCOND_INFRA) {
                wlan_connect_timer_id = g_timeout_add(
                        WLANCOND_CONNECT_TIMEOUT, 
                        wlan_connect_timer_cb, NULL);
        }
        if (connect_name_cache != NULL)
                g_free(connect_name_cache);
        
        connect_name_cache = g_strdup(dbus_message_get_sender(message));
        
        reply = new_dbus_method_return(message);
        
        append_dbus_args(reply,
                         DBUS_TYPE_STRING, &ifname,
                         DBUS_TYPE_INVALID);        
        if (send_and_unref(connection, reply) < 0) {
                DLOG_ERR("Sending message failed!");
        }
        
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
     Scan D-BUS request.
     @param message DBUS message.
     @param connection DBUS connection.
     @return status. 
*/
static DBusHandlerResult scan_request(DBusMessage    *message,
                                      DBusConnection *connection) {
        
        DBusMessage *reply = NULL;
        DBusMessageIter iter, array_iter;
        struct iwreq req;
        char *ssid;
        int ssid_len;
        int sock = 0;
        const char* sender;
        dbus_int32_t power_level;
        dbus_int32_t flags;
        int previous_state = 0;
        gboolean passive_scan = FALSE;
        
        if (in_flight_mode() || cover_closed()) {
                reply = new_dbus_error(message, WLANCOND_ERROR_WLAN_DISABLED);
                send_and_unref(connection, reply);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        sender = dbus_message_get_sender(message);
        if (sender == NULL) {
                DLOG_ERR("No sender in DBUS message\n");
                goto param_err;
        }

        DLOG_DEBUG("Got scan request from %s\n", sender);
        
        if (get_scan_state() == SCAN_ACTIVE) {
                reply = new_dbus_error(message, WLANCOND_ERROR_ALREADY_ACTIVE);
                send_and_unref(connection, reply);
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        sock = socket_open();
        
        if ((previous_state = init_if(sock)) < 0) {
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
        dbus_message_iter_get_fixed_array(&array_iter, &ssid, &ssid_len);
        dbus_message_iter_next(&iter);

        power_down_after_scan = FALSE;
        
        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_UINT32) {
                dbus_message_iter_get_basic(&iter, &flags);
                DLOG_DEBUG("Found flags: %08x", flags);

                if (flags & WLANCOND_NO_DELAYED_SHUTDOWN)
                        power_down_after_scan = TRUE;
                if (flags & WLANCOND_PASSIVE_SCAN)
                        passive_scan = TRUE;
        }

        init_iwreq(&req);
        
        if (power_level != WLANCOND_TX_POWER10 &&
            power_level != WLANCOND_TX_POWER100) {
                DLOG_ERR("Invalid power level");
                goto param_err;
        }
        if (set_tx_power(power_level, sock) != TRUE) {
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        }
        
        init_iwreq(&req);
        req.u.essid.pointer = (caddr_t)ssid;
        if (passive_scan == TRUE)
                req.u.essid.flags = IW_SCAN_ALL_ESSID;
        else
                req.u.essid.flags = IW_SCAN_THIS_ESSID;
        
        if (ssid_len > WLANCOND_MAX_SSID_SIZE + 1) {
                DLOG_DEBUG("Invalid SSID\n");
                goto param_err;
        }
        
        if (ssid != NULL && ssid_len > 1) {
                DLOG_DEBUG("Found ssid '%s' for active scan", ssid);
                req.u.essid.length = ssid_len -1; // Remove NULL termination
                
                if (scan_ssid != NULL)
                        g_free(scan_ssid);
                scan_ssid = g_strdup(ssid);
        }
        
        if (ioctl(sock, SIOCSIWSCAN, &req) < 0) {
                DLOG_ERR("Scan ioctl failed\n");
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        }

        if (scan_name_cache != NULL)
                g_free(scan_name_cache);
        scan_name_cache = g_strdup(sender);

        set_scan_state(SCAN_ACTIVE);
        
        reply = new_dbus_method_return(message);
        if (send_and_unref(connection, reply) < 0) {
                DLOG_ERR("Sending message failed!");
        }
        
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
        struct scan_results_t *results_a = (struct scan_results_t*)a;
        struct scan_results_t *results_b = (struct scan_results_t*)b;

        if (scan_ssid != NULL) {
                
                //DLOG_DEBUG("Scan ssid = %s", scan_ssid);
                
                gint a_eq = strncmp(scan_ssid, results_a->ssid, WLANCOND_MAX_SSID_SIZE);
                gint b_eq = strncmp(scan_ssid, results_b->ssid, WLANCOND_MAX_SSID_SIZE);
                // Check if either network match the scan SSID
                if (!a_eq && !b_eq) {
                        //DLOG_DEBUG("Both (%s, %s) match scan SSID", results_a->ssid, results_b->ssid);
                        return 0;
                }
                
                if (!a_eq && b_eq) {
                        //DLOG_DEBUG("%s is better than %s", results_a->ssid, results_b->ssid);
                        return -1;
                }
                
                if (a_eq && !b_eq) {
                        
                        //DLOG_DEBUG("%s is better than %s", results_b->ssid, results_a->ssid);
                        return 1;
                }
                
        }
        //DLOG_DEBUG("No scan ssid, returning just RSSI values");

        return (results_a->rssi > results_b->rssi) ? -1 : (results_a->rssi < results_b->rssi) ? 1 : 0;
}

/**  
     Scan results request.
     @return status. 
*/
int ask_scan_results(int ifindex) 
{
        struct iwreq req;
        char *buffer;
        unsigned int buflen = IW_SCAN_MAX_DATA;
        GSList *scan_results_save = NULL;
        dbus_int32_t number_of_results;
        int sock;
        unsigned int counter = 3;
        
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
                if (errno == E2BIG) {
                        DLOG_DEBUG("Too much data for buffer length %d "
                                   "needed %d\n", buflen, req.u.data.length);
                        
                        char* new_buffer = NULL;
                        buflen = (req.u.data.length > buflen ? 
                                  req.u.data.length : buflen * 2);
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
                
                DLOG_ERR("Get scan results failed\n");
                
                goto param_err;
        }
            
        if (req.u.data.length)
        {
                struct iw_event            iwe;
                struct stream_descr        stream;
                struct scan_results_t      *scan_results;
                struct wireless_iface      *wireless_if;
                int                        ret;
                gboolean                   wap_handled = FALSE;

                scan_results = g_new0(struct scan_results_t, 1);
                memset(&iwe, 0, sizeof(iwe));
                
                wireless_if = get_interface_data(ifindex);

                iw_init_event_stream(&stream, buffer, req.u.data.length);
                do
                {
                        /* Extract an event */
                        ret = iw_extract_event_stream(
                                &stream, &iwe, 
                                wireless_if->range.we_version_compiled);
                        if (ret > 0) {
                                /* Let's peek what is coming so that we can
                                   separate different access points from
                                   the stream */

                                if (iwe.cmd == SIOCGIWAP) {
                                        /* Do not save if first time
                                           because WAP comes first, then other
                                           parameters */
                                        if (wap_handled == TRUE) {
                                                scan_results_save = save_scan_results(scan_results, scan_results_save);
                                                scan_results = g_new0(struct scan_results_t, 1);
                                        } else {
                                                wap_handled = TRUE;
                                        }
                                }
                                print_event_token(&iwe, scan_results, ifindex);

                        }

                }
                while (ret > 0);
                
                /* Check if the final results is still in the queue before
                   the result is sent into DBUS */
                if (wap_handled == TRUE) {
                        scan_results_save = save_scan_results(
                                scan_results, 
                                scan_results_save);
                } else {
                        // No results
                        g_free(scan_results);
                }
        }

        if (get_wlan_state() == WLAN_INITIALIZED_FOR_SCAN &&
            power_down_after_scan == TRUE) {  
                set_interface_state(sock, CLEAR, IFF_UP);
        }
        
        number_of_results = g_slist_length(scan_results_save);
        
        /* Sort the list only if the amount of networks is very high and
         we need to restrict the results */
        if (number_of_results > WLANCOND_MAX_NETWORKS)
                scan_results_save = g_slist_sort(scan_results_save, 
                                                 network_compare);
        
        send_dbus_scan_results(scan_results_save, scan_name_cache, 
                               number_of_results);
        clean_scan_results(scan_results_save);
        
        g_free(scan_name_cache);
        scan_name_cache = NULL;
        set_scan_state(SCAN_NOT_ACTIVE);

        if (get_wlan_state() == WLAN_INITIALIZED_FOR_SCAN)
                set_wlan_state(WLAN_NOT_INITIALIZED, NO_SIGNAL, FORCE_NO);

        g_free(buffer);

        return TRUE;
        
  param_err:
        g_free(buffer);        
        DLOG_DEBUG("Scan failed");
        send_dbus_scan_results(scan_results_save, scan_name_cache, 0);
        clean_scan_results(scan_results_save);
        g_free(scan_name_cache);
        scan_name_cache = NULL;
        set_scan_state(SCAN_NOT_ACTIVE);
        return FALSE;
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
        set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, FORCE_MAYBE);

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
        char *essid = NULL;
        int essid_len;
        dbus_uint32_t sens = 0;
        dbus_uint32_t security = 0;
        dbus_uint32_t capability = 0;
        dbus_uint32_t channel = 0;
        unsigned char *bssid = NULL;
        unsigned char *key = NULL;
        int sock;

        if (get_wlan_state() != WLAN_CONNECTED && 
            get_wlan_state() != WLAN_NO_ADDRESS &&
            wlan_status.mode != WLANCOND_ADHOC) {
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
        
        channel = req.u.freq.m;
        
        if (channel < WLANCOND_MIN_WLAN_CHANNEL || 
            channel > WLANCOND_MAX_WLAN_CHANNEL) {
                channel = 0;
                DLOG_DEBUG("Got invalid channel from the kernel\n");
        }
        
        init_iwreq(&req);

        /* Mode (Adhoc/Infra) */
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
        
        init_iwreq(&req);

        /* Speed / Rate */
        if (ioctl(sock, SIOCGIWRATE, &req) < 0) {
                DLOG_ERR("Could not get the rate");
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        } 
        capability |= req.u.bitrate.value;
        
        reply = new_dbus_method_return(message);

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

        if (send_and_unref(connection, reply) < 0) {
                DLOG_ERR("sending message failed!");
        }
        g_free(essid);
        g_free(bssid);
        
        return DBUS_HANDLER_RESULT_HANDLED;
        
  param_err:
        if (essid)
                g_free(essid);
        if (bssid)
                g_free(bssid);
        if (key)
                g_free(key);
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
        
        reply = new_dbus_method_return(message);
        
        append_dbus_args(reply,
                         DBUS_TYPE_STRING, &ifname,
                         DBUS_TYPE_INVALID);        
        if (send_and_unref(connection, reply) < 0) {
                DLOG_ERR("sending message failed!");
        }
        
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

        int state_v = get_wlan_state();

        if (state_v == WLAN_INITIALIZED ||
            state_v == WLAN_NO_ADDRESS ||
            state_v == WLAN_CONNECTED)
                state = TRUE;
        
        reply = new_dbus_method_return(message);
        
        append_dbus_args(reply,
                         DBUS_TYPE_BOOLEAN, &state,
                         DBUS_TYPE_INVALID);        
        if (send_and_unref(connection, reply) < 0) {
                DLOG_ERR("sending message failed!");
        }
        
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
        struct iw_pmksa pmksa;
        struct iwreq req;
        unsigned int pmkid_len, mac_len;
        unsigned char *pmkid;
        unsigned char *mac;
        dbus_uint32_t action;
        int sock;
        DBusError derror;

	dbus_error_init(&derror);

        sock = socket_open();
        
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
        init_iwreq(&req);
        
        if (action != IW_PMKSA_ADD &&
            action != IW_PMKSA_REMOVE &&
            action != IW_PMKSA_FLUSH) {
                DLOG_ERR("Invalid action");
                goto param_err;
        }
        
        pmksa.cmd = action;
        
        if (pmkid == NULL || pmkid_len != WLANCOND_PMKID_LEN || mac == NULL 
            || mac_len != ETH_ALEN) {
                DLOG_ERR("Invalid arguments");
                goto param_err;
        }

        req.u.encoding.pointer = (caddr_t) &pmksa;
	req.u.encoding.length = sizeof(pmksa);
        
        memcpy(&pmksa.pmkid, pmkid, pmkid_len);
        memcpy(&pmksa.bssid.sa_data, mac, mac_len);
        
	if (ioctl(sock, SM_DRV_WPA_PMK_SET_KEY, &req) < 0) {
                DLOG_ERR("Could not set WPA PMKSA");
                reply = new_dbus_error(message, WLANCOND_ERROR_IOCTL_FAILED);
                goto param_err;
        }

#ifdef DEBUG        
        char* a = pmksa.bssid.sa_data;
#endif
        DLOG_DEBUG("PMKSA %s successfully for address %02x:%02x:%02x:%02x:%02x"
                   ":%02x", action==IW_PMKSA_ADD?"added":"removed/flushed", 
                   a[0],a[1],a[2],a[3],a[4],a[5]);
        
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
                if (get_wlan_state() == WLAN_NOT_INITIALIZED && !get_mic_status()) {
                        set_wlan_state(WLAN_NOT_INITIALIZED, NO_SIGNAL, FORCE_YES);
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

/** WPA IE callback 
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
                
                DLOG_DEBUG("EAP pending call result:%s", error.name);
                
                dbus_error_free(&error);
                
                set_wlan_state(WLAN_NOT_INITIALIZED,
                               DISCONNECTED_SIGNAL,
                               FORCE_MAYBE);
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
   @return status.
*/
int wpa_ie_push(unsigned char* ap_mac_addr, unsigned char* ap_wpa_ie,
                int ap_wpa_ie_len) {

        DBusMessage *msg;
        DBusPendingCall *pending;

        if (wlan_status.wpa_ie.ie_valid == IE_NOT_VALID || 
            selected_ssid == NULL) {
                DLOG_ERR("WPA IE / SSID (%s) not valid", selected_ssid);
                return -1;
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
                &selected_ssid, strlen(selected_ssid),
                DBUS_TYPE_INT32, &wlan_status.pairwise_cipher,
                DBUS_TYPE_INT32, &wlan_status.group_cipher,
                DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, 
                &ap_mac_addr, ETH_ALEN,
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
   Disassociate EAP D-BUS request. 
   @return status.
*/
int disassociate_eap(void) {
        DBusMessage *msg;
        DBusMessage *reply;
        DBusError derr;
        
        msg = dbus_message_new_method_call(
                EAP_SERVICE,
                EAP_REQ_PATH,
                EAP_REQ_INTERFACE,
                EAP_DISASSOCIATE_REQ);
        
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

#ifdef USE_MCE_COVER
static DBusHandlerResult ignore_cover_request(DBusMessage    *message,
                                              DBusConnection *connection)
{
        DBusMessage *reply;
        dbus_bool_t ignore_cover;

        if (!dbus_message_has_signature(message, ignore_cover_sgn)) {
                if (!send_invalid_args(connection, message))
                        error("sending D-BUS message failed");
                return DBUS_HANDLER_RESULT_HANDLED;
        }
        
        dbus_message_get_args(message, NULL,
                              DBUS_TYPE_BOOLEAN, &ignore_cover,
                              DBUS_TYPE_INVALID);
        
        DLOG_DEBUG("ignore_cover is (%s)", ignore_cover ? "TRUE" : "FALSE");

        /* Check cover state if signals have been ignored so far */
        if (ignore_cover_events && !ignore_cover)
                _read_cover_state();
        
        ignore_cover_events = ignore_cover;
        
        reply = new_dbus_method_return(message);

        if (!send_and_unref(connection, reply))
                error("sending D-BUS message failed!");
        
        return DBUS_HANDLER_RESULT_HANDLED;
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
        { WLANCOND_REQ_INTERFACE, WLANCOND_SETTINGS_AND_CONNECT_REQ, settings_and_connect_request},
        { WLANCOND_REQ_INTERFACE, WLANCOND_SCAN_REQ, scan_request},        
        { WLANCOND_REQ_INTERFACE, WLANCOND_STATUS_REQ, status_request},        
        { WLANCOND_REQ_INTERFACE, WLANCOND_INTERFACE_REQ, interface_request},        
        { WLANCOND_REQ_INTERFACE, WLANCOND_CONNECTION_STATUS_REQ, connection_status_request},        
        { WLANCOND_REQ_INTERFACE, WLANCOND_SET_PMKSA_REQ, set_pmksa_request},
        { WLANCOND_REQ_INTERFACE, WLANCOND_SET_POWERSAVE_REQ, set_powersave_request},
        { WLANCOND_REQ_INTERFACE, WLANCOND_DISCONNECT_REQ, disconnect_request},
#ifdef USE_MCE_COVER
        { WLANCOND_REQ_INTERFACE, WLANCOND_IGNORE_COVER_REQ, ignore_cover_request},
#endif
        
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
                                       void               *user_data) {
        method_handler_t *handler;
        const char *dest;

/*        DLOG_DEBUG("Received %s.%s",
                   dbus_message_get_interface(message),
                   dbus_message_get_member(message));
*/
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
        
        /* The rest should be just method calls */
        if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_METHOD_CALL) {
                  return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        
        dest = dbus_message_get_destination(message);
        if (!g_str_equal(dest, WLANCOND_SERVICE)) {
                DLOG_DEBUG("Received D-Bus message not addressed to me.");
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
#ifdef USE_MCE_COVER        
        if (!add_cover_listener(connection, reread_cover_state)) {
                DLOG_ERR("Adding cover listener failed");
        }
#endif
        if (!add_icd_listener(connection)) {
                DLOG_ERR("Adding icd listener failed");
        }  
}

/**
   Destroy D-BUS handlers.
   @param connection DBUS connection.
*/
void destroy_dbus_handlers(DBusConnection *connection) {
        dbus_connection_unregister_object_path(connection, WLANCOND_REQ_PATH);
}
