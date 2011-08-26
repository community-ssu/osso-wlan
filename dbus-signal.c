/**
  @file dbus-signal.c

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
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <glib-object.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <osso-log.h>
#include <wlancond-dbus.h>

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
extern char *ifname;
extern gchar own_mac[ETH_ALEN];

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
static int handle_wpa_ie_assoc_event_binary(unsigned char* custom, unsigned int length);

static inline void print_mac(const char *message, char* mac) 
{
        DLOG_DEBUG("%s %02x:%02x:%02x:%02x:%02x:%02x", message, mac[0],
                   mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/** 
    Remove saved scan results.
    @param scan_results_save structure where scan results are saved.
*/
void clean_scan_results(GSList *scan_results_save) 
{
        g_slist_foreach(scan_results_save, (GFunc)g_free, NULL);
        g_slist_free(scan_results_save);

        scan_results_save = NULL;

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

        // ssid_len includes null termination
        if (scan_results->ssid_len < 2) {
                DLOG_DEBUG("Hidden SSID not saved to scan results");
                // We have to free the result here since it is not saved
                g_free(scan_results);
                return scan_results_save;
        }
        
        scan_results_save = g_slist_append(scan_results_save, scan_results);
        
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
        
        if (sender == NULL || strnlen(sender, 5) == 0)
                return;

        DLOG_DEBUG("Sending scan results to DBUS to %s", sender);
        
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
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, 
                                       &number_of_results);
        
        for (list = scan_results_save; list != NULL && list_count <= number_of_results; list = list->next) {
                struct scan_results_t *scan_results = (struct scan_results_t*)list->data;
                DLOG_DEBUG("AP (%d) is %s, rssi:%d channel:%d cap:%08x", 
                           list_count++,
                           scan_results->ssid,
                           scan_results->rssi, scan_results->channel,
                           scan_results->cap_bits);
                
                char *p = scan_results->ssid;
                
                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &sub))
                        die("Out of memory during dbus_message_iter_open_container");
                dbus_message_iter_append_fixed_array(
                        &sub, DBUS_TYPE_BYTE, &p, scan_results->ssid_len);
                if (!dbus_message_iter_close_container(&iter, &sub))
                        die("Out of memory during dbus_message_iter_close_container");
                p = scan_results->bssid;
                if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &sub))
                        die("Out of memory during dbus_message_iter_open_container");
                dbus_message_iter_append_fixed_array(&sub, DBUS_TYPE_BYTE, 
                                                     &p, ETH_ALEN);
                if (!dbus_message_iter_close_container(&iter, &sub))
                        die("Out of memory during dbus_message_iter_close_container");
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, 
                                               &scan_results->rssi);
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, 
                                               &scan_results->channel);
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, 
                                               &scan_results->cap_bits);
        }

        if (results != NULL) {
                send_and_unref(get_dbus_connection(), results);
        }
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
        
        append_dbus_args(disconnected,
                         DBUS_TYPE_STRING, &ifname,
                         DBUS_TYPE_INVALID);
        
        if (disconnected != NULL) {
                send_and_unref(get_dbus_connection(),
                               disconnected);
        }
}

/**
   Send connected signal.
   @param scan_results Scan results to be sent.
   @param auth_status Authentication status.
*/
static void connected_signal(unsigned char* bssid, dbus_int32_t auth_status)
{
        DBusMessage *connected;
        
        connected = new_dbus_signal(
                WLANCOND_SIG_PATH,
                WLANCOND_SIG_INTERFACE,
                WLANCOND_CONNECTED_SIG,
                NULL);
        
        append_dbus_args(connected,
                         DBUS_TYPE_STRING, &ifname,
                         DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &bssid, ETH_ALEN, 
                         DBUS_TYPE_INT32, &auth_status,
                         DBUS_TYPE_INVALID);
        
        if (connected != NULL) {
                send_and_unref(get_dbus_connection(), connected);
        }
}

/**
   Handle WAP wireless event.
   @param event extracted token.
   @param scan_results structure where scan results are saved.
   @return status.
 */
static void handle_wap_event(struct scan_results_t *scan_results, 
                             struct iw_event *event) 
{
        int state, scan_state;
        gboolean zero_address = FALSE;

        // Spurious event
        if (get_wlan_state() == WLAN_NOT_INITIALIZED) {
                return;
        }

        print_mac("SIOCGIWAP:", event->u.ap_addr.sa_data);
        
        if (!memcmp(event->u.ap_addr.sa_data, "\0\0\0\0\0\0", ETH_ALEN)) {
                zero_address = TRUE;
        }
        
        scan_state = get_scan_state();
        
        if (scan_state == SCAN_ACTIVE && zero_address && !get_mic_status()) {
                DLOG_DEBUG("Got disconnected in the middle of scan");
                set_wlan_state(WLAN_NOT_INITIALIZED,
                               DISCONNECTED_SIGNAL,
                               FORCE_YES);
        }
        
        if (scan_state != SCAN_NOT_ACTIVE) {
                memcpy(scan_results->bssid, event->u.ap_addr.sa_data, ETH_ALEN);
                return;
        }
        
        // Check if the address is valid
        if (zero_address == FALSE)
        {                
                remove_connect_timer();
                
                dbus_int32_t auth_status = get_encryption_info();
                
                state = get_wlan_state();
                
                connected_signal(event->u.ap_addr.sa_data, auth_status);
                // If not roaming, set NO_ADDRESS state
                if (state != WLAN_CONNECTED) {
                        set_wlan_state(WLAN_NO_ADDRESS, NO_SIGNAL, FORCE_NO);
                }
        } else {
                
                /* Set_wlan_state puts IF down */
                set_wlan_state(WLAN_NOT_INITIALIZED,
                               DISCONNECTED_SIGNAL,
                               FORCE_MAYBE);
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
                      int ifindex)
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
                            memcpy(scan_results->ssid, event->u.essid.pointer, 
                                   len);
                    }
                    
                    // Keep the API the same i.e. add Null termination
                    len++;

                    scan_results->ssid_len = len;
                    
                    if (event->u.essid.flags)
                    {
                            /* Does it have an ESSID index ? */
                            if((event->u.essid.flags & IW_ENCODE_INDEX) > 1) {
                                    
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
                    handle_wap_event(scan_results, event);
                    break;
            case IWEVQUAL:
                    DLOG_DEBUG("RSSI: %d dBm", (signed char)event->u.qual.level);
                    scan_results->rssi = (signed char)event->u.qual.level;
                    break;
            case SIOCGIWFREQ:
            {
                    scan_results->channel = event->u.freq.m;
                    DLOG_DEBUG("Channel: %d", scan_results->channel);
            }
            break;
            case SIOCGIWMODE:
                    if (event->u.mode == IW_MODE_ADHOC) {
                            scan_results->cap_bits |= WLANCOND_ADHOC;
                    } else {
                            scan_results->cap_bits |= WLANCOND_INFRA;
                    }
                    DLOG_DEBUG("Mode: %s", scan_results->cap_bits & 
                               WLANCOND_ADHOC ? "Adhoc":"Infra");
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
                        case 52*500000:
                                scan_results->cap_bits |= WLANCOND_RATE_260;
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
                            scan_results->cap_bits |= WLANCOND_WEP;
                    } else {
                            scan_results->cap_bits |= WLANCOND_OPEN;
                    }

                    DLOG_DEBUG("Encryption: %s", 
                               scan_results->cap_bits & WLANCOND_WEP ? 
                               "Yes":"No");
                    break;
            case SIOCGIWSCAN:
            {
                    if (get_scan_state() == SCAN_ACTIVE) {
                            DLOG_DEBUG("Scan results ready -- scan active");
                            if (ask_scan_results(ifindex) == FALSE) {
                                    DLOG_ERR("Getting scan results failed");
                            }
#ifdef DEBUG
                    } else {
                            DLOG_DEBUG("Scan results ready -- not requested");
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
                            DLOG_ERR("Error in WPA IE handling, hiding SSID");
                            scan_results->ssid[0] = '\0';
                    }
                    
            }
            break;
            case IWEVASSOCRESPIE:
            case IWEVASSOCREQIE:
            {
                    if (handle_wpa_ie_assoc_event_binary(
                                event->u.data.pointer, 
                                event->u.data.length) < 0) {
                            
                            /* Set_wlan_state puts IF down */
                            set_wlan_state(WLAN_NOT_INITIALIZED,
                                           DISCONNECTED_SIGNAL,
                                           FORCE_MAYBE);
                    }
            }
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
   Handle association time WPA IE event.
   @param p WPA IE data.
   @param length WPA IE data length.
   @return status.
 */
static int handle_wpa_ie_assoc_event_binary(unsigned char* p, 
                                            unsigned int length) 
{
        int status = 0;
        int ie_len;
        int sock;

        if (get_wpa_mode() == FALSE)
                return 0;
        
        // event is MAC:IE, do minimal sanity checking
        if (length < ETH_ALEN + 1 + sizeof(struct rsn_ie_t)) {
                DLOG_DEBUG("Invalid length: %d", length);
                return -1;
        }

        ie_len = length - ETH_ALEN - 1;
        
        if (memcmp(p, own_mac, ETH_ALEN) == 0) 
        {
                //DLOG_DEBUG("Own WPA IE found");
                update_own_ie(g_memdup(p + ETH_ALEN + 1, ie_len), ie_len);
        } else {
                /* Push WPA IEs to security SW */
                status = wpa_ie_push(p, p + ETH_ALEN + 1, ie_len);
                
                /* Check if we are roaming */
                if (get_wlan_state() == WLAN_CONNECTED ||
                    get_wlan_state() == WLAN_NO_ADDRESS) {
                        sock = socket_open();
                        set_power_state(WLANCOND_POWER_ON, sock);
                }
        } 
                
        return status;
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
        gboolean no_wep = FALSE;

        if (!p || length < sizeof(struct rsn_ie_t))
                return -1;
        
        memset(&ap_info, 0, sizeof(ap_info));
        
        if (p[0] == RSN_ELEMENT) {
                DLOG_DEBUG("RSN IE");
                if (parse_rsn_ie(p, length, &ap_info) < 0) {
                        return -1;
                }
                scan_results->cap_bits |= WLANCOND_WPA2;
        } else if (p[0] == WPA_ELEMENT) {
                DLOG_DEBUG("WPA IE");
                if (parse_wpa_ie(p, length, &ap_info) < 0) {
                        return -1;
                }
        } else {
                DLOG_ERR("Invalid IE");
                return -1;
        }
        
        /* Key mgmt */
        if (ap_info.key_mgmt & WPA_PSK) {
                DLOG_DEBUG("WPA PSK supported");
                scan_results->cap_bits |= WLANCOND_WPA_PSK;
                no_wep = TRUE;
        } 
        if (ap_info.key_mgmt & WPA_802_1X) {
                DLOG_DEBUG("WPA EAP supported");
                scan_results->cap_bits |= WLANCOND_WPA_EAP;
                no_wep = TRUE;
        }
        /* Algorithms */
        /* Pairwise */
        if (ap_info.pairwise_cipher & CIPHER_SUITE_CCMP) {
                DLOG_DEBUG("WPA AES supported for unicast");
                scan_results->cap_bits |= WLANCOND_WPA_AES;
        } 
        if (ap_info.pairwise_cipher & CIPHER_SUITE_TKIP) {
                DLOG_DEBUG("WPA TKIP supported for unicast");
                scan_results->cap_bits |= WLANCOND_WPA_TKIP;
        }
        if (ap_info.pairwise_cipher & CIPHER_SUITE_WEP40 || 
            ap_info.pairwise_cipher & CIPHER_SUITE_WEP104) {
                DLOG_DEBUG("WEP supported for unicast");
                
                if (no_wep == TRUE) {
                        DLOG_DEBUG("In WPA mode WEP is not allowed");
                        scan_results->cap_bits |= WLANCOND_UNSUPPORTED_NETWORK;
                }
        }
        /* Group */
        if (ap_info.group_cipher & CIPHER_SUITE_CCMP) {
                DLOG_DEBUG("WPA AES supported for multicast");
                scan_results->cap_bits |= WLANCOND_WPA_AES_GROUP;
        }
        if (ap_info.group_cipher & CIPHER_SUITE_TKIP) {
                DLOG_DEBUG("WPA TKIP supported for multicast");
                scan_results->cap_bits |= WLANCOND_WPA_TKIP_GROUP;
        }
        if (ap_info.group_cipher & CIPHER_SUITE_WEP40 || 
            ap_info.group_cipher & CIPHER_SUITE_WEP104) {
                DLOG_DEBUG("WEP supported for multicast");

                if (no_wep == TRUE) {
                        DLOG_DEBUG("In WPA mode WEP is not allowed");
                        scan_results->cap_bits |= WLANCOND_UNSUPPORTED_NETWORK;
                }
        }
        /* Remove WEP bit to make UI show correct dialogs */
        if (no_wep) {
                scan_results->cap_bits ^= WLANCOND_WEP;
        }

        return 0;
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
        
        if (length < 11 || length > IW_GENERIC_IE_MAX) {
                DLOG_DEBUG("Invalid length event");
                return;
        }

        if (strncmp(event_pointer, "MIC_FAILURE", 11) == 0) {
                DLOG_DEBUG("MIC failure event");
                dbus_bool_t key_type = FALSE; //TODO key type when supported
                handle_mic_failure(key_type);
        } else if (strncmp(event_pointer, "DEAUTHENTICATION", 16) == 0){
                if (get_wpa_mode() == TRUE && 
                    (get_wlan_state() == WLAN_CONNECTED || 
                     get_wlan_state() == WLAN_NO_ADDRESS)) {
                        disassociate_eap();
                }
                DLOG_DEBUG("Deauthenticated");
        } else {
                DLOG_DEBUG("Unknown custom event");
        }
}

/**
   Get name of interface based on interface index.
   @param skfd Socket.
   @param ifindex Interface index.
   @param name Interface name.
   @return status.
 */
static inline int index2name(int skfd, int ifindex, char *name)
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
                        //printf("Cache : found %d-%s\n", curr->ifindex, curr->ifname);

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
                return(NULL);
        }
        curr->has_range = (iw_get_range_info(skfd, curr->ifname, &curr->range) >= 0);
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
                ret = iw_extract_event_stream(&stream, &iwe, wireless_if->range.we_version_compiled);
                if (ret != 0)
                {
                        if (ret > 0)
                                print_event_token(&iwe, &scan_results, ifindex);
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
                
                /* Got a match ? */
                if(curr->ifindex == ifindex)
                {
                        /* Unlink. Root ? */
                        if(!prev)
                                interface_cache = next;
                        else
                                prev->next = next;
                        //printf("Cache : purge %d-%s\n", curr->ifindex, curr->ifname);
                        
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
                                                   (char *)rtattr + RTA_ALIGN(sizeof(struct rtattr)),
                                                   rtattr->rta_len - RTA_ALIGN(sizeof(struct rtattr)));
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
        struct sockaddr_nl nl;
        socklen_t nl_len = sizeof(struct sockaddr_nl);
        int res;
        char buf[2048];
        
        while (1) {
                res = recvfrom (fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&nl, &nl_len);
                
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
                        
                        if ((len - sizeof(*hdr) < 0) || len > res) {
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

        if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
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
