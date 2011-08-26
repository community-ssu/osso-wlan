/**
  @file wpa.c

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <glib.h>
#include <glib-object.h>
#include <unistd.h>
#include <osso-log.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include "wpa.h"
#include "common.h"

/* MIC failure timer ID */
static guint mic_failure_timer_id = 0;

/* MIC failure timer running ID */
static guint mic_failure_running_timer_id = 0;

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

int parse_rsn_cipher_suite(guint8 *suite)
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

int parse_rsn_key_mgmt_suite(guint8 *suite)
{
	if (memcmp(suite, RSN_KEY_MGMT_802_1X, CIPHER_SUITE_LEN) == 0)
		return WPA_802_1X;
	if (memcmp(suite, RSN_KEY_MGMT_PSK, CIPHER_SUITE_LEN) == 0)
		return WPA_PSK;
	return 0;
}

int parse_wpa_cipher_suite(guint8* suite)
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

int parse_wpa_key_mgmt_suite(guint8 *suite)
{
	if (memcmp(suite, WPA_KEY_MGMT_802_1X, CIPHER_SUITE_LEN) == 0)
		return WPA_802_1X;
	if (memcmp(suite, WPA_KEY_MGMT_PSK, CIPHER_SUITE_LEN) == 0)
		return WPA_PSK;
	return 0;
}
/** 
    Set encryption method.
    @param cipher Selected encryption method.
    @return status.
*/

gboolean set_encryption_method(guint32 cipher) 
{
        int sock;
        struct iwreq req;
        
        init_iwreq(&req);
        
        switch (cipher) {
            case CIPHER_SUITE_NONE:
                    req.u.name[0] = DOT11_PRIV_INV_NONE;
                    break;
            case CIPHER_SUITE_WEP40:
            case CIPHER_SUITE_WEP104:
                    req.u.name[0] = DOT11_PRIV_INV_WEP;
                    break;
            case CIPHER_SUITE_TKIP:
                    req.u.name[0] = DOT11_PRIV_INV_TKIP;
                    break;
            case CIPHER_SUITE_CCMP:
                    req.u.name[0] = DOT11_PRIV_INV_AES_CCMP;
                    break;
            default:
                    DLOG_ERR("Invalid algorithm");
                    return FALSE;
	}

        sock = socket_open();
        
	if (ioctl(sock, SM_DRV_WPA_SET_WPA, &req) < 0) {
                DLOG_ERR("Could not set WPA mode");
                return FALSE;
	}

        return TRUE;
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
        
        DLOG_DEBUG("No MIC failures within the last 60 seconds.");
        
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
        
        DLOG_DEBUG("MIC failures off");
        
        return FALSE;
}

gboolean get_mic_status(void) 
{        
        return (mic_failure_running_timer_id != 0 ? TRUE:FALSE);
}

/**
   Handle MIC failure.
   @param key_type Key type (pairwise/group).
   @return status.
*/
int handle_mic_failure(gboolean key_type) 
{        
        
        if (mic_failure_timer_id != 0) {

                g_source_remove(mic_failure_timer_id);
                mic_failure_timer_id = 0;

                /* Second failure in 60 seconds, fatal */                
                wpa_mic_failure_event(key_type, TRUE);
                
                DLOG_ERR("Second MIC failure, AP is disconnected");

                sleep(1);
                
                set_wlan_state(WLAN_NOT_INITIALIZED,
                               DISCONNECTED_SIGNAL,
                               FORCE_NO);

                /* Set timer to remember this fatal error for 60 seconds */
                mic_failure_running_timer_id = g_timeout_add(
                        MIC_FAILURE_TIMEOUT,
                        mic_failure_running_cb,
                        NULL);
                
                return 0;
        }
        
        wpa_mic_failure_event(key_type, FALSE);
        
        mic_failure_timer_id = g_timeout_add(MIC_FAILURE_TIMEOUT,
                                             mic_failure_timer_cb,
                                             NULL);
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
        if (wpa_ie_len < sizeof(struct rsn_ie_t)) {
                DLOG_ERR("WPA IE too short");
                return -1;
        }
        
        wpa_hdr = (struct rsn_ie_t*) wpa_ie;
        
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
		cipher_count = hdr_p[0] | (hdr_p[1] << 8);
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
		cipher_count = hdr_p[0] | (hdr_p[1] << 8);
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
		ap_info->rsn_capabilities = hdr_p[0] | (hdr_p[1] << 8);
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
        if (wpa_ie_len < sizeof(struct wpa_ie_t)) {
                DLOG_ERR("WPA IE too short");
                return -1;
        }
        
        wpa_hdr = (struct wpa_ie_t*) wpa_ie;
        
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
		cipher_count = hdr_p[0] | (hdr_p[1] << 8);
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
			ap_info->pairwise_cipher |= parse_wpa_cipher_suite(hdr_p);
			ind -= CIPHER_SUITE_LEN;
                        hdr_p += CIPHER_SUITE_LEN;
		}
	} else if (ind == 1) {
                DLOG_ERR("Remaining data too short");
		return -1;
        }

     	if (ind >= 2) {
		ap_info->key_mgmt = 0;
		cipher_count = hdr_p[0] | (hdr_p[1] << 8);
		hdr_p += 2;
		ind -= 2;
		
                if (cipher_count == 0 || ind < cipher_count *
                    CIPHER_SUITE_LEN) {
                        DLOG_ERR("Invalid key mgmt cipher count (%d) or length", cipher_count);
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
		ap_info->rsn_capabilities = hdr_p[0] | (hdr_p[1] << 8);
		hdr_p += 2;
		ind -= 2;
	}
        
	if (ind > 0) {
                DLOG_ERR("IE too long?");
		return -1;
	}
        return 0;
}
