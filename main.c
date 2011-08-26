/**
  @file main.c

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
#include <getopt.h>
#include <signal.h>
#include <glib.h>
#include <glib-object.h>
#include <unistd.h>
#include <wlancond-dbus.h>

#include "dbus-helper.h"

#include "daemon.h"
#include "common.h"
#include "dbus.h"
#include "dbus-handler.h"
#include "log.h"

#define PIDFILE "/var/run/wlancond.pid"

#if WIRELESS_EXT < 21
#error "Wireless extensions are too old for this software"
#endif

static char *program_name;
static gboolean daemon_mode = FALSE;
static GMainLoop *event_loop = NULL;

/* For getopt */
static struct option const long_options[] = {
        {"help",     no_argument,       0, 'h'},
        {"version",  no_argument,       0, 'V'},
        {"daemon",   no_argument,       0, 'd'},
        {NULL, 0, NULL, 0}
};
static void usage(int status) __attribute__ ((noreturn));
/** 
    Print usage information and exit with status 
*/
static void usage(int status) {
        printf("%s - WLAN Connection Deamon %s\n", program_name, VERSION);
        
        printf("Compilation flags: ");
#ifdef DEBUG
        printf("+DEBUG ");
#else
        printf("-DEBUG ");
#endif
        
        printf(
                "\nUsage: %s [OPTION]...\n"
                "Options:\n"
                "-h, --help                 Display this help and exit\n"
                "-V, --version              Output version information and exit\n"
                "-d, --daemon               Send process to the background\n"
                "\n", program_name);
        
        exit(status);
}

/** 
    Process commandline options. Returns index of first
    non-option argument 
*/
static int decode_switches(int argc, char *argv[])
{
        int c;
        
        while ((c = getopt_long(argc, argv,
                                "h"   /* help      */
                                "V"   /* version   */
                                "d"   /* daemon    */
                                ,long_options, (int *) 0)) != EOF) {
                switch (c) {
                    case 'V':
                            printf("WLAN Connection Daemon %s\n", VERSION);
                            exit(EXIT_SUCCESS);

                    case 'h':
                            usage(EXIT_SUCCESS);
                            break;
                    case 'd':
                            daemon_mode = TRUE;
                            break;
                    default:
                            usage(EXIT_FAILURE);
                }
        }
        
        return optind;
}

static void clean_data(void) 
{
        del_all_interface_data();
        clean_dbus_handler();
}

/**
   Exit signal handler
*/
static void signal_exit(int sig) {
        DLOG_INFO("Signal received: %s.", strsignal(sig));
        g_main_loop_quit(event_loop);
}

/**
   Clean PID 
*/
static void pid_cleanup(void) {
        (void) remove_pid(PIDFILE);
}

/** 
    Main function for this program. Initializes
    D-BUS and Wireless extensions
*/
int main(int argc, char *argv[]) {
        int i, old_pid;
        
        g_type_init();
        
        program_name = argv[0];
        i = decode_switches(argc, argv);

	init_logging();
        
        DLOG_OPEN("wlancond");
        
        old_pid = check_pid(PIDFILE);
        if (old_pid) {
                die("Unable to run: another instance running (PID %d)", old_pid);
        }
        
        if (daemon_mode) {
                if (daemon(0, 0)<0)
			die("daemon() failed");
        }
        
        write_pid(PIDFILE);
        atexit(pid_cleanup);
        
        event_loop = g_main_loop_new(NULL, FALSE);
        
        if (setup_dbus_connection(WLANCOND_SERVICE, init_dbus_handlers) < 0) {
                die("D-BUS connection setup failed!");
        }
        
        if (signal(SIGINT, signal_exit) == SIG_ERR) {
                die("signal(SIGINT) failed");
        }
        if (signal(SIGTERM, signal_exit) == SIG_ERR) {
                die("signal(SIGTERM) failed");
        }
        
        /* Assume there is only one wireless device */
        if (get_we_device_name() < 0) {
                DLOG_ERR("No device supporting wireless extensions? Exiting.");
                exit(EXIT_FAILURE);
        }

        if (init_dbus_handler() < 0) {
                exit(EXIT_FAILURE);
        }
        
        DLOG_INFO("WLAN Connection Daemon %s started.", VERSION);
        
        if (monitor_wi() != TRUE) {
                DLOG_ERR("Could not listen any wireless interface");
                exit(EXIT_FAILURE);
        }
        
        gchar *mode = get_device_mode(get_dbus_connection());
        
        if (mode != NULL) {
                mode_change(mode);
                g_free(mode);
        } else {
                DLOG_ERR("Unable to determine device mode. Assuming normal mode.");
                mode_change("normal");
        }
#ifdef USE_MCE_COVER
        init_cover_state();
#endif
        /* Enter main loop */
        g_main_loop_run(event_loop);

        set_wlan_state(WLAN_NOT_INITIALIZED, DISCONNECTED_SIGNAL, FORCE_YES);

        destroy_dbus_handlers(get_dbus_connection());
        close_dbus_connection();
        g_main_loop_unref(event_loop);

        clean_data();

        DLOG_INFO("Exiting.");
        LOG_CLOSE();
        
        exit(EXIT_SUCCESS);
}

