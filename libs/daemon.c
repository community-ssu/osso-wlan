/**
  @file daemon.c

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
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <glib.h>

#include "log.h"
#include "daemon.h"

static int read_pid(const char *pidfile) {
        FILE *file;
        int pid, ret;
        
        file = fopen(pidfile, "r");
        if (file == NULL) {
                return -1;
        }
        
        ret = fscanf(file, "%d", &pid);
        fclose(file);
        if (ret != 1 || pid < 1) {
                (void) remove_pid(pidfile);
                return -1;
        }
        
        return pid;
}

int remove_pid(const char *pidfile) {
        return unlink(pidfile);
}

int check_pid(const char *pidfile) {
        int pid;
        struct stat finfo;
        
        if (stat(pidfile, &finfo) < 0)
                return 0;
        
        pid = read_pid(pidfile);
        if (pid < 0)
                return 0;
        
        if (kill(pid, 0) < 0 && errno == ESRCH) {
                (void) remove_pid(pidfile);
                return 0;
        }
        
        return pid;
}

int write_pid(const char *pidfile) {
        FILE *file;
        
        file = fopen(pidfile, "w");
        if (file == NULL) {
                return -1;
        }
        
        fprintf(file, "%d\n", getpid());
        
        fclose(file);
        
        return 0;
}

static void do_fork(void) {
        pid_t ret;
        
        ret = fork();
        if (ret == -1)
                die("fork: %s", strerror(errno));
        else if (ret > 0)
                _exit(EXIT_SUCCESS);
}

void daemonize(void) {
        int fd;
    
        //debug("Deamonizing...");
        
        /* Flush all open output streams */
        fflush(NULL);
        
        do_fork();
        
        if (setsid() < 0)
                die("setsid: %s", strerror(errno));
        
        do_fork();
        
        if ((fd = open("/dev/null", O_RDWR)) < 0)
                die("open(\"/dev/null\"): %s", strerror(errno));
        /* dup2 (2) works well because it closes the old fd if it's open */
        if (dup2(fd, STDIN_FILENO) < 0)
                die("dup2 failed (%s)", strerror(errno));
        if (dup2(fd, STDOUT_FILENO) < 0)
                die("dup2 failed (%s)", strerror(errno));
        if (dup2(fd, STDERR_FILENO) < 0)
                die("dup2 failed (%s)", strerror(errno));
        if (fd > 2)
                close(fd);
        
        /* So we don't block any umounts */
        chdir("/");
}

