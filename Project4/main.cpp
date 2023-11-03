#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <map>
#include "socket_methods.h"

using namespace std;

int main(int argc, char *argv[]) {
    Opts opts;
    auto *pinfo = new pkt_info;
    parseargs(&opts, argc, argv);
    // open the file
    int fd = open(opts.trace_file.c_str(), O_RDONLY);
    if (fd < 0) {
        err_exit("Error opening file: ", opts.trace_file);
    }

    if (opts.s_flag)
        mode_s(fd, pinfo);
    if (opts.l_flag)
        mode_l(fd, pinfo);
    if (opts.p_flag)
        mode_p(fd, pinfo);
    if (opts.c_flag)
        mode_c(fd, pinfo);

    close(fd);
    delete pinfo;
    exit(0);
}
