#include <bits/stdc++.h>
#include <filesystem>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

namespace fs = std::filesystem;

using ull = unsigned long long;

struct ProcStat {
    pid_t pid;
    std::string user;
    std::string cmd;
    ull utime = 0;
    ull stime = 0;
    ull starttime = 0;
    ull vsize = 0;
    long rss = 0;
    double cpu_percent = 0.0;
    double mem_percent = 0.0;
    ull total_time() const { return utime + stime; }
};

struct CpuTimes {
    ull user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;
    ull total() const { return user+nice+system+idle+iowait+irq+softirq+steal; }
};

static long PAGE_SIZE = sysconf(_SC_PAGESIZE);
static long CLK_TCK = sysconf(_SC_CLK_TCK);
static ull last_total_cpu = 0;

// read CPU totals from /proc/stat
CpuTimes read_total_cpu() {
    CpuTimes ct;
    std::ifstream f("/proc/stat");
    std::string line;
    if (!f.is_open()) return ct;
    std::getline(f, line);
    std::istringstream ss(line);
    std::string cpu;
    ss >> cpu >> ct.user >> ct.nice >> ct.system >> ct.idle >> ct.iowait >> ct.irq >> ct.softirq >> ct.steal;
    return ct;
}

// read memory totals from /proc/meminfo
ull get_total_memory_kb() {
    std::ifstream f("/proc/meminfo");
    std::string key;
    ull val;
    std::string unit;
    while (f >> key >> val >> unit) {
        if (key == "MemTotal:") return val; // in KB
    }
    return 0;
}

std::string uid_to_name(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (pw) return pw->pw_name;
    return std::to_string(uid);
}

bool is_number(const std::string &s){
    for(char c: s) if(!isdigit(c)) return false;
    return !s.empty();
}

// read per-process stats
bool read_proc_stat(pid_t pid, ProcStat &p) {
    std::string base = "/proc/" + std::to_string(pid) + "/";
    std::ifstream statf(base + "stat");
    if (!statf.is_open()) return false;
    std::string statline;
    std::getline(statf, statline);
    // parsing /proc/[pid]/stat is tricky because comm can have spaces inside parentheses
    // find first '(' and last ')'
    auto lpar = statline.find('(');
    auto rpar = statline.rfind(')');
    if (lpar == std::string::npos || rpar == std::string::npos || rpar <= lpar) return false;
    std::string comm = statline.substr(lpar + 1, rpar - lpar - 1);
    std::string rest = statline.substr(rpar + 2);
    std::istringstream ss(rest);
    char state;
    // fields after comm start at field 3 (pid, comm, state, ppid, ...)
    ss >> state;
    // skip some fields we don't need: ppid, pgrp, session, tty_nr, tpgid
    for (int i = 0; i < 4; ++i) {
        long tmp; ss >> tmp;
    }
    ull utime=0, stime=0, cutime=0, cstime=0, priority=0, nice=0;
    ull num_threads=0;
    long itrealvalue=0;
    ull starttime=0;
    // there are many fields; we need utime (14), stime (15), starttime (22)
    ss >> utime >> stime;
    // skip fields until we get to num_threads (we'll approximate by seeking)
    // Continue reading fields until we reach starttime index (we have read up to field 15)
    for(int i=0;i<6;i++){ ss >> num_threads; } // move forward roughly
    // Better approach: re-tokenize full statline skipping comm part
    std::vector<std::string> tokens;
    {
        std::istringstream ss2(rest);
        std::string tk;
        while (ss2 >> tk) tokens.push_back(tk);
    }
    // token indexes (0-based): 0=state, 11=utime,12=stime, 19=starttime (since rest started after comm and a space)
    // But safety check:
    if (tokens.size() > 19) {
        utime = std::stoull(tokens[11]);
        stime = std::stoull(tokens[12]);
        starttime = std::stoull(tokens[19]);
    } else {
        // fallback earlier parsed values
        // we'll attempt to continue
        // try reading /proc/[pid]/stat again but simpler; if fails, return false
        return false;
    }

    p.pid = pid;
    p.cmd = comm;
    p.utime = utime;
    p.stime = stime;
    p.starttime = starttime;

    // read memory info: rss and vsize from stat tokens: vsize token index 10
    if (tokens.size() > 10) {
        p.vsize = std::stoull(tokens[9]);
        p.rss = std::stoll(tokens[10]);
    }

    // get cmdline if available (more descriptive)
    std::ifstream cmdf(base + "cmdline");
    if (cmdf.is_open()) {
        std::string cmdline;
        std::getline(cmdf, cmdline, '\0');
        if (!cmdline.empty()) {
            // cmdline is \0 separated; convert nulls to spaces
            for(char &c: cmdline) if(c == '\0') c = ' ';
            p.cmd = cmdline;
        }
    }

    // user id from /proc/[pid]/status or stat file? Use status:
    std::ifstream statusf(base + "status");
    if (statusf.is_open()) {
        std::string line;
        while (std::getline(statusf, line)) {
            if (line.rfind("Uid:",0) == 0) {
                std::istringstream t(line.substr(4));
                uid_t uid;
                t >> uid;
                p.user = uid_to_name(uid);
                break;
            }
        }
    } else {
        p.user = "-";
    }

    return true;
}

std::vector<pid_t> list_pids() {
    std::vector<pid_t> pids;
    for (auto &entry: fs::directory_iterator("/proc")) {
        std::string name = entry.path().filename().string();
        if (is_number(name)) {
            pids.push_back(static_cast<pid_t>(std::stoi(name)));
        }
    }
    return pids;
}

// collect snapshot of all processes
std::unordered_map<pid_t, ProcStat> collect_snapshot() {
    std::unordered_map<pid_t, ProcStat> map;
    auto pids = list_pids();
    for (auto pid: pids) {
        ProcStat p;
        if (read_proc_stat(pid, p)) {
            map[pid] = p;
        }
    }
    return map;
}

void clear_screen() {
    // ANSI clear
    std::cout << "\033[2J\033[1;1H";
}

void print_header() {
    std::cout << " PID    USER        CPU%    MEM%     RSS(KB)   CMD\n";
    std::cout << "-------------------------------------------------------------\n";
}

int main(int argc, char** argv) {
    int refresh_interval = 2; // seconds
    if (argc > 1) refresh_interval = std::max(1, std::atoi(argv[1]));

    ull total_mem_kb = get_total_memory_kb();
    if (total_mem_kb == 0) total_mem_kb = 1;

    // first snapshot
    auto snap1 = collect_snapshot();
    CpuTimes cpu1 = read_total_cpu();
    ull total_cpu1 = cpu1.total();

    while (true) {
        sleep(refresh_interval);

        auto snap2 = collect_snapshot();
        CpuTimes cpu2 = read_total_cpu();
        ull total_cpu2 = cpu2.total();
        ull delta_total_cpu = (total_cpu2 > total_cpu1) ? (total_cpu2 - total_cpu1) : 1;

        // compute CPU% and mem% for each pid present in snap2
        std::vector<ProcStat> procs;
        for (auto &kv: snap2) {
            pid_t pid = kv.first;
            ProcStat p2 = kv.second;
            if (snap1.find(pid) != snap1.end()) {
                ProcStat p1 = snap1[pid];
                ull proc_time_diff = 0;
                if (p2.total_time() >= p1.total_time()) proc_time_diff = p2.total_time() - p1.total_time();
                double cpu_percent = 100.0 * (double(proc_time_diff) / double(delta_total_cpu));
                p2.cpu_percent = cpu_percent;
            } else {
                // new process - approximate using its total_time relative to delta_total_cpu
                p2.cpu_percent = 0.0;
            }
            // memory: rss * page_size / total_mem_kb
            ull rss_kb = (ull)p2.rss * (PAGE_SIZE/1024);
            p2.mem_percent = 100.0 * double(rss_kb) / double(total_mem_kb);
            procs.push_back(p2);
        }

        // sort by CPU% descending by default
        std::sort(procs.begin(), procs.end(), [](const ProcStat &a, const ProcStat &b){
            return a.cpu_percent > b.cpu_percent;
        });

        // display
        clear_screen();
        std::cout << "Simple System Monitor — refresh " << refresh_interval << "s  (type 'h' Enter for help)\n";
        print_header();
        int printed = 0;
        for (auto &p: procs) {
            // limit printed rows to keep it readable
            if (++printed > 50) break;
            ull rss_kb = (ull)p.rss * (PAGE_SIZE/1024);
            printf("%5d  %-10s  %6.2f  %6.2f  %8llu   %.60s\n",
                p.pid, p.user.c_str(), p.cpu_percent, p.mem_percent, (unsigned long long)rss_kb, p.cmd.c_str()
            );
        }

        std::cout << "\nCommands: (s)ort cpu|mem, (k)ill <pid>, (r)set interval, (l)ist all, (q)uit\n";
        std::cout << "Enter command: ";
        std::string cmdline;
        if (!std::getline(std::cin, cmdline)) break;
        if (cmdline.empty()) {
            // just continue refresh
        } else {
            std::istringstream cs(cmdline);
            std::string cmd;
            cs >> cmd;
            if (cmd == "q" || cmd == "quit") {
                break;
            } else if (cmd == "s" || cmd == "sort") {
                std::string by;
                cs >> by;
                if (by == "mem") {
                    std::sort(procs.begin(), procs.end(), [](const ProcStat &a, const ProcStat &b){
                        return a.mem_percent > b.mem_percent;
                    });
                } else { // cpu default
                    std::sort(procs.begin(), procs.end(), [](const ProcStat &a, const ProcStat &b){
                        return a.cpu_percent > b.cpu_percent;
                    });
                }
                clear_screen();
                std::cout << "Sorted by " << (by=="mem"?"MEM":"CPU") << "\n";
                print_header();
                printed = 0;
                for (auto &p: procs) {
                    if (++printed > 50) break;
                    ull rss_kb = (ull)p.rss * (PAGE_SIZE/1024);
                    printf("%5d  %-10s  %6.2f  %6.2f  %8llu   %.60s\n",
                        p.pid, p.user.c_str(), p.cpu_percent, p.mem_percent, (unsigned long long)rss_kb, p.cmd.c_str()
                    );
                }
                std::cout << "\nPress Enter to continue...";
                std::getline(std::cin, cmdline);
            } else if (cmd == "k" || cmd == "kill") {
                int pid; cs >> pid;
                if (pid <= 0) {
                    std::cout << "Invalid pid\nPress Enter...";
                    std::getline(std::cin, cmdline);
                } else {
                    if (kill(pid, SIGTERM) == 0) {
                        std::cout << "SIGTERM sent to " << pid << "\n";
                    } else {
                        perror("kill");
                    }
                    std::cout << "Press Enter...";
                    std::getline(std::cin, cmdline);
                }
            } else if (cmd == "r" || cmd == "reset") {
                int it; cs >> it;
                if (it > 0) refresh_interval = it;
            } else if (cmd == "l" || cmd == "list") {
                clear_screen();
                std::cout << "All processes:\n";
                print_header();
                for (auto &p: procs) {
                    ull rss_kb = (ull)p.rss * (PAGE_SIZE/1024);
                    printf("%5d  %-10s  %6.2f  %6.2f  %8llu   %.60s\n",
                        p.pid, p.user.c_str(), p.cpu_percent, p.mem_percent, (unsigned long long)rss_kb, p.cmd.c_str()
                    );
                }
                std::cout << "\nPress Enter...";
                std::getline(std::cin, cmdline);
            } else if (cmd == "h" || cmd == "help") {
                clear_screen();
                std::cout << "Help:\n";
                std::cout << " s mem    -> sort by memory\n";
                std::cout << " s cpu    -> sort by cpu\n";
                std::cout << " k <pid>  -> send SIGTERM to pid (may require sudo for some pids)\n";
                std::cout << " r <sec>  -> reset refresh interval in seconds\n";
                std::cout << " l        -> list all displayed processes\n";
                std::cout << " q        -> quit\n";
                std::cout << "\nPress Enter...";
                std::getline(std::cin, cmdline);
            } else {
                std::cout << "Unknown command '" << cmd << "'\nPress Enter...";
                std::getline(std::cin, cmdline);
            }
        }

        // prepare for next cycle
        snap1 = std::move(snap2);
        total_cpu1 = total_cpu2;
    }

    std::cout << "Exiting.\n";
    return 0;
}
