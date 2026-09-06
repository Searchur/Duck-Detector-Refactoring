/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lsposed/probes/cgroup_anomaly_probe.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vector>

namespace duckdetector::lsposed {
    namespace {

        constexpr const char *kCgroupRootBases[] = {
                "/sys/fs/cgroup",
                "/sys/fs/cgroup/apps",
                "/sys/fs/cgroup/system",
        };

        struct CgroupNodeInfo {
            bool exists = false;
            bool accessible = false;
            mode_t mode = 0;
            uid_t uid = static_cast<uid_t>(-1);
            gid_t gid = static_cast<gid_t>(-1);
            int parent_uid = -1;
            std::string path;
        };

        std::string read_file_chunk(const char *path, const size_t max_size) {
            const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC));
            if (fd < 0) {
                return "";
            }

            std::string buffer;
            buffer.resize(max_size);
            const ssize_t bytes_read = syscall(__NR_read, fd, buffer.data(), max_size);
            syscall(__NR_close, fd);

            if (bytes_read <= 0) {
                return "";
            }

            buffer.resize(static_cast<size_t>(bytes_read));
            return buffer;
        }

        // Process verification matching Luna libBugly.so:
        // Step 1: kill(pid, 0) - verifies existence in kernel process table.
        // Step 2: tgkill(pid, pid, 0) - verifies thread group leader (Luna sub_3CCB0).
        //         In Linux kernel (kernel/signal.c do_tkill):
        //         tgkill(tgid, pid, 0) checks if (tgid > 0 && task_tgid_vnr(p) != tgid) return -ESRCH;
        //         For secondary threads, task->tgid != pid, so kernel ALWAYS returns -ESRCH (errno 3).
        //         For process group leaders (main threads), task->tgid == pid, kernel checks
        //         permissions and returns 0 or -EPERM (errno 1).
        //         This cleanly eliminates all secondary threads (TIDs), which do NOT have cgroup nodes!
        // Step 3: process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) - verifies task->mm (Luna sub_3C194).
        //         Kernel threads have task->mm == NULL, causing process_vm_rw to return -ESRCH (errno 3).
        //         Real user processes have task->mm != NULL, returning > 0 or EPERM (1) / EACCES (13).
        bool is_user_process_alive(const int pid) {
            if (pid <= 1) {
                return false;
            }

            // Step 1: Check process existence in kernel process table
            errno = 0;
            const long kill_ret = syscall(__NR_kill, pid, 0);
            const int kill_err = (kill_ret >= 0) ? 0 : errno;
            if (kill_ret != 0 && kill_err != EPERM) {
                return false;
            }

            // Step 2: Thread group leader check (Luna sub_3CCB0 via tgkill)
            errno = 0;
#if defined(__NR_tgkill)
            const long tg_ret = syscall(__NR_tgkill, pid, pid, 0);
#elif defined(__aarch64__)
            const long tg_ret = syscall(131, pid, pid, 0);
#elif defined(__arm__)
            const long tg_ret = syscall(268, pid, pid, 0);
#elif defined(__x86_64__)
            const long tg_ret = syscall(234, pid, pid, 0);
#elif defined(__i386__)
            const long tg_ret = syscall(270, pid, pid, 0);
#else
            const long tg_ret = -1;
            errno = ENOSYS;
#endif
            const int tg_err = (tg_ret >= 0) ? 0 : errno;
            if (tg_ret != 0 && tg_err != EPERM) {
                return false;
            }

            // Step 3: Inspect task mm_struct presence via process_vm_readv (Luna sub_3C194)
            uint8_t dummy = 0;
            struct iovec local_iov {
                .iov_base = &dummy,
                .iov_len = 1,
            };
            struct iovec remote_iov {
                .iov_base = &dummy,
                .iov_len = 1,
            };

            errno = 0;
#if defined(__NR_process_vm_readv)
            const long ret = syscall(__NR_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1, 0);
#elif defined(__aarch64__)
            const long ret = syscall(270, pid, &local_iov, 1, &remote_iov, 1, 0);
#elif defined(__arm__)
            const long ret = syscall(376, pid, &local_iov, 1, &remote_iov, 1, 0);
#elif defined(__x86_64__)
            const long ret = syscall(310, pid, &local_iov, 1, &remote_iov, 1, 0);
#elif defined(__i386__)
            const long ret = syscall(347, pid, &local_iov, 1, &remote_iov, 1, 0);
#else
            const long ret = -1;
            errno = ENOSYS;
#endif
            const int vm_err = (ret > 0) ? 0 : errno;
            if (ret > 0 || vm_err == EPERM || vm_err == EACCES) {
                return true;
            }

            return false;
        }

        int get_proc_uid(const int pid) {
            if (pid <= 0) return -1;
            char path[64];
            std::snprintf(path, sizeof(path), "/proc/%d", pid);
            struct stat st{};
            if (stat(path, &st) == 0) {
                return static_cast<int>(st.st_uid);
            }
            return -1;
        }

        bool parse_proc_status(
                const int pid,
                int &out_uid,
                int &out_tgid
        ) {
            out_uid = get_proc_uid(pid);
            out_tgid = pid;

            char path[128];
            std::snprintf(path, sizeof(path), "/proc/%d/status", pid);
            const std::string text = read_file_chunk(path, 2048);
            if (!text.empty()) {
                std::istringstream stream(text);
                std::string line;
                while (std::getline(stream, line)) {
                    if (line.rfind("Uid:", 0) == 0) {
                        const char *p = line.c_str() + 4;
                        while (*p == ' ' || *p == '\t') ++p;
                        out_uid = std::atoi(p);
                    } else if (line.rfind("Tgid:", 0) == 0) {
                        const char *p = line.c_str() + 5;
                        while (*p == ' ' || *p == '\t') ++p;
                        out_tgid = std::atoi(p);
                    }
                    if (out_uid >= 0 && out_tgid >= 0) {
                        break;
                    }
                }
            }

            return out_uid >= 0;
        }

        std::string read_proc_cmdline(const int pid) {
            char path[128];
            std::snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            std::string cmd = read_file_chunk(path, 256);
            for (char &c: cmd) {
                if (c == '\0') {
                    c = ' ';
                }
            }
            while (!cmd.empty() && cmd.back() == ' ') {
                cmd.pop_back();
            }
            return cmd;
        }

        // Exactly matching Luna sub_3B080:
        // Performs stat(path, &st).
        // If stat succeeds: exists = true, accessible = true.
        // If stat fails with EACCES or EPERM: exists = true, accessible = false.
        // Otherwise (e.g. ENOENT): exists = false, accessible = false.
        CgroupNodeInfo probe_single_path(const char *path, const int uid) {
            CgroupNodeInfo info;
            struct stat st{};
            errno = 0;
            if (stat(path, &st) == 0) {
                info.exists = true;
                info.accessible = true;
                info.mode = st.st_mode;
                info.uid = st.st_uid;
                info.gid = st.st_gid;
                info.parent_uid = uid;
                info.path = path;
                return info;
            }

            const int err = errno;
            if (err == EACCES || err == EPERM) {
                info.exists = true;
                info.accessible = false;
                info.parent_uid = uid;
                info.path = path;
                return info;
            }

            return info;
        }

        // Check cgroup node by UID matching Luna's exact path layouts with trailing slash:
        // /sys/fs/cgroup/apps/uid_%d/pid_%d/
        // /sys/fs/cgroup/system/uid_%d/pid_%d/
        // /sys/fs/cgroup/uid_%d/pid_%d/
        CgroupNodeInfo query_cgroup_pid_node(const int uid, const int pid) {
            char path[256];

            // Probe 0: Check /proc/<pid>/cgroup if readable
            char proc_cg_path[64];
            std::snprintf(proc_cg_path, sizeof(proc_cg_path), "/proc/%d/cgroup", pid);
            const std::string cg_text = read_file_chunk(proc_cg_path, 512);
            if (!cg_text.empty()) {
                std::istringstream stream(cg_text);
                std::string line;
                while (std::getline(stream, line)) {
                    const size_t last_colon = line.rfind(':');
                    if (last_colon != std::string::npos && last_colon + 1 < line.size()) {
                        std::string rel = line.substr(last_colon + 1);
                        while (!rel.empty() && (rel.back() == '\r' || rel.back() == '\n' || rel.back() == ' ')) {
                            rel.pop_back();
                        }
                        if (rel.size() > 1 && rel[0] == '/') {
                            std::snprintf(path, sizeof(path), "/sys/fs/cgroup%s/", rel.c_str());
                            CgroupNodeInfo info = probe_single_path(path, uid);
                            if (info.exists) return info;
                        }
                    }
                }
            }

            // Probe 1: Apps hierarchy
            std::snprintf(path, sizeof(path), "/sys/fs/cgroup/apps/uid_%d/pid_%d/", uid, pid);
            CgroupNodeInfo info = probe_single_path(path, uid);
            if (info.exists) return info;

            // Probe 2: System hierarchy
            std::snprintf(path, sizeof(path), "/sys/fs/cgroup/system/uid_%d/pid_%d/", uid, pid);
            info = probe_single_path(path, uid);
            if (info.exists) return info;

            // Probe 3: Flat hierarchy
            std::snprintf(path, sizeof(path), "/sys/fs/cgroup/uid_%d/pid_%d/", uid, pid);
            info = probe_single_path(path, uid);
            if (info.exists) return info;

            return {};
        }

        // Discover existing UIDs by enumerating cgroup directories (Luna sub_37CEC & sub_39718)
        std::set<int> discover_cgroup_uids(const uid_t my_uid) {
            std::set<int> uids = {0, 1000, 2000, static_cast<int>(my_uid)};

            // Method 1: Directory enumeration (Luna sub_37CEC)
            for (const char *base: kCgroupRootBases) {
                DIR *dir = opendir(base);
                if (!dir) continue;

                struct dirent *entry = nullptr;
                while ((entry = readdir(dir)) != nullptr) {
                    if (std::strncmp(entry->d_name, "uid_", 4) == 0) {
                        const int parsed_uid = std::atoi(entry->d_name + 4);
                        if (parsed_uid >= 0) {
                            char subpath[256];
                            std::snprintf(subpath, sizeof(subpath), "%s/%s", base, entry->d_name);
                            struct stat st{};
                            if (stat(subpath, &st) == 0 || errno == EACCES || errno == EPERM) {
                                uids.insert(parsed_uid);
                            }
                        }
                    }
                }
                closedir(dir);
            }

            // Method 2: Direct probing of standard Android UID ranges (Luna sub_39718)
            // When opendir() is blocked by SELinux, Luna tests paths directly with stat()
            auto check_uid_dir = [&](const char *fmt, int uid) {
                char path[256];
                std::snprintf(path, sizeof(path), fmt, uid);
                struct stat st{};
                return (stat(path, &st) == 0 || errno == EACCES || errno == EPERM);
            };

            // System UIDs (0..1100)
            for (int u = 0; u <= 1100; ++u) {
                if (check_uid_dir("/sys/fs/cgroup/system/uid_%d", u) ||
                    check_uid_dir("/sys/fs/cgroup/uid_%d", u)) {
                    uids.insert(u);
                }
            }

            // App UIDs (10000..12000)
            for (int u = 10000; u <= 12000; ++u) {
                if (check_uid_dir("/sys/fs/cgroup/apps/uid_%d", u) ||
                    check_uid_dir("/sys/fs/cgroup/uid_%d", u)) {
                    uids.insert(u);
                }
            }

            return uids;
        }

    }  // namespace

    ProbeResult scan_cgroup_anomalies() {
        ProbeResult result;
        result.available = false;

        // Verify cgroup filesystem accessibility
        struct stat root_st{};
        if (stat("/sys/fs/cgroup", &root_st) != 0 && errno != EACCES && errno != EPERM) {
            return result;
        }
        result.available = true;

        const pid_t my_pid = getpid();
        const pid_t ppid = getppid();
        const uid_t my_uid = getuid();

        std::set<int> discovered_uids = discover_cgroup_uids(my_uid);
        const std::string mountinfo = read_file_chunk("/proc/self/mountinfo", 32768);

        // Luna's exact adaptive scanning algorithm (Java_luna_safe_luna_MainActivity_findlsp):
        // 1. Pass 1: Primary scan window centered around Zygote (ppid - 600, ppid + 400).
        // 2. Pass 2: Extension range (ppid + 800, ppid + 1500) executed when alive_count in Pass 1 >= 60.
        // 3. Fallback: Secondary ranges [950, 1950] and [2350, 3050] when alive_count < 60 or ppid <= 1.
        std::vector<int> target_pids;
        std::set<int> seen_pids;

        auto add_pids_in_range = [&](const int start, const int end) {
            for (int p = start; p <= end; ++p) {
                if (p <= 1 || p == my_pid || p == ppid || seen_pids.count(p)) continue;
                if (is_user_process_alive(p)) {
                    target_pids.push_back(p);
                    seen_pids.insert(p);
                }
            }
        };

        if (ppid > 1 && ppid <= 10000) {
            const int ppid_val = static_cast<int>(ppid);
            const size_t pass1_start = target_pids.size();
            add_pids_in_range(std::max(2, ppid_val - 600), ppid_val + 400);
            const size_t pass1_alive = target_pids.size() - pass1_start;

            if (pass1_alive >= 60) {
                // Luna sub_2F470 call at 0x22E18: [ppid + 800, ppid + 1500]
                add_pids_in_range(ppid_val + 800, ppid_val + 1500);
            } else {
                // Luna sub_2F470 fallback calls at 0x22FE0 and 0x23000
                add_pids_in_range(950, 1950);
                add_pids_in_range(2350, 3050);
            }
        } else {
            add_pids_in_range(950, 1950);
            add_pids_in_range(2350, 3050);
        }

        if (target_pids.size() < 60) {
            add_pids_in_range(950, 1950);
            add_pids_in_range(2350, 3050);
        }

        // Pre-seed discovered_uids with procfs inode owner UIDs of all target processes
        for (const int pid: target_pids) {
            const int u = get_proc_uid(pid);
            if (u >= 0) {
                discovered_uids.insert(u);
            }
        }

        result.scanned_count = static_cast<int>(target_pids.size());

        int abnormal_count = 0;
        int max_score = 0;
        uint32_t cumulative_reason_mask = 0;
        std::vector<int> suspicious_pids;

        for (const int pid: target_pids) {
            // Strictly matching Luna sub_2F470 (0x32228):
            // Low PIDs (< 900) such as init and early kernel daemons are ignored.
            if (pid < 900) {
                continue;
            }

            // Strictly matching Luna sub_2F470:
            // Re-verify process liveness at the exact moment of inspection.
            // If the process has terminated (e.g. transient worker/command), skip it!
            if (!is_user_process_alive(pid)) {
                continue;
            }

            int score = 1;              // Luna default base score (0x31C80: v274 = 1)
            uint32_t reason_mask = 0x01; // Luna default base reason (0x31C80: v275 = 1)

            // Step 2: Mountinfo residual check (0x30960 & 0x319B8)
            // Checks if " <cmdline> " appears in /proc/self/mountinfo.
            // If found, Luna sets v274 = 5, v275 = 3 (base score = 5, base reason = 0x03)
            const std::string cmdline = read_proc_cmdline(pid);
            if (!cmdline.empty() && !mountinfo.empty()) {
                const std::string needle = " " + cmdline + " ";
                if (mountinfo.find(needle) != std::string::npos) {
                    score = 5;
                    reason_mask = 0x03;
                }
            }

            // Step 3: Procfs status inspection
            int proc_uid = -1;
            int proc_tgid = -1;
            const bool status_ok = parse_proc_status(pid, proc_uid, proc_tgid);

            // TGID discrepancy check (Luna sub_2F470 0x33778: v296 = v381 + 1, reason |= 0x40)
            if (status_ok && proc_tgid > 0 && proc_tgid != pid) {
                score += 1;
                reason_mask |= 0x40;
            }

            // Step 4: Cgroup node discovery
            CgroupNodeInfo cgroup_info;
            if (status_ok && proc_uid >= 0) {
                cgroup_info = query_cgroup_pid_node(proc_uid, pid);
            }
            if (!cgroup_info.exists) {
                // Fallback loop through all discovered UIDs, exactly like Luna sub_2F470
                for (const int uid: discovered_uids) {
                    if (uid == proc_uid) continue;
                    cgroup_info = query_cgroup_pid_node(uid, pid);
                    if (cgroup_info.exists) {
                        break;
                    }
                }
            }

            // Step 5: Cgroup anomaly evaluation (Luna sub_2F470 0x31470 & sub_3D668)
            if (!cgroup_info.exists) {
                // Process is confirmed alive in the kernel, but its cgroup directory was hidden/missing.
                // Luna sub_2F470 line 519: v296 = v377 + 4 (Score += 4).
                // With base score >= 1, score becomes >= 5!
                score += 4;
                if (status_ok && proc_uid >= 0) {
                    reason_mask |= 0x08;  // Procfs status visible, but cgroup node hidden
                } else {
                    reason_mask |= 0x04;  // Both procfs status and cgroup node missing/hidden
                }
            } else {
                // Cgroup node exists. Only inspect inode metadata if stat was accessible.
                if (cgroup_info.accessible) {
                    // Exactly matching Luna sub_3D668:
                    // If pid > 2999 (App UIDs / user space), it returns 0 (Clean).
                    // Only for system service PIDs (<= 2999) belonging to system UIDs (<= 2999),
                    // enforce directory mode 040755 and 1000:1000 ownership.
                    if (pid <= 2999 && cgroup_info.parent_uid <= 2999) {
                        const bool mode_match = ((cgroup_info.mode & ~0x10) == 040755);
                        const bool owner_match = (cgroup_info.uid == 1000 && cgroup_info.gid == 1000);
                        if (!mode_match || !owner_match) {
                            score += 3;
                            reason_mask |= 0x30;  // 0x10 | 0x20
                        }
                    }
                }
            }

            // Step 6: Accumulate anomalies
            // STRICTLY matching Luna sub_3E27C:
            // A process is ONLY considered an anomaly if score >= 5 (score > 4).
            // Normal processes have score = 1 (< 5), so they are NEVER accumulated!
            if (score >= 5) {
                abnormal_count++;
                max_score = std::max(max_score, score);
                cumulative_reason_mask |= reason_mask;
                if (suspicious_pids.size() < 16) {
                    suspicious_pids.push_back(pid);
                }
            }
        }

        // Step 7: Match Luna's exact decision threshold (sub_36F2C 0x37AE0 & findlsp 0x23F80):
        // In Luna sub_36F2C:
        //   37ae0: CMP W8, #3
        //   37aec: CSEL W9, W9, W8, GT   ; Only if abnormal_count > 3
        //   37c2c: STR WZR, [X8]        ; abnormal_count = 0
        //   37c34: STR WZR, [X8]        ; max_score = 0
        //   37c3c: STR WZR, [X8]        ; reason_mask = 0
        //   37c44: STR WZR, [X8]        ; alert = 0
        // Luna requires abnormal_count > 3 to trigger detection, treating <= 3 anomalies as
        // transient operating system noise (e.g. processes exiting mid-scan).
        if (abnormal_count <= 3) {
            abnormal_count = 0;
            max_score = 0;
            cumulative_reason_mask = 0;
            suspicious_pids.clear();
        }

        result.hit_count = abnormal_count;

        if (abnormal_count > 0 && max_score >= 5) {
            std::ostringstream detail;
            detail << "total_scanned=" << result.scanned_count
                   << " abnormal_count=" << abnormal_count
                   << " max_score=" << max_score
                   << " reason_mask=0x" << std::hex << cumulative_reason_mask << std::dec
                   << " suspicious_pids=";

            for (size_t i = 0; i < suspicious_pids.size(); ++i) {
                if (i > 0) detail << ",";
                detail << suspicious_pids[i];
            }
            if (abnormal_count > static_cast<int>(suspicious_pids.size())) {
                detail << "...";
            }

            result.traces.push_back(NativeTrace{
                    .group = "CGROUP",
                    .label = "Framework trace hiding (cgroup anomaly)",
                    .detail = detail.str(),
                    .severity = Severity::kDanger,
            });
        }

        return result;
    }

}  // namespace duckdetector::lsposed
