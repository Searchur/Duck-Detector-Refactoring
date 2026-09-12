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
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
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

        // Luna findlsp liveness probe: kill(pid, 0) only (EPERM still means alive).
        bool is_user_process_alive(const int pid) {
            if (pid <= 1) {
                return false;
            }

            errno = 0;
            const long kill_ret = syscall(__NR_kill, pid, 0);
            return kill_ret == 0 || errno == EPERM;
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

        // Probe one cgroup path:
        // stat success => exists and accessible; EACCES/EPERM => exists but blocked;
        // otherwise try mkdirat and treat EEXIST as exists-but-inaccessible.
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

            errno = 0;
#if defined(__NR_mkdirat)
            const long mk_ret = syscall(__NR_mkdirat, AT_FDCWD, path, 0755);
#elif defined(__NR_mkdir)
            const long mk_ret = syscall(__NR_mkdir, path, 0755);
#else
            const long mk_ret = -1;
#endif
            if (mk_ret == -1 && errno == EEXIST) {
                info.exists = true;
                info.accessible = false;
                info.parent_uid = uid;
                info.path = path;
                return info;
            }

            return info;
        }

        struct CgroupLayout {
            bool flat = false;
            bool system = false;
            bool apps = false;

            bool usable() const { return flat || system || apps; }
        };

        struct EnumeratedCgroupPids {
            std::set<int> pids;
            std::map<int, int> pid_uids;  // pid -> parent uid from uid_* path
        };

        // Return true when the path exists, including permission-denied or mkdirat EEXIST.
        bool path_exists_strict(const char *path) {
            struct stat st{};
            if (stat(path, &st) == 0) {
                return true;
            }
            const int err = errno;
            if (err == EACCES || err == EPERM) {
                return true;
            }
            errno = 0;
#if defined(__NR_mkdirat)
            const long mk_ret = syscall(__NR_mkdirat, AT_FDCWD, path, 0755);
#elif defined(__NR_mkdir)
            const long mk_ret = syscall(__NR_mkdir, path, 0755);
#else
            const long mk_ret = -1;
#endif
            return (mk_ret == -1 && errno == EEXIST);
        }

        bool dir_has_uid_entries(const char *base) {
            DIR *dir = opendir(base);
            if (!dir) {
                return false;
            }
            struct dirent *entry = nullptr;
            while ((entry = readdir(dir)) != nullptr) {
                if (std::strncmp(entry->d_name, "uid_", 4) == 0) {
                    closedir(dir);
                    return true;
                }
            }
            closedir(dir);
            return false;
        }

        // Detect which per-uid layouts exist: flat, system/, and/or apps/.
        CgroupLayout detect_cgroup_layout() {
            CgroupLayout layout;
            layout.flat = dir_has_uid_entries("/sys/fs/cgroup") ||
                          path_exists_strict("/sys/fs/cgroup/uid_0");
            layout.system = dir_has_uid_entries("/sys/fs/cgroup/system") ||
                            path_exists_strict("/sys/fs/cgroup/system/uid_0");
            layout.apps = dir_has_uid_entries("/sys/fs/cgroup/apps");
            if (!layout.apps) {
                char path[128];
                std::snprintf(path, sizeof(path), "/sys/fs/cgroup/apps/uid_%d",
                              static_cast<int>(getuid()));
                layout.apps = path_exists_strict(path);
            }
            return layout;
        }

        // Walk readable uid_*/pid_* directories and record pid ownership.
        EnumeratedCgroupPids enumerate_cgroup_pids(const CgroupLayout &layout) {
            EnumeratedCgroupPids out;

            auto walk_uid_base = [&](const char *base) {
                DIR *uid_dir = opendir(base);
                if (!uid_dir) {
                    return;
                }
                struct dirent *uid_ent = nullptr;
                while ((uid_ent = readdir(uid_dir)) != nullptr) {
                    if (std::strncmp(uid_ent->d_name, "uid_", 4) != 0) {
                        continue;
                    }
                    const int uid = std::atoi(uid_ent->d_name + 4);
                    char uid_path[256];
                    std::snprintf(uid_path, sizeof(uid_path), "%s/%s", base, uid_ent->d_name);
                    DIR *pid_dir = opendir(uid_path);
                    if (!pid_dir) {
                        continue;
                    }
                    struct dirent *pid_ent = nullptr;
                    while ((pid_ent = readdir(pid_dir)) != nullptr) {
                        if (std::strncmp(pid_ent->d_name, "pid_", 4) != 0) {
                            continue;
                        }
                        const int pid = std::atoi(pid_ent->d_name + 4);
                        if (pid > 1) {
                            out.pids.insert(pid);
                            out.pid_uids[pid] = uid;
                        }
                    }
                    closedir(pid_dir);
                }
                closedir(uid_dir);
            };

            if (layout.flat) {
                walk_uid_base("/sys/fs/cgroup");
            }
            if (layout.system) {
                walk_uid_base("/sys/fs/cgroup/system");
            }
            if (layout.apps) {
                walk_uid_base("/sys/fs/cgroup/apps");
            }

            return out;
        }

        // Look up uid_*/pid_* under apps/, system/, then flat roots.
        CgroupNodeInfo query_cgroup_pid_node(
                const int uid,
                const int pid,
                const CgroupLayout &layout
        ) {
            char path[256];
            (void) layout;

            std::snprintf(path, sizeof(path), "/sys/fs/cgroup/apps/uid_%d/pid_%d/", uid, pid);
            CgroupNodeInfo info = probe_single_path(path, uid);
            if (info.exists) return info;

            std::snprintf(path, sizeof(path), "/sys/fs/cgroup/system/uid_%d/pid_%d/", uid, pid);
            info = probe_single_path(path, uid);
            if (info.exists) return info;

            std::snprintf(path, sizeof(path), "/sys/fs/cgroup/uid_%d/pid_%d/", uid, pid);
            info = probe_single_path(path, uid);
            if (info.exists) return info;

            return {};
        }

        // Collect candidate UIDs by directory listing and common Android uid ranges.
        std::set<int> discover_cgroup_uids(const uid_t my_uid, const CgroupLayout &layout) {
            std::set<int> uids = {0, 1000, 2000, static_cast<int>(my_uid)};
            if (!layout.usable()) {
                return uids;
            }

            for (const char *base: kCgroupRootBases) {
                DIR *dir = opendir(base);
                if (!dir) continue;

                struct dirent *entry = nullptr;
                while ((entry = readdir(dir)) != nullptr) {
                    if (std::strncmp(entry->d_name, "uid_", 4) == 0) {
                        const int parsed_uid = std::atoi(entry->d_name + 4);
                        if (parsed_uid >= 0) {
                            uids.insert(parsed_uid);
                        }
                    }
                }
                closedir(dir);
            }

            auto check_uid_dir = [&](const char *fmt, int uid) {
                char path[256];
                std::snprintf(path, sizeof(path), fmt, uid);
                return path_exists_strict(path);
            };

            auto probe_app_uid_range = [&](const int begin, const int end) {
                for (int u = begin; u <= end; ++u) {
                    if ((layout.apps && check_uid_dir("/sys/fs/cgroup/apps/uid_%d", u)) ||
                        check_uid_dir("/sys/fs/cgroup/uid_%d", u)) {
                        uids.insert(u);
                    }
                }
            };

            if (layout.system) {
                for (int u = 0; u <= 1100; ++u) {
                    if (check_uid_dir("/sys/fs/cgroup/system/uid_%d", u) ||
                        check_uid_dir("/sys/fs/cgroup/uid_%d", u)) {
                        uids.insert(u);
                    }
                }
            }

            if (layout.flat) {
                for (int u = 0; u <= 1100; ++u) {
                    if (check_uid_dir("/sys/fs/cgroup/uid_%d", u)) {
                        uids.insert(u);
                    }
                }
            }

            probe_app_uid_range(10000, 12000);
            probe_app_uid_range(99000, 99999);

            const int user_prefix = static_cast<int>(my_uid / 100000) * 100000;
            if (user_prefix >= 100000) {
                probe_app_uid_range(user_prefix + 10000, user_prefix + 12000);
            }

            constexpr int kExtraUserIds[] = {10, 11, 999};
            for (const int user_id: kExtraUserIds) {
                const int prefix = user_id * 100000;
                if (prefix == user_prefix) continue;
                probe_app_uid_range(prefix + 10000, prefix + 12000);
            }

            return uids;
        }

    }  // namespace

    // Scan live processes and score cgroup node mismatches against procfs identity.
    ProbeResult scan_cgroup_anomalies() {
        ProbeResult result;
        result.available = false;

        struct stat root_st{};
        if (stat("/sys/fs/cgroup", &root_st) != 0 && errno != EACCES && errno != EPERM) {
            return result;
        }
        result.available = true;

        const CgroupLayout layout = detect_cgroup_layout();
        if (!layout.usable()) {
            return result;
        }

        const pid_t my_pid = getpid();
        const pid_t ppid = getppid();
        const uid_t my_uid = getuid();

        std::set<int> discovered_uids = discover_cgroup_uids(my_uid, layout);
        const EnumeratedCgroupPids enumerated = enumerate_cgroup_pids(layout);
        const bool enum_trustworthy = enumerated.pids.size() >= 16;
        const std::string mountinfo = read_file_chunk("/proc/self/mountinfo", 32768);

        // Prefer a window around the parent process; fall back to fixed ranges when sparse.
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

        // Luna: relative windows only when 1 < ppid <= 10000; otherwise fixed fallbacks.
        if (ppid > 1 && ppid <= 10000) {
            const int ppid_val = static_cast<int>(ppid);
            const size_t pass1_start = target_pids.size();
            add_pids_in_range(std::max(2, ppid_val - 600), ppid_val + 400);
            const size_t pass1_alive = target_pids.size() - pass1_start;

            if (pass1_alive >= 60) {
                add_pids_in_range(ppid_val + 800, ppid_val + 1500);
            } else {
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

        for (const int pid: target_pids) {
            const int u = get_proc_uid(pid);
            if (u >= 0) {
                discovered_uids.insert(u);
            }
        }
        for (const auto &kv: enumerated.pid_uids) {
            discovered_uids.insert(kv.second);
        }

        auto resolve_pid_node = [&](const int pid, const int preferred_uid) -> CgroupNodeInfo {
            CgroupNodeInfo info;
            if (preferred_uid >= 0) {
                info = query_cgroup_pid_node(preferred_uid, pid, layout);
                if (info.exists) return info;
            }
            for (const int uid: discovered_uids) {
                if (uid == preferred_uid) continue;
                info = query_cgroup_pid_node(uid, pid, layout);
                if (info.exists) return info;
            }
            return {};
        };

        // Trust template path probes when enumeration is rich or our own node resolves.
        const CgroupNodeInfo self_node = resolve_pid_node(static_cast<int>(my_pid), static_cast<int>(my_uid));
        const bool self_ok = self_node.exists;
        const bool templates_trustworthy =
                enum_trustworthy || (self_ok && discovered_uids.size() >= 8);

        result.scanned_count = static_cast<int>(target_pids.size());

        struct AbnormalHit {
            int pid = 0;
            int score = 0;
            uint32_t reason_mask = 0;
        };

        std::vector<AbnormalHit> hits;

        for (const int pid: target_pids) {
            if (pid < 900) {
                continue;
            }

            if (!is_user_process_alive(pid)) {
                continue;
            }

            int score = 1;
            uint32_t reason_mask = 0x01;

            const std::string cmdline = read_proc_cmdline(pid);
            if (cmdline.size() >= 5 && !mountinfo.empty()) {
                const std::string needle = " " + cmdline + " ";
                if (mountinfo.find(needle) != std::string::npos) {
                    score = 5;
                    reason_mask = 0x03;
                }
            }

            int proc_uid = -1;
            int proc_tgid = -1;
            const bool status_ok = parse_proc_status(pid, proc_uid, proc_tgid);

            if (status_ok && proc_tgid > 0 && proc_tgid != pid) {
                score += 1;
                reason_mask |= 0x40;
            }

            CgroupNodeInfo cgroup_info;
            const bool listed = enumerated.pids.find(pid) != enumerated.pids.end();
            if (listed) {
                cgroup_info.exists = true;
                cgroup_info.accessible = false;
                const auto uid_it = enumerated.pid_uids.find(pid);
                if (uid_it != enumerated.pid_uids.end()) {
                    cgroup_info = query_cgroup_pid_node(uid_it->second, pid, layout);
                    if (!cgroup_info.exists) {
                        cgroup_info.exists = true;
                        cgroup_info.accessible = false;
                        cgroup_info.parent_uid = uid_it->second;
                    }
                }
            } else {
                cgroup_info = resolve_pid_node(pid, status_ok ? proc_uid : -1);
            }

            if (!cgroup_info.exists) {
                if (!is_user_process_alive(pid)) {
                    continue;
                }
                cgroup_info = resolve_pid_node(pid, status_ok ? proc_uid : -1);
            }

            // Missing node: visible procfs (0x08) or opaque procfs when templates are trusted (0x04).
            if (!cgroup_info.exists) {
                const bool visible_miss = status_ok && proc_uid >= 0;
                const bool opaque_miss = !visible_miss && templates_trustworthy;
                if (visible_miss || opaque_miss) {
                    score += 4;
                    reason_mask |= visible_miss ? 0x08u : 0x04u;
                }
            }

            // Luna scores mode and owner separately (+2/0x10 and +1/0x20).
            // There is no separate parent_uid!=status_uid (+4/0x10) path in findlsp.
            if (cgroup_info.exists && cgroup_info.accessible) {
                if (pid <= 2999 && cgroup_info.parent_uid <= 2999) {
                    const bool mode_match = ((cgroup_info.mode & ~0x10) == 040755);
                    const bool owner_match = (cgroup_info.uid == 1000 && cgroup_info.gid == 1000);
                    if (!mode_match) {
                        score += 2;
                        reason_mask |= 0x10u;
                    }
                    if (!owner_match) {
                        score += 1;
                        reason_mask |= 0x20u;
                    }
                }
            }

            if (score >= 5) {
                hits.push_back(AbnormalHit{pid, score, reason_mask});
            }
        }

        // Luna keeps all score>=5 hits, then caps reported results to the three lowest PIDs.
        int abnormal_count = 0;
        int max_score = 0;
        uint32_t cumulative_reason_mask = 0;
        std::vector<int> suspicious_pids;
        std::vector<AbnormalHit> trimmed = hits;
        if (trimmed.size() > 3) {
            std::sort(trimmed.begin(), trimmed.end(),
                      [](const AbnormalHit &a, const AbnormalHit &b) { return a.pid < b.pid; });
            trimmed.resize(3);
        }
        for (const auto &hit: trimmed) {
            abnormal_count++;
            max_score = std::max(max_score, hit.score);
            cumulative_reason_mask |= hit.reason_mask;
            suspicious_pids.push_back(hit.pid);
        }

        result.hit_count = abnormal_count;

        if (abnormal_count > 0 && max_score >= 5) {
            std::ostringstream detail;
            detail << "total_scanned=" << result.scanned_count
                   << " abnormal_count=" << abnormal_count
                   << " max_score=" << max_score
                   << " reason_mask=0x" << std::hex << cumulative_reason_mask << std::dec
                   << " tgids=";

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
