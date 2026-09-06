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

#include "nativeroot/probes/permission_boundary_probe.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

    namespace {

        void append_line(std::string &target, const std::string &line) {
            target += line;
            target += '\n';
        }

        // Strictly inspect physical Wi-Fi (wlan*, swlan*) and physical Ethernet (eth*) interfaces.
        // Virtual/dummy/cellular interfaces (dummy*, rmnet*, sit*, tun*, tap*, p2p*, lo) are ignored.
        bool is_target_physical_interface(const std::string &ifname) {
            if (ifname.empty()) {
                return false;
            }
            if (ifname.rfind("wlan", 0) == 0 || ifname.rfind("swlan", 0) == 0 ||
                ifname.rfind("eth", 0) == 0) {
                return true;
            }
            return false;
        }

        // Netlink RTM_GETLINK dump query & hardware MAC leak check.
        // Android 11+ (API 30+) neverallow { appdomain -shell } self:netlink_route_socket { nlmsg_read nlmsg_write };
        // Clean devices: socket creation or sendto/recv fails with EACCES, or returns dummy masked addresses (02:00:00:00:00:00).
        // Magisk / SELinux privilege escalation: allows querying RTM_GETLINK and leaking real physical interface MAC addresses.
        void check_netlink_boundary(ProbeResult &result) {
            result.checked_count++;
            const int api_level = android_get_device_api_level();
            if (api_level < 30) {
                append_line(result.extra_text, "Netlink boundary: skipped (API " + std::to_string(api_level) + " < 30).");
                return;
            }

            errno = 0;
            const int sock_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (sock_fd < 0) {
                append_line(result.extra_text, "Netlink boundary: socket creation blocked by SELinux (clean).");
                return;
            }

            // Set receive timeout so that recv() will not block indefinitely
            struct timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 250000; // 250 ms
            setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            // Standard 32-byte RTM_GETLINK dump request: nlmsghdr (16B) + rtgenmsg (16B)
            struct {
                struct nlmsghdr hdr;
                struct rtgenmsg gen;
            } req{};
            req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)); // 32 bytes
            req.hdr.nlmsg_type = RTM_GETLINK;                          // 18 (0x12)
            req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;          // 0x301
            req.hdr.nlmsg_seq = 1;
            req.gen.rtgen_family = AF_UNSPEC;

            errno = 0;
            const ssize_t sent = sendto(sock_fd, &req, req.hdr.nlmsg_len, 0, nullptr, 0);
            const int send_err = errno;
            if (sent != static_cast<ssize_t>(req.hdr.nlmsg_len)) {
                close(sock_fd);
                append_line(result.extra_text, "Netlink boundary: securely blocked by SELinux (errno=" + std::to_string(send_err) + ").");
                return;
            }

            // Receive and parse RTM_NEWLINK response to detect hardware MAC leakage
            char buffer[8192];
            ssize_t len = 0;
            bool mac_leak_detected = false;
            std::string leaked_ifname;
            std::string leaked_mac;

            while ((len = recv(sock_fd, buffer, sizeof(buffer), 0)) > 0) {
                const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
                for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
                    if (nlh->nlmsg_type == NLMSG_DONE) {
                        goto done_recv;
                    }
                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        continue;
                    }
                    if (nlh->nlmsg_type != RTM_NEWLINK) {
                        continue;
                    }

                    const auto *ifi = static_cast<const struct ifinfomsg *>(NLMSG_DATA(nlh));
                    if (ifi->ifi_flags & IFF_LOOPBACK) {
                        continue; // Skip loopback interface
                    }
                    if (!(ifi->ifi_flags & IFF_UP)) {
                        continue; // Skip inactive interface
                    }

                    const auto *rta = IFLA_RTA(ifi);
                    int rta_len = IFLA_PAYLOAD(nlh);
                    std::string ifname;
                    unsigned char mac_bytes[6]{};
                    bool has_mac = false;

                    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                        if (rta->rta_type == IFLA_IFNAME) {
                            ifname = reinterpret_cast<const char *>(RTA_DATA(rta));
                        } else if (rta->rta_type == IFLA_ADDRESS && RTA_PAYLOAD(rta) == 6) {
                            std::memcpy(mac_bytes, RTA_DATA(rta), 6);
                            has_mac = true;
                        }
                    }

                    // Only inspect targeted physical interfaces to avoid false positives on virtual devices (e.g. dummy0, rmnet)
                    if (!is_target_physical_interface(ifname)) {
                        continue;
                    }

                    if (has_mac) {
                        const bool is_multicast = (mac_bytes[0] & 0x01) != 0;
                        const bool is_all_zero = (mac_bytes[0] == 0 && mac_bytes[1] == 0 &&
                                                  mac_bytes[2] == 0 && mac_bytes[3] == 0 &&
                                                  mac_bytes[4] == 0 && mac_bytes[5] == 0);
                        const bool is_dummy = (mac_bytes[0] == 0x02 && mac_bytes[1] == 0 &&
                                               mac_bytes[2] == 0 && mac_bytes[3] == 0 &&
                                               mac_bytes[4] == 0 && mac_bytes[5] == 0);
                        if (!is_multicast && !is_all_zero && !is_dummy) {
                            mac_leak_detected = true;
                            leaked_ifname = ifname;
                            char mac_buf[20];
                            std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                                          mac_bytes[0], mac_bytes[1], mac_bytes[2],
                                          mac_bytes[3], mac_bytes[4], mac_bytes[5]);
                            leaked_mac = mac_buf;
                            goto done_recv;
                        }
                    }
                }
            }

        done_recv:
            close(sock_fd);

            if (mac_leak_detected) {
                result.flags.root = true;
                result.flags.magisk = true;
                result.hit_count++;

                Finding finding;
                finding.group = "PERMISSION_BOUNDARY";
                finding.label = "AF_NETLINK MAC Leak";
                finding.value = "Hardware MAC Exposed (" + leaked_ifname + ")";
                finding.severity = Severity::kDanger;
                finding.detail = "SELinux permission boundary breach: physical MAC leaked on " + leaked_ifname +
                                 " (" + leaked_mac + ") on API " + std::to_string(api_level) +
                                 " (AOSP neverallow rule bypassed by Magisk sepolicy injection or policy corruption).";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Netlink boundary: hardware MAC leak detected on " + leaked_ifname +
                                               " (" + leaked_mac + ") (SELinux bypass detected).");
            } else {
                append_line(result.extra_text, "Netlink boundary: clean (physical interface MAC securely masked or unavailable).");
            }
        }

#ifndef NDA_RTA
#define NDA_RTA(r) ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct ndmsg))
#endif

        // Netlink RTM_GETNEIGH dump query & ARP/neighbor table leak check.
        // Android 11+ (API 30+) kernel enforces POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH restricting
        // untrusted apps from querying neighbor/ARP tables via netlink_route_socket nlmsg_read.
        // Clean devices: socket creation or sendto fails with EACCES, or returns no unicast neighbors.
        // Policy corrupted / Magisk / SELinux bypass: allows querying RTM_GETNEIGH and leaking LAN ARP/gateway IP & MAC.
        void check_netlink_neigh_boundary(ProbeResult &result) {
            result.checked_count++;
            const int api_level = android_get_device_api_level();
            if (api_level < 30) {
                append_line(result.extra_text, "Netlink neigh boundary: skipped (API " + std::to_string(api_level) + " < 30).");
                return;
            }

            errno = 0;
            const int sock_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
            if (sock_fd < 0) {
                append_line(result.extra_text, "Netlink neigh boundary: socket creation blocked by SELinux (clean).");
                return;
            }

            struct timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 250000; // 250 ms
            setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct {
                struct nlmsghdr hdr;
                struct ndmsg msg;
            } req{};
            req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
            req.hdr.nlmsg_type = RTM_GETNEIGH;
            req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.hdr.nlmsg_seq = 2;
            req.msg.ndm_family = AF_INET;

            errno = 0;
            const ssize_t sent = sendto(sock_fd, &req, req.hdr.nlmsg_len, 0, nullptr, 0);
            const int send_err = errno;
            if (sent != static_cast<ssize_t>(req.hdr.nlmsg_len)) {
                close(sock_fd);
                append_line(result.extra_text, "Netlink neigh boundary: securely blocked by SELinux (errno=" + std::to_string(send_err) + ").");
                return;
            }

            char buffer[8192];
            ssize_t len = 0;
            bool neigh_leak_detected = false;
            std::string leaked_ip;
            std::string leaked_mac;

            while ((len = recv(sock_fd, buffer, sizeof(buffer), 0)) > 0) {
                const auto *nlh = reinterpret_cast<const struct nlmsghdr *>(buffer);
                for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
                    if (nlh->nlmsg_type == NLMSG_DONE) {
                        goto done_neigh_recv;
                    }
                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        continue;
                    }
                    if (nlh->nlmsg_type != RTM_NEWNEIGH) {
                        continue;
                    }

                    const auto *ndm = static_cast<const struct ndmsg *>(NLMSG_DATA(nlh));
                    // Skip entries marked as NOARP, FAILED, or INCOMPLETE
                    if (ndm->ndm_state & (NUD_NOARP | NUD_FAILED | NUD_INCOMPLETE)) {
                        continue;
                    }

                    const auto *rta = NDA_RTA(ndm);
                    int rta_len = NDA_PAYLOAD(nlh);

                    unsigned char mac_bytes[6]{};
                    bool has_mac = false;
                    char ip_str[INET_ADDRSTRLEN]{};
                    bool has_ip = false;
                    bool is_unicast_ip = false;

                    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                        if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == sizeof(in_addr)) {
                            struct in_addr in{};
                            std::memcpy(&in, RTA_DATA(rta), sizeof(in));
                            const uint32_t ip_host = ntohl(in.s_addr);
                            // Filter out 0.0.0.0, loopback (127.0.0.0/8), multicast (224.0.0.0/4), and broadcast (255.255.255.255)
                            const bool is_multicast = (ip_host >= 0xe0000000 && ip_host <= 0xefffffff);
                            const bool is_broadcast = (ip_host == 0xffffffff);
                            const bool is_loopback = ((ip_host & 0xff000000) == 0x7f000000);
                            const bool is_zero = (ip_host == 0);
                            if (!is_multicast && !is_broadcast && !is_loopback && !is_zero) {
                                if (inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str))) {
                                    has_ip = true;
                                    is_unicast_ip = true;
                                }
                            }
                        } else if (rta->rta_type == NDA_LLADDR && RTA_PAYLOAD(rta) == 6) {
                            std::memcpy(mac_bytes, RTA_DATA(rta), 6);
                            has_mac = true;
                        }
                    }

                    if (has_mac && is_unicast_ip) {
                        const bool is_multicast_mac = (mac_bytes[0] & 0x01) != 0;
                        const bool is_all_zero = (mac_bytes[0] == 0 && mac_bytes[1] == 0 &&
                                                  mac_bytes[2] == 0 && mac_bytes[3] == 0 &&
                                                  mac_bytes[4] == 0 && mac_bytes[5] == 0);
                        const bool is_dummy = (mac_bytes[0] == 0x02 && mac_bytes[1] == 0 &&
                                               mac_bytes[2] == 0 && mac_bytes[3] == 0 &&
                                               mac_bytes[4] == 0 && mac_bytes[5] == 0);
                        if (!is_multicast_mac && !is_all_zero && !is_dummy) {
                            neigh_leak_detected = true;
                            char mac_buf[20];
                            std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                                          mac_bytes[0], mac_bytes[1], mac_bytes[2],
                                          mac_bytes[3], mac_bytes[4], mac_bytes[5]);
                            leaked_mac = mac_buf;
                            leaked_ip = ip_str;
                            goto done_neigh_recv;
                        }
                    }
                }
            }

        done_neigh_recv:
            close(sock_fd);

            if (neigh_leak_detected) {
                result.flags.root = true;
                result.flags.magisk = true;
                result.hit_count++;

                Finding finding;
                finding.group = "PERMISSION_BOUNDARY";
                finding.label = "AF_NETLINK Neighbor Leak";
                finding.value = "Hardware ARP/Neighbor Exposed";
                finding.severity = Severity::kDanger;
                finding.detail = "SELinux permission boundary breach: ARP/neighbor entry leaked (" +
                                 leaked_ip + " -> " + leaked_mac + ") on API " + std::to_string(api_level) +
                                 " (AOSP netlink_route_socket getneigh restriction bypassed).";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Netlink neigh boundary: neighbor table leak detected (" +
                                               leaked_ip + " " + leaked_mac + ") (SELinux bypass detected).");
            } else {
                append_line(result.extra_text, "Netlink neigh boundary: clean (no unicast ARP entries leaked).");
            }
        }

        // Trust Attestor sub_9CF610: Mount namespace leak probe for /data_mirror
        void check_data_mirror_boundary(ProbeResult &result) {
            result.checked_count++;
            const int dmf = open("/data_mirror", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dmf >= 0) {
                close(dmf);
                result.flags.root = true;
                result.flags.magisk = true;
                result.hit_count++;

                Finding finding;
                finding.group = "PERMISSION_BOUNDARY";
                finding.label = "Mount Namespace /data_mirror";
                finding.value = "Directory Accessible";
                finding.severity = Severity::kDanger;
                finding.detail = "Sandbox mount boundary breach: /data_mirror directory is accessible (Magisk/KernelSU mount namespace leak).";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Mount boundary: /data_mirror directory is accessible.");
            } else {
                struct stat st{};
                if (lstat("/data_mirror", &st) == 0) {
                    result.flags.root = true;
                    result.flags.magisk = true;
                    result.hit_count++;

                    Finding finding;
                    finding.group = "PERMISSION_BOUNDARY";
                    finding.label = "Mount Namespace /data_mirror";
                    finding.value = "Directory Exists";
                    finding.severity = Severity::kDanger;
                    finding.detail = "Sandbox mount boundary breach: /data_mirror stat succeeded (Magisk/KernelSU mount namespace leak).";
                    result.findings.push_back(finding);
                    append_line(result.extra_text, "Mount boundary: /data_mirror exists (lstat succeeded).");
                } else {
                    append_line(result.extra_text, "Mount boundary: /data_mirror does not exist (clean).");
                }
            }
        }

    }  // namespace

    ProbeResult run_permission_boundary_check() {
        ProbeResult result;
        result.extra_text = "";

        check_netlink_boundary(result);
        check_netlink_neigh_boundary(result);
        check_data_mirror_boundary(result);

        return result;
    }

}  // namespace duckdetector::nativeroot
