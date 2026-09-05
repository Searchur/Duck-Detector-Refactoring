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

                    if (has_mac) {
                        const bool is_all_zero = (mac_bytes[0] == 0 && mac_bytes[1] == 0 &&
                                                  mac_bytes[2] == 0 && mac_bytes[3] == 0 &&
                                                  mac_bytes[4] == 0 && mac_bytes[5] == 0);
                        const bool is_dummy = (mac_bytes[0] == 0x02 && mac_bytes[1] == 0 &&
                                               mac_bytes[2] == 0 && mac_bytes[3] == 0 &&
                                               mac_bytes[4] == 0 && mac_bytes[5] == 0);
                        if (!is_all_zero && !is_dummy) {
                            mac_leak_detected = true;
                            leaked_ifname = ifname.empty() ? "net" : ifname;
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
                                 " (AOSP neverallow rule bypassed by Magisk sepolicy injection).";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Netlink boundary: hardware MAC leak detected on " + leaked_ifname +
                                               " (" + leaked_mac + ") (SELinux bypass detected).");
            } else {
                // sendto succeeded, indicating socket operation was allowed, but MAC was either masked or empty
                result.flags.root = true;
                result.hit_count++;

                Finding finding;
                finding.group = "PERMISSION_BOUNDARY";
                finding.label = "AF_NETLINK RTM_GETLINK";
                finding.value = "SELinux Bypass (RTM_GETLINK Allowed)";
                finding.severity = Severity::kDanger;
                finding.detail = "SELinux permission boundary breach: sendto(RTM_GETLINK) succeeded on API " +
                                 std::to_string(api_level) +
                                 " (violates AOSP netlink_route_socket nlmsg_read restriction).";
                result.findings.push_back(finding);
                append_line(result.extra_text, "Netlink boundary: sendto(RTM_GETLINK) succeeded (SELinux bypass detected).");
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
        check_data_mirror_boundary(result);

        return result;
    }

}  // namespace duckdetector::nativeroot
