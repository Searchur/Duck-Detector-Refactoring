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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

    namespace {

        void append_line(std::string &target, const std::string &line) {
            target += line;
            target += '\n';
        }

        // Trust Attestor sub_4FAB7C: Netlink RTM_GETLINK dump query check.
        // Android 11+ (API 30+) neverallow { appdomain -shell } self:netlink_route_socket { nlmsg_read nlmsg_write };
        // On clean devices, sendto(RTM_GETLINK) fails with EACCES. If it returns 20, SELinux was bypassed.
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

            struct {
                struct nlmsghdr hdr;
                char data[4];
            } req{};
            req.hdr.nlmsg_len = sizeof(req);                  // 20 bytes (0x14)
            req.hdr.nlmsg_type = RTM_GETLINK;                 // 18 (0x12)
            req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; // 0x301

            errno = 0;
            const ssize_t sent = sendto(sock_fd, &req, sizeof(req), 0, nullptr, 0);
            const int err = errno;
            close(sock_fd);

            if (sent == sizeof(req)) {
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
            } else {
                append_line(result.extra_text, "Netlink boundary: securely blocked by SELinux (errno=" + std::to_string(err) + ").");
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
