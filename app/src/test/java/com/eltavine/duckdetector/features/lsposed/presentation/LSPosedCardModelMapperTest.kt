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

package com.eltavine.duckdetector.features.lsposed.presentation

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedCardModelMapperTest {

    private val mapper = LSPosedCardModelMapper()

    @Test
    fun `zygote permission unavailable keeps clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            zygotePermissionAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.verdict.contains("reduced coverage", ignoreCase = true))
    }

    @Test
    fun `native heap unavailable keeps clean signal report at support`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            nativeHeapAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("N/A", model.scanRows.single { it.label == "Native heap" }.value)
    }

    @Test
    fun `dirty policy signal surfaces in policy section and methods`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            signals = listOf(
                LSPosedSignal(
                    id = "policy_lsposed_file_read",
                    label = "LSPosed file read",
                    value = "Allowed",
                    group = LSPosedSignalGroup.POLICY,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = "untrusted_app -> lsposed_file:file read was allowed.",
                ),
            ),
            methods = listOf(
                LSPosedMethodResult(
                    label = "Dirty sepolicy",
                    summary = "LSPosed rule present",
                    outcome = LSPosedMethodOutcome.DETECTED,
                    detail = "Dirty policy details.",
                ),
            ),
            dirtyPolicyAvailable = true,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.verdict.contains("Dirty SELinux policy", ignoreCase = true))
        assertTrue(
            model.policyRows.any {
                it.label == "LSPosed file read" && it.value == "Allowed"
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == "Dirty sepolicy" && it.value == "LSPosed rule present"
            },
        )
    }

    @Test
    fun `dirty policy unavailable does not downgrade otherwise clean LSPosed report`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            dirtyPolicyAvailable = false,
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("LSPosed scan has reduced coverage", model.verdict)
        assertTrue(
            model.policyRows.any {
                it.label == "SELinux policy" && it.value == "Unavailable"
            },
        )
    }

    @Test
    fun `supporting policy warning does not mask stronger runtime verdict`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            dirtyPolicyAvailable = true,
            signals = listOf(
                LSPosedSignal(
                    id = "runtime_bridge_field",
                    label = "XposedBridge fields",
                    value = "Detected",
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = "Bridge field exposed.",
                ),
                LSPosedSignal(
                    id = "policy_magisk_binder_call",
                    label = "Magisk binder",
                    value = "Allowed",
                    group = LSPosedSignalGroup.POLICY,
                    severity = LSPosedSignalSeverity.WARNING,
                    detail = "Supporting dirty-policy evidence.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertEquals("1 high-risk LSPosed signal(s)", model.verdict)
    }

    @Test
    fun `cgroup anomaly signal surfaces in native section, methods, and scan rows`() {
        val report = LSPosedReport.loading().copy(
            stage = LSPosedStage.READY,
            packageVisibility = LSPosedPackageVisibility.FULL,
            nativeAvailable = true,
            nativeCgroupHitCount = 1,
            nativeCgroupScannedPids = 1400,
            signals = listOf(
                LSPosedSignal(
                    id = "native_cgroup_0",
                    label = "Framework trace hiding (cgroup anomaly)",
                    value = "Trace anomaly",
                    group = LSPosedSignalGroup.NATIVE,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = "CGROUP\ntotal_scanned=1400 abnormal_count=1 max_score=5 reason_mask=0x23",
                    detailMonospace = true,
                ),
            ),
            methods = listOf(
                LSPosedMethodResult(
                    label = "Cgroup trace anomaly",
                    summary = "1 anomaly(ies)",
                    outcome = LSPosedMethodOutcome.DETECTED,
                    detail = "Cross-validates process existence in kernel process table against /sys/fs/cgroup hierarchy.",
                ),
            ),
        )

        val model = mapper.map(report)

        assertEquals(DetectionSeverity.DANGER, model.status.severity)
        assertTrue(model.verdict.contains("high-risk LSPosed signal", ignoreCase = true))
        assertTrue(
            model.nativeRows.any {
                it.label == "Framework trace hiding (cgroup anomaly)" && it.value == "Trace anomaly"
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == "Cgroup trace anomaly" && it.value == "1 anomaly(ies)"
            },
        )
        assertEquals("1", model.scanRows.single { it.label == "Cgroup anomalies" }.value)
    }
}
