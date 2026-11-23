/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.metrics;

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.FindingAnalysisDao;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class UpdateProjectMetricsDeferredWorkflowTest extends AbstractMetricsUpdateTaskTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    @BeforeEach
    void beforeEach() {
        createTestConfigProperties();

        final DexEngine engine = workflowTest.getEngine();

        // Use a short delay to keep the test fast.
        engine.registerWorkflow(
                new UpdateProjectMetricsDeferredWorkflow(Duration.ofMillis(100)),
                protoConverter(UpdateProjectMetricsArg.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.registerActivity(
                new UpdateProjectMetricsActivity(), protoConverter(UpdateProjectMetricsArg.class), voidConverter());

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "metrics-updates", 1));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-metrics", "metrics-updates", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @Test
    void shouldUpdateProjectMetricsAfterDelay() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);

        var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.createComponent(component, false);
        qm.addVulnerability(vuln, component, "none");

        final var suppressCommand = new MakeAnalysisCommand(component.getId(), vuln.getId())
                .withState(AnalysisState.FALSE_POSITIVE)
                .withSuppress(true);
        useJdbiTransaction(handle -> handle.attach(FindingAnalysisDao.class).makeAnalysis(suppressCommand));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(UpdateProjectMetricsDeferredWorkflow.class)
                        .withWorkflowInstanceId(UpdateProjectMetricsDeferredWorkflow.instanceId(project.getUuid()))
                        .withArgument(UpdateProjectMetricsArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final ProjectMetrics metrics =
                withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metrics).isNotNull();
        assertThat(metrics.getSuppressed()).isEqualTo(1);
        assertThat(metrics.getVulnerabilities()).isZero();
    }
}
