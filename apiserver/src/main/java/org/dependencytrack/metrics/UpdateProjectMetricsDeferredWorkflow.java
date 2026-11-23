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

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.UUID;

/**
 * Updates the metrics of a single project after a short delay.
 * <p>
 * Intended for user actions that affect a project's metrics, such as suppressing a finding.
 * Recomputing metrics is expensive, so doing it inline for every action does not scale.
 * Instead, the workflow is created with an instance ID that is unique per project
 * (see {@link #instanceId(UUID)}). While a run for a project is still waiting, further requests
 * for the same project are rejected by the engine, which coalesces bursts of changes into a single update.
 *
 * @since 5.3.0
 */
@WorkflowSpec(name = "update-project-metrics-deferred")
public final class UpdateProjectMetricsDeferredWorkflow implements Workflow<UpdateProjectMetricsArg, Void> {

    static final Duration DEFAULT_DELAY = Duration.ofMinutes(2);

    private final Duration delay;

    public UpdateProjectMetricsDeferredWorkflow() {
        this(DEFAULT_DELAY);
    }

    UpdateProjectMetricsDeferredWorkflow(Duration delay) {
        this.delay = delay;
    }

    public static String instanceId(UUID projectUuid) {
        return "update-project-metrics-deferred:" + projectUuid;
    }

    @Override
    public @Nullable Void execute(WorkflowContext<UpdateProjectMetricsArg> ctx, @Nullable UpdateProjectMetricsArg arg) {
        if (arg == null) {
            throw new TerminalApplicationFailureException("No argument provided");
        }

        ctx.createTimer("coalesce-changes", delay).await();
        ctx.activity(UpdateProjectMetricsActivity.class).call(arg).await();
        return null;
    }
}
