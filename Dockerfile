#
# Copyright 2017 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Razorpay hardening: build FROM the Harbor-approved Spark mirror (RSPL), not docker.io, so there
# is no non-Harbor base finding. Same 4.2.1 digest, just pulled from the approved registry.
ARG SPARK_IMAGE=c.rzp.io/razorpay-external/apache/spark@sha256:ce1d0c8407066ed44b91f699b6edd3564f143722e3ef95e19d99a67b5754b306

# Go 1.27.4 builder (via the Harbor DockerHub proxy). The bumped go.mod (x/net 0.63, x/text 0.44,
# x/mod 0.43, otel/trace 1.47) + this toolchain rebuild the operator binary with 0 Go CVEs
# (verified with Trivy). GOTOOLCHAIN=local pins the build to this toolchain.
FROM c.rzp.io/proxy_dockerhub/library/golang:1.27.4@sha256:5bd30d78fe7788dc760abe3e3437434781b3164e50fadc24611fa7fbc0cfb6ba AS builder
ENV GOTOOLCHAIN=local

WORKDIR /workspace

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download

COPY . .

ENV GOCACHE=/root/.cache/go-build

ARG TARGETARCH

# Build metadata. When unset, the Makefile derives these from the git tree
# inside the build context, preserving the behaviour of a plain `docker build`.
ARG VERSION=
ARG GIT_COMMIT=
ARG GIT_TREE_STATE=
ARG SOURCE_DATE_EPOCH=

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target="/root/.cache/go-build" \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} GO111MODULE=on \
    make build-operator \
      ${VERSION:+VERSION=$VERSION} \
      ${GIT_COMMIT:+GIT_COMMIT=$GIT_COMMIT} \
      ${GIT_TREE_STATE:+GIT_TREE_STATE=$GIT_TREE_STATE} \
      ${SOURCE_DATE_EPOCH:+SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH}

# Export-only stage. `docker build` targets the final stage by default, so this
# is never built unless requested via --target=artifacts. CI uses it to extract
# the exact binary that ships in the image.
FROM scratch AS artifacts
COPY --from=builder /workspace/bin/spark-operator /spark-operator

# Razorpay hardening: resolve the patched standalone jars (patch/minor bumps that are
# Spark-ABI-safe) via the GCS Maven Central mirror. Maven verifies each artifact's published
# checksum. These replace the vulnerable standalone jars the Spark base ships in /opt/spark/jars.
FROM c.rzp.io/proxy_dockerhub/library/maven:3.9-eclipse-temurin-21 AS jars
WORKDIR /build
COPY patched-jars.pom.xml pom.xml
COPY settings.xml settings.xml
RUN ok=0; \
    for i in 1 2 3; do \
      if mvn -B -q -s settings.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
           -DexcludeTransitive=true -DoutputDirectory=/staging; then ok=1; break; fi; \
      echo "maven attempt $i failed; retrying in $((i*15))s"; sleep $((i*15)); \
    done; \
    [ "$ok" = 1 ] || { echo "FAIL: maven resolution failed"; exit 1; }; \
    ls -1 /staging

FROM ${SPARK_IMAGE}

ARG SPARK_UID=185

ARG SPARK_GID=185

USER root

# Razorpay hardening: OS security upgrade + catatonit (operator needs it) + remove gosu.
# gosu is a Go 1.18 setuid binary (Go EOL) the Spark base ships for its own root->user entrypoint.
# This operator image runs non-root as uid 185 and its entrypoint uses catatonit, never gosu, so
# gosu is dead weight here — removing it clears the Go-EOL finding with no functional impact.
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get -y upgrade; \
    apt-get install -y --no-install-recommends catatonit; \
    rm -f /usr/sbin/gosu /usr/local/bin/gosu /usr/bin/gosu; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

# Razorpay hardening: swap the vulnerable standalone jars the Spark base ships for patched
# versions, then verify fail-CLOSED — no old vulnerable version may remain (a missed rm name is
# caught here), no artifact may carry two versions on the classpath, every patched jar present.
RUN set -eux; cd /opt/spark/jars; \
    rm -f netty-*-4.2.13.Final*.jar jackson-core-2.21.2*.jar jackson-databind-2.21.2*.jar \
          jackson-dataformat-yaml-2.21.2*.jar jackson-datatype-jsr310-2.21.2*.jar \
          jackson-module-scala_2.13-2.21.2*.jar snappy-java-1.1.10.8*.jar lz4-java-1.11.0*.jar \
          guava-33.6.0-jre*.jar jline-3.29.0*.jar derby-10.16.1.1*.jar derbyshared-10.16.1.1*.jar \
          derbytools-10.16.1.1*.jar
COPY --from=jars --chown=185:185 /staging/ /opt/spark/jars/
RUN set -eux; cd /opt/spark/jars; \
    if ls netty-*-4.2.13.Final*.jar >/dev/null 2>&1; then echo "FAIL: netty 4.2.13 still present"; exit 1; fi; \
    for v in jackson-core-2.21.2 jackson-databind-2.21.2 jackson-dataformat-yaml-2.21.2 \
             jackson-datatype-jsr310-2.21.2 jackson-module-scala_2.13-2.21.2 snappy-java-1.1.10.8 \
             lz4-java-1.11.0 guava-33.6.0-jre jline-3.29.0 derby-10.16.1.1 derbyshared-10.16.1.1 \
             derbytools-10.16.1.1; do \
      if ls ${v}*.jar >/dev/null 2>&1; then echo "FAIL: vulnerable ${v} still present:"; ls ${v}*.jar; exit 1; fi; \
    done; \
    nv=$(ls netty-*-4.2.*.Final*.jar | sed -E 's/.*-(4\.2\.[0-9]+\.Final).*/\1/' | sort -u); \
    [ "$nv" = 4.2.17.Final ] || { echo "FAIL: unexpected netty versions: $nv"; exit 1; }; \
    for a in guava snappy-java lz4-java jackson-core jackson-databind jackson-dataformat-yaml \
             jackson-datatype-jsr310 jackson-module-scala_2.13 derby; do \
      n=$(ls ${a}-*.jar 2>/dev/null | wc -l); \
      [ "$n" -eq 1 ] || { echo "FAIL: $a has $n versions:"; ls ${a}-*.jar 2>/dev/null; exit 1; }; \
    done; \
    jn=$(ls jline-3.*.jar 2>/dev/null | wc -l); [ "$jn" -eq 1 ] || { echo "FAIL: jline3 count=$jn"; ls jline-3.*.jar; exit 1; }; \
    for f in netty-handler-4.2.17.Final guava-33.7.2-jre jackson-databind-2.21.7 \
             snappy-java-1.1.10.9 lz4-java-1.11.4 jline-3.30.15 derby-10.17.1.0; do \
      [ -e "$f.jar" ] || { echo "FAIL: patched $f.jar missing"; exit 1; }; \
    done

RUN mkdir -p /etc/k8s-webhook-server/serving-certs /home/spark && \
    chmod -R g+rw /etc/k8s-webhook-server/serving-certs && \
    chown -R spark /etc/k8s-webhook-server/serving-certs /home/spark

USER ${SPARK_UID}:${SPARK_GID}

COPY --from=builder /workspace/bin/spark-operator /usr/bin/spark-operator

COPY entrypoint.sh /usr/bin/

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
