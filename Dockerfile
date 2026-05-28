# csfwctl — thin runtime image for use as a CI execution environment
#            in csfwctl-config pipelines.
#
# Built by the CI pipeline from the pre-built wheel in dist/.
# Proxy variables are accepted as build args so pip can reach
# package indexes through a corporate proxy at build time.
#
# Usage in csfwctl-config .gitlab-ci.yml:
#   image: csfwctl:latest

FROM python:3.11-slim

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

COPY dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl \
    && rm /tmp/*.whl

ENTRYPOINT ["csfwctl"]
