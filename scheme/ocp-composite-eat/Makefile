# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0
.DEFAULT_GOAL := test

GOPKG := github.com/veraison/services/scheme/ocp-composite-eat
SRCS := $(wildcard *.go)

SUBDIR += internal
SUBDIR += platformcorim
SUBDIR += plugin

include ../../mk/common.mk
include ../../mk/lint.mk
include ../../mk/pkg.mk
include ../../mk/test.mk
include ../../mk/subdir.mk