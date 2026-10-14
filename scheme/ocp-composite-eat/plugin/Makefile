# Copyright 2026 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

PLUGIN := ../../bin/scheme-ocp-composite-eat.plugin
GOPKG := github.com/veraison/services/scheme/ocp-composite-eat
SRCS := main.go

.PHONY: force-go-dependencies
force-go-dependencies:

$(PLUGIN): force-go-dependencies

include ../../../mk/common.mk
include ../../../mk/plugin.mk
include ../../../mk/lint.mk

test: