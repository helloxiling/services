// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/veraison/services/scheme/ocp-composite-eat/example/class/generator"
)

func main() {
	output := flag.String("output", "scheme/ocp-composite-eat/example/class/.example-output/snapshot", "artifact output directory")
	mixed := flag.Bool("mixed", false, "generate the manifest-driven mixed Device EAT/SPDM demo")
	class := flag.Bool("class", false, "generate two enrolled servers sharing one signed class endorsement")
	cocli := flag.String("cocli", "", "upstream cocli executable used to package and sign class sources")
	flag.Parse()
	if *class && *mixed {
		fmt.Fprintln(os.Stderr, "--class and --mixed are mutually exclusive")
		os.Exit(1)
	}
	if *cocli != "" && !*class {
		fmt.Fprintln(os.Stderr, "--cocli requires --class")
		os.Exit(1)
	}
	outputSet := false
	flag.Visit(func(option *flag.Flag) {
		if option.Name == "output" {
			outputSet = true
		}
	})
	if !outputSet {
		if *class {
			*output = "scheme/ocp-composite-eat/example/class/.example-output/class"
		} else if *mixed {
			*output = "scheme/ocp-composite-eat/example/class/.example-output/mixed"
		}
	}
	var manifest *generator.DemoManifest
	var err error
	switch {
	case *class && *cocli == "":
		manifest, err = generator.GenerateClassDemoArtifacts(*output)
	case *class:
		manifest, err = generator.GenerateClassDemoArtifactsWithCocli(*output, *cocli)
	case *mixed:
		manifest, err = generator.GenerateMixedDemoArtifacts(*output)
	default:
		manifest, err = generator.GenerateDemoArtifacts(*output)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate demo: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("generated %d artifacts in %s\n", len(manifest.Artifacts), *output)
}
