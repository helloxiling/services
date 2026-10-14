// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/veraison/corim/corim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/compiler"
	"github.com/veraison/services/scheme/ocp-composite-eat/platformcorim/manifest"
)

const defaultRegistry = "scheme/ocp-composite-eat/platformcorim/profiles.json"

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: platform-corim <validate-source|build-platform|build-vendor|build-platform-class|build-component-class|export-platform-class|export-component-class|create-class-package|emit-collection-plan|compile-demo-snapshot|inspect>")
	}
	switch os.Args[1] {
	case "build-platform-class", "build-component-class", "export-platform-class", "export-component-class":
		flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		source := flags.String("manifest", "", "class manifest JSON")
		output := flags.String("output", "", "unsigned CoRIM output file, or new cocli input directory for export")
		_ = flags.Parse(os.Args[2:])
		var unsigned *corim.UnsignedCorim
		var buildErr error
		if strings.HasSuffix(os.Args[1], "platform-class") {
			value, err := manifest.LoadPlatformClass(*source)
			if err != nil {
				fatalf("%v", err)
			}
			unsigned, buildErr = compiler.BuildPlatformClass(*value)
		} else {
			value, err := manifest.LoadComponentClass(*source)
			if err != nil {
				fatalf("%v", err)
			}
			unsigned, buildErr = compiler.BuildComponentClass(*value)
		}
		if buildErr != nil {
			fatalf("%v", buildErr)
		}
		if strings.HasPrefix(os.Args[1], "export-") {
			files, err := compiler.ExportCocliInputs(unsigned)
			if err != nil {
				fatalf("%v", err)
			}
			if *output == "" {
				fatalf("--output directory is required")
			}
			if err := os.Mkdir(*output, 0o755); err != nil {
				fatalf("create new export directory: %v", err)
			}
			for name, data := range files {
				writeFile(filepath.Join(*output, name), data, nil)
			}
		} else {
			writeCoRIM(*output, unsigned, nil)
		}
	case "create-class-package":
		flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
		platformManifest := flags.String("platform-manifest", "", "platform class manifest in the package directory")
		platformCoRIM := flags.String("platform-corim", "", "signed platform class CoRIM in the package directory")
		platformCert := flags.String("platform-cert", "", "exact DER certificate used to sign the platform CoRIM")
		enrollments := flags.String("enrollments", "", "instance enrollment JSON in the package directory")
		compatibility := flags.String("compatibility", "", "optional trusted carriage compatibility policy JSON")
		output := flags.String("output", "", "class package JSON to create")
		var componentArguments stringList
		flags.Var(&componentArguments, "component", "manifest=corim=signer-cert.der; repeat for each component source")
		_ = flags.Parse(os.Args[2:])
		config := platformcorim.ClassEndorsementPackage{APIVersion: manifest.APIVersion, Kind: "ClassEndorsementPackage", SignerScopes: map[string]string{}}
		if *compatibility != "" {
			policy := loadCompatibility(*compatibility)
			config.Compatibility = &policy
		}
		config.Platform = platformcorim.SourceFiles{
			Manifest: packageRelativePath(*output, *platformManifest),
			CoRIM:    packageRelativePath(*output, *platformCoRIM),
			SHA256:   fileSHA256(*platformCoRIM),
		}
		if _, err := manifest.LoadPlatformClass(*platformManifest); err != nil {
			fatalf("platform manifest: %v", err)
		}
		config.SignerScopes["platform"] = certificateFingerprint(*platformCert)
		seenComponents := map[string]bool{}
		componentDigests := map[string]string{}
		for _, argument := range componentArguments {
			parts := strings.SplitN(argument, "=", 3)
			if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
				fatalf("--component must use manifest=corim=signer-cert.der")
			}
			component, err := manifest.LoadComponentClass(parts[0])
			if err != nil {
				fatalf("component manifest: %v", err)
			}
			if seenComponents[component.ID] {
				fatalf("duplicate component source ID %q", component.ID)
			}
			seenComponents[component.ID] = true
			digest := fileSHA256(parts[1])
			config.Components = append(config.Components, platformcorim.SourceFiles{
				Manifest: packageRelativePath(*output, parts[0]),
				CoRIM:    packageRelativePath(*output, parts[1]),
				SHA256:   digest,
			})
			componentDigests[component.ID] = digest
			config.SignerScopes[component.ID] = certificateFingerprint(parts[2])
		}
		if len(config.Components) == 0 {
			fatalf("at least one --component is required")
		}
		config.Enrollments = packageRelativePath(*output, *enrollments)
		config.EnrollmentSHA256 = fileSHA256(*enrollments)
		if config.Compatibility != nil {
			if err := platformcorim.ValidateCompatibility(*config.Compatibility, componentDigests); err != nil {
				fatalf("%v", err)
			}
		}
		encoded, err := json.MarshalIndent(config, "", "  ")
		writeFile(*output, append(encoded, '\n'), err)
	case "validate-source":
		project, _ := loadProject(os.Args[2:])
		fmt.Printf("validated %d members\n", len(project.Members))
	case "build-platform":
		project, output := loadProject(os.Args[2:])
		unsigned, err := compiler.BuildPlatform(project, false)
		writeCoRIM(output, unsigned, err)
	case "build-vendor":
		flags := flag.NewFlagSet("build-vendor", flag.ExitOnError)
		vendorPath := flags.String("vendor", "", "vendor manifest")
		output := flags.String("output", "", "output unsigned CoRIM")
		_ = flags.Parse(os.Args[2:])
		vendor, err := manifest.LoadVendor(*vendorPath)
		if err != nil {
			fatalf("%v", err)
		}
		unsigned, err := compiler.BuildVendor(*vendor)
		writeCoRIM(*output, unsigned, err)
	case "emit-collection-plan":
		project, output := loadProject(os.Args[2:])
		data, err := compiler.MarshalCollectionPlan(project)
		writeFile(output, append(data, '\n'), err)
	case "compile-demo-snapshot":
		flags := flag.NewFlagSet("compile-demo-snapshot", flag.ExitOnError)
		platform := flags.String("platform", "", "platform inventory")
		packageRoot := flags.String("package-root", "", "root that confines referenced vendor manifests")
		registryPath := flags.String("registry", defaultRegistry, "profile registry")
		platformSourcePath := flags.String("platform-corim", "", "signed platform source CoRIM")
		sourceRootsPath := flags.String("source-roots", "", "PEM roots for signed source CoRIMs")
		scopesPath := flags.String("source-authorizations", "", "JSON map of platform/vendor scope to authorized signer certificate SHA-256")
		var vendorSourceArguments stringList
		flags.Var(&vendorSourceArguments, "vendor-corim", "signed vendor source as manifest-id=path; repeat for each vendor")
		keyPath := flags.String("signing-key", "", "external PEM signing key")
		certPath := flags.String("signing-cert", "", "PEM signing certificate")
		signer := flags.String("signer", "Composite EAT Demo Snapshot Authority", "signer name")
		output := flags.String("output", "", "signed snapshot output")
		_ = flags.Parse(os.Args[2:])
		registry, err := manifest.LoadRegistry(*registryPath)
		if err != nil {
			fatalf("%v", err)
		}
		var project *manifest.Project
		if *packageRoot == "" {
			project, err = manifest.LoadProject(*platform, registry)
		} else {
			project, err = manifest.LoadProjectAtRoot(*platform, registry, *packageRoot)
		}
		if err != nil {
			fatalf("%v", err)
		}
		platformSource, err := os.ReadFile(*platformSourcePath)
		if err != nil {
			fatalf("read platform source CoRIM: %v", err)
		}
		vendorSources := make(map[string][]byte, len(vendorSourceArguments))
		for _, argument := range vendorSourceArguments {
			identifier, path, ok := strings.Cut(argument, "=")
			if !ok || identifier == "" || path == "" {
				fatalf("--vendor-corim must use manifest-id=path")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				fatalf("read vendor source CoRIM %q: %v", identifier, err)
			}
			if _, duplicate := vendorSources[identifier]; duplicate {
				fatalf("duplicate vendor source CoRIM %q", identifier)
			}
			vendorSources[identifier] = data
		}
		sourceRootsPEM, err := os.ReadFile(*sourceRootsPath)
		if err != nil {
			fatalf("read source roots: %v", err)
		}
		sourceRoots := x509.NewCertPool()
		if !sourceRoots.AppendCertsFromPEM(sourceRootsPEM) {
			fatalf("source roots contain no PEM certificates")
		}
		key, err := os.ReadFile(*keyPath)
		if err != nil {
			fatalf("read signing key: %v", err)
		}
		certificate, err := os.ReadFile(*certPath)
		if err != nil {
			fatalf("read signing certificate: %v", err)
		}
		scopesData, err := os.ReadFile(*scopesPath)
		if err != nil {
			fatalf("read source authorizations: %v", err)
		}
		var scopes map[string]string
		if err := json.Unmarshal(scopesData, &scopes); err != nil {
			fatalf("decode source authorizations: %v", err)
		}
		signed, _, err := compiler.CompileAuthenticatedDemoSnapshot(
			project, platformSource, vendorSources, sourceRoots, time.Now(),
			key, certificate, *signer, scopes)
		writeFile(*output, signed, err)
	case "inspect":
		flags := flag.NewFlagSet("inspect", flag.ExitOnError)
		path := flags.String("file", "", "CoRIM file")
		_ = flags.Parse(os.Args[2:])
		data, err := os.ReadFile(*path)
		if err != nil {
			fatalf("%v", err)
		}
		var unsigned corim.UnsignedCorim
		if err := unsigned.FromCBOR(data); err != nil {
			fatalf("decode unsigned CoRIM: %v", err)
		}
		digest := sha256.Sum256(data)
		result := map[string]any{"id": unsigned.GetID(), "sha256": hex.EncodeToString(digest[:]), "size": len(data)}
		encoded, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(encoded))
	default:
		fatalf("unknown command %q", os.Args[1])
	}
}

func packageRelativePath(output, input string) string {
	if output == "" || input == "" {
		fatalf("package output and input paths are required")
	}
	packageDirectory, err := filepath.Abs(filepath.Dir(output))
	if err != nil {
		fatalf("resolve package directory: %v", err)
	}
	inputPath, err := filepath.Abs(input)
	if err != nil {
		fatalf("resolve package input: %v", err)
	}
	relative, err := filepath.Rel(packageDirectory, inputPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		fatalf("package input %q must be inside %q", input, packageDirectory)
	}
	return filepath.ToSlash(relative)
}

func loadCompatibility(path string) platformcorim.CompatibilityPolicy {
	file, err := os.Open(path)
	if err != nil {
		fatalf("read compatibility policy: %v", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var policy platformcorim.CompatibilityPolicy
	if err := decoder.Decode(&policy); err != nil {
		fatalf("decode compatibility policy: %v", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		fatalf("decode compatibility policy: trailing JSON")
	}
	return policy
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %q: %v", path, err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func certificateFingerprint(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read signing certificate %q: %v", path, err)
	}
	if _, err := x509.ParseCertificate(data); err != nil {
		fatalf("signing certificate %q must contain one DER certificate: %v", path, err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

type stringList []string

func (values *stringList) String() string {
	return strings.Join(*values, ",")
}

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func loadProject(arguments []string) (*manifest.Project, string) {
	flags := flag.NewFlagSet("project", flag.ExitOnError)
	platform := flags.String("platform", "", "platform inventory")
	packageRoot := flags.String("package-root", "", "root that confines referenced vendor manifests")
	registryPath := flags.String("registry", defaultRegistry, "profile registry")
	output := flags.String("output", "", "output file")
	_ = flags.Parse(arguments)
	registry, err := manifest.LoadRegistry(*registryPath)
	if err != nil {
		fatalf("%v", err)
	}
	var project *manifest.Project
	if *packageRoot == "" {
		project, err = manifest.LoadProject(*platform, registry)
	} else {
		project, err = manifest.LoadProjectAtRoot(*platform, registry, *packageRoot)
	}
	if err != nil {
		fatalf("%v", err)
	}
	return project, *output
}

func writeCoRIM(path string, unsigned *corim.UnsignedCorim, err error) {
	if err != nil {
		fatalf("%v", err)
	}
	data, err := unsigned.ToCBOR()
	writeFile(path, data, err)
}

func writeFile(path string, data []byte, err error) {
	if err != nil {
		fatalf("%v", err)
	}
	if path == "" {
		fatalf("--output is required")
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
