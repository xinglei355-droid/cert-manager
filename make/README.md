# cert-manager Make Tooling

This directory contains tools and scripts used to create development and
testing environments for cert-manager, centered around the use of [GNU Make](https://www.gnu.org/software/make/).

Most tasks that a developer might encounter day-to-day are documented in `make help`;
you can view that documentation by changing to the root of a cert-manager checkout and simply running:

```console
make help
```

If you think that the documentation in `make help` is insufficient or that an important
make target isn't documented, we'd consider that a bug. Please feel free to raise an issue!

Most of the rest of the documentation for the cert-manager build system is on the [cert-manager website](https://cert-manager.io/docs/):

- [Building cert-manager](https://cert-manager.io/docs/contributing/building/) -
  A guide to different commands which are useful for building cert-manager components locally.
- [CRDs](https://cert-manager.io/docs/contributing/crds/) -
  Information on updating, verifying and generating code centered around the cert-manager [CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/).
- [Developing with Kind](https://cert-manager.io/docs/contributing/kind/) -
  Setting up a local development cluster using [Kind](https://kind.sigs.k8s.io)
- [Running End-to-End Tests](https://cert-manager.io/docs/contributing/e2e/) -
  Details on cert-manager's end-to-end test suite and how it can be run

## Changing the Makefiles

When adding or changing a make target, you might want to consider a few questions which could have a significant
effect on the performance of your changes.

### Should it be documented?

If you want your target to appear when a user runs `make help`, you can add a documentation comment
to it which starts with `##`.

```make
.PHONY: kind-version
## kind-version prints the version of kind.
##
## Bet you didn't expect that, huh?
##
## @category Development
kind-version: | $(NEEDS_KIND)
	@$(KIND) --version
```

Categories are loosely defined; check the output of `make help` for examples of the kinds of categories we already have.

Regular comments above a target should start with a single `#`.

### Should it be `.PHONY`?

> A phony target is one that is not really the name of a file; rather it is just a name for a recipe to be executed when you make an explicit request.

The [GNU Make documentation](https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html) gives the above definition for `.PHONY` targets, and is
worth reading if you're adding a new target since getting this wrong can lead to either spurious rebuilds or unexpected failures to execute your target.

Put short: If a target doesn't create a file with the same name as the target, it should be `.PHONY`.

Mark the target as `.PHONY` by adding the declaration directly above the target, with any documentation comments in between. For example:

```make
.PHONY: my-target
## Does something awesome!
##
## @category Awesomeness
my-target:
	@echo Something awesome!
```

### Target Dependencies / Prerequisites

Make has [two types of dependency](https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html): "normal" and "order-only".

When creating or changing a target, you should choose the type based on what your dependency is.

⚠️ If your dependency is a `.PHONY` target, you should think very hard about whether to include it. A `.PHONY` dependency will force your target to be rebuilt every single time. That's rarely what you want.

If your dependency is a directory or a tool, it should likely be order-only since you don't want to rebuild your target when those dependencies change.

Otherwise, your dependency should be normal.

For example:

```make
$(bin_dir)/awesome-stuff/my-file: README.md | $(bin_dir)/awesome-stuff $(NEEDS_KIND)
	# write the kind version to $(bin_dir)/awesome-stuff/my-file
	$(KIND) --version > $@
	# append README.md
	cat README.md >> $@
```

This target will be rebuilt if `README.md` changes, but not if the installed version of kind changes or the `$(bin_dir)/awesome-stuff` folder changes.

The dependencies you'll need will inevitably depend on the target you're writing. If in doubt, feel free to ask!

## Tool Dependencies

The scripts used by make commonly require additional tooling, such as
access to `kubectl`, `helm`, `kind` and a bunch of other things.

The build system is capable of downloading and provisioning most of these tools
without any user interaction. For example, if an end-to-end test requires `kind`,
then `kind` will be downloaded and that version will be used regardless of whether
you have `kind` installed on your system.

Usually, that's what you want; it ensures that you're using the exact same tools - at the
same versions - as other developers.

Some tools must be installed locally, however. The build system will alert you if a required
tool cannot be found, and these tools are documented [on the website](https://cert-manager.io/docs/contributing/building/#prerequisites).

Specifically, note that you can choose to use your system version of Go or to [download a vendored copy](https://cert-manager.io/docs/contributing/building/#go-versions).

## Running Tests

### Quick Reference

| Goal | Command | Requires integration deps? |
|------|---------|---------------------------|
| All unit + integration tests | `make test` | Yes (etcd, kube-apiserver, kubectl) |
| All unit + integration (verbose) | `make test-pretty` | Yes |
| All unit tests only | `make unit-test` | No |
| Single package unit tests | `make unit-test-what UNIT_WHAT=./pkg/controller/...` | No |
| Single package (verbose) | `make unit-test-what UNIT_WHAT=./pkg/controller/certificates/trigger/...` | No |
| Integration tests only | `make integration-test` | Yes |
| Controller binary module tests | `make unit-test-controller` | No |

### Running Single-Package Unit Tests

The recommended way to run unit tests for a specific package is using the
`unit-test-what` target. This target only requires `gotestsum` (auto-downloaded)
and does **not** require integration test dependencies such as etcd or
kube-apiserver:

```console
# Run all tests in pkg/controller
make unit-test-what UNIT_WHAT=./pkg/controller/...

# Run tests for a specific sub-package
make unit-test-what UNIT_WHAT=./pkg/controller/certificates/trigger/...

# Run tests for internal packages
make unit-test-what UNIT_WHAT=./internal/...
```

You can also use `go test` directly if you have Go installed:

```console
# From the repository root (core module)
go test ./pkg/controller/...

# With verbose output
go test -v ./pkg/controller/certificates/trigger/...
```

### Multi-Module Testing

cert-manager uses multiple Go modules. The core module (`github.com/cert-manager/cert-manager`)
covers `./pkg/...`, `./internal/...`, and `./test/...`. Secondary modules exist
for each binary under `./cmd/`:

- `cmd/controller` — controller binary
- `cmd/webhook` — webhook binary
- `cmd/cainjector` — CA injector binary
- `cmd/acmesolver` — ACME solver binary
- `cmd/startupapicheck` — startup API check binary

**Important:** `go test ./...` from the repository root will NOT recurse into
secondary modules. To test secondary modules, either use the provided make
targets or `cd` into the module directory:

```console
# Using make (recommended)
make unit-test-controller

# Using go test directly
cd cmd/controller && go test ./...
```

### Integration Tests

Integration tests require etcd and kube-apiserver binaries, which are
auto-downloaded by the make targets. To run integration tests:

```console
make integration-test
```
