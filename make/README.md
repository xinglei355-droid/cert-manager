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

cert-manager is a multi-module Go project. The root `go.mod` covers `pkg/`, `internal/`, and `test/`, while each binary under `cmd/` has its own `go.mod` (e.g., `cmd/controller/go.mod`).

### Quick Start: Run a Single Package Unit Test

From the repository root, use `test-pretty` to run a specific package's unit tests with
pretty output. This target does **not** require etcd or kube-apiserver, making it fast
and suitable for local development:

```console
# Run tests for a single package in the root module
make test-pretty WHAT=./pkg/util/pki

# Run tests for a subtree
make test-pretty WHAT=./pkg/controller/...
```

### Running Tests in Sub-Modules

For packages under `cmd/controller`, `cmd/acmesolver`, `cmd/webhook`, etc., first `cd`
into the sub-module directory, then run `go test` directly:

```console
# Run all controller binary tests
cd cmd/controller && go test ./...

# Run a single package in the controller binary
cd cmd/controller && go test ./app/options/
```

Or use the provided `unit-test-*` make targets:

```console
make unit-test-controller   # all controller binary tests
make unit-test-acmesolver   # all acmesolver binary tests
make unit-test-core-module  # all root module unit tests
```

### Running All Unit Tests

```console
make unit-test
```

This runs all unit tests across all modules (core, controller, acmesolver, cainjector,
webhook, third_party) without requiring etcd or kube-apiserver.

### Running All Tests (Including Integration Tests)

```console
make test
```

This requires additional dependencies (etcd, kube-apiserver, kubectl) which will be
downloaded automatically. Use `WHAT` to narrow the scope:

```console
make test WHAT=./pkg/...
```

### CI Test Targets

The `make test-ci` target runs all tests and generates JUnit XML reports. It is used
in CI pipelines and should not be modified without understanding the CI workflow.

```console
make test-ci
```
