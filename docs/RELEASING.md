# Release versioning

The first tagged release is **v0.1.0**. The canonical package/application version
is `VERSION` in `src/navis_common/version.py`; setuptools reads it dynamically and
FastAPI uses the same value. Git tags add `v` (`v0.1.0`); local/container tags use
the plain version (`localhost/navis:0.1.0`). Container labels record the version
and optional Git revision, and the build refuses a package/image version mismatch.

Before 1.0, releases are development versions. Use PATCH releases such as 0.1.1
for compatible fixes and documentation updates; use MINOR releases such as 0.2.0
for incompatible API/data-contract changes. A 1.0 release requires a separately
validated stable contract and deployment/readiness assessment.

Application version, HTTP `/v1`, database migration number, named topology
version UUID and builder implementation version are separate identifiers. A new
application release does not justify rewriting an applied migration or retagging
an old graph build.

For a future release:

1. Update `VERSION` and the Dockerfile's default `NAVIS_VERSION` together.
2. Add changelog/release notes and update API docs/examples/OpenAPI for any change.
   Append new numbered SQL migrations; never edit SQL already deployed with the
   migration ledger.
3. Run unit tests and `python docs/api/verify_contract.py`; perform applicable
   live database, container and restore validation and record any gaps honestly.
4. Commit the release changes, create an annotated `vX.Y.Z` tag at that commit,
   and publish the GitHub release with explicit upgrade instructions.
5. Build containers from that tag and pass the matching `NAVIS_VERSION` and
   `VCS_REF`. If distributed, publish an immutable registry version/digest.

Do not move or overwrite a published release tag. Publish a new patch/minor
release to correct it. GitHub supplies source archives for the tagged release;
this repository does not claim a published prebuilt image unless one was
actually built and uploaded to a registry.
