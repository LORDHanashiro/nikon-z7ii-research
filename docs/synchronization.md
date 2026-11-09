# Separate synchronization

Public preparation never clones, fetches or merges the private repository. Run the publication manager against a local source workspace to refresh this repository, then audit all reachable history and inspect PUBLIC-FILES.txt and the manifest. Default operation is local only.

A public push additionally requires the operator's explicit approval of the current manifest digest. The push helper only permits the main ref and confirms the target visibility immediately before transfer. No CI or release attachments are configured.

The private backup keeps screened research-history commits separately and appends backup metadata on main. Later updates must fast-forward the screened history; a sanitizer-policy change must not silently rewrite published history. Original firmware/reference bytes and databases remain local and are never synchronized.

Use a clean destination and a new ignored work directory for each run. Review the staged paths and diff before committing a prepared update:

```sh
python3 publication-tools/sync.py private --source /path/to/local-research --destination /path/to/private-backup --workdir /path/to/ignored-work/private-run --prepare-only
python3 publication-tools/sync.py public --source /path/to/local-research --destination /path/to/public-release --workdir /path/to/ignored-work/public-run --prepare-only
```

The staged paths/diff are written to the work directory. Without `--prepare-only`, preparation commits the local update and audits every reachable history tree/blob. A completed local update does not push. Refreshes regenerate reviewed indices and tools; prose findings must be separately reviewed in build_public.py. New firmware baselines fail closed. Source Git history is read only.

Network transfer is a separate invocation using `--push --owner ACCOUNT --gh /path/to/gh`, retaining the same source/destination/workdir arguments. Configure the intended GitHub CLI account normally first; the manager never starts authentication. If a separate CLI configuration directory is used, set GH_CONFIG_DIR for that invocation. The public invocation additionally requires `--approved-manifest-sha256 DIGEST`, after explicit owner review of that exact version. Credentials stay in the CLI configuration, outside both repositories. Never use git push --mirror, --all or --force.

No GitHub Actions, automatic scheduled publication or release uploads are installed. Before publication, independently review all new material; pattern rules do not establish copyright clearance or detect every secret. A policy change that alters old screened commits requires a new independently reviewed backup generation, not a force update of published history.
