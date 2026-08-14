# Publishing `bgphorizon-mcp` to PyPI

Once published, anyone can run the server with `uvx bgphorizon-mcp` (no clone
required) and the docs' one-line install commands work as written.

## One-time setup: PyPI Trusted Publishing (recommended)

Trusted Publishing lets GitHub Actions publish via OIDC — **no API token to
create, store, or rotate**.

1. Push this directory to its own GitHub repo (e.g. `bgphorizon/bgphorizon-mcp`).
   If you change the repo path, update `[project.urls]` in `pyproject.toml`.
2. Create the project's trusted publisher on PyPI:
   - Go to <https://pypi.org/manage/account/publishing/>.
   - Add a **pending publisher** (works before the project exists):
     - PyPI Project Name: `bgphorizon-mcp`
     - Owner: `bgphorizon` (your GitHub org/user)
     - Repository name: `bgphorizon-mcp`
     - Workflow name: `publish.yml`
     - Environment name: `pypi`
3. In the GitHub repo, create an **Environment** named `pypi`
   (Settings → Environments) — optionally add reviewers to gate releases.
4. Publish a release: tag `v0.1.0`, then GitHub → Releases → *Publish release*.
   The `publish.yml` workflow runs tests, builds, and publishes automatically.

## Cutting a release

```bash
# bump the version first
sed -i 's/^version = .*/version = "0.1.1"/' pyproject.toml
git commit -am "release: v0.1.1" && git tag v0.1.1 && git push --tags
# then publish a GitHub Release for that tag (UI or `gh release create v0.1.1 --generate-notes`)
```

The version in `pyproject.toml` is the source of truth; PyPI refuses to
re-publish an existing version, so always bump before releasing.

## Manual publish (fallback, uses a token)

If you'd rather not use Actions:

```bash
uv build
# create a token at https://pypi.org/manage/account/token/ (scope: project)
uv publish --token pypi-XXXXXXXX
```

Test against TestPyPI first if you like:

```bash
uv publish --publish-url https://test.pypi.org/legacy/ --token <testpypi-token>
uvx --index-url https://test.pypi.org/simple/ bgphorizon-mcp --version
```

## After publishing — verify

```bash
uvx bgphorizon-mcp --version
BGPHORIZON_API_KEY=bgps_xxx uvx bgphorizon-mcp --selftest
```
