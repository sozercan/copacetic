---
title: Replacing Per-Package Layers (Experimental)
---

:::warning Experimental
This feature is experimental and requires `COPA_EXPERIMENTAL=1`.
:::

By default Copa adds the updated packages as a new layer on top of the image.
For images built by [Dalec](https://github.com/project-dalec/dalec) with one
layer per package (`image.layers: per-package`), Copa can instead replace the
layers of the updated packages in place:

```bash
export COPA_EXPERIMENTAL=1
copa patch -i registry.example.com/app:1.0 -r report.json -t 1.0-patched \
  --layers=replace --push
```

Copa replaces only the layers of the updated packages and the final "state"
layer, which holds the package database and generated files. Every other layer
blob is reused as-is, so pulling the patched image only downloads the changed
layers. The image does not grow a patch layer, and patching the image again
replaces the same layers.

## Requirements

- The image has the `dev.dalec.image.layers=per-package` label and Dalec layer
  history comments (`dalec.layer.v1 ...`). Copa finds layers by these comments.
- Azure Linux 3 (RPM) images, one platform at a time (`--platform` selects it in
  a multi-platform index).
- The image is in a registry, and `--push` is set: the patched image is
  assembled and pushed at the registry level.

## Safety checks

Before changing anything, Copa downloads the updated RPMs and checks that:

- every update replaces a package that is already installed, with a newer version;
- `rpm -U --test` passes against the image's own package database;
- no scriptlet or trigger that runs during the upgrade does more than refresh
  the linker cache (`ldconfig`).

If a check fails, Copa stops with the reason and nothing is pushed. Run Copa
without `--layers=replace` to patch the image by adding a layer instead.

After applying the update, Copa splits the upgraded root filesystem into layers
with Dalec's grouping rules and verifies that the flattened patched image
matches the upgraded root filesystem (file type, mode, ownership, size, content,
symlink target, device numbers, extended attributes, and file timestamps). The
image is only pushed if the verification passes.
