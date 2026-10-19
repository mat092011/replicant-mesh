# C2 fixed-child configuration

`steamboat_connector.c2_child_config` defines the closed `c2-local-compute-v2`
configuration passed to a fixed host or personal-coordinator child. It carries
absolute protected-storage paths, the complete canonical `RoleLaunchSpec`, and
the public operator verification key for hosts. Coordinator configurations must
carry `null` for that key. The key is public material, bounded to 4 KiB, and is
parsed with the existing P-256 policy used by signed group verification.

The document is a locator and declaration, not authority. A child parses the
closed schema and calls `open_c2_child_binding`; that function opens a real
`RootGenerationStore` and invokes the existing C2 host or coordinator loader.
Those loaders re-read protected configuration and the selected signed root,
compare the complete launch specification, and validate the current policy.
The returned owner keeps the root descriptors open for the binding lifetime;
call `close()` when the child is done. Closing invalidates the binding before
closing the descriptors.

This module does not start a process, load model artifacts, execute inference,
or claim readiness. A later startup adapter must establish those behaviors and
must report READY only after its own actual runtime checks.

Run the focused checks with:

```powershell
python -m unittest tests.connector.test_c2_child_config
```

The signed-root integration cases require POSIX protected files and are skipped
on other platforms. They exercise the repository's actual selected-root
fixtures and C2 loaders; they do not establish process isolation or inference
readiness.
