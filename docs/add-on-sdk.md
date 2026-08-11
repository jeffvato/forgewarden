# Forgewarden add-on SDK

Use `swarm.addon_sdk.scaffold()` to create a local add-on package with a
least-privilege manifest, a relative entrypoint, and a canonical digest.

```python
from pathlib import Path
from swarm.addon_sdk import scaffold

package = scaffold(Path("./my-addon"), "my-addon", "1.0.0")
```

The scaffold is a review artifact. It does not install or execute the add-on.
Before installation, review the manifest, run the add-on security tests, and
use the local add-on lifecycle manager. Network, shell, Git, production, and
credential access are not available to the generated package.
