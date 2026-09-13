# ForgeWarden add-on manifest contract

The current public SDK candidate contains the standalone add-on manifest
schema and this contract documentation. It does not include executable client
code or depend on ForgeWarden private Core modules.

An add-on manifest declares the package name, version, relative entrypoint,
requested capabilities, and content digest. Producing a conforming document
does not install, load, authorize, or execute an add-on. Admission remains a
separate deterministic ForgeWarden decision.

Before any future installation, validate the manifest against the bundled
schema, verify the package digest, complete add-on security review, and use the
authorized lifecycle controller. Network, shell, Git, production, credential,
and deployment authority are absent from this public contract candidate.
