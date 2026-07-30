# Forman Resolution Example

This example exercises `heresy-geom.profile/v2` with:

- a short window of 2 actions;
- a long window of 4 actions;
- a stride of 2 actions;
- unweighted integer Forman curvature;
- per-edge and whole-window L1 thresholds;
- mandatory short/long spectral and holonomy companions.

Run it from the repository root:

```sh
python -m heresy_sec monitor examples/forman_resolve/events.jsonl \
  --policy examples/forman_resolve/policy.json \
  --runs-dir runs \
  --run-name forman-resolve

python -m heresy_sec inspect runs/forman-resolve
python -m heresy_sec verify runs/forman-resolve
python -m heresy_sec replay runs/forman-resolve
```

The stream contains six classically allowed file-read descriptions. It produces three
geometry bundles at endpoints 2, 4 and 6. The engine evaluates descriptions only; it
does not read the named files.
