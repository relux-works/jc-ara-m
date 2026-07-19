# jc-ara-m architecture diagrams

The diagrams are PlantUML source files. Each file covers one lifecycle from the
multi-rule SEAC architecture; generated images are validation artifacts and are
not committed.

## Views

- `plantuml/sequence/atomic-rule-mutation.puml` — copy-on-write rule mutation
  and atomic visibility of rule metadata plus refresh tag.
- `plantuml/sequence/ota-rule-reconciliation.puml` — authenticated, resumable
  reconciliation of an N-rule desired catalog.
- `plantuml/state/v011-to-multirule-migration.puml` — guarded CARD#5 replacement
  and rollback states.

## Validate

From the repository root:

```bash
plantuml -checkonly diagrams/plantuml/sequence/*.puml diagrams/plantuml/state/*.puml
```

To render review images without changing the repository:

```bash
mkdir -p .temp/TASK-260719-3r17pa/plantuml
plantuml -tpng -o "$PWD/.temp/TASK-260719-3r17pa/plantuml" \
  diagrams/plantuml/sequence/*.puml diagrams/plantuml/state/*.puml
```
