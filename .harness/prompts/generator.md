# Generator Task Prompt

Your task is spec-first implementation: migrate one narrative spec from `openspec/specs/` to a REQ-*/SCENARIO-* capability spec in `openspec/capabilities/`.

**Task scope**: You produce code and specs. You do NOT evaluate quality — that is a separate task performed in a separate context.

## Your Inputs
1. The sprint contract (in `.harness/contracts/`)
2. The narrative spec file (in `openspec/specs/`)
3. The traceability matrix (`_bmad/traceability.md`)
4. The architecture doc (`_bmad/architecture.md`)

## Your Process

### Step 1: Read the narrative spec
Read the full narrative spec for your assigned domain.

### Step 2: Extract requirements
Identify every distinct behavioral requirement. Each requirement should be:
- Testable (has a verifiable outcome)
- Atomic (single concern)
- Named with a REQ-<DOMAIN>-<NNN> identifier

### Step 3: Extract scenarios
For each requirement, write 1-5 Given/When/Then scenarios. Each scenario:
- References one REQ-* as its parent
- Follows strict Given/When/Then format
- Has a SCENARIO-<DOMAIN>-<NNN> identifier
- Is specific enough to write a test for

### Step 4: Write the capability spec
Create `openspec/capabilities/<domain>/spec.md` following the template at:
`openspec/capabilities/execution-scheduler/spec.md`

Include:
- Header with source narrative, crates, key files
- All REQs with embedded SCENARIOs
- Traceability table at bottom (all status = "narrative" initially)

### Step 5: Update traceability matrix
Add entries to `_bmad/traceability.md` for all new REQ-*/SCENARIO-* IDs.

### Step 6: Commit and write handoff
- `git add openspec/capabilities/<domain>/ _bmad/traceability.md`
- `git commit -m "docs(openspec): migrate <domain> to REQ-*/SCENARIO-* format"`
- Write handoff to `.harness/handoffs/<domain>-generator.md`

## Handoff Format
```markdown
# Generator Handoff: <domain>

## Status: complete
## Domain: <domain>
## Spec file: openspec/capabilities/<domain>/spec.md
## REQ count: N
## SCENARIO count: M

## What was done
- Created spec with N REQs and M SCENARIOs
- Updated _bmad/traceability.md

## What remains for verification task
- Verify all narrative requirements are captured in REQ-*
- Verify scenarios are specific enough for test authorship
- Check traceability table is complete

## Decisions made
- <any non-obvious choices>
```
