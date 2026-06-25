# Spec 05 — Issue lifecycle tracking (new / open / fixed / regressed)

**Status:** draft
**Surfaces touched:** backend (`models`, `services`, API), frontend (Target detail + diff view)
**Effort:** ~1 medium feature — one new table, lifecycle logic on scan completion, a few
endpoints, a UI view. No engine changes.

## Context

Today every `Finding` is siloed inside the `Scan` that produced it. The dashboard counts
findings per scan, but nothing tracks a *single vulnerability over time* — so you can't answer
the questions that actually matter for security posture:

- What's **new** since the last scan? (a regression, or a freshly introduced bug)
- What did we **fix**? (and when)
- What **came back** after being fixed? (a regression that slipped through)
- How long has this issue been **open**?

We already have the missing ingredient: `Finding.fingerprint` is a stable id that survives
refactors. This spec promotes findings into deduplicated **Issues** keyed by
`(target_id, fingerprint)` and gives each a lifecycle, computed automatically as scans run.
The CLI's baseline diff does a one-shot version of this; this makes it first-class and durable
in the app.

## Data model — `backend/models.py`

New table:

```python
class Issue(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)
    fingerprint: str = Field(index=True)            # unique per (target_id, fingerprint)
    # Latest known descriptive fields (refreshed each time the issue is seen):
    threat_class: str
    severity: str = Field(index=True)
    title: str
    status: str = Field(default="open", index=True)  # open | fixed | regressed | suppressed
    first_seen_at: datetime
    first_seen_scan_id: int
    last_seen_at: datetime
    last_seen_scan_id: int
    fixed_at: datetime | None = None
    times_seen: int = 1
```

`status` semantics:
- **open** — present in the most recent scan that could have detected it.
- **fixed** — was open, absent from a later complete scan → presumed remediated.
- **regressed** — was fixed, then reappeared (special-cased "open" worth surfacing loudly).
- **suppressed** — muted via the suppression list (mirrors `Finding.suppressed`); never
  auto-transitions until unsuppressed.

(`Finding` stays exactly as-is — the per-scan record of truth. `Issue` is the rollup.)

## Lifecycle update — `backend/services.py`

Extend `run_scan_for()` so that, after persisting a scan's findings, it reconciles Issues for
that target. Pseudologic:

```
seen = { f.fingerprint for f in report.findings }            # non-suppressed this scan
for f in report.findings:
    issue = get_or_create(target_id, f.fingerprint)
    if new:                      status=open,      first_seen=this scan
    elif issue.status == "fixed": status=regressed                 # came back!
    else:                         status=open
    refresh severity/title; last_seen=this scan; times_seen += 1

# Auto-close issues that should have been re-detected but weren't:
for issue in open_issues_for(target_id):
    if issue.fingerprint not in seen and _was_covered(issue, report):
        issue.status="fixed"; issue.fixed_at=now

# Suppressed findings → issue.status="suppressed".
```

### The critical correctness guard: `_was_covered`

A finding's absence only means "fixed" if this scan **could have found it**. A scan where the
target was unreachable, or that ran SAST-only, must NOT mark dynamic issues as fixed (that
would silently hide real vulnerabilities — the worst failure mode for a security tool).

`_was_covered(issue, report)` returns true only when the issue's `method`/`threat_class` was
actually exercised:
- static issues → covered iff the scan ran with a `repo_path`.
- dynamic issues → covered iff the scan reached the target (recon `reachable`) and that
  threat class's module ran.

If coverage is uncertain, **leave the issue open** (fail safe). Record per-scan coverage on
the `Scan` row (e.g. `covered_static: bool`, `covered_dynamic: bool`) so this is auditable.

## API — `backend/main.py`

- `GET /api/targets/{id}/issues?status=&severity=` — the issue list (the new primary view of a
  target's posture), newest-activity first.
- `GET /api/issues/{issue_id}` — issue detail + its history (the scans that saw it, from
  `Finding` rows with that fingerprint + target).
- `GET /api/targets/{id}/diff?base={scanId}&head={scanId}` — compares two scans by fingerprint
  and returns `{ new: [...], fixed: [...], unchanged: [...] }`. Defaults: `head` = latest done
  scan, `base` = the one before it.
- Extend `GET /api/stats` with `new_this_period` and `regressions` counts.

## Frontend

- **Target detail / Issues view** (new page, or a tab on the target): a table of Issues with a
  status badge (🆕 New, ● Open, ✅ Fixed, ⚠️ Regressed, 🔇 Suppressed), severity, age
  (`first_seen` → now), `times_seen`, and last-seen scan link. Filter by status + severity.
  This becomes the natural landing page for a target — "what's wrong, and is it getting better?"
- **Scan diff view**: from a scan, a "Compare to previous" button → three columns
  *New since* / *Fixed since* / *Still open*, driven by the `/diff` endpoint. Highlight
  regressions in the New column.
- **Dashboard**: add "New findings this week" and "Regressions" cards; make the existing
  posture numbers link to the filtered Issues view.

## Tests

- **New → fixed:** scan a target, assert issues are `open`/`new`. Re-scan against a *hardened*
  variant (same target, fixed code) and assert the matching issues flip to `fixed` with a
  `fixed_at`. (Use the existing vulnerable/hardened fixture pair as "before/after".)
- **Regression:** fixed → scan vulnerable again → status becomes `regressed`.
- **Coverage guard (most important):** a SAST-only re-scan must NOT mark dynamic issues fixed;
  an unreachable-target scan must NOT close anything. Assert open issues survive an
  incomplete scan.
- **Suppression interplay:** suppressing a fingerprint sets the Issue to `suppressed` and keeps
  it out of the "new/open" counts; unsuppressing restores its computed status.
- **Diff endpoint:** returns correct new/fixed/unchanged sets between two scans.

## Migration

Additive only — `init_db()`/`create_all` creates the `Issue` table on next startup; existing
`Scan`/`Finding` rows are untouched. Issues backfill naturally as new scans run. (Optionally a
one-shot backfill script that walks historical scans oldest→newest and replays the lifecycle.)

## Open questions

1. **Coverage granularity** — track coverage per threat class on each `Scan`, or just the two
   coarse `covered_static`/`covered_dynamic` flags? Proposal: start coarse; refine if it
   produces false "fixed" closures.
2. **Notifications** — should an issue transitioning to `open`/`regressed` at ≥ a threshold fire
   a webhook/email? Out of scope here, but the lifecycle hook in `run_scan_for` is the natural
   trigger point — leave a clean seam for it (a future spec).
3. **Per-target vs. global issues** — keyed per target here. A future "same bug across many of
   my apps" rollup would key on fingerprint alone; deferred.
4. **Manual status** — let a user mark an issue "won't fix" / "accepted" distinct from
   suppression? Could fold into `status`; deferred to keep v1 lifecycle purely computed.
```
