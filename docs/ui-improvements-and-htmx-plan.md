# UI Improvements and HTMX Migration Plan

This document captures the current UI/schema improvements in LDAPHelp and the recommended next-step PR structure for a hybrid HTMX migration.

## Current implemented improvements

### Group and modal UX
- Added filtering to the group selector, including `groupOfNames`.
- Kept modal action rows fixed at the bottom for:
  - Quick Create
  - Group selector
  - Settings
  - Credential modal
  - Schema Manager

### Schema and subschema presentation
- Improved `cn=subschema` rendering in the entry details view.
- Parsed `objectClasses` and `attributeTypes` into readable schema cards with:
  - name
  - aliases
  - OID
  - kind
  - SUP / MUST / MAY
  - syntax and single-value markers where relevant
  - raw definition in collapsible details

### Object class icons
- Added configurable `ui.object_class_icons` support.
- Added a Settings field to override icons per object class.
- Tree icons continue to update dynamically from the current `objectClass` values.

## Why this remains a hybrid UI

LDAPHelp currently has two kinds of frontend behavior:

1. Rich client-side interactions
   - tree navigation
   - drag and drop
   - right-click context menus
   - inline editing
   - binary/image previews
   - dynamic icon refresh

2. Form/list-driven screens
   - settings
   - group picker
   - schema/subschema display
   - search result panes

The first category should remain JS + JSON. The second category is a strong fit for HTMX.

## Recommended PR plan for HTMX migration

### PR 1: Group selector HTMX fragment
Add:
- `/ui/groups/select`
- optional `/ui/groups/add`

Goal:
- load and filter group picker content as server-rendered HTML
- keep current JSON APIs intact

### PR 2: Settings HTMX fragment
Add:
- `/ui/settings`

Goal:
- render settings form from the server
- reduce JS-based JSON hydration and save handling

### PR 3: Schema manager HTMX fragments
Add:
- `/ui/schema/object-classes`
- `/ui/schema/attribute-types`

Goal:
- move schema card rendering out of client-side string concatenation

### PR 4: Subschema fragment
Add:
- `/ui/subschema?dn=...`

Goal:
- keep `/api/entry` for general entries
- let subschema details render from a dedicated server fragment

## Suggested routing split

### Keep JSON under `/api/*`
- `/api/roots`
- `/api/children`
- `/api/entry`
- `/api/modify`
- `/api/delete`
- `/api/move`
- `/api/create`
- `/api/password`
- `/api/search`
- `/api/schema`
- `/api/schema_manager`

### Add HTML fragments under `/ui/*`
- `/ui/groups/select`
- `/ui/groups/add`
- `/ui/settings`
- `/ui/schema/object-classes`
- `/ui/schema/attribute-types`
- `/ui/subschema`

## Suggested code organization

To keep `browser.go` from growing further, move new fragment work into:
- `ui_handlers.go`
- `ui_templates.go`

Longer term, consider moving away from the large embedded `browseHTML` string toward:
- `templates/browse.html`
- `templates/fragments/*.html`

## Validation note

The current code changes are diagnostics-clean. The environment used during implementation was not able to complete `go test` due local SSH/toolchain issues, so test execution should be re-run in a normal developer shell.
