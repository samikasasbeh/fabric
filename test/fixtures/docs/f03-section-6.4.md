Section 6.4 of the developer layer spec, copied by the public export for test/tenant-consent-sheet.test.mjs.

### 6.4 What the end user sees

The consent sheet matches Muse's (MUSE-CONNECTORS-UX.md lines 124 to 134):

| Muse | Fabric's page |
| --- | --- |
| Gmail logo and name | The app's bundled icon and name, under the developer's logo and app name |
| "You can give read-only or read and write access" | `accessLine`, from the reviewed access levels |
| What it reaches | The `reaches` point, built from the reviewed row labels |
| "You choose what Muse can do" | The `control` point, with the developer's app name |
| "Keep an eye on things" | The `caution` point |
| The app's data-use disclosure, with Learn more | The developer's note, or nothing. It is never invented. |
| Exchanges information with the provider; terms and privacy | The provider line, with reviewed links |
| One full-width Connect button; close at top right | The same. Close cancels the session. |

**What Fabric adds to the sheet:**
- the name the provider's own consent screen will show;
- "Connecting for <userHint>" when a hint was given;
- for a shared Google app in Testing mode: "Only accounts Fabric has added can connect, and access lasts 7 days";
- a level choice where one is offered (Gmail read-only as an advanced option, F10 decision 5);
- one line on the defaults, for example "Reads run without asking. Sending asks you first."

**After Connect:** "Connected as <email>", the access label (Full access, Partial access (N permissions not granted), or Pages you shared), and a Done button.

**Other purposes:**
- **`reconnect`:** "Sign in again as <displayName>". Another account ends with "That is a different account. Nothing changed." (`identity_mismatch`).
- **`manage`:** the catalog, app detail, approvals and activity (F03.10).
- **`approve`:** the exact request under Fabric's own heading. The agent's title comes second, labelled as the agent's (F08.0 section 1).
- **`handoff`:** pick one of the user's own accounts, or sign in. Then the confirm screen.

**Failures** use UI-0's codes and words (UI-0-SCREEN-CONTRACTS.md lines 96 to 106), each followed by "Contact <supportEmail>":
- `consent_denied`: "You declined access at <Provider>. Nothing was connected."
- `insufficient_scope`, `never_requested` (F10.5: the provider granted a permission Fabric never holds; the words give the provider's settings page when the definition names one), `setup_required`, `expired`, `identity_mismatch`, `account_changed`, `session_in_use`, `cancelled`.

### 6.5 (the rest of the spec is not part of this copy)
