# Approved-site browser goal reset: source grounding

Read-only exploration of the current implementation at `2d393f6`, 18 October 2026.
This is planning evidence; no new browser authority is enabled.

## Current caller and ownership model

The native app enrolls credentials through authenticated administrative XPC and signs
frozen broker challenges after fresh macOS user presence. The approval key is separate
from service credentials. The broker owns the explicit file Keychain, grants, budgets,
revocation, lifecycle journal and browser-run authority. Private UID deployment is designed
but not proven. Encryption does not protect against a process reading both database and seed.

The installed bridge is authenticated by signing identity plus kernel OS UID. Pairing grants
authority to that bridge/OS user, not an individual model or chat. Any process able to launch
that genuine bridge as the paired UID shares that authority. Agent-name strings cannot fix it.

MCP has four fixed tools: accounts_list, action_run, request_resume and request_cancel.
There is no browser observation/navigation/click/type interface. Core starts an authenticated
private host only for fixed workflows; successful login/profile collection concludes the
run and disposes the context. No agent-ready persistent session state exists.

The host privately owns Chromium/CDP, disposable contexts, compiled origin/path recipes,
interception and document CSP. The native human challenge relay is connection/step/frame-bound;
it is not an agent browsing channel. RequestGate allows all primary-origin non-document
requests, so it is not a per-endpoint/read-only firewall. Current narrow authority relies
substantially on the fixed caller/recipe surface.

## Current source anchors

- `Sources/AgentVaultMCPBridge/BridgeServer.swift`: closed agent tool surface and outputs.
- `Sources/AgentVaultCore/Broker.swift`: grants, admission, authority checks and paired UID.
- `Sources/AgentVaultCore/BrowserRuns.swift`: fixed workflows and terminating lifecycle.
- `Sources/AgentVaultWebHostLink/WebHostLink.swift`: authenticated credential delivery.
- `Sources/AgentVaultWebHost/{WebRun,RequestGate,EventRouter,ChromiumPipe}.swift`:
  workflow/navigation policy, private renderer and owned process handling.
- `Sources/AgentVaultAppSupport/{AppModel,HumanApprovalSigner,HumanStepModel}.swift`:
  human administration, protected signing and private challenge interaction.
- `Sources/AgentVaultCore/PrivateKeychainStore.swift` and
  `Sources/AgentVaultRuntime/Deployment.swift`: secret custody and installed identity design.
- `Sources/AgentVaultBrokerDaemon/BrokerMain.swift` and
  `Sources/AgentVaultAppSupport/AdminPlans.swift`: production browser remains disconnected.

## Rationale and confidence

Fixed-action/no-generic-browser constraints appear from initial commit `d76626a`, then in
FULL-PLAN and AUTHENTICATION-PROTOCOL; these are a dependent documentation lineage. Public
PR6 has no original user discussion establishing that restriction. Source history cannot
establish who first chose it. The user's new explicit website-operation choice supersedes
it as a product goal, while current code remains constrained until a replacement is reviewed.

Reuse private enrollment, grant/revocation ownership, authenticated roles, bounded transports,
recovery and private browser ownership. Reconsider the closed action enum, typed-profile-only
output, completed-login teardown and compiled-only site policy. Do not expose CDP or the human
relay as a shortcut to general browsing.

## Honest security boundary

A page receiving credentials can read its DOM and reflect/encode them into visible output.
An isolated JavaScript world does not hide shared DOM values from that page. Broad observations
increase exposure beyond current typed results. Prompt injection and misuse of authenticated
authority remain separate problems even if the password stays private.

OS/file/process isolation, whole-process egress, live-site compatibility, recovery and
notarization remain open evidence gates. The user reports a Secure Enclave + user presence
label in the native app; actual Test Approval success has not been reported. Existing model
reviews accepted older development units, not this revised browser product or security claim.

Grounding sources: two independent code explorers and a git/PR lineage investigator. They
performed no builds/tests, secret/Keychain access, browser/account access or code edits.
No project-linked team chat, analytics, observability, error tracker or external document
system was consulted; unrelated integrations are not project evidence. Original pre-repo
design intent remains unknown apart from the user conversation supplied here.
