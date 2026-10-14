# Follow-up scope

The first release retains the complete integration-library and agent-led
acquisition goals while limiting supported deployment breadth.

| Area | Practical limit in 0.9.0 |
| --- | --- |
| Frontends and custom extensions | Source components and role contracts remain available for explicit host adoption. There is no general Telegram, Slack frontend, HomeCore, Reachy or OB3 migration promise. A persistent application must own identity, audience, routing and delivery. |
| Existing application upgrades | Console acceptance covers fresh application composition. Updating an existing application's selected gateway requires the host's replacement-selection wiring; automatic upgrade across arbitrary hosts remains follow-up work. |
| Predecessor application stores | Adoption of an existing nonempty MobKit 0.8 store under authoritative Meta 0.9 startup is deferred when its composition manifest has only the legacy `created_by_mobkit` writer field. Fresh Meta 0.9 Console installations and Core realm/session CLI use are separate paths. |
| Provider onboarding | Some providers require an existing application, administrator consent or native credential. Universal registration and every remote/mobile/headless auth transport are not included. |
| Package formats and updates | Supported profiles and dependency closures are explicit. Arbitrary native addons, all MCPB/platform combinations and seamless migration or rollback are not promised. |
| Provider operations | Support covers declared operations and account profiles. It is not certification of every upstream API, MCP feature or end-to-end business workflow. |
| Remote deployment and shared workflows | Cloud/GitOps rollout, every durable store and broad unattended multi-user orchestration remain application-owned adoption work. |
| Live devices and modalities | Robot, voice, media and physical behavior need separate application and hardware acceptance. |
| Management and accessibility | Additional management parity, client modes, accessibility coverage and performance measurements require their own evidence. |

These limits do not permit broader grants, guessed accounts, hidden service
retries or claims that a configured frontend is running. Unsupported combinations
must report their missing requirement before performing the privileged effect.
