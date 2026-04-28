# Lantana: Rules of Engagement

Lantana is designed to operate safely in hostile environments and assumes that sensor hosts -- especially high-interaction ones -- will eventually be compromised. To ensure ethical, legal, and operational safety, the platform enforces strict rules of engagement at both architectural and operational levels.

---

## 1. No offensive use

Honeypots must never be used as offensive infrastructure. The honeywall zone enforces outbound traffic restrictions by default, ensuring compromised hosts cannot scan, attack, or otherwise harm third parties. Egress allowances, if any, must be explicit, narrowly scoped, and justified by a specific research goal.

## 2. Assume disposability

Honeypots are assumed to be disposable. No secrets, credentials, production access, or sensitive internal systems may reside on sensor hosts. Any compromise must be considered total, and rebuilds must be routine rather than exceptional. Persistence by adversaries is treated as signal, not failure.

## 3. No entrapment

Honeypots must not intentionally target specific individuals or organizations without explicit legal and organizational authorization. Lantana is designed for broad-spectrum observation, adversary tradecraft research, and detection engineering, not entrapment or targeted intelligence collection.

## 4. Respect privacy

Telemetry collection must respect privacy and data governance constraints. While honeypots observe hostile behavior by design, captured data must be handled, stored, and processed according to applicable policies, regulations, and ethical standards.

## 5. Align with operational goals

Narratives, exposure profiles, and sensor configurations must align with a defined operational goal. Honeypots exist to answer questions, not merely to collect noise. Sensor rotation, profile changes, and topology shifts are part of the operational lifecycle, not ad hoc events.
