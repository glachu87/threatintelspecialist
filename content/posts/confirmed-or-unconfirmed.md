---
title: Claimed, reported, corroborated or confirmed? How to read a cyber incident
date: 2026-11-15
summary: A ransomware post, a news report and an official breach notice are not the same evidence. This is how the incident tracker keeps them separate.
tags: Guide, Incidents, Threat Intelligence
---

Cybersecurity stories often move faster than the evidence. A ransomware group may name a victim before the organisation says anything. A journalist may then report disruption or leaked data. Later, a regulator, law-enforcement body or the affected organisation may confirm what actually happened.

The incident tracker therefore uses **five evidence states** instead of putting every story into a simple true-or-false bucket.

## Confirmed

**Confirmed** means the affected organisation or a competent authority has acknowledged the incident.

Examples of strong confirmation include:

- A statement, customer notice or stock-exchange filing from the affected organisation
- A regulator's breach notice or enforcement document
- A court filing, indictment or law-enforcement statement that identifies the incident
- A government or national cyber authority explicitly acknowledging the event

Confirmed does **not** mean every reported detail is proven. The organisation may confirm an incident while the number of records affected, the initial access vector or attacker attribution remains uncertain.

## Corroborated

**Corroborated** means at least two independent reputable sources report the same incident, but the tracker has not found an explicit acknowledgement from the victim or a competent authority.

This is stronger than a single report, but it is deliberately kept separate from confirmation.

## Reported

**Reported** means one reputable source reports a specific incident and there is not yet enough evidence to call it corroborated or confirmed.

This often happens during the first few hours of a developing incident.

## Claimed

**Claimed** is an early-warning state. It is used when the evidence originates from a threat actor, ransomware leak site or similar criminal claim and has not been independently verified.

Ransomware groups have incentives to exaggerate, recycle old data, misidentify organisations or publish misleading claims. A listing can be useful intelligence without being proof.

The tracker monitors Ransomware.live for these early signals, but a Ransomware.live entry by itself can never make an incident confirmed.

## Disputed

**Disputed** means the affected organisation has denied or directly challenged the allegation.

A dispute does not automatically prove that nothing happened, but readers should know that the claim is actively contested.

## How an incident changes over time

The agent scans its sources every 30 minutes and keeps the evidence attached to each incident.

A typical sequence could be:

**Claimed → Reported → Corroborated → Confirmed**

For example, a ransomware group may first list an organisation. A reputable publication may then report operational disruption. A second independent publication may corroborate the event. Finally, the affected company may issue a statement confirming a cyber incident.

The tracker records those verification changes rather than silently replacing the earlier state.

## What the AI does

AI assists with:

- Deciding whether an item describes a specific cyber incident rather than general security news
- Grouping multiple reports that appear to describe the same incident
- Producing a short neutral headline and summary
- Extracting the organisation, sector, incident type and named threat actor when the source supports them
- Writing a short **Why it matters** explanation

The model is instructed not to invent confirmation, victims, attackers, numbers or impact. Threat-actor material is treated as untrusted input, and embedded instructions are ignored.

Keyword rules remain as a fallback when an AI service is unavailable.

## What the AI does not decide alone

The incident-level evidence state is not simply whatever an AI model says.

The tracker also applies deterministic rules:

- A leak-site feed is treated as a claim source
- Two independent reputable reports can produce **Corroborated**
- Explicit acknowledgement is required for **Confirmed**
- A denial can produce **Disputed**
- The source links and verification history remain visible to the reader

## Questions worth asking

1. Who made the original claim?
2. Has the affected organisation acknowledged anything?
3. Are multiple reports genuinely independent, or are they repeating one source?
4. Is the stolen data new, recycled or unverifiable?
5. Which details are confirmed and which remain attribution or attacker claims?

Automated classification can still make mistakes. Every incident links to its evidence so you can inspect the original reporting before relying on it.
