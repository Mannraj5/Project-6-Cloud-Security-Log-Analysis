# Research report outline — Securing Database-as-a-Service

This is a structure and a set of arguments to write from, not the report itself. The report
should be in your own words.

**Target length:** 2,500–3,000 words · **References:** at least 10, peer-reviewed or recognised
industry sources (no Wikipedia, blogs or Stack Overflow) · **Style:** Harvard, consistently.

**What earns a high grade:** a critical review, not just a description. Every section should ask
*"where does this break down?"*

---

## Abstract (≤ 300 words)

Write this last. One sentence each: what DBaaS is; why security responsibility is split; the
main finding (most cloud database exposures come from customer misconfiguration, not provider
failure); what controls exist; where the gaps are; what this project's lab demonstrates.

## 1. Introduction and background (~500 words)

- What DBaaS is: managed relational and NoSQL services such as Amazon RDS, Azure SQL Database
  and Google Cloud SQL. Place it in the NIST cloud service models (SaaS / PaaS / IaaS).
- Why organisations adopt it: patching, backups, high availability and scaling are handled by the
  provider.
- The tension that frames the report: the provider runs the database, but the customer still
  decides who can reach it and what is in it.
- Scope statement and the report structure.

## 2. The shared responsibility model (~400 words)

- What the provider secures (physical, hypervisor, engine patching) vs. what the customer secures
  (identity, network exposure, encryption choices, data classification, monitoring).
- Compare how AWS, Microsoft and Google each describe the split. Note where they differ.
- **Critique:** the boundary is clear on paper and blurry in practice. Defaults matter: who is
  responsible when an insecure default is left unchanged?

## 3. How cloud databases get exposed (~500 words)

- Misconfiguration: public endpoints, permissive firewall rules, unencrypted snapshots, shared or
  public backups.
- Identity: over-privileged roles, long-lived access keys, missing MFA, compromised accounts.
- Use one or two **documented** real incidents as case studies. Check the details against the
  official report or regulator finding, not news summaries.
- Link to the lab: these are exactly the events the triggers in `sql/triggers.sql` watch for.

## 4. Controls available (~500 words)

| Area | Controls | Limitation to discuss |
|---|---|---|
| Identity and access | IAM roles, least privilege, MFA, short-lived credentials | Permissions sprawl; nobody reviews them |
| Network | Private endpoints, VPC/VNet isolation, security groups | One rule change undoes it |
| Data protection | Encryption at rest and in transit, customer-managed keys | Key management is now *your* problem |
| Configuration | CIS Benchmarks, cloud security posture management (CSPM) | Alert fatigue; drift between scans |
| Detection | Audit logging, SIEM, anomaly detection | Logs that are on but never read |

## 5. Monitoring and detection — the analyst's view (~400 words)

- Why logs are the last line of defence when prevention fails.
- The two kinds of rule demonstrated in the lab: single-event (trigger) and windowed/correlated
  (query). Trade-offs: speed vs. context.
- Report the lab honestly: what the rules caught, what they cannot catch (see
  `docs/01-detections.md` → Known limitations).

## 6. Gaps and future directions (~300 words)

- Multi-cloud visibility; inconsistent log formats.
- Detection that depends on fixed thresholds.
- Skills shortage: the controls exist but need people to configure and watch them.
- Emerging approaches: policy-as-code, confidential computing.

## 7. Conclusion (~500 words)

Restate the key findings, answer the framing tension from the introduction, and give 3–4
concrete recommendations for an organisation adopting DBaaS.

---

## Starting points for references

Look these up and confirm each title, author, year and URL before citing. Then add peer-reviewed
papers from Deakin Library (search IEEE Xplore, ACM Digital Library and ScienceDirect for
*"cloud database security"*, *"cloud misconfiguration"*, *"shared responsibility model"*).

- NIST SP 800-145 — *The NIST Definition of Cloud Computing* (Mell & Grance)
- NIST SP 800-144 — *Guidelines on Security and Privacy in Public Cloud Computing* (Jansen & Grance)
- Cloud Security Alliance — *Top Threats to Cloud Computing* (latest edition)
- Cloud Security Alliance — *Cloud Controls Matrix*
- AWS, Microsoft and Google Cloud — their official shared responsibility documentation
- CIS Benchmarks for the relevant cloud provider
- MITRE ATT&CK — Cloud matrix (for mapping the lab's detections)
- Verizon *Data Breach Investigations Report* and IBM *Cost of a Data Breach Report* (latest editions)
