# Securing Database-as-a-Service: Shared Responsibility, Exposure and Detection

*Research report · Mannraj · October 2026*

---

## Abstract

Database-as-a-Service (DBaaS) moves the work of running a database (patching, backups,
replication, hardware) to a cloud provider. It does not move responsibility for who can reach
the database, what is stored in it, or whether anyone notices when that changes. This report
examines that split. It reviews the shared responsibility model as described by providers and
government guidance, and analyses three documented incidents. In the 2019 Capital One breach, a
misconfiguration combined with an over-privileged role exposed stored customer data. In 2024,
stolen credentials without multi-factor authentication opened more than a hundred Snowflake
customer environments. Also in 2024, a password spray against a single forgotten account gave
an attacker a foothold inside Microsoft. In all three, the provider's platform was not the point
of failure; the customer-controlled layer was. The report then evaluates the main control
families, namely identity, network isolation, encryption, configuration management and logging,
and argues that each has a characteristic way of failing silently. Encryption, for example,
offers no protection against an attacker who signs in with valid credentials. Finally, it reports
on a small detection lab built for this project. Using only SQL over synthetic cloud audit logs,
the lab detected every planted incident with no false positives. It also showed that a
successful password spray is invisible to per-account rules and only appears when events are
correlated across accounts. The report concludes that DBaaS security is now mainly an identity
and visibility problem, and that the remaining gaps are less about missing technology than about
defaults, ownership and whether logs are actually read.

---

## 1. Introduction and background

Cloud computing is defined by NIST as on-demand network access to a shared pool of configurable
computing resources that can be provisioned rapidly with minimal management effort (Mell &
Grance 2011). NIST distinguishes three service models: Software, Platform and Infrastructure as
a Service. Database-as-a-Service sits between the last two. The provider operates the database
engine and everything beneath it, and the customer works with schemas, users and data.

The idea predates the major cloud platforms. Hacigümüş, Iyer and Mehrotra (2002) proposed
"providing database as a service" and identified the central difficulty early: a customer who
hands its database to a provider must trust that provider with its data, so privacy becomes the
main technical challenge. Two decades later, managed services such as Amazon RDS, Azure SQL
Database, Google Cloud SQL and Snowflake are the default way many organisations run databases.
The appeal is operational. Engine patching, backups, failover and scaling become someone else's
job.

What changed less is accountability. NIST's guidance on public cloud computing is explicit that
an organisation which outsources a service remains accountable for the security and privacy of
its data (Jansen & Grance 2011). Early academic surveys catalogued the resulting concerns by
service model: data security, network security, virtualisation, multi-tenancy and the
difficulty of auditing a system one does not operate (Subashini & Kavitha 2011; Hashizume et
al. 2013). Much of that early literature focused on the provider as the risk: a malicious
insider, a hypervisor escape, a neighbouring tenant reading memory.

Industry evidence has since moved the focus. The Cloud Security Alliance's 2022 survey of over
700 practitioners ranked "insufficient identity, credentials, access and key management" as the
top cloud threat and "misconfiguration and inadequate change control" third. Both are failures
on the customer's side of the line (Cloud Security Alliance 2022). Verizon's 2025 Data Breach
Investigations Report found credential abuse to be the most common initial access vector in
breaches, at 22%, ahead of vulnerability exploitation at 20% (Verizon 2025).

This report therefore asks a practical question: if the provider runs the database, where do
DBaaS breaches actually come from, which controls address them, and how would an organisation
know when those controls have failed? Section 2 examines the shared responsibility model.
Section 3 analyses three incidents. Section 4 critically evaluates the available controls.
Section 5 reports on a detection lab built for this project. Section 6 identifies gaps, and
Section 7 concludes.

---

## 2. The shared responsibility model

Every major provider describes security as divided between itself and its customers. Amazon Web
Services summarises the division as security "of" the cloud versus security "in" the cloud: AWS
secures the hardware, software, networking and facilities that run its services, while the
customer's responsibility depends on which services it selects (Amazon Web Services n.d.). For a
managed database, this typically means the provider patches the engine and operating system and
maintains availability. The customer decides who has database and management-plane access,
whether the endpoint is reachable from the internet, whether data and backups are encrypted, and
whether activity is logged and reviewed.

The model is clear on paper and contested in practice, for three reasons.

**The boundary moves with the service.** A customer running a database on a virtual machine
patches the engine. A customer using a managed service does not, but still configures network
exposure. A customer using a serverless data warehouse may have no network setting to configure
at all, only identity policies. The responsibility line is different for each product, and an
organisation using several products has to understand each line separately.

**Defaults decide outcomes.** If a service ships with a permissive default, such as an endpoint
that is public unless changed or MFA that is optional, the model assigns the consequence to the
customer who left the default in place. Providers have increasingly responded by changing
defaults, which is an implicit admission that the line was drawn in a place many customers could
not hold.

**The customer's half is the half attackers use.** Government guidance reflects this. The US
National Security Agency's 2024 *Top Ten Cloud Security Mitigation Strategies*, several of them
co-published with CISA, begins with "uphold the cloud shared responsibility model". Most of the
remaining nine are customer tasks: identity and access management, key management, network
segmentation, data protection and log management (National Security Agency 2024).

---

## 3. How cloud databases get exposed: three cases

### 3.1 Capital One (2019): misconfiguration plus excessive permission

In 2019 an attacker obtained personal data relating to more than 100 million Capital One
customers stored in AWS. Novaes Neto et al. (2021) reconstruct the attack. A misconfigured web
application firewall allowed a server-side request forgery, which let the attacker query the
cloud instance metadata service and obtain temporary credentials for the role attached to that
instance. The role's permissions allowed the attacker to list and read storage buckets containing
customer data.

No single setting caused the breach. A configuration error opened the door, and an
identity-policy error, a role permitted to read far more than its function required, determined
how much was behind it. The authors' central finding is that the organisation's compliance with
established control frameworks did not prevent the breach (Novaes Neto et al. 2021). Compliance
checks whether controls exist; it does not check whether a specific combination of settings is
exploitable.

### 3.2 Snowflake customer environments (2024): valid credentials, no second factor

In 2024, Mandiant reported that a financially motivated group it tracks as UNC5537 had accessed
more than a hundred Snowflake customer instances using stolen credentials, then stolen data and
attempted extortion. About 165 potentially affected organisations were notified (Mandiant 2024).
Mandiant found no breach of Snowflake's own platform. Every incident it investigated traced back
to customer credentials, mostly harvested by infostealer malware on non-Snowflake systems. Some of
those credentials dated from 2020 and had never been rotated. Three conditions were common to the
affected accounts: no multi-factor authentication, credentials that were still valid, and no
network policy limiting access to trusted locations. Once inside, the attackers ran ordinary SQL
reconnaissance queries to list users, roles and tables before exporting data (Mandiant 2024).

This case is close to a pure example of DBaaS shared responsibility. The provider's
infrastructure functioned as designed and authenticated the attackers correctly, because they
presented correct passwords. All three missing controls were customer-side settings.

### 3.3 Midnight Blizzard and Microsoft (2024): one forgotten account

In January 2024 Microsoft disclosed that a state-sponsored actor it calls Midnight Blizzard had
gained access to a small number of corporate email accounts, including those of senior
leadership (Microsoft Security Response Center 2024). The initial foothold was a password spray
against a legacy, non-production test tenant account that did not have MFA enabled. The attacker
kept the number of attempts low and routed them through residential proxies to avoid detection
and lockouts. It then used that account's permissions to move into the production environment.
Microsoft identified the activity by reviewing its own audit logs (Microsoft Threat Intelligence
2024).

The lesson for DBaaS is not the email system but the account. Test tenants, service accounts and
leftover administrator logins accumulate in every cloud estate, and they rarely receive the same
controls as production. A password spray succeeds by trying a few passwords across many
accounts, and it only needs one of them to be weak.

### 3.4 What the cases share

Across all three incidents the provider's platform held. What failed was in the customer's half:
an over-permissive role, an unrotated password, a missing second factor, an account nobody owned.
In each case the activity was recorded in logs that were available to the customer. This supports
the industry rankings in Section 1 (Cloud Security Alliance 2022; Verizon 2025) and shifts the
question from "is the cloud provider secure?" to "would we notice?"

---

## 4. Controls and how each one fails

The controls available to DBaaS customers are mature and well documented (National Security
Agency 2024). Evaluating them critically means asking not only what each one prevents but how it
fails, and whether that failure is visible.

**Identity and access management.** Least-privilege roles, MFA and short-lived credentials
address all three cases directly. MFA alone would likely have stopped the Snowflake and Midnight
Blizzard intrusions. The weakness of identity controls is coverage. Policies are applied to the
accounts an organisation knows about, and Midnight Blizzard succeeded through one it had
effectively forgotten. Permissions also tend to grow over time and are rarely reviewed. Capital
One's role could read more than it needed long before anyone tried to use it.

**Network isolation.** Private endpoints and IP allow-lists mean a stolen password is not enough
on its own. Mandiant listed the absence of network policies as a shared factor among Snowflake
victims (Mandiant 2024). The weakness is that isolation is a single setting. One change, made for
convenience or by an attacker who already has privileges, removes it, and nothing about the
database's behaviour changes to signal that it happened.

**Encryption.** Encryption at rest and in transit is now standard. Research has gone further:
CryptDB showed that a database can execute many SQL queries over encrypted data, so that a
compromised server or curious administrator sees only ciphertext (Popa et al. 2011). This directly
addresses the trust problem Hacigümüş, Iyer and Mehrotra (2002) raised. However, encryption
protects data from people who should not be able to query it. In the Snowflake incidents the
attackers were, from the database's perspective, legitimate users. Any system that decrypts data
for authorised queries will decrypt it for an attacker holding authorised credentials. Encryption
is necessary, but it is not a defence against identity compromise. Customer-managed keys also add
a new responsibility, key management, which NSA lists as a separate mitigation of its own.

**Configuration management.** Benchmarks and cloud security posture management tools scan for
public endpoints, disabled encryption and excessive permissions. They catch exactly the class of
error behind Capital One. Their limits are timing and volume: a scan finds drift after it has
happened, and large estates generate more findings than teams can triage. Novaes Neto et al.
(2021) also show that passing a framework's checks is not the same as being secure, because an
attack chain combines settings that are each individually acceptable.

**Logging and detection.** Logging is the control of last resort. When prevention fails, as each
case shows it eventually does, logs are what make the failure visible. Microsoft found Midnight
Blizzard in its audit logs. Logging's failure mode is the quietest of all: logs that are enabled
but never queried look identical, from the outside, to logs that were reviewed and found clean.
This is why the NSA's final mitigation concerns not just collecting cloud logs but managing them
"for effective threat hunting" (National Security Agency 2024).

---

## 5. Detection in practice: a SQL log-analysis lab

To test the claim that these failures are visible in logs, a small lab was built for this
project. It generates fourteen days of synthetic logs for a twenty-person organisation:
identity-provider sign-ins, IAM changes and managed-database configuration changes. Three
incidents with known timestamps are planted in them, modelled on Section 3. The first is a
password-guessing attack that leads to the attacker granting itself a database administrator
role at 2:31 am and making the production customer database public. The second is a password
spray in which one guess succeeds. The third is encryption at rest being disabled. Eight
detections are written in SQL. Three are triggers that alert the instant a single dangerous
event is inserted, such as a database becoming public. Five are queries over time windows for
patterns that need history, such as repeated failures or a first sign-in from a new country.

All nine expected alerts fired, and none of the routine activity alerted. Two results are worth
reporting beyond that headline.

First, **avoiding false positives took more design than detection did.** Each rule has a benign
look-alike in the data: a user mistyping a password twice, a colleague who regularly works from
New Zealand, the same privileged role granted at 2 pm on a Tuesday. The new-country rule only
stopped alerting on the traveller once a seven-day learning period was added. Without it, the
rule measured where the log began rather than anything the user did.

Second, **a successful password spray is invisible to per-account rules.** The compromised
account sees one failed sign-in, not the five that a brute-force rule requires. A rule that
counts failures per source IP sees the spray but cannot say whether it worked. The compromise
only appears when the two are joined, that is, a successful sign-in from an IP that was spraying.
This is precisely the Midnight Blizzard pattern. The same lab also exposes the limit of that fix:
the correlation keys on a single IP, and the real attacker rotated through residential proxies
precisely so that no single IP stood out (Microsoft Threat Intelligence 2024). Fixed thresholds,
however well tested, can be learned and stayed under.

The lab has clear limits. Its data is synthetic, which demonstrates logic rather than real-world
precision, and real cloud logs are larger, messier and use UTC timestamps across multiple
regions. Its value is in showing, with ground truth, both that log-based detection works for
these failure modes and where it stops working.

---

## 6. Gaps and future directions

**Visibility across services and clouds.** Each provider, and often each service, logs in its own
format with its own retention defaults. The NSA identifies hybrid and multi-cloud complexity as a
mitigation area in its own right (National Security Agency 2024). Correlating a sign-in in one
system with a configuration change in another, as the lab's attack chain requires, is
straightforward in one database and difficult across several.

**Ownership of the forgotten.** Test tenants, service accounts and old credentials fall outside
both the provider's responsibility and, often, any named person's. Two of the three cases began
there.

**Detection that adapts.** Threshold rules are transparent and testable but predictable.
Behavioural baselines per user and per account are harder to evade, but they are also harder to
explain to the analyst who has to act on an alert.

**Safer defaults.** The most effective change of recent years has been providers enforcing MFA
and private access by default. This partially redraws the shared responsibility line in the
customer's favour. Further movement in this direction may achieve more than any additional
control customers must remember to switch on.

---

## 7. Conclusion

DBaaS succeeds at what it promises: the provider runs the database well. The incidents examined
here show that the provider's platform is rarely where breaches begin. They begin in the half of
the shared responsibility model that stays with the customer: identities without a second factor,
roles with more permission than their purpose, credentials never rotated, accounts nobody owns,
and settings that can be changed in one step. Industry surveys and breach data point the same
way, ranking identity and misconfiguration above provider-side flaws (Cloud Security Alliance
2022; Verizon 2025).

The available controls are mature, but each fails in its own way. Identity controls fail on
coverage, network isolation through a single change, encryption against legitimate-looking
access, and configuration scanning on timing. None of these failures announce themselves. That
is why the report's practical emphasis falls on detection. The lab built for this project showed
that plain SQL over ordinary cloud logs can reconstruct an attack chain from first failed
password to exposed database within minutes of each event. It also showed that the most
realistic attack in the set, a quiet password spray, is only visible when events are correlated
across accounts. Even then, it can be evaded by an attacker who spreads the attempts across many
IPs.

For an organisation adopting DBaaS, the recommendations that follow are:

1. **Enforce MFA on every identity that can reach data**, including test and service accounts,
   and audit for accounts that have no owner.
2. **Make public network access the exception**, and alert on any change that enables it.
3. **Review role permissions against actual use** on a schedule, not only at creation.
4. **Treat audit logs as a control, not an archive.** Write detections for the known patterns,
   test them against data where the answer is known, and record what they cannot see.

The remaining gaps are less about missing technology than about defaults, ownership and
attention. Closing them is mostly a matter of organisations deciding that the customer's half of
the model is a job someone is actually assigned to do.

---

## References

Amazon Web Services n.d., *Shared responsibility model*, viewed 21 October 2026,
<https://aws.amazon.com/compliance/shared-responsibility-model/>.

Cloud Security Alliance 2022, *Top threats to cloud computing: Pandemic Eleven*, Cloud Security
Alliance, <https://cloudsecurityalliance.org/>.

Hacigümüş, H, Iyer, B & Mehrotra, S 2002, 'Providing database as a service', *Proceedings of the
18th International Conference on Data Engineering (ICDE 2002)*, IEEE, San Jose, pp. 29–38.

Hashizume, K, Rosado, DG, Fernández-Medina, E & Fernandez, EB 2013, 'An analysis of security
issues for cloud computing', *Journal of Internet Services and Applications*, vol. 4, article 5,
doi:10.1186/1869-0238-4-5.

Jansen, W & Grance, T 2011, *Guidelines on security and privacy in public cloud computing*, NIST
Special Publication 800-144, National Institute of Standards and Technology, Gaithersburg.

Mandiant 2024, 'UNC5537 targets Snowflake customer instances for data theft and extortion',
*Google Cloud Threat Intelligence*, 10 June,
<https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion>.

Mell, P & Grance, T 2011, *The NIST definition of cloud computing*, NIST Special Publication
800-145, National Institute of Standards and Technology, Gaithersburg.

Microsoft Security Response Center 2024, 'Microsoft actions following attack by nation state actor
Midnight Blizzard', *MSRC Blog*, 19 January,
<https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/>.

Microsoft Threat Intelligence 2024, 'Midnight Blizzard: guidance for responders on nation-state
attack', *Microsoft Security Blog*, 25 January,
<https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/>.

National Security Agency 2024, *NSA releases Top Ten Cloud Security Mitigation Strategies*, press
release, 7 March,
<https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3699169/nsa-releases-top-ten-cloud-security-mitigation-strategies/>.

Novaes Neto, N, Madnick, S, de Paula, AMG & Malara Borges, N 2021, 'A case study of the Capital
One data breach: why didn't compliance requirements help prevent it?', *Journal of Information
System Security*, vol. 17, no. 1, pp. 49–78.

Popa, RA, Redfield, CMS, Zeldovich, N & Balakrishnan, H 2011, 'CryptDB: protecting
confidentiality with encrypted query processing', *Proceedings of the 23rd ACM Symposium on
Operating Systems Principles (SOSP '11)*, ACM, Cascais, pp. 85–100,
doi:10.1145/2043556.2043566.

Subashini, S & Kavitha, V 2011, 'A survey on security issues in service delivery models of cloud
computing', *Journal of Network and Computer Applications*, vol. 34, no. 1, pp. 1–11.

Verizon 2025, *2025 Data Breach Investigations Report*, Verizon Business,
<https://www.verizon.com/business/resources/reports/dbir/>.
