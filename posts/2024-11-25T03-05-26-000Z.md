---
id: cmmc-part-3
title: "The CMMC Countdown: The Action Plan, Part 3"
description: Continue your CMMC action plan with this high-level review of the five-point controls required to get a conditional certificate.
author: Miguel A. Calles
date: 2024-11-25T03:05:26.000Z
---

# The CMMC Countdown: The Action Plan, Part 3

Written by Miguel A. Calles
Nov 24, 2024 • 6 min read

---

![The CMMC Countdown, Part 3](../content/images/2024/11/turkeys-doing-Cirque-du-Soleil-with-locks-and-rings-of-fire.png)

*Turkeys performing at a modern circus show. Microsoft Copilot created this image.*

As stressed in the previous [CMMC Countdown post](https://www.secjuice.com/cmmc-part-2/), the five points are make or break to get a conditional CMMC certification. We will continue briefly reviewing how to address the remaining five pointers.

## CMMC Action Plan, continued

### AC.L2-3.1.18

> Control connection of mobile devices.  
> Determine if:  
> \[a\] mobile devices that process, store, or transmit CUI are identified;  
> \[b\] mobile device connections are authorized; and  
> \[c\] mobile device connections are monitored and logged.

Consider showing that all mobile devices are managed using mobile device management (MDM) software the provides built-in authorization, monitoring and logging.

You could simplify your compliance posture by preventing mobile device access.

### AT.L2-3.2.1

> Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.  
> Determine if:  
> \[a\] security risks associated with organizational activities involving CUI are identified;  
> \[b\] policies, standards, and procedures related to the security of the system are identified;  
> \[c\] managers, systems administrators, and users of the system are made aware of the security risks associated with their activities; and  
> \[d\] managers, systems administrators, and users of the system are made aware of the applicable policies, standards, and procedures related to the security of the system.

Consider showing a security awareness and training plan document that identifies your organization's cybersecurity and CUI risks and the training courses that will educate employees on those risks. Consider using the [SANS Security Awareness Planning Toolkit.](https://www.sans.org/tools/security-awareness-planning-toolkit/?ref=secjuice.com)

### AT.L2-3.2.2

> Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.  
> Determine if:  
> \[a\] information security-related duties, roles, and responsibilities are defined;  
> \[b\] information security-related duties, roles, and responsibilities are assigned to designated personnel; and  
> \[c\] personnel are adequately trained to carry out their assigned information securityrelated duties, roles, and responsibilities.

Consider showing the training assigned to the information technology and cybersecurity team members. Also, the training should be focused on the specific IT and cybersecurity systems used at your organization. Consider identifying these training assignments in your security awareness and training plan.

### AU.L2-3.3.1

> Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.  
> Determine if:  
> \[a\] audit logs needed (i.e., event types to be logged) to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity are specified;  
> \[b\] the content of audit records needed to support monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity is defined;  
> \[c\] audit records are created (generated);  
> \[d\] audit records, once created, contain the defined content;  
> \[e\] retention requirements for audit records are defined; and  
> \[f\] audit records are retained as defined.

Consider reviewing which logs your systems are already capturing and how long they are being retained. Document those existing logs and the retention period. Review them and see whether they can help identify unlawful or unauthorized activity. Your security information and event manager (SIEM) might be able to create reports that identify unauthorized logins and anomalous behavior. Document this internal review as additional evidence. Make adjustments to the logs and retention periods as needed.

### CM.L2-3.4.1

> Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.  
> Determine if:  
> \[a\] a baseline configuration is established;  
> \[b\] the baseline configuration includes hardware, software, firmware, and documentation;  
> \[c\] the baseline configuration is maintained (reviewed and updated) throughout the system development life cycle;  
> \[d\] a system inventory is established;  
> \[e\] the system inventory includes hardware, software, firmware, and documentation; and  
> \[f\] the inventory is maintained (reviewed and updated) throughout the system development life cycle.

Consider creating a document that captures the hardware, software, and firmware when setting up new workstations, laptops, and servers. Revise this document at least annually. Create a document or use an inventory tracking system that identifies all the devices and their hardware, software, and firmware. Review the document at least annually, but ideally, as changes occur if you track it manually.

### CM.L2-3.4.2

> Establish and enforce security configuration settings for information technology products employed in organizational systems.  
> Determine if:  
> \[a\] security configuration settings for information technology products employed in the system are established and included in the baseline configuration; and  
> \[b\] security configuration settings for information technology products employed in the system are enforced.

Consider showing how you harden each new machine and maintain its hardening. Show the scripts, Windows group policy objects, and security profiles (in MDM and security management tools). Collect any reports that show how these security configurations are applied and maintained.

### IA.L2-3.5.1

> Identify system users, processes acting on behalf of users, and devices.  
> Determine if:  
> \[a\] system users are identified;  
> \[b\] processes acting on behalf of users are identified; and  
> \[c\] devices accessing the system are identified.

Consider leveraging the implementation and evidence used for [AC.L2-3.1.1](https://www.secjuice.com/cmmc-part-2/). Furthermore, consider defining how each user's unique identifier (e.g., username) and device's unique identifiers (e.g., hostname) are assigned.

### IA.L2-3.5.2

> Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.  
> Determine if:  
> \[a\] the identity of each user is authenticated or verified as a prerequisite to system access;  
> \[b\] the identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to system access; and  
> \[c\] the identity of each device accessing or connecting to the system is authenticated or verified as a prerequisite to system access.

Consider showing that all systems require a unique username and password to authenticate. Remove default usernames if possible, or change their default passwords. Avoid shared usernames if possible,e or use a password manager that logs who is accessing the shared username. For service accounts, consider creating a naming convention that identifies its purpose.

### IR.L2-3.6.1

> Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.  
> Determine if:  
> \[a\] an operational incident-handling capability is established;  
> \[b\] the operational incident-handling capability includes preparation;  
> \[c\] the operational incident-handling capability includes detection;  
> \[d\] the operational incident-handling capability includes analysis;  
> \[e\] the operational incident-handling capability includes containment;  
> \[f\] the operational incident-handling capability includes recovery; and  
> \[g\] the operational incident-handling capability includes user response activities.

Consider creating an incident response plan. The plan should show the process to addressing and resolving an incident. The plan steps should address each operational incident-handling capability defined in the CMMC control. You can use the [Cybersecurity & Infrastructure Security Agency (CISA) Incident Response Plan (IRP) Basics](https://www.cisa.gov/resources-tools/resources/incident-response-plan-irp-basics?ref=secjuice.com) to get started.

### IR.L2-3.6.2

> Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.  
> Determine if:  
> \[a\] incidents are tracked;  
> \[b\] incidents are documented;  
> \[c\] authorities to whom incidents are to be reported are identified;  
> \[d\] organizational officials to whom incidents are to be reported are identified;  
> \[e\] identified authorities are notified of incidents; and  
> \[f\] identified organizational officials are notified of incidents.

Create a form, set up an internal database, or use your security tools to document and track incidents. Update your IRP to include the contact information of internal (e.g., executives, directors) and external authorities (e.g., DIBNet, CISA, FBI) to contact during an incident and when to contact them. An incident affecting CUI must be reported using the DIBNet portal, which requires an ECA certificate.

### MA.L2-3.7.2

> Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.  
> Determine if:  
> \[a\] tools used to conduct system maintenance are controlled;  
> \[b\] techniques used to conduct system maintenance are controlled;  
> \[c\] mechanisms used to conduct system maintenance are controlled; and  
> \[d\] personnel used to conduct system maintenance are controlled.

Consider documenting:

*   The ticketing system that tracks maintenance activities.
*   The antivirus software keeps the system free of malware prior to, during, and after the maintenance activities.
*   The local and remote maintenance software used during activities.
*   The list of personnel authorized to perform maintenance activities.

### MP.L2-3.8.3

> Sanitize or destroy system media containing CUI before disposal or release for reuse.  
> Determine if:  
> \[a\] system media containing CUI is sanitized or destroyed before disposal; and  
> \[b\] system media containing CUI is sanitized before it is released for reuse.

Consider documenting a procedure on how CUI systems are sanitized (e.g., writing zeroes on the drive) and destroyed (e.g., degaussing and secure shredding). Consider reviewing and tailoring [NIST Special Publication 800-88, Revision 1, Guidelines for Media Sanitization](https://csrc.nist.gov/pubs/sp/800/88/r1/final?ref=secjuice.com).

## Before you go

We will review the more five-point controls in the next post.

Sign up for my mailing list at [https://miguelacallesmba.medium.com/subscribe](https://miguelacallesmba.medium.com/subscribe?ref=secjuice.com)

## Help Support Our Non-Profit Mission

If you enjoyed this article or found it helpful please consider making a **U.S. tax-deductible** donation, Secjuice is a non-profit and volunteer-based publication powered by donations. We will use your donation to help cover our hosting costs and **keep Secjuice an advertisement and sponsor free zone**.

[Make a tax-deductible donation](https://opencollective.com/secjuice)