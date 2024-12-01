---
id: black-basta-ransomware
title: Understanding the Black Basta Ransomware Service
description: Learn how Black Basta’s double extortion tactics works.
author: Ross Moore
date: 2024-10-31T15:28:13.000Z
---

# Understanding the Black Basta Ransomware Service

Written by Ross Moore

Oct 31, 2024 • 14 min read

---

![Understanding the Black Basta Ransomware Service](../content/images/2024/10/several-locks-shaped-as-gourds-and-pumpkins.png)

*This image was created using Microsoft Copilot.*

## Scares

During Halloween, when I was a kid, one of the big scares was the razor blades in the apples that people gave to the kids (particularly candied or caramel apples that could hide the entry point). It was big news (though I don’t remember how much it really occurred), and kids suddenly became suspicious of their long-time adult neighbors raising our best friends. Talk about spreading FUD! (BTW – nothing bad ever happened to me or my friends from any candy all those years – except for the annual stomach ache from too much sugar).

Another general, long-time, big fear was tapeworms. Everyone had to be extra wary of what was in their food. It was especially concerning when every active kid was eating all day. Was it our constant activity making us hungry? Or was it some parasitic predator? For me, it always ended up just being active.

There are dangers, real and imagined, all around us and throughout our lives. It's good to have people - whether family, friends, adults, or peers - surrounding us to help us out, whether it's just information to keep us safe or to help us out in an emergency. But even those who wish to be helpful can inadvertently spread misinformation and fear and unintentionally forget to arm people with the right ways to discern and combat whatever concern is at hand, even when it comes to an actual emergency.

To take a more serious turn, not knowing what to do in a crisis can cost lives. In 2003, a nightclub fire ended up causing 100 deaths. Most people were fleeing through the few doors available and noted for egress. About 1/3 of those who escaped the fire made it out of some of the windows. Unbeknownst to most, a front room wall was lined with several windows – but they were painted black and were unnoticed and unknown to the concert-goers. By no means am I making light of the tragedy, nor am I blaming any victims. When this was brought up in a law enforcement presentation about learning from the past, the main thought was: if only people had known they were right by several windows that they could break through (though it would have been difficult), there might have been far fewer - perhaps no - casualties.

To bring this back to the present and apply it to cybersecurity, a recent severe and ever-present threat to many companies is ransomware. While it’s not necessarily life-threatening (though it can come close when healthcare facilities are held ransom), it’s also not just a specter or apparition that is part of a kid’s tale.

Some years ago, when cyber insurance was taking hold, having an incident response (IR) plan was one of the primary requirements. There are many more requirements now that the insurance industry has grown through the struggles of what all is entailed in the policies, but that IR requirement has become much more prevalent across the board for various regulations and contracts.

The main concern was ransomware. It still is. There are plenty of threats, and there’s no way to truly prioritize the threats out there – each industry and organization has its unique challenges. But ransomware is at the top.

In this article, I want to point out one of the many ransomware groups and provide the requisite actions to protect from ransomware. 

## Who is Black Basta?

One of the newer players on the RaaS (ransomware-as-a-service) scene is Black Basta. They have their main site – Basta News - on the dark web at: stniiomyjliimcgkvdszvgen3eaaoz55hreqqx6o77yvmpwt7gklffqd\[.\]onion.

![](https://www.secjuice.com/content/images/2024/10/image.png)

A partial screen capture of the Basta News provided by the author.

Where do they score in the activity metric? According to Rapid7, Black Basta is the #4 most active.

![](https://www.secjuice.com/content/images/2024/10/image-1.png)

Source: [Rapid7 2024 Ransomware Radar Report](https://www.rapid7.com/about/press-releases/rapid7-ransomware-radar-report-charts-ransomware-group-activity-and-methodologies-for-fresh-insights/?ref=secjuice.com)

Black Basta emerged as a formidable player in the ransomware landscape in early 2022, quickly establishing itself as one of the most active and sophisticated Ransomware-as-a-Service (RaaS) operations. The group's rapid rise to prominence has drawn significant attention from cybersecurity researchers and law enforcement agencies alike.

According to the MITRE ATT&CK Navigator, Black Basta uses the following techniques (because the actual Navigator graph is so large and the techniques so spread out, I didn’t paste the view here. But you can see the full view here: [https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS1070%2FS1070-enterprise-layer.json](https://mitre-attack.github.io/attack-navigator/?ref=secjuice.com#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS1070%2FS1070-enterprise-layer.json)

**Text from the MITRE ATT&CK Navigator (techniques, not including sub-techniques)**

**Execution**

\-- Native API

\-- Windows Management Instrumentation

\-- Virtualization/Sandbox Evasion

**Defense Evasion**

\-- Debugger Evasion

\-- Modify Registry

\-- Virtualization/Sandbox Evasion

**Discovery**

**\--**Debugger Evasion

**\--** File and Directory Discovery

\-- Remote System Discovery

\-- System Information Discovery

**Impact**

\--Data Encrypted for Impact

\-- Inhibit System Recovery

Black Basta uses a highly targeted approach. Unlike some ransomware groups that cast a wide net, Black Basta carefully selects its victims, primarily focusing on organizations in countries like the United States, Japan, Canada, the United Kingdom, Australia, and New Zealand. This strategic targeting has allowed them to claim numerous high-profile victims across various industries, including construction, law practices, and real estate.

The group's tactics are particularly noteworthy. Black Basta employs a double extortion strategy. Normal ransomware encrypts data, and the victim doesn’t get it back until the thieves are paid (if one can trust thieves). Double extortion makes it tougher. The ransomware group not only encrypts victims' data but also threatens to publish sensitive information on their public leak site if ransom demands are not met. More specifically, [“cybercriminals encrypt sensitive user data and threaten to publish it on the dark web, sell it to the highest bidder, or permanently restrict access if the ransom is unpaid by a deadline.”](https://gca.isa.org/blog/double-extortion-ransomware-what-it-is-and-how-to-respond?ref=secjuice.com) This approach puts immense pressure on victims to comply, as they face both operational disruption and potential reputational damage.

Black Basta's ransomware is sophisticated. It uses a combination of the XChaCha20 algorithm for file encryption and employs unique encryption schemes that prepend each file with a 133-byte ephemeral NIST P-521 public key. This level of complexity speaks to the technical expertise behind the operation. **NOTE**: Some sources say Black Basta uses ChaCha20 instead of XChaCha20. A primary difference between XChaCha20 and ChaCha20 is the use of an extended nonce (192-bit vs.  64-bit), but this could be because of the multiple builds that Black Basta depooys.

There are strong indications of a connection between Black Basta and the infamous Conti ransomware group. The timing of Black Basta's emergence coincided with Conti's dissolution, and blockchain analysis has revealed financial links between the two groups. This connection suggests that Black Basta may have inherited some of Conti's expertise and resources. (more on this below)

Black Basta has been successful in its extortion efforts. Research suggests the group has accumulated at least $107 million in ransom payments since its inception, with some individual ransoms exceeding $1 million. These figures underscore the significant threat Black Basta poses to targeted organizations.

As Black Basta continues to evolve and refine its tactics, it remains a major concern for cybersecurity professionals and potential targets alike. The group's sophisticated approach, technical prowess, and apparent connections to established cybercriminal networks make it a formidable adversary in the ongoing battle against ransomware.

## Are they related to Conti?

Good question! Many are asking.

There are strong indications of a connection between Black Basta and the Conti ransomware group:

1\. Timing and Operational Similarities

   - Black Basta emerged in early 2022, around the same time Conti ceased operations in May 2022.

   - Both groups have similar tactics, techniques, and procedures (TTPs).

   - They [share similarities in their data leak site infrastructures, payment methods, and communication styles](https://dxc.com/us/en/insights/perspectives/report/dxc-security-threat-intelligence-report/2022/june-2022/black-basta-ransomware-emerges?ref=secjuice.com).

2\. Financial Links

   - Elliptic blockchain analysts "[traced Bitcoin worth several million dollars from Conti-linked wallets to those associated with the Black Basta operator.](https://www.elliptic.co/blog/black-basta-ransomware-victims-have-paid-over-100-million?ref=secjuice.com)"

3\. Victimology

   - Black Basta's targeting of particular industries closely resembles that of Conti.

4\. Expertise and Rapid Rise

   - Black Basta's sophisticated operations and rapid success suggest experienced cybercriminals, potentially former Conti members.

5\. Insider Speculation

   - Leaked Conti chats from February 2022 indicated that Conti operators may have planned to rebrand to evade law enforcement.

6\. Core Membership

   - BlackBerry's analysis suggests that "[Black Basta's core membership is thought to have spawned from the defunct Conti threat actor group](https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/black-basta?ref=secjuice.com)."

7\. Denial and Uncertainty

   - Conti operators denied rebranding as Black Basta, even calling the group "kids."

   - While a direct rebranding can't be conclusively proven, the connections suggest at least some collaboration or shared membership.

**Important note:** while there are strong indications of a connection, researchers cannot definitively state that Black Basta is a direct rebranding of Conti. However, evidence strongly suggests that there are likely shared members, resources, or at least a significant level of collaboration between the two groups.

How does Black Basta's double extortion tactic work?
====================================================

Here are the key aspects of Black Basta's double extortion tactic:

1\. Data Encryption

\- Black Basta encrypts files on the victim's systems using a combination of ChaCha20 and RSA-4096 encryption algorithms. **NOTE**: Some sources say Black Basta uses ChaCha20 instead of XChaCha20. A primary difference between XChaCha20 and ChaCha20 is the use of an extended nonce (192-bit vs.  64-bit), but this could be because of the multiple builds that Black Basta deploys.

\- Encrypted files typically receive a new extension, such as ".basta" or ".ransom".

\- A ransom note (usually named "readme.txt") is placed on the victim's desktop with instructions for payment.

![](https://www.secjuice.com/content/images/2024/10/image-2.png)

_(Source:_ [https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know](https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know?ref=secjuice.com)

(Reminds me of the intro to old video game of Zero Wing – “all your base are belong to us”

![](https://www.secjuice.com/content/images/2024/10/image-3.png)

2\. Data Exfiltration

\- In addition to encrypting files, Black Basta exfiltrates sensitive data from the victim's systems before encryption.

\- They use tools like [Rclone](https://rclone.org/?ref=secjuice.com) to filter and copy specific files to cloud services.

3\. Ransom Demand

\- The group demands a ransom payment in exchange for decryption keys and to prevent the release of stolen data.

\- Payments are typically requested in Bitcoin.

4\. Public Leak Site

\- Black Basta operates a dark web leak site called "Basta News" (_onion_ _link and example above_).

\- They threaten to publish the stolen sensitive information on this site if the ransom is not paid.

\- The site uses a name-and-shame approach, listing victims who have not complied with ransom demands.

5\. Pressure Tactics

\- The threat of data exposure puts additional pressure on victims to pay the ransom.

\- This tactic is effective against organizations that prioritize data confidentiality, even if they have backups of their encrypted files.

6\. Negotiation

\- Black Basta provides victims with access to a Tor site for ransom negotiations.

What tools does Black Basta use for initial access?
===================================================

This is good to know because if one can stop crime at the beginning of the attack chain, it's better for all. It's not always possible, and the criminals can pivot, but the more one knows and the sooner it can be stopped, the sooner people can rest easy.

Black Basta uses several tools and techniques for initial access. Some of their many tools used are: Mimikatz, RClone, WMI, Cobalt Strike, WinSCP, PowerShell, PSExec, and Netcat.

Some of their techniques are:

1\. Spear-phishing campaigns

   - Black Basta relied on targeted spear-phishing emails, tricking recipients into revealing credentials or downloading malicious attachments.

2\. Exploiting vulnerabilities

   - They exploit known vulnerabilities in public-facing applications, such as the ConnectWise vulnerability CVE-2024-1709.

3\. Purchasing network access

   - Black Basta advertises on illicit forums like Exploit.in and XSS.is to purchase network access from initial access brokers (IABs).

4\. Insider recruitment

   - The group is known to use forums to recruit insiders within target organizations, offering financial incentives for network access. Keep an eye on that insider threat!

6\. Collaboration with other malware operations

   - Black Basta partnered with other malware operations to install tools like Cobalt Strike for remote access.

## How does Black Basta's approach differ from other RaaS groups?

1\. Rapid Rise and Sophistication

Black Basta appeared on the scene in early 2022 and quickly emerged as one of the more active and sophisticated RaaS groups. As of May 2024, they have hit [more than 500 organizations](https://www.securityweek.com/black-basta-ransomware-hit-over-500-organizations/?ref=secjuice.com). But even before that, SRLabs had been able to create a [free decryption tool](https://www.securityweek.com/free-decryptor-released-for-black-basta-ransomware/?ref=secjuice.com) that helped many victims recover at least a portion of their files.

2\. Targeted Approach

Unlike some RaaS groups that use indiscriminate "spray-and-pray" tactics, Black Basta employs highly targeted attacks, focusing on specific organizations in countries (_as noted above also_) like the US, Japan, Canada, the UK, Australia, and New Zealand.

3\. Unique Encryption Method

Black Basta uses a combination of ChaCha20 (or XchaCha20) and RSA-4096 encryption algorithms. Their encryption process is optimized for speed, encrypting in chunks of 64 bytes with 128 bytes of unencrypted data between encrypted regions. The ransomware prepends each file with a unique 133-byte ephemeral NIST P-521 public key, which appears distinctive to Black Basta.

4\. Changing Tactics

Black Basta continuously grows, shifts, and matures its techniques, including a significant [update from version 1.0 to 2.0.](https://cryptogennepal.com/blog/black-basta-1.0-ransomware/?ref=secjuice.com) They've adopted advanced obfuscation techniques and used randomized filenames to evade detection by EDR products.

5\. Cross-Platform Capability

Black Basta targets both Windows and Linux systems, including a variant specifically designed for VMware ESXi virtual machines.

6\. Potential Ties to Other Groups

There are suspected links between Black Basta and former members of the Conti and FIN7 (Carbanak) threat actor groups, suggesting a level of experience and sophistication.

7\. Diverse Initial Access Methods

They use a variety of initial access methods, including spear-phishing, exploiting vulnerabilities, purchasing access from brokers, and even recruiting insiders within target organizations.

8\. Advanced Post-Exploitation Techniques

Black Basta employs a wide range of tools for lateral movement, credential harvesting, and data exfiltration, including QakBot, Mimikatz, Cobalt Strike, and custom EDR evasion modules.

9\. Unique Ransom Negotiation Approach:

Unlike many other RaaS groups, Black Basta provides victims with access to a Tor site for ransom negotiations.

Black Basta has demonstrated their sophisticated and adaptable approach, setting them apart from many other RaaS groups in terms of targeting, technical capabilities, and operational methods.

How do I stay safe?
===================

Now for the promised safety measures. It’s no good providing specifics of a threat without also being specific about how to protect against those threats.

Perhaps the most common Black Basta attack is a phishing email that links to a .zip file to download. The first mitigation here is to be aware of phishing emails. Unfortunately, it’s a common theme: in the midst of all the busyness – sometimes even a corporate culture of “get things done now or else!” – it’s easy to say, “don’t click anything,” while also having everyone’s job dependent on clicking on things.

Some other general and foundational protections include:

·       Updates operating systems, software, and firmware as soon as feasible (trust me – I know it’s not always as easy as “update as soon as it’s available – sometimes, updates go bad and need extensive testing before deployment).

·       Require phishing-resistant MFA for as many services as possible. (again, this is easier said than done, but make access as tough as possible).

·       Lock down remote access (if you get a chance to scan your public-facing attack surface – e.g., Shodan – please do so. That way, you’ll see what others see from the outside. Nmap can be highly beneficial here)

·       Backups, backups, backups. And test the restore process regularly.

·       The [StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide?ref=secjuice.com) is quite useful.

To get technical, this chart – combining the MITRE ATT&CK Navigator findings with MITRE mitigations – may prove helpful with the technical protections necessary.

**Techniques and Mitigations**

**Name**

**Use**

**Mitigations**

[Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059?ref=secjuice.com): [PowerShell](https://attack.mitre.org/techniques/T1059/001?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) has used PowerShell scripts for discovery and to execute files over the network.[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)[\[8\]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1059/

[Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059?ref=secjuice.com): [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can use cmd.exe to enable shadow copy deletion.[\[2\]](https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergence?ref=secjuice.com)

https://attack.mitre.org/techniques/T1059/003/

[Create or Modify System Process](https://attack.mitre.org/techniques/T1543?ref=secjuice.com): [Windows Service](https://attack.mitre.org/techniques/T1543/003?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can create a new service to establish persistence.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[4\]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware?ref=secjuice.com)

https://attack.mitre.org/techniques/T1543/

[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can encrypt files with the ChaCha20 cypher and using a multithreaded process to increase speed.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[9\]](https://blogs.blackberry.com/en/2022/05/black-basta-rebrand-of-conti-or-something-new?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)[\[10\]](https://www.uptycs.com/blog/black-basta-ransomware-goes-cross-platform-now-targets-esxi-systems?ref=secjuice.com)[\[2\]](https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergence?ref=secjuice.com)[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)[\[8\]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/?ref=secjuice.com)

[Debugger Evasion](https://attack.mitre.org/techniques/T1622?ref=secjuice.com)

The [Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) dropper can check system flags, CPU registers, CPU instructions, process timing, system libraries, and APIs to determine if a debugger is present.[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1622/](https://attack.mitre.org/techniques/T1622/?ref=secjuice.com)

[Defacement](https://attack.mitre.org/techniques/T1491?ref=secjuice.com): [Internal Defacement](https://attack.mitre.org/techniques/T1491/001?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) has set the desktop wallpaper on victims' machines to display a ransom note.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[9\]](https://blogs.blackberry.com/en/2022/05/black-basta-rebrand-of-conti-or-something-new?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)[\[4\]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware?ref=secjuice.com)[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)[\[2\]](https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergence?ref=secjuice.com)[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1491/](https://attack.mitre.org/techniques/T1491/?ref=secjuice.com)

[File and Directory Discovery](https://attack.mitre.org/techniques/T1083?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can enumerate specific files for encryption.[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[4\]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware?ref=secjuice.com)[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)[\[10\]](https://www.uptycs.com/blog/black-basta-ransomware-goes-cross-platform-now-targets-esxi-systems?ref=secjuice.com)[\[2\]](https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergence?ref=secjuice.com)[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)[\[8\]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1083/](https://attack.mitre.org/techniques/T1083/?ref=secjuice.com)

[File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222?ref=secjuice.com): [Linux and Mac File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/002?ref=secjuice.com)

The [Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) binary can use chmod to gain full permissions to targeted files.[\[10\]](https://www.uptycs.com/blog/black-basta-ransomware-goes-cross-platform-now-targets-esxi-systems?ref=secjuice.com)

https://attack.mitre.org/techniques/T1222/

https://attack.mitre.org/techniques/T1222/002/

[Impair Defenses](https://attack.mitre.org/techniques/T1562?ref=secjuice.com): [Safe Mode Boot](https://attack.mitre.org/techniques/T1562/009?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can reboot victim machines in safe mode with networking via bcdedit /set safeboot network.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)[\[4\]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware?ref=secjuice.com)[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1562/009/](https://attack.mitre.org/techniques/T1562/009/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1562/

[Inhibit System Recovery](https://attack.mitre.org/techniques/T1490?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can delete shadow copies using vssadmin.exe.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)[\[4\]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware?ref=secjuice.com)[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)[\[2\]](https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergence?ref=secjuice.com)[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)[\[8\]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)[\[8\]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/?ref=secjuice.com)

[Masquerading](https://attack.mitre.org/techniques/T1036?ref=secjuice.com): [Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) has established persistence by creating a new service named FAX after deleting the legitimate service by the same name.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1036/004/](https://attack.mitre.org/techniques/T1036/004/?ref=secjuice.com)

[Masquerading](https://attack.mitre.org/techniques/T1036?ref=secjuice.com): [Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005?ref=secjuice.com)

The [Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) dropper has mimicked an application for creating USB bootable drivers.[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1036/005/

[Modify Registry](https://attack.mitre.org/techniques/T1112?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can modify the Registry to enable itself to run in safe mode and to modify the icons and file extensions for encrypted files.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)[\[2\]](https://www.deepinstinct.com/blog/black-basta-ransomware-threat-emergence?ref=secjuice.com)[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)

https://attack.mitre.org/techniques/T1112/

[Native API](https://attack.mitre.org/techniques/T1106?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) has the ability to use native APIs for numerous functions including discovery and defense evasion.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)[\[4\]](https://www.avertium.com/resources/threat-reports/in-depth-look-at-black-basta-ransomware?ref=secjuice.com)[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1106/

[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027?ref=secjuice.com): [Binary Padding](https://attack.mitre.org/techniques/T1027/001?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) had added data prior to the Portable Executable (PE) header to prevent automatic scanners from identifying the payload.[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1027/001/

[Remote System Discovery](https://attack.mitre.org/techniques/T1018?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can use LDAP queries to connect to AD and iterate over connected workstations.[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1018/

[Subvert Trust Controls](https://attack.mitre.org/techniques/T1553?ref=secjuice.com): [Code Signing](https://attack.mitre.org/techniques/T1553/002?ref=secjuice.com)

The [Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) dropper has been digitally signed with a certificate issued by Akeo Consulting for legitimate executables used for creating bootable USB drives.[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1553/002/

[System Information Discovery](https://attack.mitre.org/techniques/T1082?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can enumerate volumes and collect system boot configuration and CPU information.[\[3\]](https://minerva-labs.com/blog/new-black-basta-ransomware-hijacks-windows-fax-service/?ref=secjuice.com)[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1082/

[System Service Discovery](https://attack.mitre.org/techniques/T1007?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can check whether the service name FAX is present.[\[6\]](https://blog.cyble.com/2022/05/06/black-basta-ransomware/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1007/

[User Execution](https://attack.mitre.org/techniques/T1204?ref=secjuice.com): [Malicious File](https://attack.mitre.org/techniques/T1204/002?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) has been downloaded and executed from malicious Excel files.[\[7\]](https://www.trendmicro.com/en_us/research/22/e/examining-the-black-basta-ransomwares-infection-routine.html?ref=secjuice.com)[\[8\]](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/?ref=secjuice.com)

[Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can make a random number of calls to the kernel32.beep function to hinder log analysis.[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

https://attack.mitre.org/techniques/T1497/

[System Checks](https://attack.mitre.org/techniques/T1497/001?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) can check system flags and libraries, process timing, and API's to detect code emulation or sandboxing.[\[1\]](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware?ref=secjuice.com)[\[11\]](https://research.checkpoint.com/2022/black-basta-and-the-unnoticed-delivery/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1497/001/](https://attack.mitre.org/techniques/T1497/001/?ref=secjuice.com)

[Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047?ref=secjuice.com)

[Black Basta](https://attack.mitre.org/software/S1070?ref=secjuice.com) has used WMI to execute files over the network.[\[5\]](https://research.nccgroup.com/2022/06/06/shining-the-light-on-black-basta/?ref=secjuice.com)

[https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/?ref=secjuice.com)

We can do all we can and all we know to prevent ransomware. But things happen. Know your enemy, know that there are lots of people on your side to help, and have an Incident Response plan ready.

Best wishes on your journey to protecting your organization!

## Sources and Resources

[https://www.rapid7.com/blog/post/2024/05/10/ongoing-social-engineering-campaign-linked-to-black-basta-ransomware-operators/](https://www.rapid7.com/blog/post/2024/05/10/ongoing-social-engineering-campaign-linked-to-black-basta-ransomware-operators/?ref=secjuice.com)

[https://dxc.com/us/en/insights/perspectives/report/dxc-security-threat-intelligence-report/2022/june-2022/black-basta-ransomware-emerges](https://dxc.com/us/en/insights/perspectives/report/dxc-security-threat-intelligence-report/2022/june-2022/black-basta-ransomware-emerges?ref=secjuice.com)

[https://attack.mitre.org/software/S1070/](https://attack.mitre.org/software/S1070/?ref=secjuice.com)

[https://securityscorecard.com/research/a-deep-dive-into-black-basta-ransomware/](https://securityscorecard.com/research/a-deep-dive-into-black-basta-ransomware/?ref=secjuice.com)

[https://www.hhs.gov/sites/default/files/black-basta-threat-profile.pdf](https://www.hhs.gov/sites/default/files/black-basta-threat-profile.pdf?ref=secjuice.com)

[https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/black-basta](https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/black-basta?ref=secjuice.com)

[https://www.ic3.gov/CSA/2024/240511.pdf](https://www.ic3.gov/CSA/2024/240511.pdf?ref=secjuice.com)

[https://www.cisa.gov/sites/default/files/2024-05/AA24-131A-StopRansomware-Black-Basta.stix\_.json](https://www.cisa.gov/sites/default/files/2024-05/AA24-131A-StopRansomware-Black-Basta.stix_.json?ref=secjuice.com)

[https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know](https://blog.qualys.com/vulnerabilities-threat-research/2024/09/19/black-basta-ransomware-what-you-need-to-know?ref=secjuice.com)

[https://www.provendata.com/blog/black-basta-ransomware/](https://www.provendata.com/blog/black-basta-ransomware/?ref=secjuice.com)

[https://www.elliptic.co/blog/black-basta-ransomware-victims-have-paid-over-100-million](https://www.elliptic.co/blog/black-basta-ransomware-victims-have-paid-over-100-million?ref=secjuice.com)

[https://therecord.media/blackbasta-ransom-payments](https://therecord.media/blackbasta-ransom-payments?ref=secjuice.com)

[https://flashpoint.io/blog/understanding-black-basta-ransomware/](https://flashpoint.io/blog/understanding-black-basta-ransomware/?ref=secjuice.com)

[https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/](https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/?ref=secjuice.com)

[https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta?ref=secjuice.com)

[https://www.zscaler.com/blogs/security-research/back-black-basta](https://www.zscaler.com/blogs/security-research/back-black-basta?ref=secjuice.com)

[https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a?ref=secjuice.com)

[https://blog.barracuda.com/2024/05/18/black-basta-nasty-tactics](https://blog.barracuda.com/2024/05/18/black-basta-nasty-tactics?ref=secjuice.com)

[https://www.telsy.com/en/black-basta-team-and-double-extortion-ransomware-attacks/](https://www.telsy.com/en/black-basta-team-and-double-extortion-ransomware-attacks/?ref=secjuice.com)

[https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a](https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a?ref=secjuice.com)

[https://aspr.hhs.gov/cyber/Documents/joint-csa-stopransomware-black-basta-508.pdf](https://aspr.hhs.gov/cyber/Documents/joint-csa-stopransomware-black-basta-508.pdf?ref=secjuice.com)

[https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis](https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis?ref=secjuice.com)

## Help Support Our Non-Profit Mission

If you enjoyed this article or found it helpful please consider making a **U.S. tax-deductible** donation, Secjuice is a non-profit and volunteer-based publication powered by donations. We will use your donation to help cover our hosting costs and **keep Secjuice an advertisement and sponsor free zone**.

[Make a tax-deductible donation](https://opencollective.com/secjuice)