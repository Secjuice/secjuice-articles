---
id: use-osint-to-investigate-a-phishing-scam
title: Use OSINT to Investigate a Phishing Scam
description: One of the greatest tools for infosec professionals to investigate and prevent phishing scams is actually just a collection of websites that produce information that is free and open to the public, also known as Open Source Intelligence (OSINT).
author: Tom Caliendo
date: 2024-03-13T00:48:39.000Z
---

# Use OSINT to Investigate a Phishing Scam

Written by Tom Caliendo
Mar 12, 2024 • 14 min read

---

![Use OSINT to Investigate a Phishing Scam](../content/images/2024/02/rhizobiu_investigate_phishing_scam_3ac36bdd-ddb0-4b64-85e7-40941e370b83.png)

One of the greatest tools for infosec professionals to investigate and prevent phishing scams is actually just a collection of websites that produce information that is free and open to the public, also known as Open Source Intelligence (OSINT). This article will identify and explain several OSINT methods that are effective and require no previous OSINT experience.  

_The following is an excerpt from the book,_ [_The OSINT Guide_](https://www.amazon.com/Open-Source-Intelligence-Guide-Investigate-ebook/dp/B0BMXRTG7P?ref=secjuice.com)_, by Thomas Caliendo._

Interestingly, OSINT is not only a major factor in the prevention/response aspect of phishing scams, but it  also plays a major role in the creation of phishing scams. We will discuss how malicious actors use OSINT, and how infosec professionals can use this knowledge against them in order to keep their companies safe.

## Why Focus on Phishing Scams? 

As an infosec professional, this is the most likely threat you will encounter.

Phishing is often considered old fashioned and outdated, easy to avoid. To be fair, the news often focuses on the more interesting new scams, while phishing takes a smaller and smaller share of the media focus. However, most people are surprised to learn that phishing is the most common Internet scam out there. However, as my colleague Daniel Miessler points out in his article, [Everyday Risk Rating](https://ahead.feedly.com/posts/everyday-risk-rating?ref=secjuice.com), some dangers are more real than others and it can be hard to know the difference.

Phishing scams are overwhelmingly the most common and dangerous Internet-based crime, according to the [FBI's Internet Crime Complaint Center (IC3)](https://www.proofpoint.com/us/blog/email-and-cloud-threats/fbi-internet-crime-report-shows-email-fraud-represents-largest?ref=secjuice.com) [Internet Crime Report 2021](https://www.ic3.gov/Home/AnnualReports?ref=secjuice.com) and  the [2021 Webroot BrightCloud Threat Report.](https://community.webroot.com/news-announcements-3/the-2021-webroot-brightcloud-threat-report-54-of-phishing-sites-use-https-to-trick-users-347178?ref=secjuice.com)  [According to the Cofense Intelligence 3rd Quarter review for 2021](https://get.cofense.com/Q3_2021_Phishing_Review.html?ref=secjuice.com#:~:text=The%20Cofense%20Intelligence%E2%84%A2%20team,summer%20activity%20experienced%20in%202020), phishing was involved in [93% of modern data breaches](https://www.comparitech.com/blog/vpn-privacy/phishing-statistics-facts/?ref=secjuice.com) (during the 3rd quarter). 

[CISCO’s 2021 Cybersecurity threat trends report](https://www.tessian.com/blog/phishing-statistics-2020/?ref=secjuice.com) (which applies to all of 2021) showed similar numbers and listed that phishing attacks account for around 90% of data breaches.

Per the CISCO data, at least one person clicked a phishing link in 86% of organizations targeted by phishing scams. 74% of US companies experienced a successful phishing attack during 2021, according to [Proofpoint’s 2021 State of the Phish](https://www.proofpoint.com/sites/default/files/threat-reports/pfpt-us-tr-state-of-the-phish-2021.pdf?ref=secjuice.com) report.  Therefore the prevalence of attempted and successful phishing attacks warrants our focus on this kind of attack.

As pointed out in [Defining OSINT and Its Role in Cyber Threat Intelligence](https://ahead.feedly.com/posts/defining-osint-and-its-role-in-cyber-threat-intelligence?ref=secjuice.com), the amount of information out there is growing fast and this data is not only the focus of businesses and government agencies, but it also attracts threat actors.

## Learn the Malicious Tactics in Use

### Using New Mediums and Sources 

Most people assume that a phishing scam takes the comparatively obvious form of a suspicious email and assume that they would know not to open or click on it. But today phishing attempts have become more advanced. For one thing, phishing scams don’t only come in the form of email, but also posts and direct messages on social media, SMS messages, and more. In addition, phishing websites are [now obtaining SSL certificates](https://www.keyfactor.com/blog/https-phishing-attacks-how-hackers-use-ssl-certificates-to-feign-trust/?ref=secjuice.com) which were once considered a marker of safety (more on that below, along with other modernizations used for phishing scams). 

### Building Trust

In addition, [social media scams](https://www.amazon.com/CYBER-SECURITY-BEGINNERS-COMPREHENSIVE-CYBERSECURITY/dp/B09S61YP3J?ref=secjuice.com) may come in the form of a message seemingly sent to the workforce from one’s friend or family with a seemingly typical message, or  one’s boss, telling the workforces to click on a link or open an attachment. [One of the common ways](https://directory.libsyn.com/episode/index/id/20269139?ref=secjuice.com) to build trust in these scenarios is to first send a message asking the recipient to do something (click a link or download a file) that is actually innocuous in order to build trust, and then send a follow up message with the true phishing content.  

### Avoiding Email Filters

In theory, the DMARC (Domain Message Authentication, Reporting, and Conformance) is [supposed to filter out suspicious emails](https://mailchimp.com/help/limitations-of-free-email-addresses/?ref=secjuice.com) based on factors like the domain sending the emails and the URLs included in the content. 

However, scammers have found the following ways around DMARC security parameters:

- For starters, scammers often use mass email services like SendGrid, MailChimp, and MailJet. [According to Cyren Security](https://www.cyren.com/blog/articles/how-scammers-leverage-email-delivery-services-like-sendgrid-and-mailchimp-in-phishing-attacks?ref=secjuice.com), the emails with unique domains ("john@definitely\_not\_a\_scam.com) that are being sent from Mailchimp and other similar services are often accepted by email filters. A reason why this is effective is that the services provide the relevant authentication used to validate emails. A lot of companies even "white list" these mass email services. 

- Scammers will often send URLs that [include part of a legitimate domain](https://mailchimp.com/help/limitations-of-free-email-addresses/?ref=secjuice.com). For example, instead of using "bankofamerica.com", they will use "hln.bankofamerican.com". This method is actually an effective way to avoid email filters.

- While many scammers buy their own domains and send emails from them, [others use free email](https://mailchimp.com/help/limitations-of-free-email-addresses/?ref=secjuice.com). If you are using a free email like gmail.com and hotmail.com. Mass emails from free emails are likely to be filtered out. Therefore, services like mailchimp will [offer a method to evade companies' filters](https://mailchimp.com/help/limitations-of-free-email-addresses/?ref=secjuice.com) by adding on a subdomain as the email domain, such as "@send.mailchimpapp.com". For example, if the scammer is using "HRrep@hotmail.com", Mailchimp can change the "From" email to  "HRrep.hotmail.com@send.mailchimpapp.com". This is an effective way to hide the true email sender. 

## What is the Role of OSINT in Our Scenario?

Phishing scams can be investigated via OSINT before or after someone has fallen victim. For the sake of clarity, when we discuss our hypothetical phishing scam, we will use the most common kind of phishing scan that is currently in use. That is, a scammer who sends out mass emails, often to specific companies’ employees. The emails invite the recipients to click on a link and input their personal sensitive information, such as username and password, on fake websites that are designed to look like certain real websites. Finally, in this example the scammers have (as most do) an infrastructure of IPs, servers, domain names, etc. that support a number of fake websites that log victims’ information and securely send it back to the scammer.

We will start with the example of someone who received a suspicious email and wants you to investigate whether it is a phishing scam. Now let's get started looking at what you can do in an OSINT investigation.

## Before You Start: Take These Simple Preventative Measures

### Provide Security Awareness Training

Before your investigation even starts, consider ensuring that your company has some form of security awareness training for its employees, even if it just involves you providing a quick overview. Educating the workforce is one of the most effective forms of preventative measures because at the end of the day phishing scams rely on human beings to be imperfect and make bad decisions (i.e. downloading a file or clicking a link). Security awareness training will keep the workforce more alert and well-educated, which will significantly reduce the possibility of someone making that bad decision.

### Remove Personal Information from Public Sources

In addition, another effective measure is to remove the company employees from the main recruitment / sales intelligence websites also known as “headhunter” sites (Apollo.io, contactout.com, rocketreach.co). Each site has an “opt out” function that allows you to remove information from the site (note that many companies choose to contract out this rather boring “personal information removal” process so you don’t necessarily need to do it yourself).

Phishing scammers used to rely primarily on buying email lists on the dark web. But today much of the same data is available for free. For example, Contactout.com reportedly has “[contact details for 75% of professionals](https://contactout.com/?ref=secjuice.com)”. 

Therefore scammers increasingly use these free, publicly available resources. If a scammer is looking for companies’ to target, and your company’s information is hidden while others’ are easily available, it is reasonable to assume the scammer might move on to other easier targets.

## Start the Investigation

### Identify Suspicious Emails to Investigate

While there are a wide variety of phishing emails, [there are a few simple ways to identify or avoid the vast majority of them](https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams?ref=secjuice.com). For starters, be aware that phishing emails often look completely legitimate whether that involves an email that appears to come from a company or bank where you have an account or even appearing to have been sent from a friend, colleague, or boss. Therefore the appearance of legitimacy should never be considered a factor in determining if the email is suspicious. Instead, consider an email suspicious if it asks you to open or download any attachment or asks you to click on a link. 

To reiterate this point, any email, especially from a company, that asks the recipient to open a file or click on a link should be considered suspicious. As a result of phishing scams, most companies will not send links or attachments in emails. Therefore any email that actually does so, can reasonably be considered suspicious. 

### Unshortened URLs

The OSINT investigation starts with the email sent to employees, regardless of whether it is a confirmed phishing scam or just a suspicious email. 

Begin with the link or URL that  you are invited to click (obviously do not click on it). Be on the lookout for shortened URLs (like bit.ly4enla45c or tinyurl.com/4emdh45c). Phishing campaigns are increasingly taking advantage of free open source tools (bitly.com, tinyurl.com, tiny.cc, cutt.ly, and shorturl.at) to shorten URLs. These URLs hide the true link destination, are less likely to be filtered out by content filters, and people are accustomed to seeing “bit.ly” URLs so they are more likely to click on it, according to a comparison of recent [phishing statistics by Comparitech](https://www.comparitech.com/blog/vpn-privacy/phishing-statistics-facts/?ref=secjuice.com).

For your investigation there are [several open source tools](https://www.aware-online.com/en/investigate-shortened-urls/?ref=secjuice.com) to unshorten those URLs and discover the true domain destination (such as unshorten.it, urlex.org, and checkshorturl.com).

### Conduct Website Scans

Once you have identified the true domain of the URL’s destination, you can enter the domain into a number of OSINT websites (also known as “scanner sites”) that [scan the suspicious domain to see if it looks safe](https://securityboulevard.com/2021/11/not-all-url-scanners-are-created-equal-checkphish-vs-urlscan-io-vs-scamadviser/?ref=secjuice.com) (you can use scamadviser.com, urlscan.io, and checkphish.ai). These scanner sites are NOT perfect but they run a number of tests on the domain and also track threat feeds in case anyone has reported the domain or its IP address for malicious activity. It is also worth noting that these tools provide you with a snapshot of the scanned websites, providing you a safe way to check it out.  

Urlscan.io has an interesting feature among its scan results. The site searches for other websites that [have a similar structure](https://urlscan.io/result/806979de-a726-4731-8dd6-8481d5f3d6a9/related/?ref=secjuice.com) to the one you scanned, but are hosted on different infrastructure. Why does this matter? Because it is a good indicator that the website was built by a phishing kit (which is basically a prebuilt phishing scam that is sold on illegal but widespread marketplaces). Phishing kits and phishing scams in general often create several versions of a fake website. Sometimes this is contingency planning for when one site gets taken down there are still others, and sometimes this action is done to create specific websites for different target sets.

### Check the IP and Domain Reputation

The sites like Urlscan.io that we just used will [also identify](https://urlscan.io/blog/?ref=secjuice.com) the possible phishing website’s [domain, IP address and its ssl security certificate](https://urlscan.io/result/896bf8f5-19b8-476a-b02e-63097e99a3ab/?ref=secjuice.com). These are useful pieces of information for an investigation. 

Starting with IP address and domain, you can use cyber security sites like virustotal.com to check if they have been previously flagged for malicious activity by other parties. Phishtank.org is another useful site that is focused specifically for checking domains for reported phishing activity. These sites will use factors and report if the site is identified as "Clean", "Malware site", "Phishing site", "Spam site", or just "Suspicious". 

### Search for Files on the Site

[A website URL can be searched](https://support.virustotal.com/hc/en-us/articles/115002719069-Reports?ref=secjuice.com#h_683c0432-fb48-4723-881b-d4fd7f4eab22) in various cyber security sites like virustotal.com (or sitelock.com) to see if there are files on the website, and whether they are believed to be safe. The cybersecurity sites  will look for any files that have been downloaded from the suspicious website in the past and check if people have reported negatively about those files. The security sites will also do their own scans of the files from afar to assess if the file is  safe, malware, etc. Finally, you can actually send an unopened file to these sites so they can provide a more [in-depth assessment](https://support.virustotal.com/hc/en-us/articles/115002719069-Reports?ref=secjuice.com#h_683c0432-fb48-4723-881b-d4fd7f4eab22) to determine if it is or is not safe.  

### Confirm a Website’s SSL Certificate

People are consistently more likely to believe that a website is safe [if it has an SSL certificate](https://www.keyfactor.com/blog/https-phishing-attacks-how-hackers-use-ssl-certificates-to-feign-trust/?ref=secjuice.com). If a website has an SSL certificate, the URL will begin with "https" instead of "http". There will also be a small lock symbol to the left of the URL.

Many people do not understand what this actually means. While there are many types of SSL certificates, the most common kind only [makes your browser's communication with the website encrypted](https://www.keyfactor.com/blog/https-phishing-attacks-how-hackers-use-ssl-certificates-to-feign-trust/?ref=secjuice.com) (so outsiders can see what you are doing). The lock and "https" gives many people the impression that the website is safe, which is not true.

[In the past, one of the ways to help identify a suspicious website](https://www.keyfactor.com/blog/https-phishing-attacks-how-hackers-use-ssl-certificates-to-feign-trust/?ref=secjuice.com)was to check if it did not have an SSL certificate. But today phishing emails have [begun obtaining SSL certificates](https://www.osintme.com/index.php/2021/12/06/how-to-investigate-a-massive-phishing-campaign/?ref=secjuice.com) by using the free service "letsencrypt.org". 

[Let's Encrypt](https://letsencrypt.org/?ref=secjuice.com) is a free service run by a nonprofit with the purpose of making SSL Certificates available for free.

However, we can use https://crt.sh/ to check a website's certificate, and [the resulting report](https://crt.sh/?ref=secjuice.com) will identify any other domains on that certificate. Multiple domains on one certificate usually means they are all more likely owned by the same person, but it is possible for multiple people to own the same one. Therefore certificates provide a good lead to other sites potentially owned by the same scammer, but it is a good idea to try to confirm that. To do so, check if the domains look nearly identical, if they fail a website scan, have a similar domain, or have had similar files on the site.

### Lookup Who Shares the IPs

In a similar fashion, you can check what IP is used by a phishing site and look at other websites on the same IP to find potential other phishing sites from the same campaign. Sometimes the scammer owns the IP, shares the IP with legitimate sites, or even hacks the IP. Regardless,  Spyonweb.com is one of several good tools to look up a website's IP and the other sites on the same IP.

### Check the Website Registration

Website registration (known as the Whois record) are usually anonymous. But if you look through the historic records you will often find that the original owner started the website with their true information and then used an anonymizer shortly thereafter. A spammer would usually try to only list their contact information, but that is often enough to find clues to the person’s identity. Usually you can only find the current Whois record online. But [tools that offer historic whois records](https://toolsforreporters.com/2021/07/07/whois-history-search-icann-gdpr/?ref=secjuice.com) often appear, though they sometimes do not stay free. As of this writing, you can use Https://drs.whoisxmlapi.com/whois-history. 

Be aware that people make mistakes, even scammers. See [this story](https://www.thesouthafrican.com/news/surprise-surprise-multiple-websites-pushing-white-monopoly-capital-agenda-traced-back-to-india/?ref=secjuice.com) about a bunch of professionals that mistakenly had their true contact info on one of several websites they had secretly created. 

### Use Analytics and Adsense IDs

In this case the website owners also made the mistake of using Google Analytics and Adsense. People that maintain multiple sites often use Google Analytics and Adsense to monitor all of them. However, these two services put an unique ID number in the coding of each website. Services like Spyonweb.com will look for these IDs on a website and find other websites that are on the same account. This is a second mistake made by the professionals in the story mentioned above.

### Find Similar Domains

Finally, several phishing websites use domains for their [fake websites that are very similar to real websites](https://dnstwister.report/?ref=secjuice.com). Consider "BANK0FAMERICA.COM" (there is a zero instead of the letter o). Therefore, when you see a url like that you can search the real website's url in https://dnstwister.report/ to find other similar domains that the scammer might use. You can also [research the known phishing website’s URL](https://www.osintme.com/index.php/2021/12/06/how-to-investigate-a-massive-phishing-campaign/?ref=secjuice.com) in the same tool which might also find URLs used by the scammer.

### Research the MX Record

An MX Lookup is another way to identify nodes in an investigation. The MX (Mail Exchange) record for your domain will tell incoming mail where to go, which server and associated IP to land on. You can lookup MX records with tools like

"https://dnschecker.org" and "https://iplocation.io," however, mxtoolbox.com will automatically check the resulting record against several blacklists. Though you can also look up the relevant IP in the tools mentioned previously. It is also important to [check if several different domains are using the same MX record](https://www.maltego.com/blog/phishing-attacks-part-2-investigating-phishing-domains/?ref=secjuice.com), a definite connection between the two sites.

### Start Connecting Dots

At this point in your investigation you will begin to look for, and connect, dots. Phishing campaigns often entail several name server records, domains, IPs, and URLs. The image below (from Virustotal.com) is a graph of a phishing campaign showing the various IP addresses, URLs, domains, and files. You can use websites like https://www.virustotal.com/graph/ to build a graph to visually represent your work, making it easier to understand.

![](blob:https://www.secjuice.com/03b53f86-7203-4154-89a2-a18583d771de)

(https://www.virustotal.com/graph/g19666e9509b94dbbb12cf573896e60bf13bd64cde2814929b3023327ada012fc)

To build out a network, use MXlookups, DNS Twisting, Shared IPs, shared SSL certificates, Analytics/Adsense ID, and shared files to find nodes and build connections. Remember that a simple connection is usually not sufficient. For example, sharing an IP address does not mean that two websites are owned by the same person. But you can conduct some follow on research to build a case for a stronger connection.

## How to Identify More Phishing Websites

When you come across a new website, IP, etc. there are a few good ways to determine if it is a phishing site or not. For example, scanning tools like URLscan.io will straight up tell you that the website is part of a phishing kit.

Check the IPs and URLs against blacklists or evidence of phishing in tools like Virustotal.com.

Additionally, the tweet below shows an example of how a campaign will use several URLs that are very similar (workers-united.com, workersunited.site, etc.). The tweet also shows how phishing campaigns will have different websites aimed at the different companies targeted (J.P. Morgan Chase, T-Mobile, etc.). Finally, notice how each website appears the same, and the only thing different from each other is the name of the companies being targeted. It is important to look for several websites that are nearly identical as this is often an aspect of a phishing kit.

![](blob:https://www.secjuice.com/209a3baf-0f8e-4bf7-b92a-e54966bce82c)

(https://twitter.com/gossithedog/status/1377682079736008710)

Once you find evidence of a phishing site, you can draw connections to other nodes and reasonably assume that they are part of the same network. Each node is not only valuable to find for the sake of avoiding the network, but also because each node has potential to include evidence about the scammer. Don’t forget, as previously mentioned, that scammers can make mistakes and there are [plenty](https://www.straitstimes.com/singapore/courts-crime/39-arrested-for-involvement-in-scams-where-losses-amounted-to-20-million?ref=secjuice.com) of [examples](https://www.wired.com/story/email-scammer-global-takedown/?ref=secjuice.com) of [law enforcement](https://www.bleepingcomputer.com/news/security/scammer-arrested-for-phishing-operation-sent-25-000-texts-in-a-day/?ref=secjuice.com)making use of those mistakes to [catch scammers](https://www.zdnet.com/article/phishing-attacks-police-make-106-arrests-as-they-break-up-online-fraud-group/?ref=secjuice.com). Furthermore, also noted above, scammers often use cheap knockoff versions of phishing kits which are more likely to have mistakes that could reveal the user. Therefore, treat every node as a useful clue about the network or the user.

## Conclusion

Now that you know how to investigate websites, confirm phishing sites, and discover nodes in a phishing network, you have several options for how to proceed with this information.

- With all or many of the nodes identified, you can keep this information within your own organization so that you can watch and avoid the phishing network.

- You can report the network to the relevant sources for public blacklists that you previously used to check the reputation for  IPs, Servers, etc. so others can stay safe.

- You can report your information to the government (use https://www.usa.gov/stop-scams-frauds), which may take action or make the information available in its public database of Internet scams.

- You can announce the network publicly via social media or some other means. This is a great way to share your knowledge, but it will likely notify the scammer that they have been caught and they will presumably move their network to new nodes of IPs, domains, etc. Some people have chosen to only report these networks to relevant databases as it may make the information to infosec professionals without necessarily notifying the scammer.

Regardless of what you choose to do, you will make the world a little bit safer. Good luck, but you won't need it!

## Help Support Our Non-Profit Mission

If you enjoyed this article or found it helpful please consider making a **U.S. tax-deductible** donation, Secjuice is a non-profit and volunteer-based publication powered by donations. We will use your donation to help cover our hosting costs and **keep Secjuice an advertisement and sponsor free zone**.

[Make a tax-deductible donation](https://opencollective.com/secjuice)
