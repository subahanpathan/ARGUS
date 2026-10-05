import { Router, type IRouter, type Request, type Response } from "express";

export type IndicatorType = "domain" | "ip" | "hash" | "url" | "cve";
export type IndicatorSeverity = "critical" | "high" | "medium" | "low";

export type IOCRecord = {
  id: string;
  type: IndicatorType;
  value: string;
  defangedValue: string;
  severity: IndicatorSeverity;
  score: number; // 0 - 100
  category: string;
  confidence: number; // 0 - 100
  threatActor?: string;
  campaign?: string;
  mitreTechniques: { id: string; name: string; tactic: string }[];
  firstSeen: string;
  lastSeen: string;
  enginesFlagged: number;
  enginesTotal: number;
  reputationVerdict: "Malicious" | "Suspicious" | "Advisory" | "Clean";
  asn?: string;
  geo?: { country: string; countryCode: string; city: string };
  registrar?: string;
  description: string;
  tags: string[];
  associatedHashes?: string[];
  associatedDomains?: string[];
  associatedIps?: string[];
  followed?: boolean;
  blocked?: boolean;
};

export type ThreatFeed = {
  id: string;
  name: string;
  provider: string;
  type: "TAXII 2.1" | "MISP" | "REST API" | "JSON Stream";
  status: "active" | "syncing" | "degraded" | "offline";
  indicatorsCount: number;
  lastSync: string;
  latencyMs: number;
  reliabilityScore: number;
  description: string;
  category: string;
  enabled: boolean;
};

export type ThreatActor = {
  id: string;
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  targetSectors: string[];
  targetedRegions: string[];
  activeSince: string;
  threatLevel: "Critical" | "High" | "Medium";
  primaryTTPs: { id: string; name: string }[];
  knownMalware: string[];
  description: string;
  activeCampaigns: string[];
  indicatorCount: number;
};

export type VulnerabilityItem = {
  cveId: string;
  title: string;
  cvss: number;
  severity: "critical" | "high" | "medium";
  epssScore: number; // 0 - 1
  cisaKev: boolean;
  published: string;
  vendor: string;
  product: string;
  vector: string;
  exploitStatus: "In-The-Wild Exploitation" | "Public PoC Available" | "Weaponized in Ransomware" | "Under Investigation";
  description: string;
  patchAvailable: boolean;
  mitreTechnique: string;
};

const INITIAL_FEEDS: ThreatFeed[] = [
  {
    id: "feed-1",
    name: "ARGUS Community Exchange",
    provider: "ARGUS Cyber Defense Net",
    type: "JSON Stream",
    status: "active",
    indicatorsCount: 4210,
    lastSync: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    latencyMs: 38,
    reliabilityScore: 99,
    description: "Curated peer indicators and behavioral signals verified across ARGUS endpoint telemetry network.",
    category: "Community & Peer Telemetry",
    enabled: true,
  },
  {
    id: "feed-2",
    name: "Northstar DNS Telemetry",
    provider: "Northstar Cyber Systems",
    type: "REST API",
    status: "active",
    indicatorsCount: 3890,
    lastSync: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    latencyMs: 45,
    reliabilityScore: 98,
    description: "Real-time passive DNS resolution, newly registered disposable domains, and DGA anomaly detection.",
    category: "DNS & Domain Intelligence",
    enabled: true,
  },
  {
    id: "feed-3",
    name: "CISA Known Exploited Vulnerabilities (KEV)",
    provider: "US Cybersecurity and Infrastructure Security Agency",
    type: "REST API",
    status: "active",
    indicatorsCount: 1145,
    lastSync: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    latencyMs: 110,
    reliabilityScore: 100,
    description: "Authoritative catalog of vulnerabilities that have been exploited in the wild.",
    category: "Government & Regulatory",
    enabled: true,
  },
  {
    id: "feed-4",
    name: "AlienVault OTX Pulse Exchange",
    provider: "AT&T Cybersecurity / OTX",
    type: "TAXII 2.1",
    status: "active",
    indicatorsCount: 2950,
    lastSync: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
    latencyMs: 142,
    reliabilityScore: 94,
    description: "Crowdsourced global threat pulses, malware samples, and adversary infrastructure tracking.",
    category: "Global Threat Sharing",
    enabled: true,
  },
  {
    id: "feed-5",
    name: "AbuseIPDB Verified Blacklist",
    provider: "AbuseIPDB Project",
    type: "REST API",
    status: "active",
    indicatorsCount: 1820,
    lastSync: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
    latencyMs: 68,
    reliabilityScore: 96,
    description: "High-confidence IP blacklist verified for SSH/RDP brute force, port scans, and web exploits.",
    category: "IP Reputation & Botnets",
    enabled: true,
  },
  {
    id: "feed-6",
    name: "Emerging Threats (ET Open Ruleset)",
    provider: "Proofpoint",
    type: "MISP",
    status: "active",
    indicatorsCount: 2310,
    lastSync: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
    latencyMs: 95,
    reliabilityScore: 97,
    description: "Suricata/Snort network signatures for active exploit kits, malware payloads, and C2 beacons.",
    category: "Network Signatures",
    enabled: true,
  },
];

const INITIAL_INDICATORS: IOCRecord[] = [
  {
    id: "ioc-1",
    type: "domain",
    value: "cdn-sync-check.com",
    defangedValue: "cdn-sync-check[.]com",
    severity: "critical",
    score: 94,
    category: "Command & Control (C2)",
    confidence: 96,
    threatActor: "DarkGate Operator",
    campaign: "DarkGate Loader Campaign 2024",
    mitreTechniques: [
      { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
      { id: "T1568.002", name: "Domain Generation Algorithms", tactic: "Command and Control" },
      { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
    ],
    firstSeen: "2024-10-11T04:12:00Z",
    lastSeen: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    enginesFlagged: 74,
    enginesTotal: 87,
    reputationVerdict: "Malicious",
    asn: "AS49505 (HostRoyale Technologies)",
    geo: { country: "Seychelles", countryCode: "SC", city: "Victoria" },
    registrar: "NameCheap Disposable Fast-Flux",
    description: "High-risk domain utilized as secondary C2 fallback and dynamic beacon endpoint for DarkGate loader. Observed delivering encoded staging scripts.",
    tags: ["c2", "darkgate", "fast-flux", "staging", "powershell-beacon"],
    associatedIps: ["185.220.101.42", "45.154.255.89"],
    associatedHashes: ["a7f18392b4c81092ef59817290ab31e892c4d1f2e840a1b2c3d4e5f6a7b8c9d0"],
    followed: true,
    blocked: true,
  },
  {
    id: "ioc-2",
    type: "ip",
    value: "185.220.101.42",
    defangedValue: "185.220.101[.]42",
    severity: "high",
    score: 88,
    category: "Tor Exit / Proxy Infrastructure",
    confidence: 92,
    threatActor: "APT29 / Cozy Bear",
    campaign: "Diplomatic Phishing & Exfiltration",
    mitreTechniques: [
      { id: "T1090.003", name: "Multi-hop Proxy", tactic: "Command and Control" },
      { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
    ],
    firstSeen: "2024-09-18T10:00:00Z",
    lastSeen: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
    enginesFlagged: 61,
    enginesTotal: 86,
    reputationVerdict: "Malicious",
    asn: "AS208294 (Tor Network Services)",
    geo: { country: "Germany", countryCode: "DE", city: "Frankfurt" },
    registrar: "Zwiebelfreunde e.V.",
    description: "Confirmed Tor exit relay and proxy hop utilized to obfuscate data exfiltration and staging operations against enterprise Active Directory environments.",
    tags: ["tor-exit", "proxy", "exfiltration", "apt29", "anonymizer"],
    associatedDomains: ["cdn-sync-check.com", "telemetry-update-node.net"],
    followed: false,
    blocked: true,
  },
  {
    id: "ioc-3",
    type: "hash",
    value: "a7f18392b4c81092ef59817290ab31e892c4d1f2e840a1b2c3d4e5f6a7b8c9d0",
    defangedValue: "a7f18392…8c9d0",
    severity: "critical",
    score: 98,
    category: "Trojan / Payload Dropper",
    confidence: 99,
    threatActor: "FIN7 / Carbanak",
    campaign: "Operation Staged Vault",
    mitreTechniques: [
      { id: "T1055", name: "Process Injection", tactic: "Defense Evasion" },
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
    ],
    firstSeen: "2024-10-02T14:22:10Z",
    lastSeen: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
    enginesFlagged: 79,
    enginesTotal: 82,
    reputationVerdict: "Malicious",
    description: "SHA-256 binary hash corresponding to Trojan.PowerDrop / Carbanak loader variant. Injects shellcode directly into explorer.exe or svchost.exe memory spaces.",
    tags: ["trojan", "dropper", "memory-injection", "fin7", "sha256"],
    associatedDomains: ["update-microsoft-patch.info"],
    associatedIps: ["91.215.85.17"],
    followed: true,
    blocked: true,
  },
  {
    id: "ioc-4",
    type: "domain",
    value: "telemetry-update-node.net",
    defangedValue: "telemetry-update-node[.]net",
    severity: "high",
    score: 82,
    category: "Phishing / Masquerading",
    confidence: 89,
    threatActor: "Volt Typhoon",
    campaign: "Living-off-the-Land Recon",
    mitreTechniques: [
      { id: "T1036.005", name: "Device / Service Masquerading", tactic: "Defense Evasion" },
      { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
    ],
    firstSeen: "2024-10-05T09:11:00Z",
    lastSeen: new Date(Date.now() - 65 * 60 * 1000).toISOString(),
    enginesFlagged: 48,
    enginesTotal: 88,
    reputationVerdict: "Malicious",
    asn: "AS13335 (Cloudflare CDN Shield)",
    geo: { country: "United States", countryCode: "US", city: "San Francisco" },
    registrar: "Tucows Domains Inc.",
    description: "Impersonates legitimate Windows telemetry collection nodes. Deploys fake OAuth consent flows and token stealing micro-scripts.",
    tags: ["masquerading", "phishing", "oauth-theft", "volt-typhoon"],
    associatedIps: ["104.21.32.188"],
    followed: false,
    blocked: false,
  },
  {
    id: "ioc-5",
    type: "ip",
    value: "45.154.255.89",
    defangedValue: "45.154.255[.]89",
    severity: "medium",
    score: 72,
    category: "Scanning & Brute Force",
    confidence: 85,
    threatActor: "Lazarus Group / APT38",
    campaign: "Global Crypto Exchange Recon",
    mitreTechniques: [
      { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
      { id: "T1046", name: "Network Service Scanning", tactic: "Discovery" },
    ],
    firstSeen: "2024-09-24T18:05:00Z",
    lastSeen: new Date(Date.now() - 120 * 60 * 1000).toISOString(),
    enginesFlagged: 39,
    enginesTotal: 85,
    reputationVerdict: "Suspicious",
    asn: "AS44592 (Krikos Datacenter)",
    geo: { country: "Russia", countryCode: "RU", city: "Moscow" },
    registrar: "RIPE NCC",
    description: "Automated scanner node conducting continuous port probes against RDP (port 3389) and SMB (port 445). Correlated with credential stuffing campaigns.",
    tags: ["brute-force", "rdp-scanner", "lazarus", "smb-probe"],
    followed: false,
    blocked: true,
  },
  {
    id: "ioc-6",
    type: "hash",
    value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    defangedValue: "e3b0c442…2b855",
    severity: "low",
    score: 15,
    category: "Zero-Byte Hash / Known Baseline",
    confidence: 100,
    mitreTechniques: [
      { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion" },
    ],
    firstSeen: "2020-01-01T00:00:00Z",
    lastSeen: new Date().toISOString(),
    enginesFlagged: 0,
    enginesTotal: 90,
    reputationVerdict: "Clean",
    description: "Standard SHA-256 representation of empty payload / zero byte stream. Observed during file zeroing or wipe attempts.",
    tags: ["baseline", "empty-hash", "safe"],
    followed: false,
    blocked: false,
  },
  {
    id: "ioc-7",
    type: "cve",
    value: "CVE-2024-38077",
    defangedValue: "CVE-2024-38077",
    severity: "critical",
    score: 99,
    category: "Remote Code Execution (RCE)",
    confidence: 100,
    campaign: "MadLicense Mass Exploitation",
    mitreTechniques: [
      { id: "T1210", name: "Exploitation of Remote Services", tactic: "Lateral Movement" },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    ],
    firstSeen: "2024-07-09T00:00:00Z",
    lastSeen: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    enginesFlagged: 85,
    enginesTotal: 85,
    reputationVerdict: "Malicious",
    description: "Windows Remote Desktop Licensing (RDL) Service Remote Code Execution vulnerability (MadLicense). Unauthenticated attacker can achieve SYSTEM privileges over network.",
    tags: ["cve", "rce", "cisa-kev", "madlicense", "critical-patch"],
    followed: true,
    blocked: true,
  },
];

const THREAT_ACTORS: ThreatActor[] = [
  {
    id: "actor-1",
    name: "APT29 / Cozy Bear",
    aliases: ["Midnight Blizzard", "Nobelium", "Cloaked Ursa"],
    origin: "Russian Federation (SVR)",
    motivation: "State Espionage & Intelligence Gathering",
    targetSectors: ["Government", "Defense", "Diplomatic", "Think Tanks", "Cloud Providers"],
    targetedRegions: ["North America", "European Union", "NATO Allies"],
    activeSince: "2008",
    threatLevel: "Critical",
    primaryTTPs: [
      { id: "T1078", name: "Valid Accounts & Cloud Token Theft" },
      { id: "T1195.002", name: "Supply Chain Compromise" },
      { id: "T1090.003", name: "Multi-hop Proxy Infrastructure" },
      { id: "T1566.002", name: "Spearphishing Link" },
    ],
    knownMalware: ["WellMess", "WellMail", "GoldFinder", "Sibot", "EnvyScout"],
    description: "Highly sophisticated cyber espionage actor linked to the Russian Foreign Intelligence Service (SVR). Known for long-term clandestine dwell times and supply chain compromises.",
    activeCampaigns: ["Diplomatic Phishing 2024", "Cloud Exfiltration Operations"],
    indicatorCount: 148,
  },
  {
    id: "actor-2",
    name: "LockBit 3.0",
    aliases: ["LockBit Black", "Bitwise Spider"],
    origin: "Eastern Europe / Transnational",
    motivation: "Financial Extortion & RaaS Bounty",
    targetSectors: ["Healthcare", "Manufacturing", "Finance", "Local Government", "Education"],
    targetedRegions: ["Global (Excluding CIS)"],
    activeSince: "2019",
    threatLevel: "Critical",
    primaryTTPs: [
      { id: "T1486", name: "Data Encrypted for Impact" },
      { id: "T1490", name: "Inhibit System Recovery" },
      { id: "T1562.001", name: "Disable Windows Defender" },
      { id: "T1070.004", name: "File Deletion / VSSAdmin Purge" },
    ],
    knownMalware: ["LockBit 3.0 Encryptor", "StealBit", "LB3-Linux-ESXi"],
    description: "Prominent Ransomware-as-a-Service (RaaS) syndicate operating under double extortion models. Uses automated password spray tools and bypasses EDR hooks via direct syscalls.",
    activeCampaigns: ["Ransomware Wave 2024", "ESXi Hypervisor Extortion"],
    indicatorCount: 312,
  },
  {
    id: "actor-3",
    name: "DarkGate Operator",
    aliases: ["Bravo-01", "Payload-Loader-3"],
    origin: "Eastern Europe",
    motivation: "Commodity Loader & Access Brokering",
    targetSectors: ["Cross-Industry", "Enterprise Workstations", "Remote Workers"],
    targetedRegions: ["Global"],
    activeSince: "2018",
    threatLevel: "High",
    primaryTTPs: [
      { id: "T1059.001", name: "PowerShell Staging" },
      { id: "T1055.012", name: "Process Hollowing" },
      { id: "T1566.001", name: "Malicious LNK & PDF Attachments" },
      { id: "T1071.001", name: "Web Protocols via Dynamic Port" },
    ],
    knownMalware: ["DarkGate v5", "AutoIt Crypt", "HiddenVNC", "Discord C2 Dropper"],
    description: "Versatile modular loader written in Delphi. Features rootkit capabilities, anti-VM checks, audio eavesdropping, and silent deployment of stealer binaries.",
    activeCampaigns: ["DarkGate Loader Campaign 2024", "Teams Phishing Vector"],
    indicatorCount: 224,
  },
  {
    id: "actor-4",
    name: "Volt Typhoon",
    aliases: ["Vanguard Panda", "Bronze Silhouette", "Insidious Taurus"],
    origin: "People's Republic of China",
    motivation: "Pre-Positioning & Critical Infrastructure Sabotage",
    targetSectors: ["Critical Infrastructure", "Telecommunications", "Energy", "Ports & Transit"],
    targetedRegions: ["United States", "Guam", "Indo-Pacific"],
    activeSince: "2021",
    threatLevel: "Critical",
    primaryTTPs: [
      { id: "T1059.003", name: "Windows Command Shell (Living-off-the-Land)" },
      { id: "T1003.001", name: "LSASS Memory Dump via Task Manager" },
      { id: "T1505.003", name: "Web Shell Injection on Edge Devices" },
      { id: "T1090.002", name: "SOHO Router KV-Botnet Proxy" },
    ],
    knownMalware: ["Custom Web Shells", "Fast Reverse Proxy", "Lithe Pair"],
    description: "State-sponsored cyber espionage group targeting critical infrastructure sectors. Emphasizes stealth through pure Living-off-the-Land (LotL) binaries and compromised SOHO routers.",
    activeCampaigns: ["Edge Router Infiltration", "Pre-Positioning Substation Wave"],
    indicatorCount: 96,
  },
];

const VULNERABILITIES: VulnerabilityItem[] = [
  {
    cveId: "CVE-2024-38077",
    title: "Windows Remote Desktop Licensing Service Remote Code Execution",
    cvss: 9.8,
    severity: "critical",
    epssScore: 0.942,
    cisaKev: true,
    published: "2024-07-09",
    vendor: "Microsoft",
    product: "Windows Server 2008 through 2022",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    exploitStatus: "In-The-Wild Exploitation",
    description: "A heap-based buffer overflow in RdlSvc allows unauthenticated remote attackers to send specially crafted packets to port 135/RPC, triggering arbitrary code execution with NT AUTHORITY\\SYSTEM privileges.",
    patchAvailable: true,
    mitreTechnique: "T1210 - Exploitation of Remote Services",
  },
  {
    cveId: "CVE-2024-21413",
    title: "Microsoft Outlook Moniker Link Remote Code Execution Vulnerability",
    cvss: 9.8,
    severity: "critical",
    epssScore: 0.895,
    cisaKev: true,
    published: "2024-02-13",
    vendor: "Microsoft",
    product: "Microsoft Office & Outlook 2016-2021 / 365",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    exploitStatus: "Weaponized in Ransomware",
    description: "Enables unauthenticated attackers to bypass Protected View and Office security warnings via malicious file:// links containing exclamation marks (!), causing automatic NTLM leak and code execution.",
    patchAvailable: true,
    mitreTechnique: "T1566.002 - Spearphishing Link",
  },
  {
    cveId: "CVE-2024-30078",
    title: "Windows Wi-Fi Driver Remote Code Execution (Dirty Wi-Fi)",
    cvss: 8.8,
    severity: "high",
    epssScore: 0.763,
    cisaKev: true,
    published: "2024-06-11",
    vendor: "Microsoft",
    product: "Windows 10, 11, Windows Server",
    vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    exploitStatus: "Public PoC Available",
    description: "An unauthenticated attacker within adjacent Wi-Fi radio range can broadcast malicious beacon frames directly to victim network adapters, triggering kernel-level code execution without user interaction.",
    patchAvailable: true,
    mitreTechnique: "T1210 - Exploitation of Remote Services",
  },
  {
    cveId: "CVE-2023-46805",
    title: "Ivanti Connect Secure & Policy Secure Authentication Bypass",
    cvss: 8.2,
    severity: "high",
    epssScore: 0.967,
    cisaKev: true,
    published: "2024-01-10",
    vendor: "Ivanti",
    product: "Connect Secure / Policy Secure Gateway",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    exploitStatus: "In-The-Wild Exploitation",
    description: "Allows an attacker to bypass authentication checks by crafting web requests to /api/v1/cav/client/status paths, chained with CVE-2024-21887 command injection to execute root web shells.",
    patchAvailable: true,
    mitreTechnique: "T1190 - Exploit Public-Facing Application",
  },
];

let indicatorsStore: IOCRecord[] = [...INITIAL_INDICATORS];
let feedsStore: ThreatFeed[] = [...INITIAL_FEEDS];

const router: IRouter = Router();

/**
 * GET /api/intelligence/summary
 * Overview metrics for threat intelligence dashboard
 */
router.get("/intelligence/summary", (_req: Request, res: Response) => {
  const total = indicatorsStore.length;
  const critical = indicatorsStore.filter((i) => i.severity === "critical").length;
  const high = indicatorsStore.filter((i) => i.severity === "high").length;
  const medium = indicatorsStore.filter((i) => i.severity === "medium").length;
  const low = indicatorsStore.filter((i) => i.severity === "low").length;
  const activeFeeds = feedsStore.filter((f) => f.status === "active").length;
  const followed = indicatorsStore.filter((i) => i.followed).length;

  res.json({
    totalIndicators: 14892 + total - INITIAL_INDICATORS.length,
    trackedInLocalStore: total,
    severityBreakdown: { critical, high, medium, low },
    activeFeedsCount: activeFeeds,
    totalFeedsCount: feedsStore.length,
    activeCampaignsCount: 8,
    newTodayCount: 312,
    followedCount: followed,
    lastGlobalSync: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
  });
});

/**
 * GET /api/intelligence/indicators
 * Search and filter indicators
 */
router.get("/intelligence/indicators", (req: Request, res: Response) => {
  const query = typeof req.query.q === "string" ? req.query.q.trim().toLowerCase() : "";
  const type = typeof req.query.type === "string" ? req.query.type : undefined;
  const severity = typeof req.query.severity === "string" ? req.query.severity : undefined;

  let results = [...indicatorsStore];

  if (type && type !== "all") {
    results = results.filter((i) => i.type === type);
  }
  if (severity && severity !== "all") {
    results = results.filter((i) => i.severity === severity);
  }
  if (query) {
    results = results.filter((i) =>
      i.value.toLowerCase().includes(query) ||
      i.defangedValue.toLowerCase().includes(query) ||
      i.category.toLowerCase().includes(query) ||
      (i.threatActor && i.threatActor.toLowerCase().includes(query)) ||
      (i.campaign && i.campaign.toLowerCase().includes(query)) ||
      i.tags.some((t) => t.toLowerCase().includes(query))
    );
  }

  res.json({ indicators: results, count: results.length });
});

/**
 * GET /api/intelligence/lookup
 * Fast IOC enrichment lookup for a specific value
 */
router.get("/intelligence/lookup", (req: Request, res: Response) => {
  const query = typeof req.query.query === "string" ? req.query.query.trim().toLowerCase() : "";
  if (!query) {
    res.status(400).json({ error: "Query parameter required" });
    return;
  }

  // Exact or partial match in store
  const matched = indicatorsStore.find(
    (i) => i.value.toLowerCase() === query ||
           i.defangedValue.toLowerCase() === query ||
           i.value.toLowerCase().includes(query) ||
           query.includes(i.value.toLowerCase())
  );

  if (matched) {
    res.json({ found: true, record: matched });
    return;
  }

  // Generate dynamic contextual dossier if not in static list
  let inferredType: IndicatorType = "domain";
  if (/^[a-f0-9]{32,64}$/i.test(query)) inferredType = "hash";
  else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query)) inferredType = "ip";
  else if (/^cve-\d{4}-\d{4,7}$/i.test(query)) inferredType = "cve";
  else if (/^https?:\/\//i.test(query)) inferredType = "url";

  const dynamicRecord: IOCRecord = {
    id: `dyn-${Date.now()}`,
    type: inferredType,
    value: query,
    defangedValue: query.replace(/\./g, "[.]"),
    severity: "medium",
    score: 65,
    category: "Dynamic Reputation Lookup",
    confidence: 78,
    mitreTechniques: [
      { id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
    ],
    firstSeen: new Date(Date.now() - 7 * 86400 * 1000).toISOString(),
    lastSeen: new Date().toISOString(),
    enginesFlagged: 18,
    enginesTotal: 84,
    reputationVerdict: "Suspicious",
    description: `Dynamic query result for ${query}. Queried across Northstar DNS and ARGUS global exchange. 18 of 84 engines flag suspicious telemetry.`,
    tags: ["ad-hoc-query", "synthetic-correlation"],
    followed: false,
    blocked: false,
  };

  res.json({ found: false, dynamicAnalysis: dynamicRecord });
});

/**
 * POST /api/intelligence/indicators
 * Submit new indicator
 */
router.post("/intelligence/indicators", (req: Request, res: Response) => {
  const { value, type, severity, category, description, threatActor, tags } = req.body || {};
  if (!value || !type) {
    res.status(400).json({ error: "Missing required value or type" });
    return;
  }

  const newIoc: IOCRecord = {
    id: `ioc-user-${Date.now()}`,
    type: type as IndicatorType,
    value: String(value).trim(),
    defangedValue: String(value).trim().replace(/\./g, "[.]"),
    severity: (severity || "medium") as IndicatorSeverity,
    score: severity === "critical" ? 95 : severity === "high" ? 85 : 60,
    category: category || "Manual Threat Submission",
    confidence: 90,
    threatActor: threatActor || "Unknown / Analyst Identified",
    mitreTechniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    ],
    firstSeen: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    enginesFlagged: 45,
    enginesTotal: 86,
    reputationVerdict: severity === "critical" || severity === "high" ? "Malicious" : "Suspicious",
    description: description || "Analyst-submitted indicator added to workspace intelligence repository.",
    tags: Array.isArray(tags) ? tags : ["analyst-submitted", "manual"],
    followed: true,
    blocked: false,
  };

  indicatorsStore.unshift(newIoc);
  res.status(201).json({ success: true, indicator: newIoc });
});

/**
 * PATCH /api/intelligence/indicators/:id/toggle-follow
 */
router.patch("/intelligence/indicators/:id/toggle-follow", (req: Request, res: Response) => {
  const id = req.params.id;
  const item = indicatorsStore.find((i) => i.id === id);
  if (!item) {
    res.status(404).json({ error: "Indicator not found" });
    return;
  }
  item.followed = !item.followed;
  res.json({ success: true, followed: item.followed });
});

/**
 * PATCH /api/intelligence/indicators/:id/toggle-block
 */
router.patch("/intelligence/indicators/:id/toggle-block", (req: Request, res: Response) => {
  const id = req.params.id;
  const item = indicatorsStore.find((i) => i.id === id);
  if (!item) {
    res.status(404).json({ error: "Indicator not found" });
    return;
  }
  item.blocked = !item.blocked;
  res.json({ success: true, blocked: item.blocked });
});

/**
 * GET /api/intelligence/feeds
 */
router.get("/intelligence/feeds", (_req: Request, res: Response) => {
  res.json({ feeds: feedsStore });
});

/**
 * POST /api/intelligence/feeds/refresh
 */
router.post("/intelligence/feeds/refresh", (_req: Request, res: Response) => {
  feedsStore = feedsStore.map((f) => ({
    ...f,
    lastSync: new Date().toISOString(),
    latencyMs: Math.floor(Math.random() * 40) + 25,
  }));
  res.json({ success: true, message: "All feeds refreshed successfully", feeds: feedsStore });
});

/**
 * GET /api/intelligence/actors
 */
router.get("/intelligence/actors", (_req: Request, res: Response) => {
  res.json({ actors: THREAT_ACTORS });
});

/**
 * GET /api/intelligence/vulnerabilities
 */
router.get("/intelligence/vulnerabilities", (_req: Request, res: Response) => {
  res.json({ vulnerabilities: VULNERABILITIES });
});

/**
 * GET /api/intelligence/stix
 * Download full STIX 2.1 JSON Bundle
 */
router.get("/intelligence/stix", (_req: Request, res: Response) => {
  const now = new Date().toISOString();
  const stixObjects = [
    {
      type: "bundle",
      id: `bundle--${Date.now()}`,
      spec_version: "2.1",
      objects: [
        ...indicatorsStore.map((ioc) => ({
          type: "indicator",
          spec_version: "2.1",
          id: `indicator--${ioc.id}`,
          created: ioc.firstSeen,
          modified: ioc.lastSeen,
          name: `${ioc.type.toUpperCase()}: ${ioc.value}`,
          description: ioc.description,
          indicator_types: [ioc.category],
          pattern: ioc.type === "domain" ? `[domain-name:value = '${ioc.value}']` :
                   ioc.type === "ip" ? `[ipv4-addr:value = '${ioc.value}']` :
                   ioc.type === "hash" ? `[file:hashes.'SHA-256' = '${ioc.value}']` :
                   `[url:value = '${ioc.value}']`,
          pattern_type: "stix",
          valid_from: ioc.firstSeen,
          confidence: ioc.confidence,
        })),
        ...THREAT_ACTORS.map((act) => ({
          type: "threat-actor",
          spec_version: "2.1",
          id: `threat-actor--${act.id}`,
          created: now,
          modified: now,
          name: act.name,
          aliases: act.aliases,
          threat_actor_types: [act.motivation],
          description: act.description,
          sophistication: "advanced",
        })),
      ],
    },
  ];

  res.setHeader("Content-Disposition", "attachment; filename=\"argus-threat-intel-stix2.1.json\"");
  res.setHeader("Content-Type", "application/json");
  res.json(stixObjects[0]);
});

export default router;
