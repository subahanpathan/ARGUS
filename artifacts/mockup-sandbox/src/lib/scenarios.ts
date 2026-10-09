export type SimulationPhase =
  | 'IDLE'
  | 'ATTACK'
  | 'DETECTED'
  | 'CONTAINED'
  | 'LEAK_ASSESSMENT'
  | 'REPORTING'
  | 'INVESTIGATING'
  | 'ADAPTING'
  | 'RECOVERED';

export type FileStatus = 'safe' | 'malware' | 'corrupted' | 'leaked' | 'recovered' | 'deleted';
export type FileType = 'system' | 'image' | 'sensitive' | 'document' | 'executable';

export interface SimulatedFile {
  id: string;
  name: string;
  status: FileStatus;
  type: FileType;
  hash: string;
}

export interface AttackStep {
  id: string;
  title: string;
  description: string;
  technique: string; // MITRE ATT&CK technique
  delayMs: number;
}

export interface ScenarioDef {
  id: string;
  name: string;
  family: string;
  confidence: number;
  entryVector: string;
  description: string;
  initialFiles: SimulatedFile[];
  steps: AttackStep[];
}

export const SCENARIOS: ScenarioDef[] = [
  {
    id: 's-001',
    name: 'Ransomware / Data Extortion',
    family: 'CryptoLocker Variant (Simulated)',
    confidence: 98.5,
    entryVector: 'Phishing Email -> Malicious Attachment',
    description: 'A multi-stage attack that drops an executable, attempts to encrypt images, and exfiltrates sensitive documents.',
    initialFiles: [
      { id: 'f1', name: 'System_Config.sys', status: 'safe', type: 'system', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      { id: 'f2', name: 'Family_Photo.jpg', status: 'safe', type: 'image', hash: '8a9f3b5c4d7e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b' },
      { id: 'f3', name: 'Q4_Financial_Report.pdf', status: 'safe', type: 'sensitive', hash: '1f2e3d4c5b6a7988091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e' },
      { id: 'f4', name: 'Customer_Records.csv', status: 'safe', type: 'document', hash: '5b6a7988091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e1f2e3d4c' },
    ],
    steps: [
      {
        id: 'st-1',
        title: 'Initial Access',
        description: 'User opened malicious invoice.pdf.exe from email.',
        technique: 'T1566.001 - Spearphishing Attachment',
        delayMs: 2000
      },
      {
        id: 'st-2',
        title: 'Execution',
        description: 'Dropper executable unpacked and loaded into memory.',
        technique: 'T1204.002 - Malicious File',
        delayMs: 1500
      },
      {
        id: 'st-3',
        title: 'Discovery',
        description: 'Scanning user directories for valuable files.',
        technique: 'T1083 - File and Directory Discovery',
        delayMs: 1000
      },
      {
        id: 'st-4',
        title: 'Collection & Exfiltration',
        description: 'Staging Q4_Financial_Report.pdf for exfiltration to 185.199.x.x',
        technique: 'T1048 - Exfiltration Over Alternative Protocol',
        delayMs: 2500
      },
      {
        id: 'st-5',
        title: 'Impact',
        description: 'Encrypting Family_Photo.jpg',
        technique: 'T1486 - Data Encrypted for Impact',
        delayMs: 2000
      }
    ]
  },
  {
    id: 's-002',
    name: 'Stealth Credential Harvester',
    family: 'AgentTesla Variant (Simulated)',
    confidence: 94.2,
    entryVector: 'Drive-by Compromise',
    description: 'A stealthy trojan that hooks into browsers to steal credentials without modifying files.',
    initialFiles: [
      { id: 'f1', name: 'Browser_Cache.db', status: 'safe', type: 'system', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
      { id: 'f2', name: 'Passwords.kdbx', status: 'safe', type: 'sensitive', hash: '8a9f3b5c4d7e1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b' },
    ],
    steps: [
      {
        id: 'st-1',
        title: 'Initial Access',
        description: 'Exploited browser vulnerability on compromised site.',
        technique: 'T1189 - Drive-by Compromise',
        delayMs: 2000
      },
      {
        id: 'st-2',
        title: 'Credential Access',
        description: 'Reading Browser_Cache.db for stored session tokens.',
        technique: 'T1555.003 - Credentials from Web Browsers',
        delayMs: 2500
      }
    ]
  }
];
