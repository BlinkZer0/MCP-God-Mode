/**
 * Crime Reporter Tool - Type Definitions
 */

export interface EvidenceRef {
  kind: 'file' | 'url' | 'text';
  path?: string;
  url?: string;
  content?: string;
  description?: string;
  metadata?: Record<string, any>;
}

export interface AIModelNote {
  model: string;
  summary: string;
  confidence?: number;
  provenance?: string;
  timestamp?: string;
}

export interface TimelineEvent {
  when: string;
  title: string;
  details?: string;
  location?: string;
  witnesses?: string[];
}

export interface PersonInfo {
  name?: string;
  email?: string;
  phone?: string;
  address?: string;
  relationship?: string;
}

export interface CaseBundle {
  caseId?: string;
  narrative: string;
  location: {
    raw: string;
    lat?: number;
    lon?: number;
    address?: string;
    city?: string;
    state?: string;
    zip?: string;
  };
  crimeType?: string;
  anonymous?: boolean;
  evidence?: EvidenceRef[];
  timeline?: TimelineEvent[];
  aiNotes?: AIModelNote[];
  persons?: PersonInfo[];
  metadata?: Record<string, any>;
}

export interface NormalizedReport {
  caseId: string;
  timestamp: string;
  narrative: string;
  location: CaseBundle['location'];
  crimeType: string;
  anonymous: boolean;
  evidence: EvidenceRef[];
  timeline: TimelineEvent[];
  aiNotes: AIModelNote[];
  jurisdiction?: any;
  metadata: {
    preparedBy: string;
    version: string;
    source: string;
    [key: string]: any;
  };
}

export interface FilingResult {
  status: 'submitted' | 'partial' | 'failed' | 'captcha_required';
  receipt?: {
    referenceId?: string;
    confirmationNumber?: string;
    timestamp: string;
    method: 'form' | 'email' | 'phone';
  };
  artifacts: {
    screenshots?: string[];
    pdf?: string;
    html?: string;
    json?: string;
  };
  errors?: string[];
  nextSteps?: string[];
  captchaUrl?: string;
}

export interface CrimeReporterConfig {
  sources: {
    webSearch: {
      enabled: boolean;
      apiKey?: string;
    };
    civicApi: {
      enabled: boolean;
      apiKey: string;
    };
    heuristics: {
      enabled: boolean;
    };
  };
  legal: {
    requireLegalAcknowledgment: boolean;
    maxFileSize: number;
    allowedFileTypes: string[];
    auditLogging: boolean;
  };
  email: {
    host: string;
    port: number;
    secure: boolean;
    auth: {
      user: string;
      pass: string;
    };
  };
}
