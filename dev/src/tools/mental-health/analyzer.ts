import { 
  ALL_DIAGNOSTIC_CRITERIA, 
  PSYCHOLOGICAL_MARKERS, 
  CRISIS_SEVERITY,
  DiagnosticCriteria,
  PsychologicalMarker 
} from './diagnostic-data.js';
import { PLATFORM, IS_MOBILE } from '../../config/environment.js';

export interface AnalysisResult {
  psychologicalProfile: PsychologicalProfile;
  potentialDiagnoses: DiagnosticMatch[];
  crisisLevel: CrisisLevel;
  riskFactors: RiskFactor[];
  recommendations: string[];
  confidence: number;
}

export interface PsychologicalProfile {
  markers: { [key: string]: number };
  dominantThemes: string[];
  emotionalTone: string;
  cognitivePatterns: string[];
  behavioralIndicators: string[];
  riskLevel: 'low' | 'moderate' | 'high' | 'critical';
}

export interface DiagnosticMatch {
  criteria: DiagnosticCriteria;
  matchScore: number;
  matchedIndicators: string[];
  confidence: number;
  severity: string;
  specifiers?: string[];
}

export interface CrisisLevel {
  level: 'low' | 'moderate' | 'high' | 'critical';
  score: number;
  description: string;
  immediateActions: string[];
  emergencyContacts: string[];
}

export interface RiskFactor {
  factor: string;
  severity: number;
  description: string;
  mitigation: string;
}

export class MentalHealthAnalyzer {
  private diagnosticCriteria: DiagnosticCriteria[];
  private psychologicalMarkers: PsychologicalMarker[];
  private platform: string;
  private isMobile: boolean;

  constructor() {
    this.diagnosticCriteria = ALL_DIAGNOSTIC_CRITERIA;
    this.psychologicalMarkers = PSYCHOLOGICAL_MARKERS;
    this.platform = PLATFORM;
    this.isMobile = IS_MOBILE;
  }

  async analyzeTextSamples(textSamples: string[]): Promise<AnalysisResult> {
    // Combine all text samples
    const combinedText = textSamples.join(' ').toLowerCase();
    
    // Extract psychological markers
    const psychologicalProfile = this.extractPsychologicalProfile(combinedText);
    
    // Match against diagnostic criteria
    const potentialDiagnoses = this.matchDiagnosticCriteria(psychologicalProfile);
    
    // Assess crisis level
    const crisisLevel = this.assessCrisisLevel(psychologicalProfile, potentialDiagnoses);
    
    // Identify risk factors
    const riskFactors = this.identifyRiskFactors(psychologicalProfile, potentialDiagnoses);
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(psychologicalProfile, potentialDiagnoses, crisisLevel);
    
    // Calculate overall confidence
    const confidence = this.calculateConfidence(psychologicalProfile, potentialDiagnoses);

    return {
      psychologicalProfile,
      potentialDiagnoses,
      crisisLevel,
      riskFactors,
      recommendations,
      confidence
    };
  }

  private extractPsychologicalProfile(text: string): PsychologicalProfile {
    const markers: { [key: string]: number } = {};
    const dominantThemes: string[] = [];
    const cognitivePatterns: string[] = [];
    const behavioralIndicators: string[] = [];

    // Analyze each psychological marker
    for (const marker of this.psychologicalMarkers) {
      const score = this.calculateMarkerScore(text, marker);
      markers[marker.name] = score;
      
      if (score > 0.3) {
        dominantThemes.push(marker.category);
        if (marker.category === 'cognition') {
          cognitivePatterns.push(marker.name);
        } else if (marker.category === 'behavior') {
          behavioralIndicators.push(marker.name);
        }
      }
    }

    // Determine emotional tone
    const emotionalTone = this.determineEmotionalTone(markers);
    
    // Calculate overall risk level
    const riskLevel = this.calculateRiskLevel(markers);

    return {
      markers,
      dominantThemes: [...new Set(dominantThemes)],
      emotionalTone,
      cognitivePatterns,
      behavioralIndicators,
      riskLevel
    };
  }

  private calculateMarkerScore(text: string, marker: PsychologicalMarker): number {
    let totalScore = 0;
    let keywordCount = 0;
    
    for (const keyword of marker.keywords) {
      const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
      const matches = text.match(regex);
      if (matches) {
        keywordCount += matches.length;
        totalScore += matches.length * marker.weight;
      }
    }
    
    // Normalize by text length and keyword frequency
    const textLength = text.split(/\s+/).length;
    const normalizedScore = Math.min(1, totalScore / (textLength / 1000));
    
    return normalizedScore;
  }

  private determineEmotionalTone(markers: { [key: string]: number }): string {
    const toneScores = {
      depressed: markers.depressed_mood || 0,
      anxious: markers.excessive_worry || 0,
      angry: markers.irritability || 0,
      euphoric: markers.elevated_mood || 0,
      fearful: markers.panic_attacks || 0,
      numb: markers.anhedonia || 0
    };

    const dominantTone = Object.entries(toneScores)
      .sort(([,a], [,b]) => b - a)[0];

    if (dominantTone[1] > 0.5) {
      return dominantTone[0];
    } else if (dominantTone[1] > 0.3) {
      return `mixed-${dominantTone[0]}`;
    } else {
      return 'neutral';
    }
  }

  private calculateRiskLevel(markers: { [key: string]: number }): 'low' | 'moderate' | 'high' | 'critical' {
    const suicideRisk = markers.suicidal_ideation || 0;
    const selfHarmRisk = markers.impulsivity || 0;
    const psychosisRisk = (markers.delusions || 0) + (markers.hallucinations || 0);
    
    if (suicideRisk > 0.7 || psychosisRisk > 0.8) {
      return 'critical';
    } else if (suicideRisk > 0.4 || selfHarmRisk > 0.6 || psychosisRisk > 0.5) {
      return 'high';
    } else if (suicideRisk > 0.2 || selfHarmRisk > 0.3 || psychosisRisk > 0.2) {
      return 'moderate';
    } else {
      return 'low';
    }
  }

  private matchDiagnosticCriteria(profile: PsychologicalProfile): DiagnosticMatch[] {
    const matches: DiagnosticMatch[] = [];

    for (const criteria of this.diagnosticCriteria) {
      const matchScore = this.calculateDiagnosticMatch(profile, criteria);
      
      if (matchScore > 0.3) {
        const matchedIndicators = criteria.indicators.filter(indicator => 
          profile.markers[indicator] > 0.2
        );
        
        const confidence = this.calculateDiagnosticConfidence(matchScore, matchedIndicators.length, criteria.indicators.length);
        
        matches.push({
          criteria,
          matchScore,
          matchedIndicators,
          confidence,
          severity: this.determineSeverity(matchScore, profile.markers),
          specifiers: this.identifySpecifiers(profile, criteria)
        });
      }
    }

    // Sort by match score and confidence
    return matches.sort((a, b) => (b.matchScore * b.confidence) - (a.matchScore * a.confidence));
  }

  private calculateDiagnosticMatch(profile: PsychologicalProfile, criteria: DiagnosticCriteria): number {
    let totalScore = 0;
    let matchedIndicators = 0;
    
    for (const indicator of criteria.indicators) {
      const markerScore = profile.markers[indicator] || 0;
      if (markerScore > 0.2) {
        matchedIndicators++;
        totalScore += markerScore;
      }
    }
    
    // Weight by number of matched indicators
    const indicatorRatio = matchedIndicators / criteria.indicators.length;
    return (totalScore / criteria.indicators.length) * indicatorRatio;
  }

  private calculateDiagnosticConfidence(matchScore: number, matchedCount: number, totalCount: number): number {
    const coverageRatio = matchedCount / totalCount;
    return Math.min(1, matchScore * coverageRatio);
  }

  private determineSeverity(matchScore: number, markers: { [key: string]: number }): string {
    if (matchScore > 0.8) return 'Severe';
    if (matchScore > 0.6) return 'Moderate';
    if (matchScore > 0.4) return 'Mild';
    return 'Subthreshold';
  }

  private identifySpecifiers(profile: PsychologicalProfile, criteria: DiagnosticCriteria): string[] {
    const specifiers: string[] = [];
    
    if (criteria.specifiers) {
      for (const specifier of criteria.specifiers) {
        if (this.matchesSpecifier(profile, specifier)) {
          specifiers.push(specifier);
        }
      }
    }
    
    return specifiers;
  }

  private matchesSpecifier(profile: PsychologicalProfile, specifier: string): boolean {
    const specifierMap: { [key: string]: string[] } = {
      'With anxious distress': ['excessive_worry', 'panic_attacks'],
      'With melancholic features': ['depressed_mood', 'anhedonia', 'guilt'],
      'With atypical features': ['excessive_worry', 'sleep_disturbance'],
      'With psychotic features': ['delusions', 'hallucinations'],
      'With catatonia': ['psychomotor_agitation'],
      'With rapid cycling': ['elevated_mood', 'depressed_mood'],
      'With seasonal pattern': ['depressed_mood', 'sleep_disturbance']
    };
    
    const requiredMarkers = specifierMap[specifier] || [];
    return requiredMarkers.some(marker => profile.markers[marker] > 0.3);
  }

  private assessCrisisLevel(profile: PsychologicalProfile, diagnoses: DiagnosticMatch[]): CrisisLevel {
    const suicideRisk = profile.markers.suicidal_ideation || 0;
    const selfHarmRisk = profile.markers.impulsivity || 0;
    const psychosisRisk = (profile.markers.delusions || 0) + (profile.markers.hallucinations || 0);
    const severeDiagnosis = diagnoses.some(d => d.severity === 'Severe');
    
    const crisisScore = Math.max(suicideRisk, selfHarmRisk, psychosisRisk);
    
    let level: 'low' | 'moderate' | 'high' | 'critical';
    let description: string;
    let immediateActions: string[];
    let emergencyContacts: string[];

    if (crisisScore > 0.8 || severeDiagnosis) {
      level = 'critical';
      description = 'Immediate crisis intervention required - high risk of self-harm or harm to others';
      immediateActions = [
        'Call emergency services (911) immediately',
        'Do not leave the person alone',
        'Remove any means of self-harm',
        'Contact crisis intervention team'
      ];
      emergencyContacts = [
        'National Suicide Prevention Lifeline: 988',
        'Crisis Text Line: Text HOME to 741741',
        'Emergency Services: 911'
      ];
    } else if (crisisScore > 0.6) {
      level = 'high';
      description = 'High risk situation requiring immediate professional intervention';
      immediateActions = [
        'Contact mental health professional immediately',
        'Ensure safety of individual',
        'Monitor closely for escalation',
        'Have crisis resources available'
      ];
      emergencyContacts = [
        'National Suicide Prevention Lifeline: 988',
        'Crisis Text Line: Text HOME to 741741'
      ];
    } else if (crisisScore > 0.3) {
      level = 'moderate';
      description = 'Moderate risk requiring professional assessment and support';
      immediateActions = [
        'Schedule appointment with mental health professional',
        'Implement safety plan',
        'Monitor symptoms',
        'Provide emotional support'
      ];
      emergencyContacts = [
        'National Suicide Prevention Lifeline: 988'
      ];
    } else {
      level = 'low';
      description = 'Low risk with manageable symptoms';
      immediateActions = [
        'Continue monitoring',
        'Implement self-care strategies',
        'Consider preventive mental health services'
      ];
      emergencyContacts = [];
    }

    return {
      level,
      score: crisisScore,
      description,
      immediateActions,
      emergencyContacts
    };
  }

  private identifyRiskFactors(profile: PsychologicalProfile, diagnoses: DiagnosticMatch[]): RiskFactor[] {
    const riskFactors: RiskFactor[] = [];

    // Suicide risk factors
    if (profile.markers.suicidal_ideation > 0.3) {
      riskFactors.push({
        factor: 'Suicidal Ideation',
        severity: profile.markers.suicidal_ideation,
        description: 'Expressed thoughts of self-harm or suicide',
        mitigation: 'Immediate crisis intervention and safety planning required'
      });
    }

    // Self-harm risk factors
    if (profile.markers.impulsivity > 0.5) {
      riskFactors.push({
        factor: 'High Impulsivity',
        severity: profile.markers.impulsivity,
        description: 'Tendency toward impulsive, potentially harmful behaviors',
        mitigation: 'Remove access to means of self-harm, implement impulse control strategies'
      });
    }

    // Psychosis risk factors
    if (profile.markers.delusions > 0.3 || profile.markers.hallucinations > 0.3) {
      riskFactors.push({
        factor: 'Psychotic Symptoms',
        severity: Math.max(profile.markers.delusions, profile.markers.hallucinations),
        description: 'Presence of delusions or hallucinations',
        mitigation: 'Immediate psychiatric evaluation and potential medication management'
      });
    }

    // Substance abuse risk factors
    if (profile.markers.impulsivity > 0.4 && profile.markers.depressed_mood > 0.4) {
      riskFactors.push({
        factor: 'Substance Abuse Risk',
        severity: (profile.markers.impulsivity + profile.markers.depressed_mood) / 2,
        description: 'High risk for substance abuse as coping mechanism',
        mitigation: 'Substance abuse screening and prevention strategies'
      });
    }

    // Social isolation risk factors
    if (profile.markers.avoidance > 0.5) {
      riskFactors.push({
        factor: 'Social Isolation',
        severity: profile.markers.avoidance,
        description: 'Tendency to avoid social contact and support',
        mitigation: 'Gradual social re-engagement and support system building'
      });
    }

    return riskFactors;
  }

  private generateRecommendations(profile: PsychologicalProfile, diagnoses: DiagnosticMatch[], crisisLevel: CrisisLevel): string[] {
    const recommendations: string[] = [];

    // Crisis-level recommendations
    if (crisisLevel.level === 'critical') {
      recommendations.push('IMMEDIATE: Contact emergency services and crisis intervention team');
      recommendations.push('IMMEDIATE: Do not leave the person alone');
      recommendations.push('IMMEDIATE: Remove access to means of self-harm');
    } else if (crisisLevel.level === 'high') {
      recommendations.push('URGENT: Schedule immediate appointment with mental health professional');
      recommendations.push('URGENT: Implement safety plan with crisis contacts');
    }

    // Diagnosis-specific recommendations
    for (const diagnosis of diagnoses.slice(0, 3)) { // Top 3 diagnoses
      const specificRecommendations = this.getDiagnosisSpecificRecommendations(diagnosis);
      recommendations.push(...specificRecommendations);
    }

    // General recommendations based on profile
    if (profile.markers.depressed_mood > 0.4) {
      recommendations.push('Consider antidepressant medication evaluation');
      recommendations.push('Implement behavioral activation strategies');
      recommendations.push('Regular exercise and sleep hygiene');
    }

    if (profile.markers.excessive_worry > 0.4) {
      recommendations.push('Cognitive-behavioral therapy for anxiety');
      recommendations.push('Mindfulness and relaxation techniques');
      recommendations.push('Consider anti-anxiety medication if severe');
    }

    if (profile.markers.trauma_exposure > 0.3) {
      recommendations.push('Trauma-focused therapy (EMDR, TF-CBT)');
      recommendations.push('Safety and stabilization work');
      recommendations.push('PTSD-specific treatment protocols');
    }

    if (profile.markers.psychosis > 0.3) {
      recommendations.push('Immediate psychiatric evaluation');
      recommendations.push('Antipsychotic medication consideration');
      recommendations.push('Family psychoeducation and support');
    }

    // General wellness recommendations
    recommendations.push('Regular mental health check-ins');
    recommendations.push('Maintain social support network');
    recommendations.push('Healthy lifestyle habits (sleep, nutrition, exercise)');
    recommendations.push('Stress management techniques');

    return [...new Set(recommendations)]; // Remove duplicates
  }

  private getDiagnosisSpecificRecommendations(diagnosis: DiagnosticMatch): string[] {
    const recommendations: string[] = [];
    
    switch (diagnosis.criteria.code) {
      case '296.20':
      case 'F32.9':
        recommendations.push('Major Depression: Antidepressant medication evaluation');
        recommendations.push('Major Depression: Cognitive-behavioral therapy');
        recommendations.push('Major Depression: Behavioral activation');
        break;
      case '300.02':
      case 'F41.1':
        recommendations.push('Generalized Anxiety: CBT with exposure therapy');
        recommendations.push('Generalized Anxiety: Anti-anxiety medication if needed');
        recommendations.push('Generalized Anxiety: Relaxation training');
        break;
      case '309.81':
      case 'F43.10':
        recommendations.push('PTSD: Trauma-focused therapy (EMDR/TF-CBT)');
        recommendations.push('PTSD: Safety and stabilization work');
        recommendations.push('PTSD: Medication for sleep and anxiety if needed');
        break;
      case '295.90':
      case 'F20.9':
        recommendations.push('Schizophrenia: Antipsychotic medication');
        recommendations.push('Schizophrenia: Family psychoeducation');
        recommendations.push('Schizophrenia: Supported employment/education');
        break;
      case '296.89':
      case 'F31.9':
        recommendations.push('Bipolar: Mood stabilizer medication');
        recommendations.push('Bipolar: Psychoeducation about mood episodes');
        recommendations.push('Bipolar: Regular sleep schedule maintenance');
        break;
    }
    
    return recommendations;
  }

  private calculateConfidence(profile: PsychologicalProfile, diagnoses: DiagnosticMatch[]): number {
    if (diagnoses.length === 0) return 0;
    
    const topDiagnosis = diagnoses[0];
    const markerStrength = Object.values(profile.markers).reduce((sum, val) => sum + val, 0) / Object.keys(profile.markers).length;
    
    return Math.min(1, (topDiagnosis.confidence + markerStrength) / 2);
  }
}
