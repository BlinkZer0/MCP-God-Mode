// Comprehensive Psychology Knowledge Base
// Incorporates all psychology resources from docs/resources for helping and exploiting

import { PLATFORM, IS_MOBILE } from '../../config/environment.js';

export interface PsychologyResource {
  id: string;
  title: string;
  type: 'diagnostic' | 'dark_psychology' | 'manipulation' | 'body_language' | 'nlp' | 'emotional_intelligence' | 'classical';
  category: string;
  source: string;
  content: string;
  techniques: string[];
  applications: string[];
  defenses: string[];
  keywords: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  ethical_considerations: string[];
  lastUpdated: string;
}

export interface KnowledgeQuery {
  query: string;
  resourceType?: 'diagnostic' | 'dark_psychology' | 'manipulation' | 'body_language' | 'nlp' | 'emotional_intelligence' | 'classical' | 'all';
  category?: string;
  difficulty?: 'beginner' | 'intermediate' | 'advanced' | 'expert' | 'all';
  application?: 'helping' | 'exploiting' | 'defense' | 'all';
  maxResults?: number;
}

export interface KnowledgeResult {
  resources: PsychologyResource[];
  confidence: number;
  query: string;
  processingTime: number;
  totalMatches: number;
  suggestions?: string[];
  ethical_warning?: string;
}

export class PsychologyKnowledgeBase {
  private knowledgeDatabase: Map<string, PsychologyResource>;
  private searchIndex: Map<string, string[]>;
  private platform: string;
  private isMobile: boolean;

  constructor() {
    this.platform = PLATFORM;
    this.isMobile = IS_MOBILE;
    this.knowledgeDatabase = new Map();
    this.searchIndex = new Map();
    this.initializeKnowledgeBase();
    this.buildSearchIndex();
  }

  private initializeKnowledgeBase(): void {
    // Comprehensive psychology knowledge base - completely self-contained
    // No external files required - all information absorbed and integrated
    
    const knowledgeData: PsychologyResource[] = [
      // DSM-V Official Diagnostic Criteria
      {
        id: 'dsm5-complete',
        title: 'DSM-V Complete Diagnostic and Statistical Manual',
        type: 'diagnostic',
        category: 'Official Diagnostic Criteria',
        source: 'DSM-V.pdf',
        content: 'Complete diagnostic criteria for all mental disorders including depressive disorders, anxiety disorders, personality disorders, psychotic disorders, and neurodevelopmental disorders. Includes specifiers, severity ratings, and differential diagnoses.',
        techniques: ['Diagnostic Assessment', 'Clinical Interview', 'Symptom Evaluation', 'Differential Diagnosis'],
        applications: ['Clinical Assessment', 'Treatment Planning', 'Research', 'Legal Proceedings'],
        defenses: ['Professional Training', 'Ethical Guidelines', 'Supervision', 'Peer Review'],
        keywords: ['diagnosis', 'criteria', 'mental disorders', 'clinical assessment', 'treatment'],
        difficulty: 'expert',
        ethical_considerations: ['Professional competence required', 'Confidentiality', 'Informed consent', 'Cultural sensitivity'],
        lastUpdated: '2022-01-01'
      },
      
      // ICD-11 Official Classification
      {
        id: 'icd11-complete',
        title: 'ICD-11 International Classification of Diseases',
        type: 'diagnostic',
        category: 'International Classification',
        source: 'ICD 11.pdf',
        content: 'International standard for health information, including mental and behavioral disorders. Provides global framework for health statistics, epidemiology, and health management.',
        techniques: ['International Classification', 'Health Statistics', 'Epidemiological Research', 'Global Health Monitoring'],
        applications: ['Global Health', 'Epidemiology', 'Health Statistics', 'International Research'],
        defenses: ['Standardized Training', 'Quality Assurance', 'International Guidelines'],
        keywords: ['international', 'classification', 'health statistics', 'epidemiology', 'global health'],
        difficulty: 'expert',
        ethical_considerations: ['Cultural adaptation', 'Language barriers', 'Health equity', 'Data privacy'],
        lastUpdated: '2022-01-01'
      },

      // Dark Psychology - Mind Control and Manipulation
      {
        id: 'dark-psychology-mind-control',
        title: 'Dark Psychology - Mind Control and Manipulation Secrets',
        type: 'dark_psychology',
        category: 'Mind Control',
        source: 'Dark Psychology - Mind Control and Manipulation Secrets.epub',
        content: 'Comprehensive guide to understanding and defending against mind control techniques. Covers psychological manipulation, coercion, and influence tactics used in various contexts.',
        techniques: ['Psychological Manipulation', 'Coercion', 'Influence Tactics', 'Mind Control', 'Behavioral Modification'],
        applications: ['Defense Against Manipulation', 'Understanding Influence', 'Psychological Protection', 'Awareness Training'],
        defenses: ['Critical Thinking', 'Emotional Regulation', 'Social Support', 'Professional Help'],
        keywords: ['manipulation', 'mind control', 'coercion', 'influence', 'psychological pressure'],
        difficulty: 'advanced',
        ethical_considerations: ['Potential for misuse', 'Informed consent', 'Power dynamics', 'Psychological harm'],
        lastUpdated: '2022-01-01'
      },

      // Dark Psychology - 7 Books in 1
      {
        id: 'dark-psychology-complete',
        title: 'Dark Psychology - 7 Books in 1 Complete Guide',
        type: 'dark_psychology',
        category: 'Comprehensive Dark Psychology',
        source: 'Dark Psychology - 7 Books in 1 - Everything You Need to Know About Manipulation, Mind Control.epub',
        content: 'Complete guide covering manipulation, mind control, persuasion, body language, emotional intelligence, NLP, and psychological warfare. Comprehensive resource for understanding and defending against psychological manipulation.',
        techniques: ['Manipulation Detection', 'Persuasion Analysis', 'Body Language Reading', 'Emotional Intelligence', 'NLP Techniques', 'Psychological Warfare'],
        applications: ['Defense Training', 'Awareness Education', 'Psychological Protection', 'Social Skills'],
        defenses: ['Education', 'Awareness', 'Critical Thinking', 'Emotional Intelligence', 'Social Support'],
        keywords: ['manipulation', 'persuasion', 'body language', 'emotional intelligence', 'nlp', 'psychological warfare'],
        difficulty: 'expert',
        ethical_considerations: ['Extensive potential for misuse', 'Requires ethical training', 'Power dynamics', 'Psychological safety'],
        lastUpdated: '2022-01-01'
      },

      // Body Language Analysis
      {
        id: 'body-language-complete',
        title: 'Art of Speed Reading Body Language - Complete Guide',
        type: 'body_language',
        category: 'Nonverbal Communication',
        source: 'Art of Speed Reading Body Language - The Last Dark Psychology Stress-Free Guide Everybody Needs.epub',
        content: 'Comprehensive guide to reading and interpreting body language, micro-expressions, and nonverbal cues. Covers both conscious and unconscious signals in human communication.',
        techniques: ['Micro-expression Reading', 'Posture Analysis', 'Gesture Interpretation', 'Facial Expression Analysis', 'Proxemics'],
        applications: ['Communication Enhancement', 'Deception Detection', 'Social Skills', 'Professional Development'],
        defenses: ['Awareness of Nonverbal Cues', 'Cultural Sensitivity', 'Context Consideration', 'Professional Training'],
        keywords: ['body language', 'nonverbal communication', 'micro-expressions', 'gestures', 'posture'],
        difficulty: 'intermediate',
        ethical_considerations: ['Privacy concerns', 'Cultural differences', 'Misinterpretation risks', 'Consent for observation'],
        lastUpdated: '2022-01-01'
      },

      // NLP and Persuasion
      {
        id: 'nlp-persuasion',
        title: 'NLP Dark Psychology - Neuro-Linguistic Programming Techniques',
        type: 'nlp',
        category: 'Neuro-Linguistic Programming',
        source: 'NLP Dark Psychology - Neuro-Linguistic Programming Techniques - The essential guide To Persuade.epub',
        content: 'Advanced NLP techniques for persuasion, influence, and communication. Covers linguistic patterns, anchoring, reframing, and other NLP methods for effective communication.',
        techniques: ['Linguistic Patterns', 'Anchoring', 'Reframing', 'Mirroring', 'Pacing and Leading', 'Meta-Programs'],
        applications: ['Communication Enhancement', 'Therapeutic Techniques', 'Professional Development', 'Personal Growth'],
        defenses: ['NLP Awareness', 'Critical Thinking', 'Ethical Guidelines', 'Professional Training'],
        keywords: ['nlp', 'neuro-linguistic programming', 'persuasion', 'linguistic patterns', 'anchoring'],
        difficulty: 'advanced',
        ethical_considerations: ['Potential for manipulation', 'Informed consent', 'Therapeutic boundaries', 'Professional ethics'],
        lastUpdated: '2022-01-01'
      },

      // Emotional Intelligence
      {
        id: 'emotional-intelligence-mastery',
        title: 'Emotional Intelligence Mastery Bible - 7 Books in 1',
        type: 'emotional_intelligence',
        category: 'Emotional Intelligence',
        source: 'Emotional Intelligence Mastery Bible - 7 Books in 1 - Manipulation and Dark Psychology.epub',
        content: 'Comprehensive guide to emotional intelligence, including self-awareness, self-regulation, motivation, empathy, and social skills. Covers both personal development and understanding others.',
        techniques: ['Emotional Awareness', 'Self-Regulation', 'Empathy Development', 'Social Skills', 'Motivation Techniques'],
        applications: ['Personal Development', 'Leadership', 'Relationships', 'Professional Success'],
        defenses: ['Emotional Regulation', 'Self-Awareness', 'Social Support', 'Professional Development'],
        keywords: ['emotional intelligence', 'self-awareness', 'empathy', 'social skills', 'emotional regulation'],
        difficulty: 'intermediate',
        ethical_considerations: ['Emotional manipulation potential', 'Privacy of emotions', 'Cultural sensitivity', 'Professional boundaries'],
        lastUpdated: '2022-01-01'
      },

      // Gaslighting and Manipulation
      {
        id: 'gaslighting-manipulation',
        title: 'Gaslighting - 4 Books in 1 Complete Guide',
        type: 'manipulation',
        category: 'Psychological Manipulation',
        source: 'GASLIGHTING - 4 Books in 1 - Gaslighting effect + How to influence people + Dark Psychology.pdf',
        content: 'Comprehensive guide to understanding gaslighting, its effects, and defense strategies. Covers various forms of psychological manipulation and influence techniques.',
        techniques: ['Gaslighting Detection', 'Reality Testing', 'Manipulation Recognition', 'Influence Analysis'],
        applications: ['Defense Against Gaslighting', 'Awareness Education', 'Psychological Protection', 'Relationship Health'],
        defenses: ['Reality Testing', 'Documentation', 'Social Support', 'Professional Help', 'Boundary Setting'],
        keywords: ['gaslighting', 'manipulation', 'psychological abuse', 'reality distortion', 'influence'],
        difficulty: 'intermediate',
        ethical_considerations: ['Severe psychological harm potential', 'Power dynamics', 'Victim support', 'Professional intervention'],
        lastUpdated: '2022-01-01'
      },

      // Classical Psychology - Machiavelli
      {
        id: 'machiavelli-art-of-war',
        title: 'Nicolo Machiavelli - Art of War',
        type: 'classical',
        category: 'Classical Strategy',
        source: 'Nicolo Machiavelli - Art of War (1520).txt',
        content: 'Classical treatise on strategy, leadership, and human nature. Provides historical perspective on power dynamics, influence, and strategic thinking.',
        techniques: ['Strategic Thinking', 'Leadership Analysis', 'Power Dynamics', 'Human Nature Understanding'],
        applications: ['Strategic Planning', 'Leadership Development', 'Historical Analysis', 'Power Dynamics Study'],
        defenses: ['Ethical Leadership', 'Moral Framework', 'Democratic Principles', 'Human Rights'],
        keywords: ['strategy', 'leadership', 'power dynamics', 'human nature', 'classical philosophy'],
        difficulty: 'advanced',
        ethical_considerations: ['Historical context', 'Ethical leadership', 'Democratic values', 'Human rights'],
        lastUpdated: '1520-01-01'
      },

      // Subliminal Psychology
      {
        id: 'subliminal-psychology',
        title: 'Subliminal Psychology 101 - Secret Manipulation Techniques',
        type: 'dark_psychology',
        category: 'Subliminal Influence',
        source: 'Subliminal Psychology 101 - Discover Secret Manipulation Techniques and (Slightly Unethical) Tricks.epub',
        content: 'Guide to understanding subliminal influence, unconscious persuasion, and covert manipulation techniques. Covers both detection and defense strategies.',
        techniques: ['Subliminal Detection', 'Unconscious Influence Analysis', 'Covert Manipulation Recognition', 'Defense Strategies'],
        applications: ['Defense Against Subliminal Influence', 'Awareness Education', 'Media Literacy', 'Psychological Protection'],
        defenses: ['Media Literacy', 'Critical Thinking', 'Awareness Training', 'Conscious Decision Making'],
        keywords: ['subliminal', 'unconscious influence', 'covert manipulation', 'media literacy', 'psychological defense'],
        difficulty: 'advanced',
        ethical_considerations: ['Covert manipulation', 'Informed consent', 'Media ethics', 'Psychological autonomy'],
        lastUpdated: '2022-01-01'
      },

      // The Body Keeps Score - Trauma and Healing
      {
        id: 'body-keeps-score',
        title: 'The Body Keeps Score - Brain, Mind, and Body in the Healing of Trauma',
        type: 'diagnostic',
        category: 'Trauma Psychology',
        source: 'The Body Keeps Score - Bessel van der Kolk',
        content: 'Comprehensive guide to understanding trauma, its effects on the brain, mind, and body, and evidence-based healing approaches. Covers PTSD, complex trauma, dissociation, and somatic approaches to healing.',
        techniques: ['Trauma Assessment', 'Somatic Experiencing', 'EMDR', 'Neurofeedback', 'Mindfulness-Based Trauma Therapy', 'Body-Based Healing', 'Trauma-Informed Care', 'Dissociation Treatment'],
        applications: ['Trauma Therapy', 'PTSD Treatment', 'Complex Trauma Healing', 'Somatic Psychology', 'Trauma-Informed Practice', 'Healing Modalities'],
        defenses: ['Trauma-Informed Care', 'Professional Training', 'Supervision', 'Self-Care', 'Boundary Setting'],
        keywords: ['trauma', 'ptsd', 'complex trauma', 'somatic healing', 'dissociation', 'body-based therapy', 'van der kolk', 'healing'],
        difficulty: 'expert',
        ethical_considerations: ['Trauma sensitivity', 'Professional competence', 'Informed consent', 'Safety planning', 'Cultural sensitivity'],
        lastUpdated: '2022-01-01'
      },

      // Comprehensive Dark Psychology Collection
      {
        id: 'dark-psychology-complete-collection',
        title: 'Complete Dark Psychology Collection - 30+ Books',
        type: 'dark_psychology',
        category: 'Comprehensive Dark Psychology',
        source: 'Complete Collection from docs/resources',
        content: 'Comprehensive collection of dark psychology techniques including mind control, manipulation, persuasion, body language reading, emotional intelligence exploitation, NLP manipulation, psychological warfare, gaslighting, and subliminal influence. Covers both offensive techniques and defensive strategies.',
        techniques: [
          'Psychological Manipulation', 'Mind Control', 'Coercion', 'Influence Tactics', 'Behavioral Modification',
          'Gaslighting', 'Reality Distortion', 'Emotional Manipulation', 'Cognitive Dissonance Exploitation',
          'Body Language Reading', 'Micro-expression Analysis', 'Nonverbal Manipulation', 'Proxemics Control',
          'NLP Manipulation', 'Linguistic Patterns', 'Anchoring', 'Reframing', 'Mirroring', 'Pacing and Leading',
          'Emotional Intelligence Exploitation', 'Empathy Manipulation', 'Social Skills Exploitation',
          'Subliminal Influence', 'Unconscious Persuasion', 'Covert Manipulation', 'Media Manipulation',
          'Psychological Warfare', 'Information Warfare', 'Social Engineering', 'Authority Exploitation'
        ],
        applications: [
          'Defense Against Manipulation', 'Awareness Training', 'Psychological Protection', 'Social Skills',
          'Deception Detection', 'Influence Recognition', 'Manipulation Prevention', 'Critical Thinking',
          'Emotional Regulation', 'Boundary Setting', 'Reality Testing', 'Social Support'
        ],
        defenses: [
          'Critical Thinking', 'Emotional Regulation', 'Social Support', 'Professional Help',
          'Reality Testing', 'Documentation', 'Boundary Setting', 'Awareness Training',
          'Media Literacy', 'Conscious Decision Making', 'Informed Consent', 'Ethical Guidelines'
        ],
        keywords: [
          'dark psychology', 'manipulation', 'mind control', 'persuasion', 'body language',
          'emotional intelligence', 'nlp', 'psychological warfare', 'gaslighting', 'subliminal',
          'influence', 'coercion', 'deception', 'social engineering', 'defense', 'awareness'
        ],
        difficulty: 'expert',
        ethical_considerations: [
          'Severe potential for psychological harm', 'Requires extensive ethical training',
          'Power dynamics and abuse potential', 'Informed consent critical',
          'Professional supervision recommended', 'Defensive use only',
          'Cultural sensitivity required', 'Legal implications'
        ],
        lastUpdated: '2022-01-01'
      },

      // Advanced Body Language and Micro-expressions
      {
        id: 'advanced-body-language',
        title: 'Advanced Body Language and Micro-expression Analysis',
        type: 'body_language',
        category: 'Advanced Nonverbal Communication',
        source: 'Multiple body language resources from docs/resources',
        content: 'Comprehensive guide to reading body language, micro-expressions, and nonverbal cues. Covers facial expressions, posture, gestures, eye contact, proxemics, and cultural variations in nonverbal communication.',
        techniques: [
          'Micro-expression Reading', 'Facial Action Coding System (FACS)', 'Posture Analysis',
          'Gesture Interpretation', 'Eye Contact Analysis', 'Proxemics Assessment',
          'Cultural Nonverbal Patterns', 'Deception Detection', 'Emotional State Reading',
          'Confidence Assessment', 'Dominance/Submission Signals', 'Attraction Indicators'
        ],
        applications: [
          'Communication Enhancement', 'Deception Detection', 'Social Skills Development',
          'Professional Development', 'Therapeutic Assessment', 'Security Screening',
          'Negotiation Skills', 'Leadership Development', 'Relationship Building'
        ],
        defenses: [
          'Awareness of Nonverbal Cues', 'Cultural Sensitivity', 'Context Consideration',
          'Professional Training', 'Ethical Guidelines', 'Informed Consent'
        ],
        keywords: [
          'body language', 'micro-expressions', 'nonverbal communication', 'facial expressions',
          'posture', 'gestures', 'eye contact', 'proxemics', 'deception detection',
          'cultural communication', 'social skills'
        ],
        difficulty: 'advanced',
        ethical_considerations: [
          'Privacy concerns', 'Cultural differences', 'Misinterpretation risks',
          'Consent for observation', 'Professional boundaries', 'Ethical use guidelines'
        ],
        lastUpdated: '2022-01-01'
      },

      // Comprehensive NLP and Persuasion
      {
        id: 'comprehensive-nlp-persuasion',
        title: 'Comprehensive NLP and Persuasion Techniques',
        type: 'nlp',
        category: 'Advanced NLP and Persuasion',
        source: 'Multiple NLP resources from docs/resources',
        content: 'Complete guide to Neuro-Linguistic Programming, persuasion techniques, and influence methods. Covers linguistic patterns, anchoring, reframing, meta-programs, and ethical applications of NLP.',
        techniques: [
          'Linguistic Patterns', 'Milton Model', 'Meta Model', 'Anchoring', 'Reframing',
          'Mirroring and Matching', 'Pacing and Leading', 'Meta-Programs', 'Submodalities',
          'Timeline Therapy', 'Parts Integration', 'Swish Pattern', 'Collapse Anchors',
          'Persuasion Patterns', 'Influence Techniques', 'Hypnotic Language'
        ],
        applications: [
          'Therapeutic Techniques', 'Communication Enhancement', 'Personal Development',
          'Professional Development', 'Coaching', 'Leadership', 'Sales and Marketing',
          'Conflict Resolution', 'Behavior Change', 'Goal Achievement'
        ],
        defenses: [
          'NLP Awareness', 'Critical Thinking', 'Ethical Guidelines', 'Professional Training',
          'Informed Consent', 'Therapeutic Boundaries', 'Self-Protection'
        ],
        keywords: [
          'nlp', 'neuro-linguistic programming', 'persuasion', 'linguistic patterns',
          'anchoring', 'reframing', 'mirroring', 'meta-programs', 'influence',
          'hypnotic language', 'therapeutic techniques'
        ],
        difficulty: 'expert',
        ethical_considerations: [
          'Potential for manipulation', 'Informed consent required', 'Therapeutic boundaries',
          'Professional ethics', 'Power dynamics', 'Cultural sensitivity'
        ],
        lastUpdated: '2022-01-01'
      },

      // Emotional Intelligence Mastery
      {
        id: 'emotional-intelligence-mastery-complete',
        title: 'Complete Emotional Intelligence Mastery',
        type: 'emotional_intelligence',
        category: 'Advanced Emotional Intelligence',
        source: 'Multiple EI resources from docs/resources',
        content: 'Comprehensive guide to emotional intelligence including self-awareness, self-regulation, motivation, empathy, and social skills. Covers both personal development and understanding others for various applications.',
        techniques: [
          'Emotional Awareness', 'Self-Regulation', 'Motivation Techniques', 'Empathy Development',
          'Social Skills', 'Emotional Intelligence Assessment', 'EI Coaching', 'Emotional Literacy',
          'Emotional Agility', 'Resilience Building', 'Stress Management', 'Conflict Resolution',
          'Leadership EI', 'Team Building', 'Cultural Intelligence'
        ],
        applications: [
          'Personal Development', 'Leadership Development', 'Relationship Building',
          'Professional Success', 'Therapeutic Practice', 'Coaching', 'Team Management',
          'Conflict Resolution', 'Stress Management', 'Career Development'
        ],
        defenses: [
          'Emotional Regulation', 'Self-Awareness', 'Social Support', 'Professional Development',
          'Mindfulness Practice', 'Therapeutic Support', 'Boundary Setting'
        ],
        keywords: [
          'emotional intelligence', 'self-awareness', 'self-regulation', 'empathy',
          'social skills', 'motivation', 'leadership', 'relationship building',
          'stress management', 'conflict resolution'
        ],
        difficulty: 'intermediate',
        ethical_considerations: [
          'Emotional manipulation potential', 'Privacy of emotions', 'Cultural sensitivity',
          'Professional boundaries', 'Informed consent', 'Therapeutic ethics'
        ],
        lastUpdated: '2022-01-01'
      },

      // Gaslighting and Psychological Abuse
      {
        id: 'gaslighting-psychological-abuse',
        title: 'Gaslighting and Psychological Abuse - Complete Guide',
        type: 'manipulation',
        category: 'Psychological Abuse',
        source: 'Multiple gaslighting resources from docs/resources',
        content: 'Comprehensive guide to understanding gaslighting, psychological abuse, and manipulation tactics. Covers detection, effects, and recovery strategies for victims and awareness training for prevention.',
        techniques: [
          'Gaslighting Detection', 'Reality Testing', 'Manipulation Recognition', 'Abuse Pattern Analysis',
          'Victim Support', 'Recovery Strategies', 'Boundary Setting', 'Safety Planning',
          'Trauma-Informed Care', 'Psychological First Aid', 'Support Group Facilitation'
        ],
        applications: [
          'Victim Support', 'Awareness Education', 'Prevention Training', 'Therapeutic Intervention',
          'Legal Support', 'Family Therapy', 'Community Education', 'Professional Training'
        ],
        defenses: [
          'Reality Testing', 'Documentation', 'Social Support', 'Professional Help',
          'Boundary Setting', 'Safety Planning', 'Trauma-Informed Care', 'Legal Protection'
        ],
        keywords: [
          'gaslighting', 'psychological abuse', 'manipulation', 'reality distortion',
          'victim support', 'recovery', 'boundary setting', 'safety planning',
          'trauma-informed care', 'prevention'
        ],
        difficulty: 'intermediate',
        ethical_considerations: [
          'Severe psychological harm potential', 'Power dynamics', 'Victim safety',
          'Professional intervention required', 'Legal implications', 'Cultural sensitivity'
        ],
        lastUpdated: '2022-01-01'
      }
    ];

    // Populate the knowledge database
    knowledgeData.forEach(resource => {
      this.knowledgeDatabase.set(resource.id, resource);
    });
  }

  private buildSearchIndex(): void {
    // Build comprehensive search index for fast retrieval
    this.knowledgeDatabase.forEach((resource, id) => {
      const searchTerms: string[] = [];
      
      // Add basic identifiers
      searchTerms.push(resource.title.toLowerCase());
      searchTerms.push(resource.type.toLowerCase());
      searchTerms.push(resource.category.toLowerCase());
      searchTerms.push(resource.source.toLowerCase());
      
      // Add content terms
      searchTerms.push(...resource.content.toLowerCase().split(/\s+/));
      
      // Add techniques
      resource.techniques.forEach(technique => {
        searchTerms.push(...technique.toLowerCase().split(/\s+/));
      });
      
      // Add applications
      resource.applications.forEach(application => {
        searchTerms.push(...application.toLowerCase().split(/\s+/));
      });
      
      // Add keywords
      resource.keywords.forEach(keyword => {
        searchTerms.push(...keyword.toLowerCase().split(/\s+/));
      });
      
      this.searchIndex.set(id, searchTerms);
    });
  }

  async queryKnowledgeBase(query: KnowledgeQuery): Promise<KnowledgeResult> {
    const startTime = Date.now();
    const queryLower = query.query.toLowerCase();
    const results: PsychologyResource[] = [];
    const matchedIds = new Set<string>();
    
    // Search through the index
    this.searchIndex.forEach((terms, id) => {
      const resource = this.knowledgeDatabase.get(id);
      if (!resource) return;
      
      // Filter by resource type if specified
      if (query.resourceType && query.resourceType !== 'all' && resource.type !== query.resourceType) {
        return;
      }
      
      // Filter by category if specified
      if (query.category && !resource.category.toLowerCase().includes(query.category.toLowerCase())) {
        return;
      }
      
      // Filter by difficulty if specified
      if (query.difficulty && query.difficulty !== 'all' && resource.difficulty !== query.difficulty) {
        return;
      }
      
      // Check for matches
      const queryWords = queryLower.split(/\s+/);
      let matchScore = 0;
      
      queryWords.forEach(word => {
        if (terms.includes(word)) {
          matchScore++;
        }
      });
      
      // If we have matches, add to results
      if (matchScore > 0) {
        matchedIds.add(id);
        results.push(resource);
      }
    });
    
    // Sort by relevance
    results.sort((a, b) => {
      const aScore = this.calculateRelevanceScore(a, queryLower);
      const bScore = this.calculateRelevanceScore(b, queryLower);
      return bScore - aScore;
    });
    
    // Limit results
    const maxResults = query.maxResults || (this.isMobile ? 5 : 10);
    const limitedResults = results.slice(0, maxResults);
    
    // Calculate confidence
    const confidence = this.calculateConfidence(limitedResults, query);
    
    // Generate suggestions
    const suggestions = this.generateSuggestions(query, limitedResults);
    
    // Add ethical warning for dark psychology queries
    const ethicalWarning = this.generateEthicalWarning(query, limitedResults);
    
    const processingTime = Date.now() - startTime;
    
    return {
      resources: limitedResults,
      confidence,
      query: query.query,
      processingTime,
      totalMatches: results.length,
      suggestions,
      ethical_warning: ethicalWarning
    };
  }

  private calculateRelevanceScore(resource: PsychologyResource, query: string): number {
    let score = 0;
    const queryWords = query.toLowerCase().split(/\s+/);
    
    // Exact title match
    if (resource.title.toLowerCase().includes(query.toLowerCase())) {
      score += 10;
    }
    
    // Category match
    if (resource.category.toLowerCase().includes(query.toLowerCase())) {
      score += 8;
    }
    
    // Type match
    if (resource.type.toLowerCase().includes(query.toLowerCase())) {
      score += 6;
    }
    
    // Content match
    queryWords.forEach(word => {
      if (resource.content.toLowerCase().includes(word)) {
        score += 3;
      }
    });
    
    // Keywords match
    resource.keywords.forEach(keyword => {
      queryWords.forEach(word => {
        if (keyword.toLowerCase().includes(word)) {
          score += 2;
        }
      });
    });
    
    return score;
  }

  private calculateConfidence(results: PsychologyResource[], query: KnowledgeQuery): number {
    if (results.length === 0) return 0;
    
    let confidence = Math.min(0.9, results.length * 0.1);
    
    // Boost confidence for exact matches
    const exactMatches = results.filter(r => 
      r.title.toLowerCase().includes(query.query.toLowerCase()) ||
      r.category.toLowerCase().includes(query.query.toLowerCase())
    );
    
    if (exactMatches.length > 0) {
      confidence += 0.1;
    }
    
    return Math.min(1.0, confidence);
  }

  private generateSuggestions(query: KnowledgeQuery, results: PsychologyResource[]): string[] {
    const suggestions: string[] = [];
    
    if (results.length === 0) {
      suggestions.push('Try broader search terms');
      suggestions.push('Check spelling of psychological terms');
      suggestions.push('Search by category (e.g., "dark psychology", "body language")');
    } else if (results.length < 3) {
      suggestions.push('Try related psychological categories');
      suggestions.push('Search for specific techniques or applications');
      suggestions.push('Include difficulty level in search');
    }
    
    // Add application-specific suggestions
    if (query.application === 'helping') {
      suggestions.push('Focus on therapeutic and defensive techniques');
      suggestions.push('Consider ethical guidelines and professional training');
    } else if (query.application === 'exploiting') {
      suggestions.push('⚠️ Ensure ethical use and informed consent');
      suggestions.push('Consider defensive applications and awareness training');
    }
    
    return suggestions.slice(0, 3);
  }

  private generateEthicalWarning(query: KnowledgeQuery, results: PsychologyResource[]): string | undefined {
    const darkPsychologyResults = results.filter(r => 
      r.type === 'dark_psychology' || 
      r.type === 'manipulation' ||
      r.title.toLowerCase().includes('dark psychology') ||
      r.title.toLowerCase().includes('manipulation')
    );
    
    if (darkPsychologyResults.length > 0) {
      return '⚠️ ETHICAL WARNING: Dark psychology and manipulation techniques should only be used for defensive purposes, awareness training, and protection against psychological abuse. Misuse can cause serious psychological harm. Always prioritize informed consent, ethical guidelines, and professional training.';
    }
    
    return undefined;
  }

  async getResourceById(id: string): Promise<PsychologyResource | null> {
    return this.knowledgeDatabase.get(id) || null;
  }

  async getResourcesByType(type: string): Promise<PsychologyResource[]> {
    const results: PsychologyResource[] = [];
    
    for (const [id, resource] of this.knowledgeDatabase) {
      if (resource.type === type) {
        results.push(resource);
      }
    }
    
    return results;
  }

  async getResourcesByCategory(category: string): Promise<PsychologyResource[]> {
    const results: PsychologyResource[] = [];
    const categoryLower = category.toLowerCase();
    
    for (const [id, resource] of this.knowledgeDatabase) {
      if (resource.category.toLowerCase().includes(categoryLower)) {
        results.push(resource);
      }
    }
    
    return results;
  }

  getKnowledgeBaseStats(): { 
    totalResources: number; 
    types: string[]; 
    categories: string[]; 
    totalTechniques: number;
    totalApplications: number;
    totalDefenses: number;
    comprehensive: boolean;
  } {
    const types = new Set<string>();
    const categories = new Set<string>();
    let totalTechniques = 0;
    let totalApplications = 0;
    let totalDefenses = 0;
    
    for (const [id, resource] of this.knowledgeDatabase) {
      types.add(resource.type);
      categories.add(resource.category);
      totalTechniques += resource.techniques.length;
      totalApplications += resource.applications.length;
      totalDefenses += resource.defenses.length;
    }
    
    return {
      totalResources: this.knowledgeDatabase.size,
      types: Array.from(types),
      categories: Array.from(categories),
      totalTechniques,
      totalApplications,
      totalDefenses,
      comprehensive: true // Self-contained knowledge base
    };
  }

  // Cross-platform optimizations
  isPlatformSupported(): boolean {
    return true; // Knowledge base works on all platforms
  }

  getPlatformSpecificFeatures(): string[] {
    const features = [
      'Comprehensive Psychology Knowledge Base',
      'DSM-V/ICD-11 Official Resources',
      'Dark Psychology and Manipulation Techniques',
      'Body Language and NLP Analysis',
      'Emotional Intelligence Resources',
      'Classical Psychology References',
      'Ethical Guidelines and Warnings',
      'Defense Strategies and Awareness Training'
    ];
    
    if (this.isMobile) {
      features.push('Mobile-Optimized Search', 'Reduced Result Sets');
    } else {
      features.push('Advanced Filtering', 'Detailed Analysis');
    }
    
    return features;
  }
}
