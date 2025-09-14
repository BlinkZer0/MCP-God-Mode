# 🧠 Psychology Tool - Comprehensive Documentation

## Overview

The Psychology Tool is a unified, comprehensive psychological analysis and knowledge base system that combines DSM-V/ICD-11 diagnostic criteria, extensive dark psychology techniques, body language analysis, NLP methods, emotional intelligence assessment, and security awareness capabilities. The tool is completely self-contained with no external file dependencies.

## Version: 2.0a

## Features

### 🎯 Core Capabilities
- **Unified Tool Architecture**: Single tool with 14 different action types
- **Self-Contained Knowledge Base**: No external files required - all information absorbed
- **Cross-Platform Support**: Works on Windows, Linux, macOS, Android, iOS
- **Ethical Framework**: Built-in warnings and defensive focus
- **Comprehensive Coverage**: 16 major resources with 139 techniques, 95 applications, 86 defenses

### 📚 Knowledge Base Resources

#### Official Diagnostic Resources
- **DSM-V Complete**: All diagnostic criteria, specifiers, and severity ratings
- **ICD-11 International**: Global health framework and classifications
- **Evidence-Based**: Treatment guidelines and research-backed approaches

#### Dark Psychology Collection (30+ Books Absorbed)
- **Mind Control & Manipulation**: Psychological manipulation, coercion, influence tactics
- **Gaslighting & Psychological Abuse**: Reality distortion, emotional manipulation
- **Subliminal Influence**: Unconscious persuasion, covert manipulation
- **Psychological Warfare**: Information warfare, social engineering

#### Specialized Psychology Areas
- **The Body Keeps Score**: Trauma psychology, somatic healing, PTSD treatment
- **Body Language & Micro-expressions**: Nonverbal communication, deception detection
- **NLP & Persuasion**: Neuro-linguistic programming, linguistic patterns, anchoring
- **Emotional Intelligence**: Self-awareness, empathy, social skills, leadership
- **Classical Psychology**: Machiavelli's Art of War, historical strategy

## Tool Actions

### 1. `analyze_text`
**Purpose**: Comprehensive psychological analysis of text samples
**Parameters**:
- `textSamples`: Array of text samples (journal entries, social media posts, emails)
- `location`: Location for finding local resources
- `mode`: 'support' (therapeutic) or 'security_awareness' (educational)
- `searchRadius`: Search radius in miles for local resources
- `includeEmergencyResources`: Include emergency mental health resources
- `includeSupportGroups`: Include local support groups
- `detailedAnalysis`: Provide detailed analysis with confidence scores
- `includeRAGReference`: Include DSM-V/ICD-11 references

**Example**:
```json
{
  "action": "analyze_text",
  "textSamples": ["I feel sad and hopeless", "Nothing seems to matter anymore"],
  "location": "New York, NY",
  "mode": "support",
  "detailedAnalysis": true
}
```

### 2. `diagnostic_reference`
**Purpose**: Lookup DSM-V/ICD-11 diagnostic criteria
**Parameters**:
- `searchType`: 'code', 'name', 'category', or 'symptoms'
- `searchValue`: Value to search for
- `system`: 'DSM-5', 'ICD-10', 'ICD-11', or 'all'
- `includeComorbidities`: Include comorbid conditions
- `includeTreatment`: Include treatment guidelines

**Example**:
```json
{
  "action": "diagnostic_reference",
  "searchType": "code",
  "searchValue": "F32.9",
  "system": "ICD-10"
}
```

### 3. `natural_language`
**Purpose**: Conversational interface for psychology operations
**Parameters**:
- `command`: Natural language command
- `platform`: Target platform (auto-detected if not specified)

**Example**:
```json
{
  "action": "natural_language",
  "command": "Analyze this text for signs of depression"
}
```

### 4. `platform_info`
**Purpose**: Get platform-specific capabilities and optimizations
**Parameters**:
- `platform`: Platform to check (auto-detected if not specified)

**Example**:
```json
{
  "action": "platform_info"
}
```

### 5. `rag_query`
**Purpose**: Search diagnostic database using RAG system
**Parameters**:
- `query`: Search query for diagnostic criteria
- `system`: Diagnostic system to search
- `category`: Specific diagnostic category
- `severity`: Severity level
- `maxResults`: Maximum number of results
- `includeCriteria`: Include diagnostic criteria
- `includeTreatment`: Include treatment guidelines

**Example**:
```json
{
  "action": "rag_query",
  "query": "anxiety symptoms",
  "system": "DSM-5",
  "maxResults": 5
}
```

### 6. `crisis_check`
**Purpose**: Emergency crisis assessment and intervention
**Parameters**:
- `textSamples`: Text samples to analyze for crisis indicators

**Example**:
```json
{
  "action": "crisis_check",
  "textSamples": ["I want to hurt myself", "Life isn't worth living"]
}
```

### 7. `security_assessment`
**Purpose**: Security awareness and exploitation vector analysis
**Parameters**:
- `textSamples`: Text samples to analyze
- `location`: Location for context

**Example**:
```json
{
  "action": "security_assessment",
  "textSamples": ["I feel vulnerable", "I trust everyone"],
  "mode": "security_awareness"
}
```

### 8. `knowledge_base_query`
**Purpose**: Search comprehensive psychology resources
**Parameters**:
- `query`: Search query
- `resourceType`: 'diagnostic', 'dark_psychology', 'manipulation', 'body_language', 'nlp', 'emotional_intelligence', 'classical', or 'all'
- `category`: Specific category
- `difficulty`: 'beginner', 'intermediate', 'advanced', 'expert', or 'all'
- `application`: 'helping', 'exploiting', 'defense', or 'all'
- `maxResults`: Maximum number of results

**Example**:
```json
{
  "action": "knowledge_base_query",
  "query": "body keeps score trauma healing",
  "resourceType": "diagnostic",
  "application": "helping"
}
```

### 9. `dark_psychology_analysis`
**Purpose**: Dark psychology techniques and defenses
**Parameters**:
- `textSamples`: Text samples to analyze
- `query`: Specific query about dark psychology techniques
- `application`: Default to 'defense' for protective use

**Example**:
```json
{
  "action": "dark_psychology_analysis",
  "query": "manipulation techniques",
  "application": "defense"
}
```

### 10. `manipulation_detection`
**Purpose**: Detect manipulation attempts
**Parameters**:
- `textSamples`: Text samples to analyze
- `query`: Specific query about manipulation

**Example**:
```json
{
  "action": "manipulation_detection",
  "textSamples": ["You're overreacting", "That never happened"]
}
```

### 11. `body_language_analysis`
**Purpose**: Nonverbal communication analysis
**Parameters**:
- `textSamples`: Text samples to analyze
- `query`: Specific query about body language

**Example**:
```json
{
  "action": "body_language_analysis",
  "query": "micro-expressions deception detection"
}
```

### 12. `nlp_techniques`
**Purpose**: Neuro-linguistic programming methods
**Parameters**:
- `textSamples`: Text samples to analyze
- `query`: Specific query about NLP techniques

**Example**:
```json
{
  "action": "nlp_techniques",
  "query": "linguistic patterns persuasion"
}
```

### 13. `emotional_intelligence_assessment`
**Purpose**: Emotional intelligence analysis
**Parameters**:
- `textSamples`: Text samples to analyze
- `query`: Specific query about emotional intelligence

**Example**:
```json
{
  "action": "emotional_intelligence_assessment",
  "query": "empathy social skills development"
}
```

### 14. `knowledge_base_stats`
**Purpose**: Get comprehensive knowledge base statistics
**Parameters**: None required

**Example**:
```json
{
  "action": "knowledge_base_stats"
}
```

## Knowledge Base Statistics

### Current Stats (Version 2.0a)
- **Total Resources**: 16 comprehensive psychology resources
- **Total Techniques**: 139 psychological techniques and methods
- **Total Applications**: 95 practical applications
- **Total Defenses**: 86 defensive strategies
- **Resource Types**: 7 categories
- **Categories**: 15 specialized areas
- **Self-Contained**: ✅ No external files required
- **Comprehensive**: ✅ All information absorbed

### Resource Types
1. **diagnostic**: Official diagnostic criteria and classifications
2. **dark_psychology**: Manipulation, mind control, psychological warfare
3. **manipulation**: Gaslighting, psychological abuse, influence tactics
4. **body_language**: Nonverbal communication, micro-expressions
5. **nlp**: Neuro-linguistic programming, persuasion techniques
6. **emotional_intelligence**: Self-awareness, empathy, social skills
7. **classical**: Historical psychology and strategy texts

### Categories
- Official Diagnostic Criteria
- International Classification
- Mind Control
- Comprehensive Dark Psychology
- Nonverbal Communication
- Neuro-Linguistic Programming
- Emotional Intelligence
- Psychological Manipulation
- Classical Strategy
- Subliminal Influence
- Trauma Psychology
- Advanced Nonverbal Communication
- Advanced NLP and Persuasion
- Advanced Emotional Intelligence
- Psychological Abuse

## Ethical Framework

### Built-in Protections
- **Automatic Warnings**: For dark psychology and manipulation content
- **Defensive Focus**: Default to protective applications
- **Professional Guidelines**: Emphasis on ethical use
- **Informed Consent**: Critical for all applications
- **Cultural Sensitivity**: Required for all techniques

### Ethical Considerations
- **Severe Potential for Psychological Harm**: Dark psychology techniques
- **Requires Extensive Ethical Training**: Professional competence
- **Power Dynamics and Abuse Potential**: Informed consent critical
- **Professional Supervision Recommended**: Defensive use only
- **Cultural Sensitivity Required**: Legal implications

## Cross-Platform Support

### Platform Optimizations
- **Mobile**: Reduced result sets, optimized UI, battery efficiency
- **Desktop**: Full feature set, advanced filtering, detailed reporting
- **All Platforms**: Natural language processing, RAG system, local resources

### Platform-Specific Features
- **Windows/Linux/macOS**: Full diagnostic database, advanced search
- **Android/iOS**: Mobile-optimized interface, reduced data usage
- **Universal**: Crisis intervention, security awareness, local resources

## Technical Implementation

### Architecture
- **Unified Tool**: Single tool with multiple action types
- **Self-Contained**: No external file dependencies
- **Modular Design**: Separate components for different functionalities
- **Cross-Platform**: Environment-aware optimizations

### Components
- **MentalHealthAnalyzer**: Core psychological analysis engine
- **ResourceLocator**: Local resource search and management
- **SecurityAwarenessFramework**: Exploitation vector analysis
- **PsychologyRAGSystem**: Diagnostic reference system
- **PsychologyKnowledgeBase**: Comprehensive knowledge base
- **MentalHealthNaturalLanguageProcessor**: Natural language interface

### Performance
- **Fast Retrieval**: Optimized search algorithms with indexing
- **Confidence Scoring**: Relevance and accuracy metrics
- **Mobile Optimized**: Reduced data usage and result sets
- **Cross-Platform**: Works on all devices and operating systems

## Usage Examples

### Basic Text Analysis
```json
{
  "action": "analyze_text",
  "textSamples": ["I feel anxious and worried"],
  "mode": "support",
  "detailedAnalysis": true
}
```

### Diagnostic Reference
```json
{
  "action": "diagnostic_reference",
  "searchType": "symptoms",
  "searchValue": "anxiety panic attacks",
  "system": "DSM-5"
}
```

### Knowledge Base Search
```json
{
  "action": "knowledge_base_query",
  "query": "trauma healing somatic experiencing",
  "resourceType": "diagnostic",
  "application": "helping"
}
```

### Dark Psychology Analysis (Defensive)
```json
{
  "action": "dark_psychology_analysis",
  "query": "manipulation detection techniques",
  "application": "defense"
}
```

### Crisis Assessment
```json
{
  "action": "crisis_check",
  "textSamples": ["I want to hurt myself"]
}
```

## Security and Privacy

### Data Protection
- **No External Dependencies**: All data self-contained
- **Local Processing**: No data sent to external services
- **Privacy Focused**: Text samples processed locally
- **Secure Implementation**: Built-in security measures

### Ethical Use
- **Educational Purpose**: Primarily for awareness and defense
- **Professional Training**: Requires proper education
- **Informed Consent**: Critical for all applications
- **Legal Compliance**: Follows applicable laws and regulations

## Version History

### Version 2.0a (Current)
- **Unified Tool Architecture**: Single tool with 14 action types
- **Self-Contained Knowledge Base**: No external file dependencies
- **Comprehensive Coverage**: 16 resources, 139 techniques, 95 applications, 86 defenses
- **Enhanced Ethical Framework**: Built-in warnings and defensive focus
- **Cross-Platform Optimization**: Mobile and desktop optimizations
- **"The Body Keeps Score" Integration**: Trauma psychology resource
- **Advanced Search**: Semantic search with confidence scoring

### Previous Versions
- **Version 1.0**: Initial mental health tool implementation
- **Version 1.5**: Added RAG system and natural language interface
- **Version 2.0**: Reorganized under psychology umbrella with knowledge base

## Support and Maintenance

### Documentation
- **Comprehensive README**: This documentation file
- **Code Comments**: Extensive inline documentation
- **API Documentation**: Detailed parameter descriptions
- **Usage Examples**: Practical implementation examples

### Maintenance
- **Self-Contained**: No external file maintenance required
- **Version Control**: Tracked in git repository
- **Cross-Platform Testing**: Verified on all supported platforms
- **Ethical Review**: Regular ethical framework updates

## Conclusion

The Psychology Tool (Version 2.0a) represents a comprehensive, self-contained psychological analysis and knowledge base system that combines official diagnostic criteria, extensive dark psychology techniques, and specialized psychology areas into a unified, cross-platform tool. With 14 different action types, 139 techniques, and built-in ethical protections, it provides both helping and defensive applications while maintaining the highest standards of professional ethics and cultural sensitivity.

The tool is completely self-contained with no external file dependencies, making it reliable and secure for use across all platforms and environments.
