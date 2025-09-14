// Comprehensive DSM-V and ICD-10 diagnostic criteria database
// Extracted and structured from official diagnostic manuals
// DSM-V Diagnostic Criteria
export const DSM_V_CRITERIA = [
    {
        code: "296.20",
        name: "Major Depressive Disorder, Single Episode, Unspecified",
        description: "A mood disorder characterized by persistent sadness and loss of interest",
        system: "DSM-V",
        category: "Depressive Disorders",
        criteria: [
            "Five or more symptoms during a 2-week period",
            "At least one symptom is depressed mood or loss of interest/pleasure",
            "Symptoms cause clinically significant distress or impairment"
        ],
        indicators: ["depressed_mood", "anhedonia", "weight_change", "sleep_disturbance", "psychomotor_agitation", "fatigue", "worthlessness", "concentration_problems", "suicidal_ideation"],
        severityLevels: ["Mild", "Moderate", "Severe"],
        specifiers: ["With anxious distress", "With melancholic features", "With atypical features"]
    },
    {
        code: "296.33",
        name: "Major Depressive Disorder, Recurrent Episode, Severe",
        description: "Recurrent episodes of major depression with severe symptoms",
        system: "DSM-V",
        category: "Depressive Disorders",
        criteria: [
            "Two or more major depressive episodes",
            "Severe symptoms causing marked impairment",
            "No manic or hypomanic episodes"
        ],
        indicators: ["depressed_mood", "anhedonia", "weight_change", "sleep_disturbance", "psychomotor_agitation", "fatigue", "worthlessness", "concentration_problems", "suicidal_ideation"],
        severityLevels: ["Severe"],
        specifiers: ["With psychotic features", "With catatonia"]
    },
    {
        code: "300.02",
        name: "Generalized Anxiety Disorder",
        description: "Excessive anxiety and worry about multiple events or activities",
        system: "DSM-V",
        category: "Anxiety Disorders",
        criteria: [
            "Excessive anxiety and worry occurring more days than not for at least 6 months",
            "Difficulty controlling the worry",
            "Anxiety and worry associated with three or more symptoms"
        ],
        indicators: ["excessive_worry", "restlessness", "fatigue", "concentration_difficulty", "irritability", "muscle_tension", "sleep_disturbance"],
        severityLevels: ["Mild", "Moderate", "Severe"]
    },
    {
        code: "300.01",
        name: "Panic Disorder",
        description: "Recurrent unexpected panic attacks with persistent concern",
        system: "DSM-V",
        category: "Anxiety Disorders",
        criteria: [
            "Recurrent unexpected panic attacks",
            "At least one attack followed by persistent concern about additional attacks",
            "Significant maladaptive change in behavior related to attacks"
        ],
        indicators: ["panic_attacks", "fear_of_attacks", "avoidance_behavior", "palpitations", "sweating", "trembling", "shortness_of_breath", "chest_pain", "nausea", "dizziness"],
        severityLevels: ["Mild", "Moderate", "Severe"]
    },
    {
        code: "309.81",
        name: "Posttraumatic Stress Disorder",
        description: "Development of characteristic symptoms following exposure to traumatic event",
        system: "DSM-V",
        category: "Trauma- and Stressor-Related Disorders",
        criteria: [
            "Exposure to actual or threatened death, serious injury, or sexual violence",
            "Presence of intrusion symptoms",
            "Persistent avoidance of stimuli associated with trauma",
            "Negative alterations in cognitions and mood",
            "Marked alterations in arousal and reactivity"
        ],
        indicators: ["trauma_exposure", "intrusive_thoughts", "nightmares", "flashbacks", "avoidance", "negative_emotions", "hypervigilance", "startle_response", "sleep_disturbance"],
        severityLevels: ["Mild", "Moderate", "Severe"],
        specifiers: ["With dissociative symptoms", "With delayed expression"]
    },
    {
        code: "295.90",
        name: "Schizophrenia",
        description: "Psychotic disorder with characteristic symptoms",
        system: "DSM-V",
        category: "Schizophrenia Spectrum and Other Psychotic Disorders",
        criteria: [
            "Two or more of: delusions, hallucinations, disorganized speech, grossly disorganized behavior, negative symptoms",
            "Continuous signs of disturbance for at least 6 months",
            "Significant social/occupational dysfunction"
        ],
        indicators: ["delusions", "hallucinations", "disorganized_speech", "disorganized_behavior", "negative_symptoms", "social_dysfunction"],
        severityLevels: ["First episode", "Multiple episodes", "Continuous"],
        specifiers: ["With catatonia"]
    },
    {
        code: "296.89",
        name: "Bipolar II Disorder",
        description: "Pattern of depressive episodes and hypomanic episodes",
        system: "DSM-V",
        category: "Bipolar and Related Disorders",
        criteria: [
            "At least one major depressive episode",
            "At least one hypomanic episode",
            "No manic episodes"
        ],
        indicators: ["depressed_mood", "elevated_mood", "increased_energy", "decreased_need_for_sleep", "grandiosity", "racing_thoughts", "distractibility", "increased_activity"],
        severityLevels: ["Mild", "Moderate", "Severe"],
        specifiers: ["With rapid cycling", "With seasonal pattern"]
    },
    {
        code: "301.83",
        name: "Borderline Personality Disorder",
        description: "Pattern of instability in interpersonal relationships, self-image, and affects",
        system: "DSM-V",
        category: "Personality Disorders",
        criteria: [
            "Pattern of instability in interpersonal relationships, self-image, and affects",
            "Marked impulsivity beginning by early adulthood",
            "Five or more specific criteria"
        ],
        indicators: ["fear_of_abandonment", "unstable_relationships", "identity_disturbance", "impulsivity", "suicidal_behavior", "affective_instability", "chronic_emptiness", "anger_problems", "paranoid_ideation"],
        severityLevels: ["Mild", "Moderate", "Severe"]
    },
    {
        code: "301.7",
        name: "Antisocial Personality Disorder",
        description: "Pattern of disregard for and violation of rights of others",
        system: "DSM-V",
        category: "Personality Disorders",
        criteria: [
            "Pattern of disregard for and violation of rights of others since age 15",
            "Individual is at least 18 years old",
            "Evidence of conduct disorder before age 15"
        ],
        indicators: ["law_violations", "deceitfulness", "impulsivity", "irritability", "recklessness", "irresponsibility", "lack_of_remorse"],
        severityLevels: ["Mild", "Moderate", "Severe"]
    },
    {
        code: "307.1",
        name: "Anorexia Nervosa",
        description: "Restriction of energy intake leading to significantly low body weight",
        system: "DSM-V",
        category: "Feeding and Eating Disorders",
        criteria: [
            "Restriction of energy intake relative to requirements",
            "Intense fear of gaining weight or becoming fat",
            "Disturbance in the way body weight or shape is experienced"
        ],
        indicators: ["weight_loss", "fear_of_weight_gain", "body_image_distortion", "restrictive_eating", "excessive_exercise", "amenorrhea"],
        severityLevels: ["Mild", "Moderate", "Severe", "Extreme"],
        specifiers: ["Restricting type", "Binge-eating/purging type"]
    }
];
// ICD-10 Diagnostic Criteria
export const ICD_10_CRITERIA = [
    {
        code: "F32.9",
        name: "Major depressive disorder, single episode, unspecified",
        description: "Single episode of major depression",
        system: "ICD-10",
        category: "Mood [affective] disorders",
        criteria: [
            "Depressed mood most of the day",
            "Markedly diminished interest or pleasure",
            "Significant weight loss or gain",
            "Insomnia or hypersomnia",
            "Psychomotor agitation or retardation",
            "Fatigue or loss of energy",
            "Feelings of worthlessness or guilt",
            "Diminished ability to think or concentrate",
            "Recurrent thoughts of death"
        ],
        indicators: ["depressed_mood", "anhedonia", "weight_change", "sleep_disturbance", "psychomotor_agitation", "fatigue", "worthlessness", "concentration_problems", "suicidal_ideation"]
    },
    {
        code: "F33.9",
        name: "Major depressive disorder, recurrent, unspecified",
        description: "Recurrent episodes of major depression",
        system: "ICD-10",
        category: "Mood [affective] disorders",
        criteria: [
            "Two or more major depressive episodes",
            "No manic or hypomanic episodes",
            "Episodes separated by at least 2 months"
        ],
        indicators: ["depressed_mood", "anhedonia", "weight_change", "sleep_disturbance", "psychomotor_agitation", "fatigue", "worthlessness", "concentration_problems", "suicidal_ideation"]
    },
    {
        code: "F41.1",
        name: "Generalized anxiety disorder",
        description: "Chronic anxiety disorder with excessive worry",
        system: "ICD-10",
        category: "Neurotic, stress-related and somatoform disorders",
        criteria: [
            "Excessive anxiety and worry for at least 6 months",
            "Difficulty controlling worry",
            "Associated physical symptoms"
        ],
        indicators: ["excessive_worry", "restlessness", "fatigue", "concentration_difficulty", "irritability", "muscle_tension", "sleep_disturbance"]
    },
    {
        code: "F41.0",
        name: "Panic disorder [episodic paroxysmal anxiety]",
        description: "Recurrent panic attacks with persistent concern",
        system: "ICD-10",
        category: "Neurotic, stress-related and somatoform disorders",
        criteria: [
            "Recurrent unexpected panic attacks",
            "Persistent concern about additional attacks",
            "Significant behavioral change"
        ],
        indicators: ["panic_attacks", "fear_of_attacks", "avoidance_behavior", "palpitations", "sweating", "trembling", "shortness_of_breath", "chest_pain", "nausea", "dizziness"]
    },
    {
        code: "F43.10",
        name: "Post-traumatic stress disorder, unspecified",
        description: "Development of symptoms following traumatic exposure",
        system: "ICD-10",
        category: "Neurotic, stress-related and somatoform disorders",
        criteria: [
            "Exposure to traumatic event",
            "Intrusion symptoms",
            "Avoidance symptoms",
            "Negative alterations in cognitions and mood",
            "Alterations in arousal and reactivity"
        ],
        indicators: ["trauma_exposure", "intrusive_thoughts", "nightmares", "flashbacks", "avoidance", "negative_emotions", "hypervigilance", "startle_response", "sleep_disturbance"]
    },
    {
        code: "F20.9",
        name: "Schizophrenia, unspecified",
        description: "Psychotic disorder with characteristic symptoms",
        system: "ICD-10",
        category: "Schizophrenia, schizotypal and delusional disorders",
        criteria: [
            "Characteristic psychotic symptoms",
            "Duration of at least 1 month",
            "Social/occupational dysfunction"
        ],
        indicators: ["delusions", "hallucinations", "disorganized_speech", "disorganized_behavior", "negative_symptoms", "social_dysfunction"]
    },
    {
        code: "F31.9",
        name: "Bipolar affective disorder, unspecified",
        description: "Episodes of mania and depression",
        system: "ICD-10",
        category: "Mood [affective] disorders",
        criteria: [
            "Episodes of mania or hypomania",
            "Episodes of depression",
            "No organic cause"
        ],
        indicators: ["depressed_mood", "elevated_mood", "increased_energy", "decreased_need_for_sleep", "grandiosity", "racing_thoughts", "distractibility", "increased_activity"]
    },
    {
        code: "F60.3",
        name: "Emotionally unstable personality disorder",
        description: "Borderline personality disorder",
        system: "ICD-10",
        category: "Disorders of adult personality and behaviour",
        criteria: [
            "Pattern of instability in relationships",
            "Identity disturbance",
            "Impulsivity",
            "Affective instability"
        ],
        indicators: ["fear_of_abandonment", "unstable_relationships", "identity_disturbance", "impulsivity", "suicidal_behavior", "affective_instability", "chronic_emptiness", "anger_problems", "paranoid_ideation"]
    },
    {
        code: "F60.2",
        name: "Dissocial personality disorder",
        description: "Antisocial personality disorder",
        system: "ICD-10",
        category: "Disorders of adult personality and behaviour",
        criteria: [
            "Disregard for rights of others",
            "Deceitfulness",
            "Impulsivity",
            "Irritability and aggressiveness",
            "Reckless disregard for safety",
            "Consistent irresponsibility",
            "Lack of remorse"
        ],
        indicators: ["law_violations", "deceitfulness", "impulsivity", "irritability", "recklessness", "irresponsibility", "lack_of_remorse"]
    },
    {
        code: "F50.0",
        name: "Anorexia nervosa",
        description: "Eating disorder with weight loss",
        system: "ICD-10",
        category: "Behavioural syndromes associated with physiological disturbances and physical factors",
        criteria: [
            "Weight loss or failure to gain weight",
            "Distorted body image",
            "Intense fear of gaining weight",
            "Amenorrhea in females"
        ],
        indicators: ["weight_loss", "fear_of_weight_gain", "body_image_distortion", "restrictive_eating", "excessive_exercise", "amenorrhea"]
    }
];
// Psychological markers for text analysis
export const PSYCHOLOGICAL_MARKERS = [
    {
        name: "depressed_mood",
        keywords: ["sad", "depressed", "down", "blue", "hopeless", "empty", "miserable", "gloomy", "despair", "melancholy", "dejected", "sorrowful", "grief", "mourning", "bereaved"],
        weight: 0.9,
        category: "mood"
    },
    {
        name: "anhedonia",
        keywords: ["no pleasure", "can't enjoy", "nothing interests", "bored", "uninterested", "apathetic", "indifferent", "numb", "empty", "hollow", "lifeless"],
        weight: 0.8,
        category: "mood"
    },
    {
        name: "suicidal_ideation",
        keywords: ["suicide", "kill myself", "end it all", "not worth living", "better off dead", "want to die", "end my life", "self harm", "cut myself", "overdose", "jump", "hang myself"],
        weight: 1.0,
        category: "safety"
    },
    {
        name: "worthlessness",
        keywords: ["worthless", "useless", "failure", "loser", "pathetic", "disgusting", "hate myself", "stupid", "ugly", "unlovable", "burden", "waste of space"],
        weight: 0.8,
        category: "cognition"
    },
    {
        name: "guilt",
        keywords: ["guilty", "blame myself", "my fault", "should have", "could have", "responsible", "ashamed", "regret", "remorse", "self-blame"],
        weight: 0.7,
        category: "cognition"
    },
    {
        name: "excessive_worry",
        keywords: ["worry", "anxious", "nervous", "concerned", "fearful", "scared", "panic", "overwhelmed", "stressed", "tense", "on edge", "worried sick"],
        weight: 0.8,
        category: "anxiety"
    },
    {
        name: "panic_attacks",
        keywords: ["panic attack", "can't breathe", "heart racing", "chest pain", "dizzy", "sweating", "trembling", "shaking", "losing control", "going crazy", "dying"],
        weight: 0.9,
        category: "anxiety"
    },
    {
        name: "trauma_exposure",
        keywords: ["trauma", "abuse", "assault", "rape", "violence", "accident", "death", "war", "disaster", "attack", "threatened", "hurt", "injured"],
        weight: 0.9,
        category: "trauma"
    },
    {
        name: "intrusive_thoughts",
        keywords: ["can't stop thinking", "flashbacks", "nightmares", "memories", "intrusive", "unwanted thoughts", "replaying", "haunted", "can't forget"],
        weight: 0.8,
        category: "trauma"
    },
    {
        name: "avoidance",
        keywords: ["avoid", "stay away", "hide", "isolate", "withdraw", "escape", "run away", "don't want to", "can't face", "scared of"],
        weight: 0.7,
        category: "behavior"
    },
    {
        name: "hypervigilance",
        keywords: ["on guard", "watchful", "alert", "scanning", "checking", "paranoid", "suspicious", "danger", "threat", "unsafe", "vulnerable"],
        weight: 0.7,
        category: "arousal"
    },
    {
        name: "sleep_disturbance",
        keywords: ["can't sleep", "insomnia", "tired", "exhausted", "fatigue", "sleeping too much", "nightmares", "restless", "wake up", "early morning"],
        weight: 0.6,
        category: "physical"
    },
    {
        name: "concentration_problems",
        keywords: ["can't concentrate", "focus", "attention", "distracted", "mind wandering", "forgetful", "memory problems", "brain fog", "confused"],
        weight: 0.6,
        category: "cognition"
    },
    {
        name: "irritability",
        keywords: ["irritable", "angry", "rage", "frustrated", "annoyed", "snappy", "short tempered", "losing it", "explosive", "hostile"],
        weight: 0.7,
        category: "mood"
    },
    {
        name: "impulsivity",
        keywords: ["impulsive", "act without thinking", "rash", "reckless", "spontaneous", "out of control", "can't stop", "compulsive", "addictive"],
        weight: 0.7,
        category: "behavior"
    },
    {
        name: "delusions",
        keywords: ["they're watching", "conspiracy", "government", "aliens", "mind control", "special powers", "chosen one", "persecuted", "paranoid"],
        weight: 0.9,
        category: "psychosis"
    },
    {
        name: "hallucinations",
        keywords: ["hear voices", "see things", "voices talking", "someone calling", "shadows", "figures", "sounds", "visual", "auditory"],
        weight: 0.9,
        category: "psychosis"
    },
    {
        name: "elevated_mood",
        keywords: ["euphoric", "high", "manic", "energetic", "invincible", "special", "powerful", "unstoppable", "brilliant", "creative"],
        weight: 0.8,
        category: "mood"
    },
    {
        name: "racing_thoughts",
        keywords: ["racing thoughts", "mind racing", "thoughts flying", "can't slow down", "overwhelming", "too fast", "jumping", "scattered"],
        weight: 0.8,
        category: "cognition"
    },
    {
        name: "grandiosity",
        keywords: ["special", "chosen", "famous", "rich", "powerful", "genius", "superior", "better than", "above others", "destined"],
        weight: 0.8,
        category: "cognition"
    }
];
// Combined diagnostic criteria
export const ALL_DIAGNOSTIC_CRITERIA = [...DSM_V_CRITERIA, ...ICD_10_CRITERIA];
// Crisis severity levels
export const CRISIS_SEVERITY = {
    LOW: { threshold: 0.3, description: "Mild symptoms, self-care recommended" },
    MODERATE: { threshold: 0.6, description: "Moderate symptoms, professional help recommended" },
    HIGH: { threshold: 0.8, description: "Severe symptoms, immediate professional intervention needed" },
    CRITICAL: { threshold: 0.9, description: "Crisis level, emergency intervention required" }
};
