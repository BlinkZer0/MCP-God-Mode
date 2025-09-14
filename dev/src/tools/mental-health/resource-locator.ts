import { DiagnosticMatch } from './analyzer.js';
import { PLATFORM, IS_MOBILE } from '../../config/environment.js';

export interface LocalResource {
  id: string;
  name: string;
  type: 'crisis_hotline' | 'therapist' | 'psychiatrist' | 'support_group' | 'emergency_room' | 'crisis_center';
  address: string;
  city: string;
  state: string;
  zipCode: string;
  phone: string;
  email?: string;
  website?: string;
  specialties: string[];
  insuranceAccepted: string[];
  languages: string[];
  hours: string;
  description: string;
  distance?: number;
  rating?: number;
  cost?: string;
  accessibility?: string[];
}

export interface CrisisResource {
  name: string;
  phone: string;
  text?: string;
  chat?: string;
  description: string;
  available24_7: boolean;
  specializedFor: string[];
}

export interface ResourceSearchResult {
  crisisResources: CrisisResource[];
  localResources: LocalResource[];
  emergencyResources: LocalResource[];
  supportGroups: LocalResource[];
  totalFound: number;
  searchRadius: number;
  lastUpdated: string;
}

export class ResourceLocator {
  private crisisHotlines: CrisisResource[];
  private therapists: LocalResource[];
  private psychiatrists: LocalResource[];
  private supportGroups: LocalResource[];
  private emergencyResources: LocalResource[];
  private platform: string;
  private isMobile: boolean;

  constructor() {
    this.platform = PLATFORM;
    this.isMobile = IS_MOBILE;
    this.initializeCrisisResources();
    this.initializeTherapists();
    this.initializePsychiatrists();
    this.initializeSupportGroups();
    this.initializeEmergencyResources();
  }

  async findLocalResources(
    location: string, 
    diagnoses: DiagnosticMatch[], 
    searchRadius: number = 25
  ): Promise<ResourceSearchResult> {
    const locationData = this.parseLocation(location);
    const specialties = this.extractSpecialties(diagnoses);
    
    // Find crisis resources (always available)
    const crisisResources = this.getCrisisResources(diagnoses);
    
    // Find local resources within radius
    const localResources = this.findResourcesInRadius(locationData, specialties, searchRadius);
    
    // Find emergency resources
    const emergencyResources = this.findEmergencyResources(locationData, searchRadius);
    
    // Find support groups
    const supportGroups = this.findSupportGroups(locationData, specialties, searchRadius);

    return {
      crisisResources,
      localResources,
      emergencyResources,
      supportGroups,
      totalFound: localResources.length + emergencyResources.length + supportGroups.length,
      searchRadius,
      lastUpdated: new Date().toISOString()
    };
  }

  private parseLocation(location: string): { city: string; state: string; zipCode?: string } {
    // Simple location parsing - in production, use a geocoding service
    const parts = location.split(',').map(p => p.trim());
    
    if (parts.length >= 2) {
      return {
        city: parts[0],
        state: parts[1],
        zipCode: parts[2] || undefined
      };
    } else if (/^\d{5}(-\d{4})?$/.test(location)) {
      return {
        city: '',
        state: '',
        zipCode: location
      };
    } else {
      return {
        city: location,
        state: '',
        zipCode: undefined
      };
    }
  }

  private extractSpecialties(diagnoses: DiagnosticMatch[]): string[] {
    const specialties: string[] = [];
    
    for (const diagnosis of diagnoses) {
      switch (diagnosis.criteria.code) {
        case '296.20':
        case 'F32.9':
        case '296.33':
        case 'F33.9':
          specialties.push('Depression', 'Mood Disorders', 'Cognitive Behavioral Therapy');
          break;
        case '300.02':
        case 'F41.1':
        case '300.01':
        case 'F41.0':
          specialties.push('Anxiety Disorders', 'Panic Disorder', 'Generalized Anxiety');
          break;
        case '309.81':
        case 'F43.10':
          specialties.push('PTSD', 'Trauma Therapy', 'EMDR', 'Trauma-Focused CBT');
          break;
        case '295.90':
        case 'F20.9':
          specialties.push('Schizophrenia', 'Psychotic Disorders', 'Psychiatric Care');
          break;
        case '296.89':
        case 'F31.9':
          specialties.push('Bipolar Disorder', 'Mood Disorders', 'Psychiatric Care');
          break;
        case '301.83':
        case 'F60.3':
          specialties.push('Borderline Personality Disorder', 'Dialectical Behavior Therapy', 'DBT');
          break;
        case '301.7':
        case 'F60.2':
          specialties.push('Antisocial Personality Disorder', 'Personality Disorders');
          break;
        case '307.1':
        case 'F50.0':
          specialties.push('Eating Disorders', 'Anorexia Nervosa', 'Nutritional Counseling');
          break;
      }
    }
    
    return [...new Set(specialties)];
  }

  private getCrisisResources(diagnoses: DiagnosticMatch[]): CrisisResource[] {
    const resources = [...this.crisisHotlines];
    
    // Add specialized crisis resources based on diagnoses
    for (const diagnosis of diagnoses) {
      switch (diagnosis.criteria.code) {
        case '309.81':
        case 'F43.10':
          resources.push({
            name: "Veterans Crisis Line",
            phone: "1-800-273-8255",
            text: "838255",
            description: "Specialized crisis support for veterans and military personnel",
            available24_7: true,
            specializedFor: ["PTSD", "Military Trauma", "Veterans"]
          });
          break;
        case '307.1':
        case 'F50.0':
          resources.push({
            name: "National Eating Disorders Association Helpline",
            phone: "1-800-931-2237",
            text: "NEDA to 741741",
            description: "Crisis support for eating disorders",
            available24_7: true,
            specializedFor: ["Eating Disorders", "Anorexia", "Bulimia"]
          });
          break;
      }
    }
    
    return resources;
  }

  private findResourcesInRadius(
    location: { city: string; state: string; zipCode?: string }, 
    specialties: string[], 
    radius: number
  ): LocalResource[] {
    // In a real implementation, this would use geocoding and distance calculation
    // For now, return filtered resources based on location and specialties
    let resources = [...this.therapists, ...this.psychiatrists];
    
    // Filter by location (simplified)
    if (location.state) {
      resources = resources.filter(r => r.state.toLowerCase().includes(location.state.toLowerCase()));
    }
    if (location.city) {
      resources = resources.filter(r => r.city.toLowerCase().includes(location.city.toLowerCase()));
    }
    
    // Filter by specialties
    if (specialties.length > 0) {
      resources = resources.filter(r => 
        specialties.some(specialty => 
          r.specialties.some(s => s.toLowerCase().includes(specialty.toLowerCase()))
        )
      );
    }
    
    // Sort by rating and distance (mock distance calculation)
    return resources
      .map(r => ({ ...r, distance: Math.random() * radius, rating: Math.random() * 5 }))
      .sort((a, b) => (b.rating || 0) - (a.rating || 0))
      .slice(0, 20); // Limit to top 20 results
  }

  private findEmergencyResources(
    location: { city: string; state: string; zipCode?: string }, 
    radius: number
  ): LocalResource[] {
    return this.emergencyResources.filter(r => {
      if (location.state) {
        return r.state.toLowerCase().includes(location.state.toLowerCase());
      }
      return true;
    });
  }

  private findSupportGroups(
    location: { city: string; state: string; zipCode?: string }, 
    specialties: string[], 
    radius: number
  ): LocalResource[] {
    let groups = [...this.supportGroups];
    
    // Filter by location
    if (location.state) {
      groups = groups.filter(g => g.state.toLowerCase().includes(location.state.toLowerCase()));
    }
    
    // Filter by specialties
    if (specialties.length > 0) {
      groups = groups.filter(g => 
        specialties.some(specialty => 
          g.specialties.some(s => s.toLowerCase().includes(specialty.toLowerCase()))
        )
      );
    }
    
    return groups.slice(0, 10); // Limit to top 10 results
  }

  private initializeCrisisResources(): void {
    this.crisisHotlines = [
      {
        name: "National Suicide Prevention Lifeline",
        phone: "988",
        text: "988",
        chat: "https://suicidepreventionlifeline.org/chat/",
        description: "24/7 crisis support for anyone in emotional distress or suicidal crisis",
        available24_7: true,
        specializedFor: ["Suicide Prevention", "Crisis Intervention", "Emotional Support"]
      },
      {
        name: "Crisis Text Line",
        phone: "Text HOME to 741741",
        text: "HOME to 741741",
        description: "24/7 crisis support via text message",
        available24_7: true,
        specializedFor: ["Crisis Support", "Text Support", "Youth Support"]
      },
      {
        name: "SAMHSA National Helpline",
        phone: "1-800-662-4357",
        description: "24/7 treatment referral and information service for mental health and substance use disorders",
        available24_7: true,
        specializedFor: ["Substance Abuse", "Mental Health", "Treatment Referrals"]
      },
      {
        name: "National Domestic Violence Hotline",
        phone: "1-800-799-7233",
        text: "START to 88788",
        description: "24/7 support for domestic violence survivors",
        available24_7: true,
        specializedFor: ["Domestic Violence", "Trauma", "Safety Planning"]
      },
      {
        name: "RAINN National Sexual Assault Hotline",
        phone: "1-800-656-4673",
        chat: "https://hotline.rainn.org/online",
        description: "24/7 support for sexual assault survivors",
        available24_7: true,
        specializedFor: ["Sexual Assault", "Trauma", "Crisis Support"]
      },
      {
        name: "Trans Lifeline",
        phone: "1-877-565-8860",
        description: "Peer support for transgender people in crisis",
        available24_7: true,
        specializedFor: ["LGBTQ+", "Transgender", "Peer Support"]
      },
      {
        name: "Trevor Project",
        phone: "1-866-488-7386",
        text: "START to 678678",
        chat: "https://www.thetrevorproject.org/get-help-now/",
        description: "24/7 crisis support for LGBTQ+ youth",
        available24_7: true,
        specializedFor: ["LGBTQ+", "Youth", "Crisis Support"]
      }
    ];
  }

  private initializeTherapists(): void {
    this.therapists = [
      {
        id: "t001",
        name: "Dr. Sarah Johnson, PhD",
        type: "therapist",
        address: "123 Main Street, Suite 200",
        city: "New York",
        state: "NY",
        zipCode: "10001",
        phone: "(555) 123-4567",
        email: "sarah.johnson@therapy.com",
        website: "https://sarahjohnson.com",
        specialties: ["Depression", "Anxiety", "Cognitive Behavioral Therapy", "Trauma Therapy"],
        insuranceAccepted: ["Blue Cross", "Aetna", "Cigna", "UnitedHealth"],
        languages: ["English", "Spanish"],
        hours: "Mon-Fri 9AM-6PM, Sat 10AM-2PM",
        description: "Licensed clinical psychologist specializing in depression and anxiety disorders",
        cost: "$150-200/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      },
      {
        id: "t002",
        name: "Michael Chen, LCSW",
        type: "therapist",
        address: "456 Oak Avenue, Suite 150",
        city: "Los Angeles",
        state: "CA",
        zipCode: "90210",
        phone: "(555) 234-5678",
        email: "michael.chen@therapy.com",
        specialties: ["PTSD", "EMDR", "Trauma-Focused CBT", "Military Veterans"],
        insuranceAccepted: ["Blue Cross", "Kaiser", "Medicare", "Medicaid"],
        languages: ["English", "Mandarin"],
        hours: "Mon-Thu 8AM-7PM, Fri 8AM-5PM",
        description: "Licensed clinical social worker specializing in trauma and PTSD treatment",
        cost: "$120-180/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      },
      {
        id: "t003",
        name: "Dr. Maria Rodriguez, PsyD",
        type: "therapist",
        address: "789 Pine Street, Suite 300",
        city: "Chicago",
        state: "IL",
        zipCode: "60601",
        phone: "(555) 345-6789",
        email: "maria.rodriguez@therapy.com",
        specialties: ["Borderline Personality Disorder", "Dialectical Behavior Therapy", "DBT", "Personality Disorders"],
        insuranceAccepted: ["Blue Cross", "Aetna", "Cigna", "Medicaid"],
        languages: ["English", "Spanish", "Portuguese"],
        hours: "Mon-Fri 9AM-6PM",
        description: "Licensed psychologist specializing in personality disorders and DBT",
        cost: "$160-220/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      },
      {
        id: "t004",
        name: "James Wilson, LMFT",
        type: "therapist",
        address: "321 Elm Street, Suite 100",
        city: "Houston",
        state: "TX",
        zipCode: "77001",
        phone: "(555) 456-7890",
        email: "james.wilson@therapy.com",
        specialties: ["Bipolar Disorder", "Mood Disorders", "Family Therapy", "Couples Therapy"],
        insuranceAccepted: ["Blue Cross", "Aetna", "UnitedHealth", "Medicare"],
        languages: ["English"],
        hours: "Mon-Thu 9AM-7PM, Fri 9AM-5PM, Sat 10AM-3PM",
        description: "Licensed marriage and family therapist specializing in mood disorders",
        cost: "$130-190/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      },
      {
        id: "t005",
        name: "Dr. Lisa Thompson, PhD",
        type: "therapist",
        address: "654 Maple Drive, Suite 250",
        city: "Phoenix",
        state: "AZ",
        zipCode: "85001",
        phone: "(555) 567-8901",
        email: "lisa.thompson@therapy.com",
        specialties: ["Eating Disorders", "Anorexia Nervosa", "Body Image", "Nutritional Counseling"],
        insuranceAccepted: ["Blue Cross", "Aetna", "Cigna", "UnitedHealth"],
        languages: ["English", "French"],
        hours: "Mon-Fri 8AM-6PM",
        description: "Licensed psychologist specializing in eating disorders and body image issues",
        cost: "$170-230/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      }
    ];
  }

  private initializePsychiatrists(): void {
    this.psychiatrists = [
      {
        id: "p001",
        name: "Dr. Robert Kim, MD",
        type: "psychiatrist",
        address: "987 Broadway, Suite 400",
        city: "New York",
        state: "NY",
        zipCode: "10002",
        phone: "(555) 678-9012",
        email: "robert.kim@psychiatry.com",
        website: "https://robertkim.com",
        specialties: ["Schizophrenia", "Psychotic Disorders", "Psychiatric Medication", "Severe Mental Illness"],
        insuranceAccepted: ["Blue Cross", "Aetna", "Cigna", "UnitedHealth", "Medicare"],
        languages: ["English", "Korean"],
        hours: "Mon-Fri 8AM-5PM",
        description: "Board-certified psychiatrist specializing in psychotic disorders and medication management",
        cost: "$250-350/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      },
      {
        id: "p002",
        name: "Dr. Jennifer Davis, MD",
        type: "psychiatrist",
        address: "147 Cedar Lane, Suite 180",
        city: "Los Angeles",
        state: "CA",
        zipCode: "90211",
        phone: "(555) 789-0123",
        email: "jennifer.davis@psychiatry.com",
        specialties: ["Bipolar Disorder", "Mood Disorders", "Psychiatric Medication", "Medication Management"],
        insuranceAccepted: ["Blue Cross", "Kaiser", "Aetna", "Medicare"],
        languages: ["English", "Spanish"],
        hours: "Mon-Thu 9AM-6PM, Fri 9AM-4PM",
        description: "Board-certified psychiatrist specializing in bipolar disorder and mood stabilizers",
        cost: "$280-380/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      },
      {
        id: "p003",
        name: "Dr. Ahmed Hassan, MD",
        type: "psychiatrist",
        address: "258 Willow Street, Suite 320",
        city: "Chicago",
        state: "IL",
        zipCode: "60602",
        phone: "(555) 890-1234",
        email: "ahmed.hassan@psychiatry.com",
        specialties: ["Depression", "Anxiety", "Psychiatric Medication", "Antidepressants"],
        insuranceAccepted: ["Blue Cross", "Aetna", "Cigna", "Medicaid", "Medicare"],
        languages: ["English", "Arabic", "French"],
        hours: "Mon-Fri 8AM-6PM",
        description: "Board-certified psychiatrist specializing in depression and anxiety medication management",
        cost: "$260-360/session",
        accessibility: ["Wheelchair Accessible", "Online Sessions Available"]
      }
    ];
  }

  private initializeSupportGroups(): void {
    this.supportGroups = [
      {
        id: "sg001",
        name: "Depression Support Group",
        type: "support_group",
        address: "Community Center, 100 Main Street",
        city: "New York",
        state: "NY",
        zipCode: "10001",
        phone: "(555) 111-2222",
        email: "depression@supportgroup.org",
        website: "https://depressionsupport.org",
        specialties: ["Depression", "Mood Disorders", "Peer Support"],
        insuranceAccepted: [],
        languages: ["English"],
        hours: "Tuesdays 7PM-8:30PM",
        description: "Weekly peer support group for individuals with depression",
        cost: "Free",
        accessibility: ["Wheelchair Accessible"]
      },
      {
        id: "sg002",
        name: "Anxiety Recovery Group",
        type: "support_group",
        address: "Mental Health Center, 200 Oak Avenue",
        city: "Los Angeles",
        state: "CA",
        zipCode: "90210",
        phone: "(555) 222-3333",
        email: "anxiety@supportgroup.org",
        specialties: ["Anxiety Disorders", "Panic Disorder", "Peer Support"],
        insuranceAccepted: [],
        languages: ["English", "Spanish"],
        hours: "Wednesdays 6PM-7:30PM",
        description: "Weekly support group for anxiety and panic disorders",
        cost: "Free",
        accessibility: ["Wheelchair Accessible"]
      },
      {
        id: "sg003",
        name: "PTSD Veterans Group",
        type: "support_group",
        address: "VA Medical Center, 300 Veterans Drive",
        city: "Chicago",
        state: "IL",
        zipCode: "60601",
        phone: "(555) 333-4444",
        email: "ptsd@va.gov",
        specialties: ["PTSD", "Military Trauma", "Veterans", "Trauma Recovery"],
        insuranceAccepted: [],
        languages: ["English"],
        hours: "Thursdays 6PM-8PM",
        description: "Support group for veterans with PTSD",
        cost: "Free for veterans",
        accessibility: ["Wheelchair Accessible"]
      },
      {
        id: "sg004",
        name: "Bipolar Support Alliance",
        type: "support_group",
        address: "Community Center, 400 Pine Street",
        city: "Houston",
        state: "TX",
        zipCode: "77001",
        phone: "(555) 444-5555",
        email: "bipolar@supportgroup.org",
        specialties: ["Bipolar Disorder", "Mood Disorders", "Peer Support"],
        insuranceAccepted: [],
        languages: ["English"],
        hours: "Mondays 7PM-8:30PM",
        description: "Weekly support group for individuals with bipolar disorder",
        cost: "Free",
        accessibility: ["Wheelchair Accessible"]
      }
    ];
  }

  private initializeEmergencyResources(): void {
    this.emergencyResources = [
      {
        id: "er001",
        name: "City General Hospital - Psychiatric Emergency",
        type: "emergency_room",
        address: "500 Hospital Drive",
        city: "New York",
        state: "NY",
        zipCode: "10001",
        phone: "(555) 911-0000",
        email: "emergency@citygeneral.org",
        website: "https://citygeneral.org",
        specialties: ["Psychiatric Emergency", "Crisis Intervention", "Emergency Mental Health"],
        insuranceAccepted: ["All Major Insurance", "Medicare", "Medicaid"],
        languages: ["English", "Spanish", "Multiple Languages"],
        hours: "24/7",
        description: "24/7 psychiatric emergency services and crisis intervention",
        cost: "Emergency rates apply",
        accessibility: ["Wheelchair Accessible", "Emergency Access"]
      },
      {
        id: "er002",
        name: "Regional Crisis Center",
        type: "crisis_center",
        address: "600 Crisis Lane",
        city: "Los Angeles",
        state: "CA",
        zipCode: "90210",
        phone: "(555) 911-0001",
        email: "crisis@regional.org",
        specialties: ["Crisis Intervention", "Suicide Prevention", "Mental Health Crisis"],
        insuranceAccepted: ["All Major Insurance", "Medicare", "Medicaid", "Sliding Scale"],
        languages: ["English", "Spanish", "Multiple Languages"],
        hours: "24/7",
        description: "24/7 crisis intervention and mental health emergency services",
        cost: "Sliding scale available",
        accessibility: ["Wheelchair Accessible", "Emergency Access"]
      }
    ];
  }
}
