# Social Engineering Tool

## Overview
The Social Engineering tool provides comprehensive awareness training and testing framework for assessing human factor vulnerabilities in security systems. This tool helps organizations identify and mitigate social engineering risks through controlled testing and employee education.

## Features
- **Phishing Testing**: Simulate phishing attacks to test awareness
- **Pretexting Scenarios**: Test response to fabricated scenarios
- **Baiting Attacks**: Assess susceptibility to bait-based attacks
- **Quid Pro Quo**: Test response to exchange-based manipulation
- **Tailgating Tests**: Evaluate physical security awareness
- **Training Programs**: Deliver security awareness education
- **Assessment Reports**: Generate detailed vulnerability reports

## Parameters

### Required Parameters
- **action** (string): Social engineering action to perform
  - Options: `test`, `train`, `simulate`, `assess`, `report`
- **technique** (string): Social engineering technique to use
  - Options: `phishing`, `pretexting`, `baiting`, `quid_pro_quo`, `tailgating`
- **target_group** (string): Target group for testing/training

### Optional Parameters
- **scenario** (string): Specific scenario to simulate

## Usage Examples

### Phishing Awareness Test
```bash
# Conduct phishing awareness test
python -m mcp_god_mode.tools.security.social_engineering \
  --action "test" \
  --technique "phishing" \
  --target_group "employees" \
  --scenario "urgent_password_reset_email"
```

### Security Training Program
```bash
# Deliver security awareness training
python -m mcp_god_mode.tools.security.social_engineering \
  --action "train" \
  --technique "phishing" \
  --target_group "new_employees" \
  --scenario "comprehensive_security_training"
```

### Pretexting Simulation
```bash
# Simulate pretexting attack
python -m mcp_god_mode.tools.security.social_engineering \
  --action "simulate" \
  --technique "pretexting" \
  --target_group "help_desk" \
  --scenario "it_support_impersonation"
```

### Security Assessment
```bash
# Conduct comprehensive security assessment
python -m mcp_god_mode.tools.security.social_engineering \
  --action "assess" \
  --technique "baiting" \
  --target_group "all_staff" \
  --scenario "usb_drop_attack"
```

### Generate Assessment Report
```bash
# Generate detailed assessment report
python -m mcp_god_mode.tools.security.social_engineering \
  --action "report" \
  --technique "phishing" \
  --target_group "employees"
```

## Output Format

The tool returns structured results including:
- **success** (boolean): Operation success status
- **message** (string): Detailed operation message
- **se_results** (object): Social engineering specific results
  - **participants** (number): Number of participants in test/training
  - **success_rate** (number): Success rate of the social engineering attempt
  - **awareness_level** (string): Overall awareness level assessment

## Platform Support
- ✅ **Windows**: Full support with email and web-based testing
- ✅ **Linux**: Complete support with command-line interfaces
- ✅ **macOS**: Native support with integrated security features
- ✅ **Android**: Mobile-specific social engineering tests
- ✅ **iOS**: iOS-specific attack vectors and defenses

## Social Engineering Techniques

### Phishing
- **Email Phishing**: Simulate malicious email campaigns
- **SMS Phishing**: Test mobile messaging awareness
- **Voice Phishing**: Simulate phone-based attacks
- **Spear Phishing**: Targeted attacks on specific individuals

### Pretexting
- **Authority Impersonation**: Test response to authority figures
- **Technical Support**: Simulate IT support scenarios
- **Vendor Impersonation**: Test vendor verification procedures
- **Emergency Scenarios**: Assess response to urgent situations

### Baiting
- **USB Drops**: Physical device-based attacks
- **Malicious Downloads**: Test software installation awareness
- **Gift Scenarios**: Assess response to unexpected items
- **Contest Entries**: Test response to fake competitions

### Quid Pro Quo
- **Information Exchange**: Test data sharing policies
- **Service Offers**: Assess response to unsolicited services
- **Reward Programs**: Test response to fake incentives
- **Help Requests**: Assess response to assistance requests

### Tailgating
- **Physical Access**: Test building security awareness
- **Badge Sharing**: Assess ID verification procedures
- **Visitor Escort**: Test visitor management protocols
- **Emergency Access**: Assess response to emergency situations

## Use Cases
- **Security Awareness Training**: Employee education programs
- **Penetration Testing**: Human factor vulnerability assessment
- **Compliance Testing**: Regulatory requirement validation
- **Incident Response**: Social engineering attack simulation
- **Risk Assessment**: Organizational vulnerability analysis
- **Training Evaluation**: Security training effectiveness measurement

## Best Practices
1. **Authorization**: Always obtain proper authorization before testing
2. **Documentation**: Maintain detailed records of all activities
3. **Debriefing**: Provide feedback to participants after testing
4. **Gradual Escalation**: Start with low-risk scenarios
5. **Legal Compliance**: Ensure all activities comply with local laws
6. **Ethical Guidelines**: Follow ethical hacking principles

## Security Considerations
- **Legal Authorization**: Ensure proper legal authorization for all testing
- **Data Protection**: Protect participant data and results
- **Ethical Boundaries**: Maintain ethical standards in all activities
- **Incident Response**: Have procedures for handling successful attacks
- **Documentation**: Maintain comprehensive audit trails

## Compliance & Legal
- **GDPR Compliance**: Ensure data protection compliance
- **Industry Standards**: Follow relevant security frameworks
- **Legal Review**: Obtain legal review for testing activities
- **Consent Management**: Proper consent for all participants
- **Data Retention**: Follow data retention policies

## Related Tools
- [Security Testing Tool](security_testing.md) - Comprehensive security assessment
- [Penetration Testing Toolkit](penetration_testing_toolkit.md) - Complete PT framework
- [Threat Intelligence Tool](threat_intelligence.md) - Threat analysis and monitoring
- [Compliance Assessment Tool](compliance_assessment.md) - Regulatory compliance testing

## Troubleshooting
- **Low Participation**: Improve communication and incentives
- **False Positives**: Refine testing scenarios and parameters
- **Legal Issues**: Consult with legal team before testing
- **Technical Problems**: Check system configurations and permissions
- **Reporting Issues**: Verify data collection and analysis processes
