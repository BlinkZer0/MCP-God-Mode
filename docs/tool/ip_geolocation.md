# IP Geolocation Tool

## Overview
The **IP Geolocation Tool** provides comprehensive IP-based geolocation capabilities using multiple commercial and free databases. This tool enables accurate location determination for IP addresses without requiring external API dependencies.

## Features
- **Multiple Database Support**: MaxMind GeoIP, IP2Location, DB-IP, ipinfo.io, ip-api.com
- **High Accuracy**: City-level and neighborhood-level precision
- **Comprehensive Data**: ISP, organization, timezone, and ASN information
- **Cross-Platform**: Works on Windows, Linux, macOS, Android, and iOS
- **No API Dependencies**: Self-contained geolocation capabilities

## Supported Databases

### Commercial Databases
- **MaxMind GeoIP**: Industry-standard geolocation database
- **IP2Location**: Comprehensive IP geolocation service
- **DB-IP**: High-accuracy IP geolocation database

### Free Services
- **ipinfo.io**: Free IP geolocation API
- **ip-api.com**: Free IP geolocation service

## Parameters

### Required Parameters
- `ip_address` (string): IP address to geolocate
- `database` (enum): Geolocation database to use
  - Options: "maxmind", "ip2location", "dbip", "ipinfo", "ipapi", "all"

### Optional Parameters
- `accuracy_level` (enum): Desired accuracy level
  - Options: "city", "neighborhood", "precise"
- `include_isp` (boolean): Include ISP information
- `include_timezone` (boolean): Include timezone information

## Output Schema

```json
{
  "success": boolean,
  "message": string,
  "geolocation_data": {
    "ip": string,
    "country": string,
    "country_code": string,
    "region": string,
    "city": string,
    "latitude": number,
    "longitude": number,
    "accuracy_radius": number,
    "isp": string,
    "organization": string,
    "timezone": string,
    "postal_code": string,
    "asn": string,
    "database_used": string
  }
}
```

## Natural Language Access
Users can request ip geolocation operations using natural language:
- "Use ip geolocation functionality"
- "Access ip geolocation features"
- "Control ip geolocation operations"
- "Manage ip geolocation tasks"
- "Execute ip geolocation functions"

## Usage Examples

### Basic Geolocation
```json
{
  "ip_address": "8.8.8.8",
  "database": "ipinfo"
}
```

### Comprehensive Geolocation
```json
{
  "ip_address": "192.168.1.1",
  "database": "all",
  "accuracy_level": "neighborhood",
  "include_isp": true,
  "include_timezone": true
}
```

### High-Precision Geolocation
```json
{
  "ip_address": "1.1.1.1",
  "database": "maxmind",
  "accuracy_level": "precise",
  "include_isp": true,
  "include_timezone": true
}
```

## Accuracy Levels

### City Level
- **Accuracy**: 50-100km radius
- **Use Case**: General location identification
- **Database**: All supported databases

### Neighborhood Level
- **Accuracy**: 1-5km radius
- **Use Case**: Local area identification
- **Database**: MaxMind, IP2Location, DB-IP

### Precise Level
- **Accuracy**: 100m-1km radius
- **Use Case**: Building-level identification
- **Database**: MaxMind, IP2Location (premium)

## Error Handling

### Common Errors
- **Invalid IP Address**: Malformed or private IP addresses
- **Database Unavailable**: Database service temporarily unavailable
- **Rate Limiting**: Too many requests in short time period
- **Permission Denied**: Insufficient permissions for database access

### Error Response Format
```json
{
  "success": false,
  "message": "Error description",
  "geolocation_data": null
}
```

## Performance Considerations

### Response Times
- **Free Services**: 100-500ms
- **Commercial Databases**: 50-200ms
- **Local Database**: 10-50ms

### Rate Limits
- **Free Services**: 1000 requests/day
- **Commercial Databases**: Varies by license
- **Local Database**: No limits

## Security Considerations

### Data Privacy
- No external API calls for local databases
- Encrypted communication for remote databases
- No storage of geolocation data
- Compliance with privacy regulations

### Authorization
- Requires proper database licenses
- Respects terms of service
- Authorized use only

## Integration Examples

### Network Security Analysis
```json
{
  "workflow": [
    {
      "step": 1,
      "tool": "network_discovery",
      "target": "192.168.1.0/24"
    },
    {
      "step": 2,
      "tool": "ip_geolocation",
      "ip_address": "{{discovered_ip}}",
      "database": "all"
    }
  ]
}
```

### Threat Intelligence
```json
{
  "threat_analysis": {
    "suspicious_ip": "1.2.3.4",
    "geolocation": {
      "tool": "ip_geolocation",
      "database": "maxmind",
      "accuracy_level": "city"
    },
    "risk_assessment": "High - Foreign IP from known threat region"
  }
}
```

## Best Practices

### Database Selection
- Use commercial databases for production environments
- Free services for testing and development
- Combine multiple databases for verification

### Accuracy Optimization
- Use appropriate accuracy level for use case
- Consider database-specific capabilities
- Validate results across multiple sources

### Performance Optimization
- Cache frequently accessed IP addresses
- Use local databases when possible
- Implement proper rate limiting

## Troubleshooting

### Common Issues
1. **No Results**: Check IP address format and validity
2. **Low Accuracy**: Try different database or accuracy level
3. **Slow Response**: Check network connectivity and database status
4. **Permission Errors**: Verify database licenses and permissions

### Debug Information
- Enable verbose logging for detailed error information
- Check database connectivity and status
- Validate input parameters and formats

## Related Tools
- `network_triangulation`: Wi-Fi and cell tower triangulation
- `latency_geolocation`: Ping-based geolocation
- `osint_reconnaissance`: WHOIS and domain information
- `network_discovery`: Network reconnaissance and scanning
