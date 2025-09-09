# Version 1.7c Changelog - Individual Tool Installation & Consolidated Flipper Zero Support

**Release Date:** January 2025  
**Version:** 1.7c  
**Focus:** Individual Tool Installation & Consolidated Flipper Zero Support

## 🚀 Major Features

### Individual Tool Installation System
- **NEW**: Complete individual tool specification system for modular server
- **NEW**: `--tools` parameter for installing specific tools by name
- **NEW**: `--auto-deps` flag for automatic dependency resolution
- **NEW**: `--list-tools` command to browse all available tools
- **NEW**: Mixed configuration support (categories + individual tools)
- **NEW**: Comprehensive tool dependency validation and management

### Consolidated Flipper Zero Support
- **ENHANCED**: Consolidated Flipper Zero tool with comprehensive functionality
- **ENHANCED**: Single unified interface for all Flipper Zero operations
- **ENHANCED**: Improved device discovery and connection management
- **ENHANCED**: Streamlined file operations and session management

## 🔧 Installation Enhancements

### New Installation Methods
```bash
# Individual tools only
node install.js --modular --tools health,system_info,fs_list

# With automatic dependencies
node install.js --modular --tools port_scanner --auto-deps

# Mixed configuration
node install.js --modular --categories core,network --tools packet_sniffer

# List all available tools
node install.js --list-tools
```

### Enhanced Build Server
- **NEW**: `--modular` flag for creating modular configurations
- **ENHANCED**: Integration with tool configuration system
- **ENHANCED**: Fallback to custom server creation
- **ENHANCED**: Improved help and usage information

## 🛠️ Technical Improvements

### Tool Configuration System
- **NEW**: `createConfigFromTools()` for individual tool configuration
- **NEW**: `createConfigFromMixed()` for categories + individual tools
- **NEW**: `validateToolNames()` for tool name validation
- **NEW**: `validateToolDependencies()` for dependency checking
- **NEW**: `includeToolDependencies()` for automatic dependency resolution
- **NEW**: Comprehensive tool dependency mapping

### Dependency Management
- **NEW**: Automatic detection of tool dependencies
- **NEW**: Warning system for missing dependencies
- **NEW**: Auto-inclusion of required dependencies
- **NEW**: Manual dependency control options

## 📚 Documentation Updates

### New Documentation
- **NEW**: [Individual Tool Installation Guide](dev/src/docs/guides/INDIVIDUAL_TOOL_INSTALLATION.md)
- **UPDATED**: Main README with individual tool installation section
- **UPDATED**: Documentation index with new guides
- **UPDATED**: Installation examples and usage patterns

### Enhanced Guides
- **ENHANCED**: Installation examples for different use cases
- **ENHANCED**: Troubleshooting section for individual tool installation
- **ENHANCED**: Best practices for tool selection and configuration

## 🔍 Flipper Zero Improvements

### Consolidated Tool Features
- **UNIFIED**: Single tool interface for all Flipper Zero operations
- **ENHANCED**: Device discovery and connection management
- **ENHANCED**: File system operations (list, read, write, delete)
- **ENHANCED**: IR transmission and raw data sending
- **ENHANCED**: Sub-GHz transmission capabilities
- **ENHANCED**: NFC/RFID operations and dumping
- **ENHANCED**: BadUSB scripting and DuckyScript support
- **ENHANCED**: UART sniffing and GPIO control
- **ENHANCED**: Bluetooth Low Energy scanning and pairing

### Improved User Experience
- **STREAMLINED**: Simplified command structure
- **ENHANCED**: Better error handling and feedback
- **ENHANCED**: Comprehensive session management
- **ENHANCED**: Cross-platform compatibility maintained

## 🎯 Use Case Examples

### Security Testing Setup
```bash
node install.js --modular --tools port_scanner,vulnerability_scanner,network_discovery --auto-deps
```

### File Management Only
```bash
node install.js --modular --tools fs_list,fs_read_text,fs_write_text,file_ops
```

### Mobile Development
```bash
node install.js --modular --tools mobile_device_info,mobile_app_security_toolkit --auto-deps
```

### Flipper Zero Operations
```bash
# List available Flipper Zero devices
node dist/server-modular.js
# Then use the consolidated flipper_zero tool for all operations
```

## 🔧 Configuration File Format

The new system creates `tool-config.json` with enhanced structure:

```json
{
  "enabledTools": ["health", "system_info", "fs_list"],
  "disabledTools": [],
  "toolCategories": {
    "core": { "enabled": false, "tools": ["health", "system_info"] },
    "file_system": { "enabled": false, "tools": ["fs_list", "fs_read_text", ...] }
  },
  "customTools": []
}
```

## 🚀 Migration Guide

### From Previous Versions
1. **No Breaking Changes**: All existing configurations continue to work
2. **Optional Upgrade**: Individual tool installation is optional
3. **Backward Compatible**: All existing installation methods remain functional

### Recommended Migration
1. **Test Individual Tools**: Try the new individual tool installation
2. **Update Documentation**: Review new installation guides
3. **Explore Flipper Zero**: Test the consolidated Flipper Zero tool

## 🐛 Bug Fixes

- **FIXED**: Tool dependency validation edge cases
- **FIXED**: Configuration file parsing improvements
- **FIXED**: Error handling in modular server initialization
- **FIXED**: Flipper Zero connection stability issues

## 🔮 Future Roadmap

### Planned Features
- **Enhanced Tool Discovery**: Improved tool browsing and search
- **Configuration Templates**: Pre-built configurations for common use cases
- **Advanced Dependency Resolution**: More sophisticated dependency management
- **Performance Optimization**: Faster tool loading and initialization

### Community Feedback
- **User Requests**: Individual tool installation system
- **Flipper Zero**: Consolidated tool interface
- **Documentation**: Comprehensive installation guides
- **Flexibility**: More granular control over tool selection

## 📊 Statistics

- **Total Tools**: 147 (maintained)
- **New Installation Methods**: 4
- **New Configuration Options**: 6
- **Documentation Pages Added**: 1
- **Dependency Mappings**: 20+

## 🎉 Acknowledgments

Special thanks to the community for feedback on:
- Individual tool installation requirements
- Flipper Zero tool consolidation needs
- Documentation improvements
- User experience enhancements

---

**Next Version Preview**: Enhanced tool discovery, configuration templates, and performance optimizations.

**Support**: For issues or questions, please refer to the [Individual Tool Installation Guide](dev/src/docs/guides/INDIVIDUAL_TOOL_INSTALLATION.md) or create an issue on GitHub.
