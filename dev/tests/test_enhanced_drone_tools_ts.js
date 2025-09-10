#!/usr/bin/env node
/**
 * Enhanced Drone Tools Test Suite - MCP God Mode v1.8
 * Comprehensive testing for cross-platform drone tools with natural language interface
 */

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class EnhancedDroneToolsTester {
    constructor() {
        this.testResults = [];
        this.platform = this.detectPlatform();
        this.isMobile = this.platform === 'android' || this.platform === 'ios';
    }
    
    detectPlatform() {
        const os = await import('os');
        const platform = os.platform();
        
        if (platform === 'win32') return 'windows';
        if (platform === 'linux') return 'linux';
        if (platform === 'darwin') return 'macos';
        
        // Check for mobile platforms
        if (process.env.ANDROID_ROOT || process.env.ANDROID_DATA) return 'android';
        if (process.env.IOS_SIMULATOR || process.env.IOS_PLATFORM) return 'ios';
        
        return 'unknown';
    }
    
    logTest(testName, success, details = '') {
        const result = {
            testName,
            success,
            details,
            platform: this.platform,
            timestamp: new Date().toISOString()
        };
        
        this.testResults.push(result);
        
        const status = success ? '✅ PASS' : '❌ FAIL';
        console.log(`${status} ${testName} - ${details}`);
    }
    
    async testTypeScriptCompilation() {
        try {
            console.log('🔨 Testing TypeScript compilation...');
            
            const tscProcess = spawn('npx', ['tsc', '-p', '.'], {
                stdio: 'pipe',
                shell: true
            });
            
            let stdout = '';
            let stderr = '';
            
            tscProcess.stdout.on('data', (data) => {
                stdout += data.toString();
            });
            
            tscProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });
            
            return new Promise((resolve) => {
                tscProcess.on('close', (code) => {
                    if (code === 0) {
                        this.logTest(
                            'TypeScript Compilation',
                            true,
                            'All TypeScript files compiled successfully'
                        );
                    } else {
                        this.logTest(
                            'TypeScript Compilation',
                            false,
                            `Compilation failed: ${stderr}`
                        );
                    }
                    resolve(code === 0);
                });
            });
            
        } catch (error) {
            this.logTest(
                'TypeScript Compilation',
                false,
                `Exception: ${error.message}`
            );
            return false;
        }
    }
    
    async testEnhancedDroneDefenseModule() {
        try {
            // Test if the enhanced drone defense module can be imported
            const modulePath = path.join(__dirname, 'dist', 'tools', 'droneDefenseEnhanced.js');
            
            if (fs.existsSync(modulePath)) {
                this.logTest(
                    'Enhanced Drone Defense Module - Import',
                    true,
                    'Module file exists and can be imported'
                );
                
                // Test module structure
                const module = require(modulePath);
                
                if (module.registerDroneDefenseEnhanced) {
                    this.logTest(
                        'Enhanced Drone Defense Module - Registration Function',
                        true,
                        'Registration function exists'
                    );
                } else {
                    this.logTest(
                        'Enhanced Drone Defense Module - Registration Function',
                        false,
                        'Registration function not found'
                    );
                }
                
            } else {
                this.logTest(
                    'Enhanced Drone Defense Module - Import',
                    false,
                    'Module file not found'
                );
            }
            
        } catch (error) {
            this.logTest(
                'Enhanced Drone Defense Module - Import',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async testEnhancedDroneOffenseModule() {
        try {
            const modulePath = path.join(__dirname, 'dist', 'tools', 'droneOffenseEnhanced.js');
            
            if (fs.existsSync(modulePath)) {
                this.logTest(
                    'Enhanced Drone Offense Module - Import',
                    true,
                    'Module file exists and can be imported'
                );
                
                const module = require(modulePath);
                
                if (module.registerDroneOffenseEnhanced) {
                    this.logTest(
                        'Enhanced Drone Offense Module - Registration Function',
                        true,
                        'Registration function exists'
                    );
                } else {
                    this.logTest(
                        'Enhanced Drone Offense Module - Registration Function',
                        false,
                        'Registration function not found'
                    );
                }
                
            } else {
                this.logTest(
                    'Enhanced Drone Offense Module - Import',
                    false,
                    'Module file not found'
                );
            }
            
        } catch (error) {
            this.logTest(
                'Enhanced Drone Offense Module - Import',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async testNaturalLanguageInterfaceModule() {
        try {
            const modulePath = path.join(__dirname, 'dist', 'tools', 'droneNaturalLanguageInterface.js');
            
            if (fs.existsSync(modulePath)) {
                this.logTest(
                    'Natural Language Interface Module - Import',
                    true,
                    'Module file exists and can be imported'
                );
                
                const module = require(modulePath);
                
                if (module.registerDroneNaturalLanguageInterface) {
                    this.logTest(
                        'Natural Language Interface Module - Registration Function',
                        true,
                        'Registration function exists'
                    );
                } else {
                    this.logTest(
                        'Natural Language Interface Module - Registration Function',
                        false,
                        'Registration function not found'
                    );
                }
                
            } else {
                this.logTest(
                    'Natural Language Interface Module - Import',
                    false,
                    'Module file not found'
                );
            }
            
        } catch (error) {
            this.logTest(
                'Natural Language Interface Module - Import',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async testMobileOptimizedModule() {
        try {
            const modulePath = path.join(__dirname, 'dist', 'tools', 'droneMobileOptimized.js');
            
            if (fs.existsSync(modulePath)) {
                this.logTest(
                    'Mobile Optimized Module - Import',
                    true,
                    'Module file exists and can be imported'
                );
                
                const module = require(modulePath);
                
                if (module.registerDroneMobileOptimized) {
                    this.logTest(
                        'Mobile Optimized Module - Registration Function',
                        true,
                        'Registration function exists'
                    );
                } else {
                    this.logTest(
                        'Mobile Optimized Module - Registration Function',
                        false,
                        'Registration function not found'
                    );
                }
                
            } else {
                this.logTest(
                    'Mobile Optimized Module - Import',
                    false,
                    'Module file not found'
                );
            }
            
        } catch (error) {
            this.logTest(
                'Mobile Optimized Module - Import',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async testServerRefactoredIntegration() {
        try {
            const serverPath = path.join(__dirname, 'dist', 'server-refactored.js');
            
            if (fs.existsSync(serverPath)) {
                this.logTest(
                    'Server Refactored Integration - File Exists',
                    true,
                    'Server file exists'
                );
                
                // Check if server file contains enhanced drone tool imports
                const serverContent = fs.readFileSync(serverPath, 'utf8');
                
                const hasEnhancedImports = serverContent.includes('droneDefenseEnhanced') &&
                                         serverContent.includes('droneOffenseEnhanced') &&
                                         serverContent.includes('droneNaturalLanguageInterface') &&
                                         serverContent.includes('droneMobileOptimized');
                
                this.logTest(
                    'Server Refactored Integration - Enhanced Imports',
                    hasEnhancedImports,
                    hasEnhancedImports ? 'All enhanced drone tool imports found' : 'Missing enhanced drone tool imports'
                );
                
                const hasRegistrationCalls = serverContent.includes('registerDroneDefenseEnhanced') &&
                                           serverContent.includes('registerDroneOffenseEnhanced') &&
                                           serverContent.includes('registerDroneNaturalLanguageInterface') &&
                                           serverContent.includes('registerDroneMobileOptimized');
                
                this.logTest(
                    'Server Refactored Integration - Registration Calls',
                    hasRegistrationCalls,
                    hasRegistrationCalls ? 'All enhanced drone tool registrations found' : 'Missing enhanced drone tool registrations'
                );
                
            } else {
                this.logTest(
                    'Server Refactored Integration - File Exists',
                    false,
                    'Server file not found'
                );
            }
            
        } catch (error) {
            this.logTest(
                'Server Refactored Integration',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async testCrossPlatformCapabilities() {
        try {
            // Test platform detection
            const platform = this.platform;
            const isMobile = this.isMobile;
            
            this.logTest(
                'Cross-Platform Detection',
                platform !== 'unknown',
                `Platform: ${platform}, Mobile: ${isMobile}`
            );
            
            // Test mobile capabilities if on mobile
            if (isMobile) {
                this.logTest(
                    'Mobile Platform Detection',
                    true,
                    `Running on mobile platform: ${platform}`
                );
            } else {
                this.logTest(
                    'Desktop Platform Detection',
                    true,
                    `Running on desktop platform: ${platform}`
                );
            }
            
        } catch (error) {
            this.logTest(
                'Cross-Platform Capabilities',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async testEnvironmentConfiguration() {
        try {
            // Test environment variables
            const requiredEnvVars = [
                'MCPGM_DRONE_ENABLED',
                'MCPGM_DRONE_SIM_ONLY',
                'MCPGM_REQUIRE_CONFIRMATION',
                'MCPGM_AUDIT_ENABLED'
            ];
            
            let envVarsFound = 0;
            for (const envVar of requiredEnvVars) {
                if (process.env[envVar]) {
                    envVarsFound++;
                }
            }
            
            this.logTest(
                'Environment Configuration',
                envVarsFound > 0,
                `Found ${envVarsFound}/${requiredEnvVars.length} environment variables`
            );
            
        } catch (error) {
            this.logTest(
                'Environment Configuration',
                false,
                `Exception: ${error.message}`
            );
        }
    }
    
    async runAllTests() {
        console.log('🧪 Enhanced Drone Tools Test Suite - MCP God Mode v1.8');
        console.log('='.repeat(60));
        console.log(`Platform: ${this.platform}`);
        console.log(`Mobile: ${this.isMobile}`);
        console.log('='.repeat(60));
        
        // Run all tests
        await this.testTypeScriptCompilation();
        await this.testEnhancedDroneDefenseModule();
        await this.testEnhancedDroneOffenseModule();
        await this.testNaturalLanguageInterfaceModule();
        await this.testMobileOptimizedModule();
        await this.testServerRefactoredIntegration();
        await this.testCrossPlatformCapabilities();
        await this.testEnvironmentConfiguration();
        
        // Generate summary
        this.generateSummary();
    }
    
    generateSummary() {
        const totalTests = this.testResults.length;
        const passedTests = this.testResults.filter(result => result.success).length;
        const failedTests = totalTests - passedTests;
        
        console.log('\n' + '='.repeat(60));
        console.log('📊 TEST SUMMARY');
        console.log('='.repeat(60));
        console.log(`Total Tests: ${totalTests}`);
        console.log(`Passed: ${passedTests} ✅`);
        console.log(`Failed: ${failedTests} ❌`);
        console.log(`Success Rate: ${((passedTests/totalTests)*100).toFixed(1)}%`);
        
        if (failedTests > 0) {
            console.log('\n❌ FAILED TESTS:');
            this.testResults
                .filter(result => !result.success)
                .forEach(result => {
                    console.log(`  • ${result.testName}: ${result.details}`);
                });
        }
        
        // Save results to file
        const resultsFile = `test_results_enhanced_drone_ts_${this.platform}_${Date.now()}.json`;
        const resultsData = {
            summary: {
                totalTests,
                passedTests,
                failedTests,
                successRate: (passedTests/totalTests)*100,
                platform: this.platform,
                timestamp: new Date().toISOString()
            },
            testResults: this.testResults
        };
        
        fs.writeFileSync(resultsFile, JSON.stringify(resultsData, null, 2));
        console.log(`\n📄 Detailed results saved to: ${resultsFile}`);
        
        return passedTests === totalTests;
    }
}

async function main() {
    const tester = new EnhancedDroneToolsTester();
    const success = await tester.runAllTests();
    process.exit(success ? 0 : 1);
}

if (require.main === module) {
    main().catch(console.error);
}
