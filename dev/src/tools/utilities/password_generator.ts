import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerPasswordGenerator(server: McpServer) {
  server.registerTool("password_generator", {
    description: "Secure password generation with customizable options",
    inputSchema: {
      length: z.number().optional().describe("Password length (default: 16)"),
      include_uppercase: z.boolean().optional().describe("Include uppercase letters"),
      include_lowercase: z.boolean().optional().describe("Include lowercase letters"),
      include_numbers: z.boolean().optional().describe("Include numbers"),
      include_symbols: z.boolean().optional().describe("Include special symbols"),
      exclude_similar: z.boolean().optional().describe("Exclude similar characters (l, 1, I, O, 0)"),
      exclude_ambiguous: z.boolean().optional().describe("Exclude ambiguous characters")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      password: z.string().optional(),
      strength: z.string().optional(),
      entropy: z.number().optional()
    }
  }, async ({ length, include_uppercase, include_lowercase, include_numbers, include_symbols, exclude_similar, exclude_ambiguous }) => {
    try {
      // Password generation implementation
      const passwordLength = length || 16;
      const useUppercase = include_uppercase !== false;
      const useLowercase = include_lowercase !== false;
      const useNumbers = include_numbers !== false;
      const useSymbols = include_symbols !== false;
      
      let charset = "";
      if (useUppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (useLowercase) charset += "abcdefghijklmnopqrstuvwxyz";
      if (useNumbers) charset += "0123456789";
      if (useSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";
      
      if (exclude_similar) {
        charset = charset.replace(/[l1IO0]/g, '');
      }
      
      if (exclude_ambiguous) {
        charset = charset.replace(/[{}[\]()/\\'"`~,;:.<>]/g, '');
      }
      
      let password = "";
      for (let i = 0; i < passwordLength; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
      }
      
      // Calculate entropy (bits of randomness)
      const entropy = Math.log2(Math.pow(charset.length, passwordLength));
      
      // Determine strength
      let strength = "weak";
      if (entropy >= 128) strength = "very strong";
      else if (entropy >= 64) strength = "strong";
      else if (entropy >= 32) strength = "medium";
      
      return { 
        content: [], 
        structuredContent: { 
          success: true, 
          message: `Password generated successfully with ${passwordLength} characters`,
          password,
          strength,
          entropy: Math.round(entropy)
        } 
      };
    } catch (error) {
      return { content: [], structuredContent: { success: false, message: `Password generation failed: ${(error as Error).message}` } };
    }
  });
}
