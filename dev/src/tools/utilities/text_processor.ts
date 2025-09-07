import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM } from "../../config/environment.js";

export function registerTextProcessor(server: McpServer) {
  server.registerTool("text_processor", {
    description: "Text processing and manipulation utilities",
    inputSchema: {
      action: z.enum(["count_words", "count_chars", "find_replace", "extract_emails", "extract_urls", "format_case", "remove_duplicates"]).describe("Text processing action to perform"),
      text: z.string().describe("Input text to process"),
      find_text: z.string().optional().describe("Text to find for replace operations"),
      replace_text: z.string().optional().describe("Text to replace with"),
      case_type: z.enum(["lowercase", "uppercase", "titlecase", "sentencecase"]).optional().describe("Case formatting type")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      result: z.string().optional(),
      statistics: z.object({
        word_count: z.number().optional(),
        char_count: z.number().optional(),
        line_count: z.number().optional(),
        email_count: z.number().optional(),
        url_count: z.number().optional()
      }).optional()
    }
  }, async ({ action, text, find_text, replace_text, case_type }) => {
    try {
      // Text processing implementation
      let result = "";
      let statistics = {};
      
      switch (action) {
        case "count_words":
          const wordCount = text.trim().split(/\s+/).filter(word => word.length > 0).length;
          statistics = { word_count: wordCount };
          result = `Word count: ${wordCount}`;
          break;
        case "count_chars":
          const charCount = text.length;
          const lineCount = text.split('\n').length;
          statistics = { char_count: charCount, line_count: lineCount };
          result = `Character count: ${charCount}, Line count: ${lineCount}`;
          break;
        case "find_replace":
          if (find_text && replace_text) {
            result = text.replace(new RegExp(find_text, 'g'), replace_text);
            statistics = { char_count: result.length };
          }
          break;
        case "extract_emails":
          const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
          const emails = text.match(emailRegex) || [];
          result = emails.join(', ');
          statistics = { email_count: emails.length };
          break;
        case "extract_urls":
          const urlRegex = /https?:\/\/[^\s]+/g;
          const urls = text.match(urlRegex) || [];
          result = urls.join(', ');
          statistics = { url_count: urls.length };
          break;
        case "format_case":
          switch (case_type) {
            case "lowercase":
              result = text.toLowerCase();
              break;
            case "uppercase":
              result = text.toUpperCase();
              break;
            case "titlecase":
              result = text.replace(/\w\S*/g, (txt) => txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase());
              break;
            case "sentencecase":
              result = text.toLowerCase().replace(/(^\w|\.\s+\w)/g, (letter) => letter.toUpperCase());
              break;
            default:
              result = text;
          }
          statistics = { char_count: result.length };
          break;
        case "remove_duplicates":
          const lines = text.split('\n');
          const uniqueLines = Array.from(new Set(lines));
          result = uniqueLines.join('\n');
          statistics = { line_count: uniqueLines.length };
          break;
      }
      
      return { 
        content: [], 
        structuredContent: { 
          success: true, 
          message: `Text processing completed successfully: ${action}`,
          result,
          statistics
        } 
      };
    } catch (error) {
      return { content: [], structuredContent: { success: false, message: `Text processing failed: ${(error as Error).message}` } };
    }
  });
}
