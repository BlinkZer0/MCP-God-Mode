import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as crypto from "node:crypto";

/**
 * Dice Rolling Tool
 * 
 * Cross-platform dice rolling with support for:
 * - Any sided dice (d4, d6, d8, d10, d12, d20, d100, etc.)
 * - Multiple dice (3d6, 2d20, etc.)
 * - Modifiers (+5, -2, etc.)
 * - Multiple rolls
 * 
 * Supports all 5 platforms: Windows, Linux, macOS, Android, iOS
 */

export function registerDiceRolling(server: any) {
  server.registerTool("dice_rolling", {
    description: "Roll dice with various configurations and get random numbers. Supports any sided dice, multiple dice, and modifiers.",
    inputSchema: {
      dice: z.string().describe("Dice notation (e.g., 'd6', '3d20', '2d10+5', 'd100'). Format: [count]d[sides][+/-modifier]"),
      count: z.number().optional().describe("Number of times to roll (default: 1)"),
      modifier: z.number().optional().describe("Additional modifier to apply to the final result (default: 0)")
    },
    outputSchema: {
      dice: z.string(),
      rolls: z.array(z.array(z.number())),
      total: z.number(),
      modifier: z.number(),
      breakdown: z.string()
    }
  }, async ({ dice, count = 1, modifier = 0 }: { dice: string; count?: number; modifier?: number }) => {
    try {
      // Parse dice notation (e.g., "3d20+5" -> { number: 3, sides: 20, modifier: 5 })
      const diceRegex = /^(\d+)?d(\d+)([+-]\d+)?$/;
      const match = dice.match(diceRegex);
      
      if (!match) {
        throw new Error(`Invalid dice notation: ${dice}. Use format like 'd6', '3d20', or '2d10+5'`);
      }
      
      const diceNumber = match[1] ? parseInt(match[1]) : 1;
      const diceSides = parseInt(match[2]);
      const diceModifier = match[3] ? parseInt(match[3]) : 0;
      
      if (diceSides < 1) {
        throw new Error(`Invalid dice sides: ${diceSides}. Must be at least 1.`);
      }
      
      if (diceNumber < 1) {
        throw new Error(`Invalid dice count: ${diceNumber}. Must be at least 1.`);
      }
      
      // Generate random rolls
      const rolls: number[][] = [];
      for (let i = 0; i < count; i++) {
        const diceRolls: number[] = [];
        for (let j = 0; j < diceNumber; j++) {
          // Cross-platform random number generation
          const roll = Math.floor(Math.random() * diceSides) + 1;
          diceRolls.push(roll);
        }
        rolls.push(diceRolls);
      }
      
      // Calculate totals
      const totals = rolls.map(diceRolls => 
        diceRolls.reduce((sum, roll) => sum + roll, 0) + diceModifier + modifier
      );
      
      const total = totals.reduce((sum, t) => sum + t, 0);
      
      // Create breakdown string
      const breakdown = rolls.map((diceRolls, index) => {
        const diceTotal = diceRolls.reduce((sum, roll) => sum + roll, 0) + diceModifier + modifier;
        const diceBreakdown = diceRolls.join(' + ');
        return `Roll ${index + 1}: [${diceBreakdown}] + ${diceModifier + modifier} = ${diceTotal}`;
      }).join('\n');
      
      return {
        content: [],
        structuredContent: {
          dice: dice,
          rolls: rolls,
          total: total,
          modifier: modifier + diceModifier,
          breakdown: breakdown
        }
      };
      
    } catch (error) {
      throw new Error(`Dice rolling error: ${error instanceof Error ? error.message : String(error)}`);
    }
  });
}

/**
 * Alternative implementation for environments that need more secure random numbers
 * Uses crypto.randomBytes when available, falls back to Math.random
 */
export function generateSecureRandom(min: number, max: number): number {
  try {
    // Try to use crypto.randomBytes for more secure random numbers
    if (typeof crypto !== 'undefined' && crypto.randomBytes) {
      const bytes = crypto.randomBytes(4);
      const value = bytes.readUInt32BE(0);
      const range = max - min + 1;
      return min + (value % range);
    }
  } catch {
    // Fallback to Math.random if crypto.randomBytes is not available
  }
  
  // Fallback to Math.random (still works across all platforms)
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Parse dice notation and return components
 */
export function parseDiceNotation(dice: string): { number: number; sides: number; modifier: number } {
  const diceRegex = /^(\d+)?d(\d+)([+-]\d+)?$/;
  const match = dice.match(diceRegex);
  
  if (!match) {
    throw new Error(`Invalid dice notation: ${dice}`);
  }
  
  return {
    number: match[1] ? parseInt(match[1]) : 1,
    sides: parseInt(match[2]),
    modifier: match[3] ? parseInt(match[3]) : 0
  };
}

/**
 * Roll a single die with specified sides
 */
export function rollDie(sides: number): number {
  return generateSecureRandom(1, sides);
}

/**
 * Roll multiple dice and return results
 */
export function rollDice(count: number, sides: number): number[] {
  const results: number[] = [];
  for (let i = 0; i < count; i++) {
    results.push(rollDie(sides));
  }
  return results;
}
