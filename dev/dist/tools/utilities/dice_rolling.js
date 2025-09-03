"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerDiceRolling = registerDiceRolling;
exports.generateSecureRandom = generateSecureRandom;
exports.parseDiceNotation = parseDiceNotation;
exports.rollDie = rollDie;
exports.rollDice = rollDice;
const zod_1 = require("zod");
const crypto = __importStar(require("node:crypto"));
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
function registerDiceRolling(server) {
    server.registerTool("dice_rolling", {
        description: "Roll dice with various configurations and get random numbers. Supports any sided dice, multiple dice, and modifiers.",
        inputSchema: {
            dice: zod_1.z.string().describe("Dice notation (e.g., 'd6', '3d20', '2d10+5', 'd100'). Format: [count]d[sides][+/-modifier]"),
            count: zod_1.z.number().optional().describe("Number of times to roll (default: 1)"),
            modifier: zod_1.z.number().optional().describe("Additional modifier to apply to the final result (default: 0)")
        },
        outputSchema: {
            dice: zod_1.z.string(),
            rolls: zod_1.z.array(zod_1.z.array(zod_1.z.number())),
            total: zod_1.z.number(),
            modifier: zod_1.z.number(),
            breakdown: zod_1.z.string()
        }
    }, async ({ dice, count = 1, modifier = 0 }) => {
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
            const rolls = [];
            for (let i = 0; i < count; i++) {
                const diceRolls = [];
                for (let j = 0; j < diceNumber; j++) {
                    // Cross-platform random number generation
                    const roll = Math.floor(Math.random() * diceSides) + 1;
                    diceRolls.push(roll);
                }
                rolls.push(diceRolls);
            }
            // Calculate totals
            const totals = rolls.map(diceRolls => diceRolls.reduce((sum, roll) => sum + roll, 0) + diceModifier + modifier);
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
        }
        catch (error) {
            throw new Error(`Dice rolling error: ${error instanceof Error ? error.message : String(error)}`);
        }
    });
}
/**
 * Alternative implementation for environments that need more secure random numbers
 * Uses crypto.randomBytes when available, falls back to Math.random
 */
function generateSecureRandom(min, max) {
    try {
        // Try to use crypto.randomBytes for more secure random numbers
        if (typeof crypto !== 'undefined' && crypto.randomBytes) {
            const bytes = crypto.randomBytes(4);
            const value = bytes.readUInt32BE(0);
            const range = max - min + 1;
            return min + (value % range);
        }
    }
    catch {
        // Fallback to Math.random if crypto.randomBytes is not available
    }
    // Fallback to Math.random (still works across all platforms)
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
/**
 * Parse dice notation and return components
 */
function parseDiceNotation(dice) {
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
function rollDie(sides) {
    return generateSecureRandom(1, sides);
}
/**
 * Roll multiple dice and return results
 */
function rollDice(count, sides) {
    const results = [];
    for (let i = 0; i < count; i++) {
        results.push(rollDie(sides));
    }
    return results;
}
