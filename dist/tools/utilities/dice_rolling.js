import { z } from "zod";
export function registerDiceRolling(server) {
    server.registerTool("dice_rolling", {
        description: "Advanced dice rolling simulator for tabletop games",
        inputSchema: {
            dice_notation: z.string().describe("Dice notation (e.g., '2d6', '1d20', '3d8+5')"),
            count: z.number().optional().describe("Number of times to roll (default: 1)"),
            advantage: z.boolean().optional().describe("Roll with advantage (take highest of 2 rolls)"),
            disadvantage: z.boolean().optional().describe("Roll with disadvantage (take lowest of 2 rolls)")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            results: z.array(z.number()).optional(),
            total: z.number().optional(),
            notation: z.string().optional()
        }
    }, async ({ dice_notation, count, advantage, disadvantage }) => {
        try {
            // Parse dice notation (e.g., "2d6+5")
            const match = dice_notation.match(/^(\d+)d(\d+)([+-]\d+)?$/);
            if (!match) {
                throw new Error("Invalid dice notation. Use format like '2d6', '1d20+5'");
            }
            const numDice = parseInt(match[1]);
            const sides = parseInt(match[2]);
            const modifier = match[3] ? parseInt(match[3]) : 0;
            const rollCount = count || 1;
            const results = [];
            for (let i = 0; i < rollCount; i++) {
                let roll;
                if (advantage) {
                    const roll1 = Math.floor(Math.random() * sides) + 1;
                    const roll2 = Math.floor(Math.random() * sides) + 1;
                    roll = Math.max(roll1, roll2);
                }
                else if (disadvantage) {
                    const roll1 = Math.floor(Math.random() * sides) + 1;
                    const roll2 = Math.floor(Math.random() * sides) + 1;
                    roll = Math.min(roll1, roll2);
                }
                else {
                    roll = Math.floor(Math.random() * sides) + 1;
                }
                results.push(roll + modifier);
            }
            const total = results.reduce((sum, roll) => sum + roll, 0);
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Rolled ${dice_notation} ${rollCount} time(s)`,
                    results,
                    total,
                    notation: dice_notation
                }
            };
        }
        catch (error) {
            return { content: [], structuredContent: { success: false, message: `Dice rolling failed: ${error.message}` } };
        }
    });
}
