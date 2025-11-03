import fetch from 'node-fetch';
import { CONFIG } from './config.js';
import { logger } from './logger.js';

let currentAgentIndex = 0;

function selectNextAgent() {
    const agent = CONFIG.LLM_AGENTS[currentAgentIndex];
    currentAgentIndex = (currentAgentIndex + 1) % CONFIG.LLM_AGENTS.length;
    return agent;
}

export async function queryLLM(promptText, options = {}) {
    const maxRetries = options.maxRetries || 3;
    const timeout = options.timeout || CONFIG.LLM_TIMEOUT;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            logger.debug(`LLM query attempt ${attempt}/${maxRetries}`);
            
            const agent = selectNextAgent();
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);
            
            const response = await fetch(agent.endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: agent.model,
                    prompt: promptText,
                    stream: false
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            
            if (!result.response) {
                throw new Error('Empty response from LLM');
            }
            
            logger.debug('LLM query successful');
            return result.response;
            
        } catch (error) {
            logger.warn(`LLM query attempt ${attempt} failed:`, error.message);
            
            if (attempt === maxRetries) {
                throw new Error(`LLM query failed after ${maxRetries} attempts: ${error.message}`);
            }
            
            // Exponential backoff
            const delay = Math.pow(2, attempt) * 1000;
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

export function generateDDoSPrompt(flaggedEntry, analysisType = 'explanation') {
    const basePrompt = `You are a cybersecurity expert. Analyze this suspicious log entry in 2-3 sentences maximum:

IP: ${flaggedEntry.sourceIP || 'N/A'}
Requests: ${flaggedEntry.requestCount || 'N/A'}
Time: ${flaggedEntry.timestamp || 'N/A'}
Risk Score: ${flaggedEntry.riskScore || 'N/A'}

`;

    if (analysisType === 'explanation') {
        return basePrompt + `Briefly explain why this might indicate a DDoS attack. Keep response under 100 words.`;
    } else if (analysisType === 'anomaly') {
        return basePrompt + `Suggest 1-2 specific detection rules for this pattern. Keep response under 100 words.`;
    }

    return basePrompt + 'Briefly analyze this entry for DDoS indicators. Keep response under 100 words.';
}

export async function getDDoSExplanation(flaggedEntry) {
    const prompt = generateDDoSPrompt(flaggedEntry, 'explanation');
    return await queryLLM(prompt);
}

export async function getAnomalyDetectionSuggestions(flaggedEntry) {
    const prompt = generateDDoSPrompt(flaggedEntry, 'anomaly');
    return await queryLLM(prompt);
}

export async function getSummaryAnalysis(flaggedEntries) {
    const entriesSummary = flaggedEntries.map((flaggedEntry, index) => 
        `${index + 1}. IP: ${flaggedEntry.sourceIP}, Requests: ${flaggedEntry.requestCount}, Risk: ${flaggedEntry.riskScore}`
    ).join('\n');

    const prompt = `You are a cybersecurity expert. Analyze these suspicious entries in 3-4 sentences maximum:

${entriesSummary}

Provide a brief threat assessment and 1-2 immediate actions. Keep response under 150 words.`;

    return await queryLLM(prompt);
} 