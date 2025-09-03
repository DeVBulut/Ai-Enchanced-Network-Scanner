// Simple logging utility for the DDoS Detection System
class Logger {
    constructor(level = 'INFO') {
        this.levels = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3 };
        this.currentLevel = this.levels[level.toUpperCase()] || 1;
    }

    log(level, message, ...args) {
        if (this.levels[level] <= this.currentLevel) {
            const timestamp = new Date().toISOString();
            const prefix = `[${timestamp}] [${level}]`;
            console.log(prefix, message, ...args);
        }
    }

    error(message, ...args) { this.log('ERROR', message, ...args); }
    warn(message, ...args) { this.log('WARN', message, ...args); }
    info(message, ...args) { this.log('INFO', message, ...args); }
    debug(message, ...args) { this.log('DEBUG', message, ...args); }
}

export const logger = new Logger(process.env.LOG_LEVEL || 'INFO');
export default Logger;
