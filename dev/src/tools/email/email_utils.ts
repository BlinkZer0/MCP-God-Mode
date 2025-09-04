import * as nodemailer from "nodemailer";

// Email configuration cache
const emailTransports = new Map<string, any>();

export async function getEmailTransport(config: any) {
  const cacheKey = `${config.service}-${config.email}-${config.host || 'default'}`;
  
  if (emailTransports.has(cacheKey)) {
    return emailTransports.get(cacheKey);
  }

  let transport;
  
  if (config.service === 'gmail') {
    transport = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: config.email,
        pass: config.password
      }
    });
  } else if (config.service === 'outlook') {
    transport = nodemailer.createTransport({
      host: 'smtp-mail.outlook.com',
      port: 587,
      secure: false,
      auth: {
        user: config.email,
        pass: config.password
      }
    });
  } else if (config.service === 'yahoo') {
    transport = nodemailer.createTransport({
      host: 'smtp.mail.yahoo.com',
      port: 587,
      secure: false,
      auth: {
        user: config.email,
        pass: config.password
      }
    });
  } else {
    transport = nodemailer.createTransport({
      host: config.host,
      port: config.port || 587,
      secure: config.secure || false,
      auth: {
        user: config.email,
        pass: config.password
      }
    });
  }

  // Test the connection
  try {
    await transport.verify();
    emailTransports.set(cacheKey, transport);
    return transport;
  } catch (error) {
    return {
          content: [{ type: "text", text: `Error: ${`Failed to create email transport: ${error}`}` }],
          structuredContent: {
            success: false,
            error: `${`Failed to create email transport: ${error}`}`
          }
        };
  }
}

export function extractLinksFromText(text: string): string[] {
  const urlRegex = /https?:\/\/[^\s]+/g;
  return text.match(urlRegex) || [];
}

export function extractEmailsFromText(text: string): string[] {
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  return text.match(emailRegex) || [];
}
