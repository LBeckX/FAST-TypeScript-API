import {emailConfig} from "../config/email.config.js";
import path from "node:path";
import Email from "email-templates";

export class EmailService {
    static emailBaseConfig: Email.EmailConfig = {
        message: {
            from: emailConfig.from,
        },
        send: !emailConfig.debug,
        preview: emailConfig.debug,
        transport: {
            from: emailConfig.from,
            host: emailConfig.host,
            port: emailConfig.port,
            secure: emailConfig.secure,
            auth: {
                user: emailConfig.user,
                pass: emailConfig.password,
            },
            logger: true,
            debug: emailConfig.debug,
        },
        juice: true,
        juiceResources: {
            applyStyleTags: true,
            webResources: {
                relativeTo: path.resolve('emails')
            }
        },
    }

    static email = new Email(EmailService.emailBaseConfig);

    static async sendRegistration(args: {
        email: string,
        returnUrl: string,
        token: string
    }) {
        return EmailService.email.send({
            template: 'registration',
            message: {
                to: args.email
            },
            locals: args,
        })
    }
}