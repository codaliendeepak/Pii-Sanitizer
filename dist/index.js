"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const node_crypto_1 = require("node:crypto");
class Sanitizer {
    constructor(cfg) {
        this.cfg = cfg;
        if (!this.cfg?.signingSecret)
            throw new Error('signingSecret is required');
    }
    sanitizeObject(obj, route) {
        if (this.cfg.disable)
            return obj;
        // Route allow/deny logic (defensive)
        if (this.cfg.allowlistRoutes && !this.cfg.allowlistRoutes.includes(route))
            return obj;
        if (this.cfg.denylistRoutes && this.cfg.denylistRoutes.includes(route))
            return obj;
        const sanitizedObjectValue = this.walk(obj, []);
        return sanitizedObjectValue;
    }
    decodeBody(object) {
        if (object && typeof object == "object" && !Array.isArray(object)) {
            const out = {};
            for (const [k, v] of Object.entries(object)) {
                out[k] = this.decodeBody(v);
            }
            return out;
        }
        //if it is array 
        if (Array.isArray(object)) {
            return object.map((item) => this.decodeBody(item));
        }
        //if it is encoded
        if (typeof object == "string" && object.includes(':')) {
            return this.decodeValue(object);
        }
        return object;
    }
    expressMiddleware() {
        return (req, res, next) => {
            const route = req.url || '';
            const body = req.body;
            //zero to check for route if present in skip list or allow list 
            if ((this.cfg.allowlistRoutes && !this.cfg.allowlistRoutes.includes(route)) || (this.cfg.denylistRoutes && this.cfg.denylistRoutes.includes(route))) {
                return next();
            }
            else {
                req.body = this.sanitizeObject(body, route);
            }
            return next();
        };
    }
    detectPatternToSanitize(key, value) {
        //if key is similar to or has some of the pii type or the value is a pii pattern type return the piitype 
        //for pan card assuming it is capital case 
        let lowerKey = key.toLowerCase();
        if (/^[A-Z]{5}\d{4}[A-Z]$/g.test(value) || /pan|pan_card/.test(lowerKey)) {
            return "pan_card";
        }
        if (/^\d{10}/g.test(value) || /mobile|phone/.test(lowerKey)) {
            return "phone";
        }
        if (/^\d{12}/g.test(value)) {
            return "aadhar";
        }
        if (/cvv|cvc|cvn|cid/.test(lowerKey) || /\d{2,4}/.test(value)) {
            return "cvv";
        }
        if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/.test(value)) {
            return "email";
        }
        if (/password|pwd|passphrase/.test(lowerKey)) {
            return "password";
        }
        if ((/credit|debit/.test(lowerKey)) || (value.length > 13 && value.length < 19 && this.luhnAlgorithm(value))) {
            return "credit_card";
        }
        return "custom";
    }
    luhnAlgorithm(num) {
        let sum = 0;
        let alt = false;
        //detect even position number from right and double them if greater than 9 then and add their digits  
        for (let i = num.length - 1; i >= 0; i--) {
            let n = parseInt(num[i], 10);
            if (alt) {
                n *= 2;
                if (n > 9)
                    n -= 9;
            }
            sum += n;
            alt = !alt;
        }
        return sum % 10 === 0;
    }
    maskPattern(piiType, val) {
        switch (piiType) {
            case 'aadhar':
                return this.encodeValue(val); // replace(/^\d{4}\d{4}(\d{4})$/, 'XXXXX$1');
            case 'credit_card':
                return this.encodeValue(val); // replace(/^(\d{4})$/g,'XXXXX$1');
            case 'email':
                return this.encodeValue(val);
            // const [user, domain] = val.split('@');
            // return user[0] + "****@" + domain;
            case 'cvv':
                return this.encodeValue(val); // replace(/(\d{1})\d/,'$1XXXX');
            case 'pan_card':
                return this.encodeValue(val); //replace(/^(.{2})(.*)(.{2})$/, (m, f, mid, l) => f + "XXXXXX" + l );
            case 'password':
                return this.encodeValue(val);
            case 'phone':
                return this.encodeValue(val); // replace(/.(?=.{2})/g, 'X');
            case 'custom':
            default:
                return this.encodeValue(val); // replace(/./g, 'X');
        }
    }
    // Always derive a proper 32-byte key from signingSecret
    getKey() {
        return (0, node_crypto_1.createHash)("sha256").update(this.cfg.signingSecret).digest();
    }
    encodeValue(val) {
        const iv = (0, node_crypto_1.randomBytes)(16);
        const key = this.getKey();
        const cipher = (0, node_crypto_1.createCipheriv)("aes-256-ctr", key, iv);
        const encrypted = Buffer.concat([cipher.update(val, "utf8"), cipher.final()]);
        const encryptedValue = iv.toString("hex") + ":" + encrypted.toString("hex");
        return encryptedValue;
    }
    decodeValue(data) {
        const [ivHex, encryptedHex] = data.split(":");
        const iv = Buffer.from(ivHex, "hex");
        const encryptedText = Buffer.from(encryptedHex, "hex");
        const decipher = (0, node_crypto_1.createDecipheriv)("aes-256-ctr", this.getKey(), iv);
        const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        return decrypted.toString("utf8");
    }
    walk(val, path) {
        if (val && typeof val === "object" && !Array.isArray(val)) {
            const out = {};
            for (const [k, v] of Object.entries(val)) {
                out[k] = this.walk(v, [...path, k]);
            }
            return out;
        }
        if (typeof (val) == "string") {
            const key = path[path.length - 1];
            //first check if to check for fields to sanitize and fields to skip if present sanitize those 
            if (this.cfg.fieldsToSkip?.includes(key))
                return val;
            //second to check if the regex is present will  only detect that regex 
            if (this.cfg.regexToSanitize?.length) {
                for (const reStr of this.cfg.regexToSanitize) {
                    const re = new RegExp(reStr, "g");
                    if (re.test(val)) {
                        return val.replace(re, (m) => this.maskPattern('custom', m));
                    }
                }
            }
            //third check if fields are present
            if (this.cfg.fieldsToSanitize) {
                if (this.cfg.fieldsToSanitize.includes(key)) {
                    const piiType = this.detectPatternToSanitize(key, val);
                    return this.maskPattern(piiType, val);
                }
                else {
                    return val;
                }
            }
            //by default
            //check if detectors are present it will check for the all by default detect regex for all the pii types
            // detectors (auto detection)
            const piiType = this.detectPatternToSanitize(key, val);
            if (piiType !== 'custom') {
                return this.maskPattern(piiType, val);
            }
            return val;
        }
    }
}
module.exports = { Sanitizer };
