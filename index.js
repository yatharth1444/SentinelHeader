#!/usr/bin/env node


const fs = require("fs");
const https = require("https");
const axios = require("axios");
const { Command } = require("commander");
const oraImport = require("ora");
const chalkImport = require("chalk");

const ora = oraImport.default || oraImport;
const chalk = chalkImport.default || chalkImport;

// CLI
const program = new Command();
program
  .option("-u, --url <url>", "Target URL to scan")
  .option("-f, --file <path>", "File with list of URLs to scan")
  .parse(process.argv);

const { url, file } = program.opts();

if (!url && !file) {
  console.error(chalk.red("Please provide either --url or --file."));
  process.exit(1);
}

// softer red for warnings
const softRed = chalk.hex("#cc4444");

// helper: safe header lookup
function getHeader(headers, name) {
  const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

// recommendations
const snippets = {
  "Content-Security-Policy": {
    nginx: `add_header Content-Security-Policy "default-src 'self';" always;`,
    apache: `Header set Content-Security-Policy "default-src 'self';"`,
    express: `app.use((req,res,next)=>{res.setHeader("Content-Security-Policy","default-src 'self'");next();});`
  },
  "Strict-Transport-Security": {
    nginx: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
    apache: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"`,
    express: `app.use((req,res,next)=>{res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains; preload");next();});`
  },
  "X-Frame-Options": {
    nginx: `add_header X-Frame-Options "DENY" always;`,
    apache: `Header always set X-Frame-Options "DENY"`,
    express: `app.use((req,res,next)=>{res.setHeader("X-Frame-Options","DENY");next();});`
  },
  "X-Content-Type-Options": {
    nginx: `add_header X-Content-Type-Options "nosniff" always;`,
    apache: `Header always set X-Content-Type-Options "nosniff"`,
    express: `app.use((req,res,next)=>{res.setHeader("X-Content-Type-Options","nosniff");next();});`
  },
  "Referrer-Policy": {
    nginx: `add_header Referrer-Policy "no-referrer-when-downgrade" always;`,
    apache: `Header always set Referrer-Policy "no-referrer-when-downgrade"`,
    express: `app.use((req,res,next)=>{res.setHeader("Referrer-Policy","no-referrer-when-downgrade");next();});`
  },
  "Permissions-Policy": {
    nginx: `add_header Permissions-Policy "geolocation=(), microphone=()" always;`,
    apache: `Header set Permissions-Policy "geolocation=(), microphone=()"`,
    express: `app.use((req,res,next)=>{res.setHeader("Permissions-Policy","geolocation=(), microphone=()");next();});`
  }
};

// big six check
function analyzeBigSix(headers) {
  const results = [];

  const csp = getHeader(headers, "content-security-policy") || getHeader(headers, "content-security-policy-report-only");
  if (!csp) {
    results.push({ name: "Content-Security-Policy", found: false, note: "Missing CSP — prevents XSS" });
  } else {
    const lower = String(csp).toLowerCase();
    const weak = lower.includes("unsafe-inline") || lower.includes("unsafe-eval") || /default-src\s+['"]?\*/.test(lower);
    results.push({ name: "Content-Security-Policy", found: true, value: csp, weak, note: weak ? "CSP weak — avoid unsafe-inline/eval" : "Good CSP" });
  }

  const hsts = getHeader(headers, "strict-transport-security");
  if (!hsts) {
    results.push({ name: "Strict-Transport-Security", found: false, note: "Missing HSTS — enforces HTTPS" });
  } else {
    const maxAge = parseInt((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1] || 0);
    const includeSub = /includesubdomains/i.test(hsts);
    const good = maxAge >= 31536000 && includeSub;
    results.push({ name: "Strict-Transport-Security", found: true, value: hsts, weak: !good, note: good ? "Strong HSTS" : "HSTS weak — increase max-age & includeSubDomains" });
  }

  const xfo = getHeader(headers, "x-frame-options");
  if (!xfo) {
    results.push({ name: "X-Frame-Options", found: false, note: "Missing — prevents clickjacking" });
  } else {
    const val = String(xfo).toLowerCase();
    const good = ["deny", "sameorigin"].some(v => val.includes(v));
    results.push({ name: "X-Frame-Options", found: true, value: xfo, weak: !good, note: good ? "Good X-Frame-Options" : "Non-standard value" });
  }

  const xcto = getHeader(headers, "x-content-type-options");
  if (!xcto) {
    results.push({ name: "X-Content-Type-Options", found: false, note: "Missing — prevents MIME sniffing" });
  } else {
    results.push({ name: "X-Content-Type-Options", found: true, value: xcto, weak: !/nosniff/i.test(xcto), note: /nosniff/i.test(xcto) ? "Correct nosniff" : "Incorrect value" });
  }

  const refp = getHeader(headers, "referrer-policy");
  if (!refp) {
    results.push({ name: "Referrer-Policy", found: false, note: "Missing — controls referrer leakage" });
  } else {
    results.push({ name: "Referrer-Policy", found: true, value: refp, note: "Present" });
  }

  const perm = getHeader(headers, "permissions-policy");
  if (!perm) {
    results.push({ name: "Permissions-Policy", found: false, note: "Missing — restricts features" });
  } else {
    results.push({ name: "Permissions-Policy", found: true, value: perm, note: "Present" });
  }

  return results;
}

// SSL expiry check
function checkSSLCertExpiry(hostname) {
  return new Promise((resolve, reject) => {
    const socket = https.connect({ host: hostname, port: 443, servername: hostname }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();

      if (!cert || !cert.valid_to) {
        return reject("No valid SSL certificate found.");
      }

      const expiryDate = new Date(cert.valid_to);
      const daysLeft = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
      resolve({ expiryDate, daysLeft });
    });

    socket.on("error", reject);
  });
}

// fetch + scan
async function scanURL(targetUrl) {
  const spinner = ora(`Scanning ${targetUrl}...`).start();
  try {
    const { hostname } = new URL(targetUrl);

    // SSL check
    let sslInfo;
    try {
      sslInfo = await checkSSLCertExpiry(hostname);
    } catch (e) {
      sslInfo = { error: e };
    }

    const res = await axios.get(targetUrl, {
      timeout: 15000,
      headers: { "User-Agent": "Mozilla/5.0 SecurityScanner/1.0" },
      maxRedirects: 5
    });

    spinner.succeed(`Headers fetched from ${targetUrl}`);
    const server = getHeader(res.headers, "server") || "Unknown";

    console.log(chalk.bold(`\nServer:`), chalk.cyan(server));
    if (sslInfo.error) {
      console.log(softRed(`[!] SSL: ${sslInfo.error}`));
    } else {
      if (sslInfo.daysLeft < 15) {
        console.log(chalk.yellow(`[!] SSL expires in ${sslInfo.daysLeft} days — renew soon!`));
      } else {
        console.log(chalk.green(`[+] SSL valid until ${sslInfo.expiryDate.toDateString()} (${sslInfo.daysLeft} days left)`));
      }
    }

    const results = analyzeBigSix(res.headers);
    console.log(chalk.bold("\nSecurity Headers Check:"));
    results.forEach(r => {
      if (!r.found) {
        console.log(softRed(`[Missing] ${r.name}: ${r.note}`));
        const s = snippets[r.name];
        if (s) console.log(chalk.gray(`   Fix (Nginx): ${s.nginx}`));
      } else if (r.weak) {
        console.log(chalk.keyword("orange")(`[Weak] ${r.name}: ${r.note}`));
      } else {
        console.log(chalk.green(`[OK] ${r.name}: ${r.note}`));
      }
    });

  } catch (err) {
    spinner.fail(`Failed to scan ${targetUrl}: ${err.message}`);
  }
}

// run
(async () => {
  if (file) {
    const urls = fs.readFileSync(file, "utf-8").split("\n").map(u => u.trim()).filter(Boolean);
    for (const u of urls) {
      await scanURL(u);
    }
  } else {
    await scanURL(url);
  }
})();
