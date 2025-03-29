import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import { URL } from "url";
import path from "path";
import Chart from 'chart.js/auto';

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.static("user_webpage"));

// Serve index.html as the default page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "user_webpage", "index.html"));
});

const extractDomain = (url) => {
    try {
        const hostname = new URL(url).hostname;
        return hostname.startsWith("www.") ? hostname.slice(4) : hostname;
    } catch (error) {
        return null;
    }
};

const fetchASN = async (ip) => {
    try {
        const response = await fetch(`https://api.iptoasn.com/v1/as/ip/${ip}`);
        const data = await response.json();
        return data.asn || "Unknown";
    } catch (error) {
        return "Error";
    }
};

app.get("/check-dns", async (req, res) => {
    const url = req.query.url;
    const domain = extractDomain(url);

    if (!domain) {
        return res.json({ error: "Invalid URL format. Please enter a valid website URL." });
    }

    try {
        const resolvers = {
            google: `https://dns.google/resolve?name=${domain}&type=A`,
            cloudflare: `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`
        };

        const fetchDNS = async (url) => {
            try {
                const response = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
                const data = await response.json();
                return data.Answer ? data.Answer.map(a => a.data)[0] : "Error";
            } catch (error) {
                return "Error";
            }
        };

        const [googleIP, cloudflareIP] = await Promise.all([
            fetchDNS(resolvers.google),
            fetchDNS(resolvers.cloudflare)
        ]);

        let isSpoofed = false;
        let message = "✅ No Spoofing Detected!";

        if (googleIP === "Error" || cloudflareIP === "Error") {
            isSpoofed = true;
            message = "⚠️ Possible DNS Manipulation Detected!";
        } else if (googleIP !== cloudflareIP) {
            const [googleASN, cloudflareASN] = await Promise.all([
                fetchASN(googleIP),
                fetchASN(cloudflareIP)
            ]);

            if (googleASN !== cloudflareASN) {
                isSpoofed = true;
                message = "⚠️ Possible DNS Spoofing Detected!";
            }
        }

        res.json({
            spoofed: message,
            extractedDomain: domain,
            googleDNS: googleIP,
            cloudflareDNS: cloudflareIP
        });
    } catch (error) {
        console.error(error);
        res.json({ error: "Failed to fetch DNS records." });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});
