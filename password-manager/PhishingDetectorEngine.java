import java.util.HashMap;
import java.util.LinkedList;

public class PhishingDetectorEngine {

    private final PhishingTrie trustedDomainTrie;
    private final HashMap<Character, Character> homoglyphMap;
    private final HashMap<String, Integer> scoreWeights;
    private final LinkedList<String> reasons;
    private boolean criticalThreat;
    private int totalScore;

    public PhishingDetectorEngine() {
        trustedDomainTrie = new PhishingTrie();
        homoglyphMap = new HashMap<>();
        scoreWeights = new HashMap<>();
        reasons = new LinkedList<>();
        initTrustedDomains();
        initHomoglyphMap();
        initScoreWeights();
    }

    public PhishingAnalysisResult analyze(String inputUrl) {
        PhishingURLParser parser = new PhishingURLParser();
        parser.parse(inputUrl);
        reasons.clear();
        totalScore = 0;
        criticalThreat = false;

        checkTrustedDomain(parser);
        checkHTTPS(parser);
        checkBrandMisuse(parser);
        checkHomoglyph(parser);
        checkPunycode(parser);
        checkShortener(parser);
        checkTLD(parser);
        checkSubdomain(parser);
        checkHyphen(parser);
        checkKeywords(parser);
        checkIPAddress(parser);

        int finalScore = criticalThreat ? Math.max(totalScore, 11) : totalScore;

        return new PhishingAnalysisResult(
            inputUrl,
            finalScore,
            PhishingScoreEngine.getVerdict(finalScore),
            PhishingScoreEngine.getVerdictDetail(finalScore),
            reasons,
            parser.protocol,
            parser.domain,
            parser.subdomain,
            parser.rootDomain,
            parser.tld,
            parser.path
        );
    }

    private void initTrustedDomains() {
        String[] domains = {
            "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotakbank.com",
            "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
            "indusind.com", "yesbank.in", "paytm.com", "phonepe.com", "razorpay.com",
            "mobikwik.com", "paypal.com", "wise.com", "stripe.com", "mastercard.com",
            "visa.com", "google.com", "gmail.com", "youtube.com", "microsoft.com",
            "apple.com", "github.com", "stackoverflow.com", "linkedin.com", "zoom.us",
            "dropbox.com", "slack.com", "notion.so", "atlassian.com", "amazon.com",
            "amazon.in", "flipkart.com", "myntra.com", "meesho.com", "snapdeal.com",
            "ebay.com", "shopify.com", "facebook.com", "instagram.com", "twitter.com",
            "whatsapp.com", "reddit.com", "pinterest.com", "telegram.org", "netflix.com",
            "hotstar.com", "spotify.com", "primevideo.com", "jiocinema.com", "wikipedia.org",
            "khanacademy.org", "coursera.org", "udemy.com", "nptel.ac.in", "gov.in",
            "uidai.gov.in", "irctc.co.in", "incometax.gov.in", "mca.gov.in",
            "digitalindia.gov.in", "digilocker.gov.in"
        };

        for (String domain : domains) {
            trustedDomainTrie.insert(domain);
        }
    }

    private void initHomoglyphMap() {
        homoglyphMap.put('\u0430', 'a');
        homoglyphMap.put('\u0435', 'e');
        homoglyphMap.put('\u043E', 'o');
        homoglyphMap.put('\u0440', 'p');
        homoglyphMap.put('\u0441', 'c');
        homoglyphMap.put('\u0456', 'i');
        homoglyphMap.put('\u0455', 's');
        homoglyphMap.put('\u0501', 'd');
        homoglyphMap.put('\u03BF', 'o');
        homoglyphMap.put('\u03F2', 'c');
        homoglyphMap.put('\u03C5', 'u');
        homoglyphMap.put('\u217C', 'l');
        homoglyphMap.put('\u0261', 'g');
        homoglyphMap.put('\u0131', 'i');
        homoglyphMap.put('\u0185', 'b');
        homoglyphMap.put('\u0292', 'z');
    }

    private void initScoreWeights() {
        scoreWeights.put("TrustedDomain", -6);
        scoreWeights.put("HTTPS", -2);
        scoreWeights.put("BrandMisuse", 5);
        scoreWeights.put("Homoglyph", 6);
        scoreWeights.put("Punycode", 3);
        scoreWeights.put("Shortener", 2);
        scoreWeights.put("SuspiciousTLD", 3);
        scoreWeights.put("SubdomainAbuse", 3);
        scoreWeights.put("HyphenOveruse", 2);
        scoreWeights.put("KeywordFound", 3);
        scoreWeights.put("IPAddress", 5);
    }

    private void addReason(String ruleName, String message) {
        int points = scoreWeights.getOrDefault(ruleName, 0);
        totalScore += points;
        String prefix = points >= 0 ? "+" + points : String.valueOf(points);
        reasons.add(prefix + " " + message);
    }

    private void checkTrustedDomain(PhishingURLParser url) {
        if (trustedDomainTrie.search(url.domain)) {
            addReason("TrustedDomain", "Domain is in the trusted-domain trie: " + url.domain);
        }
    }

    private void checkHTTPS(PhishingURLParser url) {
        if ("https".equals(url.protocol)) {
            addReason("HTTPS", "HTTPS protocol detected for encrypted transport.");
        }
    }

    private void checkBrandMisuse(PhishingURLParser url) {
        String[] brands = {
            "paypal", "google", "amazon", "apple", "microsoft", "facebook", "netflix",
            "linkedin", "twitter", "sbi", "hdfc", "icici", "axis", "kotak", "flipkart",
            "instagram", "whatsapp", "spotify", "youtube", "gmail", "paytm", "phonepe",
            "razorpay", "irctc", "uidai"
        };

        for (String brand : brands) {
            if (url.domain.contains(brand) && !trustedDomainTrie.search(url.domain)) {
                addReason("BrandMisuse", "Known brand '" + brand + "' appears inside a non-official domain.");
                return;
            }
        }
    }

    private void checkHomoglyph(PhishingURLParser url) {
        StringBuilder normalized = new StringBuilder();
        for (char ch : url.domain.toCharArray()) {
            normalized.append(homoglyphMap.getOrDefault(ch, ch));
        }

        String normalizedDomain = normalized.toString();
        if (!url.domain.equals(normalizedDomain) && trustedDomainTrie.search(normalizedDomain)) {
            criticalThreat = true;
            addReason("Homoglyph", "Unicode lookalike characters suggest impersonation of " + normalizedDomain + ".");
        }
    }

    private void checkPunycode(PhishingURLParser url) {
        if (url.domain.startsWith("xn--") || url.domain.contains(".xn--")) {
            addReason("Punycode", "Punycode encoding detected, which is common in IDN spoofing.");
        }
    }

    private void checkShortener(PhishingURLParser url) {
        String[] shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "lnkd.in", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io", "bl.ink"
        };

        for (String shortener : shorteners) {
            if (url.domain.equals(shortener)) {
                addReason("Shortener", "URL shortener detected, so the final destination is hidden.");
                return;
            }
        }
    }

    private void checkTLD(PhishingURLParser url) {
        String[] suspiciousTlds = {
            ".xyz", ".top", ".click", ".biz", ".tk", ".ml", ".ga", ".cf",
            ".gq", ".pw", ".rest", ".zip", ".mov", ".fit", ".surf"
        };

        for (String tld : suspiciousTlds) {
            if (url.tld.equals(tld)) {
                addReason("SuspiciousTLD", "High-risk TLD detected: " + tld);
                return;
            }
        }
    }

    private void checkSubdomain(PhishingURLParser url) {
        int dotCount = 0;
        for (char ch : url.domain.toCharArray()) {
            if (ch == '.') {
                dotCount++;
            }
        }
        if (dotCount > 2) {
            addReason("SubdomainAbuse", "Excessive subdomains detected (" + dotCount + " dots).");
        }
    }

    private void checkHyphen(PhishingURLParser url) {
        int hyphenCount = 0;
        for (char ch : url.domain.toCharArray()) {
            if (ch == '-') {
                hyphenCount++;
            }
        }
        if (hyphenCount >= 2) {
            addReason("HyphenOveruse", "Multiple hyphens in the domain resemble common phishing naming patterns.");
        }
    }

    private void checkKeywords(PhishingURLParser url) {
        String[] keywords = {
            "login", "verify", "update", "secure", "password", "bank", "account",
            "signin", "confirm", "alert", "suspend", "urgent", "validate", "recover",
            "unlock", "billing", "checkout", "cardverify", "otp", "kyc"
        };

        String value = url.rawInput.toLowerCase();
        for (String keyword : keywords) {
            if (value.contains(keyword)) {
                addReason("KeywordFound", "Suspicious keyword found in the URL: '" + keyword + "'.");
                return;
            }
        }
    }

    private void checkIPAddress(PhishingURLParser url) {
        if (url.domain.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            addReason("IPAddress", "Raw IP address used instead of a normal domain name.");
        }
    }
}
