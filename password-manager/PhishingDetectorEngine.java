import java.net.URI;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PhishingDetectorEngine {

    private static final Pattern FORM_ACTION_PATTERN =
        Pattern.compile("action\\s*=\\s*[\"']?([^\"'\\s>]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HIDDEN_INPUT_PATTERN =
        Pattern.compile("<input[^>]*type\\s*=\\s*[\"']hidden[\"'][^>]*>", Pattern.CASE_INSENSITIVE);

    private final PhishingTrie trustedDomainTrie;
    private final HashMap<Character, Character> homoglyphMap;
    private final HashMap<Character, Character> lookalikeMap;
    private final HashMap<String, Integer> scoreWeights;
    private final LinkedList<String> trustedDomains;
    private final LinkedList<String> reasons;
    private boolean trustedDomainMatch;
    private boolean criticalThreat;
    private boolean shortenerDetected;
    private int totalScore;

    public PhishingDetectorEngine() {
        trustedDomainTrie = new PhishingTrie();
        homoglyphMap = new HashMap<>();
        lookalikeMap = new HashMap<>();
        scoreWeights = new HashMap<>();
        trustedDomains = new LinkedList<>();
        reasons = new LinkedList<>();
        initTrustedDomains();
        initHomoglyphMap();
        initLookalikeMap();
        initScoreWeights();
    }

    public PhishingAnalysisResult analyze(String inputUrl) {
        PhishingURLParser parser = new PhishingURLParser();
        parser.parse(inputUrl);
        reasons.clear();
        totalScore = 0;
        trustedDomainMatch = false;
        criticalThreat = false;
        shortenerDetected = false;

        checkTrustedDomain(parser);
        checkHTTPS(parser);
        checkLookalikeDomain(parser);
        checkBrandMisuse(parser);
        checkHomoglyph(parser);
        checkPunycode(parser);
        checkShortener(parser);
        checkTLD(parser);
        checkSubdomain(parser);
        checkHyphen(parser);
        checkKeywords(parser);
        checkIPAddress(parser);
        inspectLivePage(inputUrl, parser);

        int finalScore = criticalThreat ? Math.max(totalScore, 11) : totalScore;
        boolean plainHttpTrustedDomain = trustedDomainMatch && "http".equals(parser.protocol);

        return new PhishingAnalysisResult(
            inputUrl,
            finalScore,
            PhishingScoreEngine.getVerdict(finalScore, plainHttpTrustedDomain),
            PhishingScoreEngine.getVerdictDetail(finalScore, plainHttpTrustedDomain),
            reasons,
            parser.protocol,
            parser.domain,
            parser.subdomain,
            parser.rootDomain,
            parser.tld,
            parser.path,
            plainHttpTrustedDomain
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
            trustedDomains.add(domain);
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

    private void initLookalikeMap() {
        lookalikeMap.put('0', 'o');
        lookalikeMap.put('1', 'l');
        lookalikeMap.put('3', 'e');
        lookalikeMap.put('4', 'a');
        lookalikeMap.put('5', 's');
        lookalikeMap.put('7', 't');
        lookalikeMap.put('8', 'b');
        lookalikeMap.put('@', 'a');
        lookalikeMap.put('$', 's');
    }

    private void initScoreWeights() {
        scoreWeights.put("TrustedDomain", -6);
        scoreWeights.put("HTTPS", -2);
        scoreWeights.put("LookalikeDomain", 7);
        scoreWeights.put("BrandMisuse", 5);
        scoreWeights.put("Homoglyph", 6);
        scoreWeights.put("Punycode", 3);
        scoreWeights.put("Shortener", 2);
        scoreWeights.put("RiskyShortener", 4);
        scoreWeights.put("SuspiciousTLD", 3);
        scoreWeights.put("SubdomainAbuse", 3);
        scoreWeights.put("HyphenOveruse", 2);
        scoreWeights.put("KeywordFound", 3);
        scoreWeights.put("IPAddress", 5);
        scoreWeights.put("RedirectDepth", 3);
        scoreWeights.put("RedirectLoop", 5);
        scoreWeights.put("RedirectDomainChange", 4);
        scoreWeights.put("RedirectDowngrade", 4);
        scoreWeights.put("PasswordForm", 6);
        scoreWeights.put("ExternalFormAction", 5);
        scoreWeights.put("BrandContentMismatch", 5);
        scoreWeights.put("HiddenFieldAbuse", 2);
        scoreWeights.put("SuspiciousScript", 3);
    }

    private void addReason(String ruleName, String message) {
        int points = scoreWeights.getOrDefault(ruleName, 0);
        totalScore += points;
        String prefix = points >= 0 ? "+" + points : String.valueOf(points);
        reasons.add(prefix + " " + message);
    }

    private void checkTrustedDomain(PhishingURLParser url) {
        if (trustedDomainTrie.search(url.domain)) {
            trustedDomainMatch = true;
            addReason("TrustedDomain", "Domain is in the trusted-domain trie: " + url.domain);
        }
    }

    private void checkHTTPS(PhishingURLParser url) {
        if ("https".equals(url.protocol)) {
            addReason("HTTPS", "HTTPS protocol detected for encrypted transport.");
        }
    }

    private void checkLookalikeDomain(PhishingURLParser url) {
        String normalizedDomain = normalizeLookalikes(url.domain);
        if (!url.domain.equals(normalizedDomain) && trustedDomainTrie.search(normalizedDomain)) {
            criticalThreat = true;
            addReason("LookalikeDomain", "Domain visually imitates trusted site " + normalizedDomain + ".");
            return;
        }

        for (String trustedDomain : trustedDomains) {
            if (url.domain.equals(trustedDomain)) {
                continue;
            }

            if (!sameFamily(url, trustedDomain)) {
                continue;
            }

            int distance = levenshteinDistance(url.domain, trustedDomain);
            if (distance > 0 && distance <= 2) {
                criticalThreat = true;
                addReason("LookalikeDomain", "Domain is only " + distance + " edit away from trusted site " + trustedDomain + ".");
                return;
            }
        }
    }

    private void checkBrandMisuse(PhishingURLParser url) {
        String[] brands = getKnownBrands();

        String normalizedDomain = normalizeLookalikes(url.domain);
        for (String brand : brands) {
            if ((url.domain.contains(brand) || normalizedDomain.contains(brand)) && !trustedDomainTrie.search(url.domain)) {
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
            "bit.ly", "tinyurl.com", "t.co", "lnkd.in", "goo.gl", "goo.su", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io", "bl.ink"
        };
        String[] riskyShorteners = {
            "goo.su"
        };

        for (String shortener : shorteners) {
            if (url.domain.equals(shortener)) {
                shortenerDetected = true;
                addReason("Shortener", "Shortened URL detected, so the final destination needs verification.");
                for (String riskyShortener : riskyShorteners) {
                    if (url.domain.equals(riskyShortener)) {
                        addReason("RiskyShortener", "This shortener has elevated abuse reports, so treat it with extra caution.");
                        break;
                    }
                }
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

    private void inspectLivePage(String inputUrl, PhishingURLParser originalParser) {
        PhishingFetchResult fetchResult = PhishingPageFetcher.fetch(inputUrl);
        if (!fetchResult.wasFetched()) {
            return;
        }

        analyzeRedirects(fetchResult, originalParser);

        String html = fetchResult.getHtml();
        PhishingURLParser finalParser = new PhishingURLParser();
        finalParser.parse(fetchResult.getFinalUrl());
        reconcileShortenerRisk(fetchResult, finalParser);

        if (html == null || html.isBlank()) {
            return;
        }

        analyzeFetchedHtml(html, finalParser);
    }

    private void reconcileShortenerRisk(PhishingFetchResult fetchResult, PhishingURLParser finalParser) {
        if (!shortenerDetected) {
            return;
        }

        boolean trustedFinalDomain = trustedDomainTrie.search(finalParser.domain);
        boolean httpsFinalDomain = "https".equals(finalParser.protocol);
        boolean resolvedThroughRedirect = fetchResult.getRedirectChain().size() > 1;

        if (trustedFinalDomain && httpsFinalDomain && resolvedThroughRedirect && !fetchResult.hasRedirectLoop()) {
            totalScore -= scoreWeights.getOrDefault("Shortener", 0);
            reasons.add("-2 Shortened link resolves cleanly to a trusted HTTPS destination.");
        }
    }

    private void analyzeRedirects(PhishingFetchResult fetchResult, PhishingURLParser originalParser) {
        LinkedList<String> chain = fetchResult.getRedirectChain();
        if (fetchResult.hasRedirectLoop()) {
            criticalThreat = true;
            addReason("RedirectLoop", "Redirect loop detected while expanding the URL.");
        }

        if (fetchResult.isRedirectLimitReached() || chain.size() > 3) {
            addReason("RedirectDepth", "Long redirect chain detected before reaching the final page.");
        }

        for (int i = 1; i < chain.size(); i++) {
            PhishingURLParser previous = new PhishingURLParser();
            PhishingURLParser current = new PhishingURLParser();
            previous.parse(chain.get(i - 1));
            current.parse(chain.get(i));

            if ("https".equals(previous.protocol) && "http".equals(current.protocol)) {
                addReason("RedirectDowngrade", "Redirect chain downgrades from HTTPS to HTTP.");
                break;
            }
        }

        if (chain.size() > 1) {
            PhishingURLParser finalParser = new PhishingURLParser();
            finalParser.parse(fetchResult.getFinalUrl());
            if (!sameFamily(finalParser, originalParser.domain)) {
                addReason("RedirectDomainChange", "Redirect chain ends on a different domain: " + finalParser.domain + ".");
            }
        }
    }

    private void analyzeFetchedHtml(String html, PhishingURLParser finalParser) {
        String lowerHtml = html.toLowerCase();
        boolean trustedFinalDomain = trustedDomainTrie.search(finalParser.domain);
        boolean hasPasswordField = containsPasswordField(lowerHtml);
        boolean hasForm = lowerHtml.contains("<form");

        if (hasForm && hasPasswordField && !trustedFinalDomain) {
            addReason("PasswordForm", "Fetched page contains a password form on an untrusted domain.");
            criticalThreat = true;
        }

        if (hasSuspiciousFormAction(html, finalParser.domain)) {
            addReason("ExternalFormAction", "Form submits data to a different host than the page itself.");
        }

        if (countHiddenInputs(html) >= 4) {
            addReason("HiddenFieldAbuse", "Page contains many hidden form fields, which is a common phishing trait.");
        }

        if (containsSuspiciousScript(lowerHtml)) {
            addReason("SuspiciousScript", "Page contains obfuscated or redirect-heavy script patterns.");
        }

        String normalizedDomain = normalizeLookalikes(finalParser.domain);
        for (String brand : getKnownBrands()) {
            if (lowerHtml.contains(brand) && !trustedFinalDomain && !normalizedDomain.contains(brand)) {
                addReason("BrandContentMismatch", "Page content mentions trusted brand '" + brand + "' on an unrelated domain.");
                if (hasPasswordField) {
                    criticalThreat = true;
                }
                return;
            }
        }
    }

    private boolean containsPasswordField(String lowerHtml) {
        return lowerHtml.contains("type=\"password\"")
            || lowerHtml.contains("type='password'")
            || lowerHtml.contains("type=password");
    }

    private boolean hasSuspiciousFormAction(String html, String currentDomain) {
        Matcher matcher = FORM_ACTION_PATTERN.matcher(html);
        while (matcher.find()) {
            String action = matcher.group(1).trim();
            if (action.isEmpty() || action.startsWith("/") || action.startsWith("#")) {
                continue;
            }

            try {
                URI actionUri = URI.create(action);
                String actionHost = actionUri.getHost();
                if (actionHost != null && !actionHost.equalsIgnoreCase(currentDomain)) {
                    return true;
                }
            } catch (Exception ignored) {
                // Non-absolute action targets are not treated as suspicious here.
            }
        }
        return false;
    }

    private int countHiddenInputs(String html) {
        Matcher matcher = HIDDEN_INPUT_PATTERN.matcher(html);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    private boolean containsSuspiciousScript(String lowerHtml) {
        return lowerHtml.contains("eval(")
            || lowerHtml.contains("atob(")
            || lowerHtml.contains("fromcharcode(")
            || lowerHtml.contains("document.location")
            || lowerHtml.contains("window.location");
    }

    private String[] getKnownBrands() {
        return new String[] {
            "paypal", "google", "amazon", "apple", "microsoft", "facebook", "netflix",
            "linkedin", "twitter", "sbi", "hdfc", "icici", "axis", "kotak", "flipkart",
            "instagram", "whatsapp", "spotify", "youtube", "gmail", "paytm", "phonepe",
            "razorpay", "irctc", "uidai"
        };
    }

    private String normalizeLookalikes(String domain) {
        StringBuilder normalized = new StringBuilder();
        for (char ch : domain.toCharArray()) {
            char unicodeNormalized = homoglyphMap.getOrDefault(ch, ch);
            normalized.append(lookalikeMap.getOrDefault(unicodeNormalized, unicodeNormalized));
        }
        return normalized.toString();
    }

    private boolean sameFamily(PhishingURLParser url, String trustedDomain) {
        String trustedTld = extractTld(trustedDomain);
        return url.tld.equals(trustedTld) || url.domain.endsWith(trustedTld) || trustedDomain.endsWith(url.tld);
    }

    private String extractTld(String domain) {
        int lastDot = domain.lastIndexOf('.');
        return lastDot == -1 ? "" : domain.substring(lastDot);
    }

    private int levenshteinDistance(String left, String right) {
        int[][] dp = new int[left.length() + 1][right.length() + 1];

        for (int i = 0; i <= left.length(); i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= right.length(); j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= left.length(); i++) {
            for (int j = 1; j <= right.length(); j++) {
                int cost = left.charAt(i - 1) == right.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(
                    Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                    dp[i - 1][j - 1] + cost
                );
            }
        }

        return dp[left.length()][right.length()];
    }
}
