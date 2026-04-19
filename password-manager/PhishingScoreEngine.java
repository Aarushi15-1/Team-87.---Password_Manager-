public class PhishingScoreEngine {

    public static String getVerdict(int score) {
        if (score <= 0) return "SAFE";
        if (score <= 5) return "SUSPICIOUS";
        if (score <= 10) return "HIGH RISK";
        return "VERY HIGH RISK";
    }

    public static String getVerdictDetail(int score) {
        if (score <= 0) {
            return "This URL appears to be legitimate and safe to visit.";
        }
        if (score <= 5) {
            return "This URL has some suspicious traits. Proceed with caution.";
        }
        if (score <= 10) {
            return "This URL shows strong signs of phishing. Avoid visiting it.";
        }
        return "This URL is almost certainly a phishing attempt. Do not visit it.";
    }
}
