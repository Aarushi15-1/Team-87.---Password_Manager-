public class PhishingScan {
    private final String url;
    private final int score;
    private final String verdict;
    private final String detail;
    private final String scannedAt;

    public PhishingScan(String url, int score, String verdict, String detail, String scannedAt) {
        this.url = url;
        this.score = score;
        this.verdict = verdict;
        this.detail = detail;
        this.scannedAt = scannedAt;
    }

    public String getUrl() { return url; }
    public int getScore() { return score; }
    public String getVerdict() { return verdict; }
    public String getDetail() { return detail; }
    public String getScannedAt() { return scannedAt; }
}
