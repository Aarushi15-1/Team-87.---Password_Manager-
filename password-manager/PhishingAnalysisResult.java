import java.util.LinkedList;
import java.util.List;

public class PhishingAnalysisResult {
    private final String url;
    private final int score;
    private final String verdict;
    private final String detail;
    private final LinkedList<String> reasons;
    private final String protocol;
    private final String domain;
    private final String subdomain;
    private final String rootDomain;
    private final String tld;
    private final String path;

    public PhishingAnalysisResult(
        String url,
        int score,
        String verdict,
        String detail,
        LinkedList<String> reasons,
        String protocol,
        String domain,
        String subdomain,
        String rootDomain,
        String tld,
        String path
    ) {
        this.url = url;
        this.score = score;
        this.verdict = verdict;
        this.detail = detail;
        this.reasons = new LinkedList<>(reasons);
        this.protocol = protocol;
        this.domain = domain;
        this.subdomain = subdomain;
        this.rootDomain = rootDomain;
        this.tld = tld;
        this.path = path;
    }

    public String getUrl() { return url; }
    public int getScore() { return score; }
    public String getVerdict() { return verdict; }
    public String getDetail() { return detail; }
    public List<String> getReasons() { return reasons; }
    public String getProtocol() { return protocol; }
    public String getDomain() { return domain; }
    public String getSubdomain() { return subdomain; }
    public String getRootDomain() { return rootDomain; }
    public String getTld() { return tld; }
    public String getPath() { return path; }
}
