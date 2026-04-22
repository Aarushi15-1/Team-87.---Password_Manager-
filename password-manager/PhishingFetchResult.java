import java.util.LinkedList;

public class PhishingFetchResult {
    private final String startUrl;
    private final String finalUrl;
    private final String contentType;
    private final String html;
    private final LinkedList<String> redirectChain;
    private final boolean fetched;
    private final boolean redirectLoop;
    private final boolean redirectLimitReached;

    public PhishingFetchResult(
        String startUrl,
        String finalUrl,
        String contentType,
        String html,
        LinkedList<String> redirectChain,
        boolean fetched,
        boolean redirectLoop,
        boolean redirectLimitReached
    ) {
        this.startUrl = startUrl;
        this.finalUrl = finalUrl;
        this.contentType = contentType;
        this.html = html;
        this.redirectChain = new LinkedList<>(redirectChain);
        this.fetched = fetched;
        this.redirectLoop = redirectLoop;
        this.redirectLimitReached = redirectLimitReached;
    }

    public String getStartUrl() { return startUrl; }
    public String getFinalUrl() { return finalUrl; }
    public String getContentType() { return contentType; }
    public String getHtml() { return html; }
    public LinkedList<String> getRedirectChain() { return new LinkedList<>(redirectChain); }
    public boolean wasFetched() { return fetched; }
    public boolean hasRedirectLoop() { return redirectLoop; }
    public boolean isRedirectLimitReached() { return redirectLimitReached; }
}
