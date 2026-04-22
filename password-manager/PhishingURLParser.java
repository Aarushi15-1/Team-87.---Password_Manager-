public class PhishingURLParser {

    public String protocol = "";
    public String domain = "";
    public String subdomain = "";
    public String rootDomain = "";
    public String tld = "";
    public String path = "";
    public String rawInput = "";

    public void parse(String url) {
        rawInput = url == null ? "" : url.trim();
        String value = normalizeForAnalysis(rawInput).toLowerCase();

        if (value.startsWith("https://")) {
            protocol = "https";
            value = value.substring(8);
        } else if (value.startsWith("http://")) {
            protocol = "http";
            value = value.substring(7);
        } else if (value.startsWith("ftp://")) {
            protocol = "ftp";
            value = value.substring(6);
        } else {
            protocol = "https";
        }

        int queryIndex = value.indexOf('?');
        if (queryIndex != -1) {
            value = value.substring(0, queryIndex);
        }

        int slashIndex = value.indexOf('/');
        if (slashIndex != -1) {
            domain = value.substring(0, slashIndex);
            path = value.substring(slashIndex);
        } else {
            domain = value;
            path = "";
        }

        int portIndex = domain.indexOf(':');
        if (portIndex != -1) {
            domain = domain.substring(0, portIndex);
        }

        int lastDot = domain.lastIndexOf('.');
        if (lastDot != -1) {
            tld = domain.substring(lastDot);
            String withoutTld = domain.substring(0, lastDot);
            int secondLastDot = withoutTld.lastIndexOf('.');

            if (secondLastDot != -1) {
                subdomain = withoutTld.substring(0, secondLastDot);
                rootDomain = withoutTld.substring(secondLastDot + 1);
            } else {
                subdomain = "";
                rootDomain = withoutTld;
            }
        } else {
            tld = "";
            subdomain = "";
            rootDomain = domain;
        }
    }

    public static String normalizeForAnalysis(String url) {
        if (url == null) {
            return "";
        }

        String normalized = url.trim();
        normalized = normalized.replace("[.]", ".");
        normalized = normalized.replace("(.)", ".");
        normalized = normalized.replace("{.}", ".");
        normalized = normalized.replace("hxxps://", "https://");
        normalized = normalized.replace("hxxp://", "http://");
        normalized = normalized.replace("hxxps:", "https:");
        normalized = normalized.replace("hxxp:", "http:");
        return normalized;
    }
}
