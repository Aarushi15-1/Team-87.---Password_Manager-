import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedList;

public class PhishingPageFetcher {
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 7000;
    private static final int MAX_REDIRECTS = 5;
    private static final int MAX_HTML_BYTES = 200000;

    public static PhishingFetchResult fetch(String inputUrl) {
        String currentUrl = ensureScheme(inputUrl);
        LinkedList<String> redirectChain = new LinkedList<>();
        HashSet<String> visited = new HashSet<>();
        redirectChain.add(currentUrl);
        visited.add(currentUrl);

        boolean redirectLoop = false;
        boolean redirectLimitReached = false;

        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            HttpURLConnection connection = null;
            try {
                URL url = new URL(currentUrl);
                connection = (HttpURLConnection) url.openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(READ_TIMEOUT_MS);
                connection.setRequestProperty("User-Agent", "PassVault-PhishingDetector/1.0");
                connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*");
                connection.setRequestMethod("GET");

                int status = connection.getResponseCode();
                if (isRedirect(status)) {
                    String location = connection.getHeaderField("Location");
                    if (location == null || location.isBlank()) {
                        break;
                    }

                    String resolvedUrl = new URL(url, location).toString();
                    if (visited.contains(resolvedUrl)) {
                        redirectLoop = true;
                        redirectChain.add(resolvedUrl);
                        break;
                    }

                    redirectChain.add(resolvedUrl);
                    visited.add(resolvedUrl);
                    currentUrl = resolvedUrl;

                    if (hop == MAX_REDIRECTS) {
                        redirectLimitReached = true;
                    }
                    continue;
                }

                String contentType = connection.getContentType();
                String html = "";
                InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
                if (stream != null && contentType != null && contentType.toLowerCase().contains("text/html")) {
                    html = readLimited(stream);
                }

                return new PhishingFetchResult(
                    inputUrl,
                    currentUrl,
                    contentType == null ? "" : contentType,
                    html,
                    redirectChain,
                    true,
                    redirectLoop,
                    redirectLimitReached
                );
            } catch (Exception ignored) {
                break;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        return new PhishingFetchResult(
            inputUrl,
            currentUrl,
            "",
            "",
            redirectChain,
            false,
            redirectLoop,
            redirectLimitReached
        );
    }

    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private static String ensureScheme(String inputUrl) {
        String value = inputUrl == null ? "" : inputUrl.trim();
        if (value.startsWith("http://") || value.startsWith("https://")) {
            return value;
        }
        return "https://" + value;
    }

    private static String readLimited(InputStream stream) throws Exception {
        try (InputStream in = stream; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int total = 0;
            int read;
            while ((read = in.read(buffer)) != -1 && total < MAX_HTML_BYTES) {
                int toWrite = Math.min(read, MAX_HTML_BYTES - total);
                out.write(buffer, 0, toWrite);
                total += toWrite;
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }
}
