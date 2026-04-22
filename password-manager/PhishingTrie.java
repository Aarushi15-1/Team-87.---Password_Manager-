public class PhishingTrie {

    private static class TrieNode {
        TrieNode[] children = new TrieNode[128];
        boolean isEndOfWord;
    }

    private final TrieNode root;

    public PhishingTrie() {
        this.root = new TrieNode();
    }

    public void insert(String domain) {
        TrieNode current = root;
        String normalized = domain.toLowerCase().trim();

        for (char ch : normalized.toCharArray()) {
            int index = ch;
            if (index < 0 || index >= 128) {
                continue;
            }
            if (current.children[index] == null) {
                current.children[index] = new TrieNode();
            }
            current = current.children[index];
        }

        current.isEndOfWord = true;
    }

    public boolean search(String domain) {
        TrieNode current = root;
        String normalized = domain.toLowerCase().trim();

        for (char ch : normalized.toCharArray()) {
            int index = ch;
            if (index < 0 || index >= 128 || current.children[index] == null) {
                return false;
            }
            current = current.children[index];
        }

        return current.isEndOfWord;
    }
}
