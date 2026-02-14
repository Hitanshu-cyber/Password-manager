import java.util.*;
import java.io.*;

public class AIPasswordAnalyzer {

    public static class AnalysisResult {
        public String strengthLabel;
        public String suggestion;

        public AnalysisResult(String label, String suggestion) {
            this.strengthLabel = label;
            this.suggestion = suggestion;
        }

        public String getStrengthLabel() {
            return strengthLabel;
        }

        @Override
        public String toString() {
            return "[AI Analysis] " + strengthLabel + ": " + suggestion;
        }
    }

    private MarkovChain markovModel;
    private BloomFilter breachFilter;
    private Set<String> topTierBreach = new HashSet<>();
    private static final String MODEL_FILE = "ai_model.dat";
    private static final String BREACH_FILE = "breach_db.bloom";
    private static final String BREACH_LIST_TEXT = "breach_list.txt";

    public AIPasswordAnalyzer() {
        markovModel = new MarkovChain();
        File modelFile = new File(MODEL_FILE);
        if (modelFile.exists()) {
            markovModel.loadModel(MODEL_FILE);
        } else {
            markovModel.train("password123adminrootuserqwerty");
        }

        File breachFile = new File(BREACH_FILE);
        if (breachFile.exists()) {
            breachFilter = BloomFilter.load(BREACH_FILE);
        } else {
            breachFilter = new BloomFilter(100000, 0.01);
            // Auto-seed from text list if available
            File textList = new File(BREACH_LIST_TEXT);
            if (textList.exists()) {
                importBreachList(BREACH_LIST_TEXT);
            }
        }
        // Load top tier for O(1) primary check
        loadTopTier(BREACH_LIST_TEXT);
    }

    private void loadTopTier(String path) {
        File f = new File(path);
        if (!f.exists())
            return;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                topTierBreach.add(line.trim().toLowerCase());
            }
        } catch (IOException ignored) {
        }
    }

    public void trainModel(String filePath) {
        System.out.println("[AI] Training Markov Chain from " + filePath + "...");
        markovModel.trainFromFile(filePath);
        markovModel.saveModel(MODEL_FILE);
        System.out.println("[AI] Training complete. Model saved.");
    }

    public void importBreachList(String filePath) {
        System.out.println("[AI] Importing Breach List from " + filePath + "...");
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                breachFilter.add(line.trim());
            }
            breachFilter.save(BREACH_FILE);
            System.out.println("[AI] Import complete. Bloom Filter saved.");
        } catch (IOException e) {
            System.out.println("[AI] Error importing breach list: " + e.getMessage());
        }
    }

    public AnalysisResult analyzePassword(String password) {
        // Use Markov Score + Heuristics
        double probability = markovModel.calculateProbability(password);

        // Lower probability = more random/unique (better)
        // High probability = looks like common words (worse)

        String strength = "Weak";
        String feat = "";

        // Hueristics still apply as baseline
        int len = password.length();
        boolean hasUpper = !password.equals(password.toLowerCase());
        boolean hasLower = !password.equals(password.toUpperCase());
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[!@#$%^&*].*");

        if (len < 8) {
            return new AnalysisResult("Weak", "Too short.");
        }

        // Combine scores
        int score = 0;
        if (hasUpper)
            score++;
        if (hasLower)
            score++;
        if (hasDigit)
            score++;
        if (hasSpecial)
            score++;
        if (len >= 12)
            score++;

        // Markov penalty for common patterns
        if (probability > 0.05) { // Threshold for "too common"
            score--;
            feat = "Common pattern detected by AI. ";
        } else {
            feat = "Unique pattern. ";
        }

        if (score >= 4) {
            strength = "Very Strong";
            feat += "Excellent entropy.";
        } else if (score >= 3) {
            strength = "Strong";
            feat += "Good, but add more variety.";
        } else {
            strength = "Medium";
            feat += "Add special chars or length.";
        }

        return new AnalysisResult(strength, feat);
    }

    public boolean checkBreach(String password) {
        String p = password.toLowerCase();
        if (topTierBreach.contains(p))
            return true;
        if (breachFilter != null) {
            return breachFilter.mightContain(p);
        }
        return false;
    }

    public List<String> generateSuggestions(String context) {
        List<String> suggestions = new ArrayList<>();

        if (context.contains("memorable")) {
            // Generate using Markov chain (more human-like)
            for (int i = 0; i < 3; i++) {
                suggestions.add(markovModel.generate(12));
            }
        } else {
            // Strong random (Legacy/Hybrid)
            Random r = new Random();
            String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++)
                sb.append(chars.charAt(r.nextInt(chars.length())));
            suggestions.add(sb.toString());

            // AI varied
            suggestions.add(markovModel.generate(14) + "!");
            suggestions.add(markovModel.generate(10) + r.nextInt(100));
        }
        return suggestions;
    }

    /**
     * Generates contextual suggestions based on a rejected password.
     * Priority 1: Fragmented/Adjusted rejected phrase.
     * Priority 2: Humanly readable (Markov).
     * Priority 3: Random.
     */
    public List<String> generateContextualSuggestions(String rejected) {
        List<String> suggestions = new ArrayList<>();
        Random r = new Random();

        // 1. Fragmented/Phase-wise 조정 (Deep Scrambling while keeping structure)
        // Split by middle if long, or just transform chars and add noise
        String fragmented;
        if (rejected.length() > 6) {
            String part1 = rejected.substring(0, rejected.length() / 2);
            String part2 = rejected.substring(rejected.length() / 2);
            fragmented = transformPhase(part1) + "_" + r.nextInt(100) + transformPhase(part2);
        } else {
            fragmented = transformPhase(rejected) + "!" + (r.nextInt(9000) + 1000);
        }
        suggestions.add(fragmented);

        // 2. Humanly Readable (Markov Chain + Random Suffix)
        String memorable = markovModel.generate(10);
        if (memorable.isEmpty())
            memorable = "SecPass";
        memorable = memorable.substring(0, 1).toUpperCase() + memorable.substring(1).toLowerCase();
        memorable += (char) (r.nextInt(26) + 'A') + String.valueOf(r.nextInt(99));
        suggestions.add(memorable);

        // 3. Random (Cryptographic Grade)
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 18; i++)
            sb.append(chars.charAt(r.nextInt(chars.length())));
        suggestions.add(sb.toString());

        return suggestions;
    }

    private String transformPhase(String text) {
        return text.replace('a', '@').replace('A', '4')
                .replace('e', '3').replace('E', '3')
                .replace('i', '1').replace('I', '1')
                .replace('o', '0').replace('O', '0')
                .replace('s', '$').replace('S', '5');
    }
}
