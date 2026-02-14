import java.io.*;
import java.util.*;

public class MarkovChain {
    // Map: Current Char -> (Next Char -> Frequency)
    private Map<Character, Map<Character, Integer>> chain = new HashMap<>();
    private Random random = new Random();

    public void train(String text) {
        if (text == null || text.length() < 2)
            return;

        for (int i = 0; i < text.length() - 1; i++) {
            char current = text.charAt(i);
            char next = text.charAt(i + 1);

            chain.putIfAbsent(current, new HashMap<>());
            Map<Character, Integer> nextMap = chain.get(current);
            nextMap.put(next, nextMap.getOrDefault(next, 0) + 1);
        }
    }

    public void trainFromFile(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                train(line);
            }
        } catch (IOException e) {
            System.out.println("Error training from file: " + e.getMessage());
        }
    }

    public String generate(int length) {
        if (chain.isEmpty())
            return "";

        StringBuilder sb = new StringBuilder();
        // Start with a random key
        List<Character> keys = new ArrayList<>(chain.keySet());
        char current = keys.get(random.nextInt(keys.size()));
        sb.append(current);

        for (int i = 1; i < length; i++) {
            Map<Character, Integer> nextMap = chain.get(current);
            if (nextMap == null || nextMap.isEmpty()) {
                // Dead end, pick random again
                current = keys.get(random.nextInt(keys.size()));
            } else {
                current = getNextChar(nextMap);
            }
            sb.append(current);
        }
        return sb.toString();
    }

    private char getNextChar(Map<Character, Integer> nextMap) {
        int total = 0;
        for (int count : nextMap.values()) {
            total = total + count;
        }

        int randVal = random.nextInt(total);
        int sum = 0;
        for (Map.Entry<Character, Integer> entry : nextMap.entrySet()) {
            sum = sum + entry.getValue();
            if (randVal < sum) {
                return entry.getKey();
            }
        }
        // Fallback
        return nextMap.keySet().iterator().next();
    }

    public double calculateProbability(String password) {
        if (password == null || password.length() < 2 || chain.isEmpty())
            return 0.0;

        double logProb = 0.0;
        int transitions = 0;

        for (int i = 0; i < password.length() - 1; i++) {
            char current = password.charAt(i);
            char next = password.charAt(i + 1);

            if (chain.containsKey(current)) {
                Map<Character, Integer> nextMap = chain.get(current);
                if (nextMap.containsKey(next)) {
                    int count = nextMap.get(next);
                    int total = 0;
                    for (int c : nextMap.values())
                        total += c;

                    double prob = (double) count / total;
                    logProb += Math.log(prob);
                    transitions++;
                } else {
                    // Penalty for unseen transition
                    logProb += Math.log(0.0001);
                }
            } else {
                logProb += Math.log(0.0001);
            }
        }

        // Return normalized score 0-1 (higher is more "word-like" according to
        // training)
        // For password strength, we want LOWER probability (less predictable)
        // But for "memorable", we want HIGHER.
        return Math.exp(logProb / transitions);
    }

    // Serialization
    public void saveModel(String filename) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filename))) {
            oos.writeObject(chain);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    public void loadModel(String filename) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filename))) {
            chain = (Map<Character, Map<Character, Integer>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
