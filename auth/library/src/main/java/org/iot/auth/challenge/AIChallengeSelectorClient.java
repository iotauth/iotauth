package org.iot.auth.challenge;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Client for sending Feasible Challenge Set to the external AI Challenge Selector HTTP service
 * and receiving the selected physical challenge decisions.
 * 
 * @author Dongha Kim
 */
public class AIChallengeSelectorClient {
    private static final Logger logger = LoggerFactory.getLogger(AIChallengeSelectorClient.class);
    private static final String DEFAULT_AI_SERVER_URL = "http://localhost:8000/select_challenge";
    private static final int TIMEOUT_MS = 10000;

    /**
     * Sends feasible challenge payload to AI Selector server via HTTP POST.
     * 
     * @param feasibleSetJson Feasible Challenge Set JSON object computed by FeasibleChallengeMatcher.
     * @param aiServerUrl     URL of the AI Selector server (or null to use default).
     * @return JSONObject containing the selected challenges decision from AI model.
     */
    public static JSONObject requestChallengeSelection(JSONObject feasibleSetJson, String aiServerUrl) {
        String targetUrlStr = (aiServerUrl != null && !aiServerUrl.isEmpty()) ? aiServerUrl : DEFAULT_AI_SERVER_URL;
        logger.info("[AIChallengeSelectorClient] Sending Feasible Challenge Set to AI Selector at {}", targetUrlStr);

        try {
            URL url = new URL(targetUrlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);

            String jsonInputString = feasibleSetJson.toJSONString();
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                StringBuilder response = new StringBuilder();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String responseLine;
                    while ((responseLine = br.readLine()) != null) {
                        response.append(responseLine.trim());
                    }
                }
                logger.info("[AIChallengeSelectorClient] Received Response from AI Selector: {}", response.toString());
                return (JSONObject) new JSONParser().parse(response.toString());
            } else {
                logger.error("[AIChallengeSelectorClient] AI Server returned HTTP error code: {}", responseCode);
            }
        } catch (Exception e) {
            logger.error("[AIChallengeSelectorClient] Failed to communicate with AI Selector Server at {}: {}",
                    targetUrlStr, e.getMessage());
        }

        return null;
    }
}
