package org.iot.auth.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Calendar;

public class QPSCalculator {
    public QPSCalculator(float qpsLimit, int qpsBucketSizeInSec) {
        this.qpsLimit = qpsLimit;
        this.qpsBucketSizeInSec = qpsBucketSizeInSec;
        numTotalRequestsWithinSec = new int[qpsBucketSizeInSec];
        numAcceptedRequestsWithinSec = new int[qpsBucketSizeInSec];
    }

    /**
     * Check whether the QPS limit is exceeded and increase the counter for the number of accepted requests only when
     * the QPS limit is exceeded. QPS is calculated over a minute.
     * @return Boolean value to indicate if the QPS limit is exceeded.
     */
    public synchronized boolean checkQpsLimitExceededOtherwiseIncreaseRequestCounter() {
        long currentTimeInSec = Calendar.getInstance().getTimeInMillis() / 1000;
        int secondIndex = (int) (currentTimeInSec % qpsBucketSizeInSec);
        logger.info("current second index:  " + secondIndex + " time in sec: " + currentTimeInSec);
        resetPastTimeRequests(numTotalRequestsWithinSec, secondIndex, currentTimeInSec - lastTimeInSec);
        resetPastTimeRequests(numAcceptedRequestsWithinSec, secondIndex, currentTimeInSec - lastTimeInSec);
        numTotalRequestsWithinSec[secondIndex]++;
        boolean isQpsExceeded = false;
        if (((float) getRequestsWithinBucket(numAcceptedRequestsWithinSec) / qpsBucketSizeInSec) < qpsLimit) {
            numAcceptedRequestsWithinSec[secondIndex]++;
        }
        else {
            isQpsExceeded = true;
            logger.info("qps limit reached! " + qpsLimit);
        }
        logger.info("current total req/sec:  " + numTotalRequestsWithinSec[secondIndex]);
        logger.info("current accepted req/sec:  " + numAcceptedRequestsWithinSec[secondIndex]);
        logger.info("Total:    " + printIntArray(numTotalRequestsWithinSec));
        logger.info("Accepted: " + printIntArray(numAcceptedRequestsWithinSec));
        int totalRequestsPerBucket = getRequestsWithinBucket(numTotalRequestsWithinSec);
        int acceptedRequestsPerBucket = getRequestsWithinBucket(numAcceptedRequestsWithinSec);
        float currentTotalQps = (float)totalRequestsPerBucket / qpsBucketSizeInSec;
        if (currentTotalQps > maxTotalQps) {
            maxTotalQps = currentTotalQps;
        }
        float currentAcceptedQps = (float)acceptedRequestsPerBucket / qpsBucketSizeInSec;
        if (currentAcceptedQps > maxAcceptedQps) {
            maxAcceptedQps = currentAcceptedQps;
        }
        logger.info("current total req/" + qpsBucketSizeInSec + "sec: " + totalRequestsPerBucket + " QPS: " + currentTotalQps + " Max QPS: " + maxTotalQps);
        logger.info("current accepted req/" + qpsBucketSizeInSec + "sec: " + acceptedRequestsPerBucket + " QPS: " + currentAcceptedQps + " Max QPS: " + maxAcceptedQps);
        lastTimeInSec = currentTimeInSec;
        return isQpsExceeded;
    }
    private float maxTotalQps = 0f;
    private float maxAcceptedQps = 0f;
    private final float qpsLimit;
    private final int qpsBucketSizeInSec;
    private int[] numTotalRequestsWithinSec;
    private int[] numAcceptedRequestsWithinSec;
    private long lastTimeInSec = 0;
    private static int getRequestsWithinBucket(int[] requestsWithinSec) {
        int sum = 0;
        for (int i = 0; i < requestsWithinSec.length; i++) {
            sum += requestsWithinSec[i];
        }
        return sum;
    }
    private String printIntArray (int[] array) {
        String result = "";
        for (int i = 0; i < array.length; i++) {
            result += array[i] + " ";
        }
        return result;
    }
    private static void resetPastTimeRequests(int[] requestsWithinSec, int currentSecondIndex, long pastAmountWithoutRequests) {
        int numEntriesToBeReset = pastAmountWithoutRequests >= requestsWithinSec.length ? requestsWithinSec.length : (int) pastAmountWithoutRequests;
        int numResets = 0;
        for (int i = currentSecondIndex;; i--, numResets++) {
            if (numResets >= numEntriesToBeReset) {
                break;
            }
            if (i < 0) {
                i = requestsWithinSec.length - 1;
            }
            requestsWithinSec[i] = 0;
        }
    }
    private static final Logger logger = LoggerFactory.getLogger(QPSCalculator.class);
}

