package org.onos.httpddosdetector.classifier;

import org.onos.httpddosdetector.flow.parser.FlowData;

/**
 * Classifier class to load and predict if a flow is an http ddos attack
 */
public class Classifier {
    public enum Class {
        /**
         * Indicates if there was an error while classifying the flow
         */
        ERROR(-1),
        /**
         * Indicates if the flow is part of normal network traffic
         */
        NORMAL(0),
        /**
         * Indicates if the flow is part of a http ddos attack
         */
        ATTACK(1);

        private final int value;

        private Class(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    protected boolean isLoaded = false;

    /**
     * Loads the model to be used for the classification
     *
     * @param filepath String the model to be loaded on the classifier
     */
    public void Load(String filepath){
        isLoaded = true;
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
	public int Classify(FlowData f){
        if(!isLoaded){
            return Class.ERROR.value;
        }
        return Class.NORMAL.value;
    }
}