package org.onos.httpddosdetector.classifier.randomforest;

import org.onos.httpddosdetector.classifier.Classifier;
import org.onos.httpddosdetector.classifier.randomforest.codec.RandomForestCodec;
import org.onos.httpddosdetector.flow.parser.FlowData;
import org.onos.httpddosdetector.Helpers;

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.onosproject.rest.AbstractWebResource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Classifier class to predict http ddos attacks with RandomForests
 */
public class RandomForestBinClassifier extends Classifier {
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

        public static Class valueOf(int value) {
            switch(value){
                case 0:
                    return Class.NORMAL;
                case 1:
                    return Class.ATTACK;
                default:
                    return Class.ERROR;
            }
        }
    }

    private static Logger log = LoggerFactory.getLogger(RandomForestBinClassifier.class);

    private RandomForest forest;

    /**
     * Loads the model to be used for the classification
     *
     * @param filepath String the model to be loaded on the classifier
     */
    @Override
    public void Load(String filepath){
        RandomForestCodec codec = new RandomForestCodec();
        ObjectNode json = Helpers.readJsonFile(filepath);
        AbstractWebResource context = new AbstractWebResource();

        if (json != null) {
            forest = codec.decode(json, context);
            if(forest.isLoaded){
                super.Load(filepath);
            }
        } else {
            log.error("Random forests json is null");
        }

        if(isLoaded){
            log.info("Random forest classifier loaded");
        } else{
            log.error("Error while loading random forest classifier");
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
	@Override
    public int Classify(FlowData f){
        if(super.Classify(f) == -1){
            return Class.ERROR.value;
        }
        return forest.Classify(f);
    }
}