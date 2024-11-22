package org.onos.httpddosdetector.classifier.randomforest;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomStump {
    public Integer splitVariable = null;
    public Float splitValue = null;
    public Integer splitSat = null;
    public Integer splitNot = null;

    /**
     * Loads the stump model to be used for the classification
     *
     * @param model JsonNode the model to be used for classification
     */
    public void Load(JsonNode model){
        if(model.has("d")){
            splitVariable = model.get("d").asInt();
        } else {
            splitVariable = null;
        }
        if(model.has("x")){
            splitValue = (float) model.get("x").asDouble();
        } else {
            splitValue = null;
        }
        if(model.has("s")){
            splitSat = model.get("s").asInt();
        } else {
            splitSat = null;
        }
        if(model.has("n")){
            splitNot = model.get("n").asInt();
        } else {
            splitNot = null;
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(ArrayList<Long> X) {
        if(splitVariable == null){
            return splitSat;
        }
        int yhat = 0;
        if (X.get(splitVariable) > splitValue) {
            yhat = splitSat;
        } else {
            yhat = splitNot;
        }

        return yhat;
    }
}