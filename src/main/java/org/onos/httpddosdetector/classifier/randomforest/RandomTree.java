package org.onos.httpddosdetector.classifier.randomforest;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomTree {
    public RandomStump splitModel;
    public RandomTree subModel0;
    public RandomTree subModel1;

    private static Logger log = LoggerFactory.getLogger(RandomTree.class);

    /**
     * Loads the tree model to be used for the classification
     *
     * @param model JsonNode the model to be used for classification
     */
    public void Load(JsonNode model){
        splitModel = new RandomStump();
        splitModel.Load(model);
        if(model.has("0")){
            subModel0 = new RandomTree();
            subModel0.Load(model.get("0"));
        } else {
            subModel0 = null;
        }
            
        if(model.has("1")){
            subModel1 = new RandomTree();
            subModel1.Load(model.get("1"));
        } else {
            subModel1 = null;
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(ArrayList<Long> X) {
        int y = 0;
        // Get values from model
        Integer splitVariable = splitModel.splitVariable;
        Float splitValue = splitModel.splitValue;
        Integer splitSat = splitModel.splitSat;

        if(splitVariable == null){
            // If no further splitting, return the majority label
            y = splitSat;
        }else if(subModel1 == null){
            y = splitModel.Classify(X);
        }else{
            if(X!=null) {
                if (X.get(splitVariable) > splitValue) {
                    y = subModel1.Classify(X);
                } else {
                    y = subModel0.Classify(X);
                }
            }
        }
        return y;
    }
}