package org.onos.httpddosdetector.classifier.randomforest;

import org.onos.httpddosdetector.flow.parser.FlowData;
import org.onos.httpddosdetector.Helpers;

import com.fasterxml.jackson.databind.JsonNode;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.util.ArrayList;

/**
 * Classifier interface to load and predict if a flow is an http ddos attack
 */
public class RandomForest {
    private static Logger log = LoggerFactory.getLogger(RandomForest.class);

    public boolean isLoaded = false;
    public ArrayList<RandomTree> trees;

    /**
     * Loads the model to be used for the classification
     *
     * @param json JsonNode the array of trees to be used in the classification
     */
    public void Load(JsonNode json){
        if(json != null && json.isArray()){
            // Iterate over tree array and parse it
            trees = new ArrayList<RandomTree>();
            json.forEach( treeData -> { 
                RandomTree t = new RandomTree();
                t.Load(treeData);
                trees.add(t);
            } );
            isLoaded = true;
        } else {
            log.error("Couldn't load json into random forest because json is not an array");
        }
    }

    /**
     * Classifies the flow
     *
     * @return int enumerator that determines the class of the FlowData parameter
     */
    public int Classify(FlowData f) {
        ArrayList<Integer> predictions = new ArrayList<Integer>();
        log.info("Data detect: {}", f.ToArrayList());
        for(int i = 0; i < trees.size(); i++){
            int prediction = trees.get(i).Classify(f.ToArrayList());
            predictions.add(prediction);
        }
        return Helpers.mode(predictions);
    }
}