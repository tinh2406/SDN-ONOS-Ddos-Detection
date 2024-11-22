package org.onos.httpddosdetector.classifier.randomforest.codec;

import org.onos.httpddosdetector.classifier.randomforest.RandomForest;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;

/**
 * Codec to load a json model into a random forest classifier
 */
public class RandomForestCodec extends JsonCodec<RandomForest> {
    @Override
    public RandomForest decode(ObjectNode json, CodecContext context) {
        RandomForest forest = new RandomForest();
        forest.Load(json.get("model"));
        return forest;
    }
    
}